//! `PutDerivedMapping` server-side verification tests (`inarch-cli`).
//!
//! A remote client must never be able to plant an arbitrary derived-data root for a changeset: the
//! server recomputes the Fsnode / Unode root itself and refuses (and never stores) a client value
//! that differs. Only the Fsnode and Unode families may be written by clients at all.
//!
//! Each test starts a fresh anonymous in-memory server and seeds one real changeset with file
//! content directly through the server's own engine (`land_patch` writes the blobs and the
//! changeset but never a derived mapping, so no mapping exists before the client speaks). The true
//! derived roots are computed by an independent reference engine fed the identical submission;
//! changesets are content addressed, so both engines hold the same changeset id.

use std::collections::BTreeMap;
use std::sync::Arc;

use inarch_cli::HttpServerHandle;
use inarch_engine::{PatchFileEdit, PatchSubmission, ScionEngine};
use inarch_store::{
    DerivedDataKind, MemBlobStore, MemMetadataStore, RemoteRpcClient, RpcRequest, RpcResponse,
};
use inarch_types::bonsai::FileType;
use inarch_types::hash::{ChangesetId, ObjectHash};
use inarch_types::path::MPath;

/// A running anonymous server plus the seeded changeset and its true (reference) derived roots.
struct Seeded {
    server: HttpServerHandle,
    client: RemoteRpcClient,
    cs_id: ChangesetId,
    true_fsnode: ObjectHash,
    true_unode: ObjectHash,
}

fn submission() -> PatchSubmission {
    PatchSubmission {
        target_ref: "seed".to_string(),
        base_changeset: None,
        author: "derived-dev@example.com".to_string(),
        timestamp: 1_761_400_001,
        tz_offset_secs: 0,
        message: "seed changeset with file content".to_string(),
        extra: BTreeMap::new(),
        edits: vec![
            PatchFileEdit::Upsert {
                path: MPath::new("README.md").unwrap(),
                content: b"# Derived mapping verification\n".to_vec(),
                file_type: FileType::Regular,
            },
            PatchFileEdit::Upsert {
                path: MPath::new("src/lib.rs").unwrap(),
                content: b"pub fn answer() -> u32 { 42 }\n".to_vec(),
                file_type: FileType::Regular,
            },
        ],
    }
}

fn mem_engine() -> Arc<ScionEngine> {
    Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ))
}

fn bogus_hash() -> ObjectHash {
    ObjectHash([0xAB; 32])
}

fn seed_server() -> Seeded {
    // Server engine: holds the blobs and the changeset, but no derived mappings.
    let server_engine = mem_engine();
    let landed = server_engine
        .land_patch(submission())
        .expect("seed changeset on the server engine");
    let cs_id = landed.changeset_id;

    // Reference engine: identical content-addressed changeset, used only to learn the true roots.
    let reference = mem_engine();
    let reference_landed = reference
        .land_patch(submission())
        .expect("seed changeset on the reference engine");
    assert_eq!(
        reference_landed.changeset_id, cs_id,
        "reference and server changesets must be identical"
    );
    let true_fsnode = reference
        .derived()
        .derive_fsnode(cs_id)
        .expect("reference fsnode derivation")
        .0;
    let true_unode = reference
        .derived()
        .derive_unode(cs_id)
        .expect("reference unode derivation")
        .0;
    assert_ne!(
        true_fsnode,
        bogus_hash(),
        "bogus hash must differ from truth"
    );
    assert_ne!(
        true_unode,
        bogus_hash(),
        "bogus hash must differ from truth"
    );

    // Sanity: the server holds no mapping yet (so a stored bogus value could only come from the
    // client's PutDerivedMapping below).
    assert_eq!(
        server_engine
            .meta()
            .get_derived_mapping(cs_id, DerivedDataKind::Fsnode)
            .expect("read server fsnode mapping"),
        None,
        "server must start without an Fsnode mapping"
    );
    assert_eq!(
        server_engine
            .meta()
            .get_derived_mapping(cs_id, DerivedDataKind::Unode)
            .expect("read server unode mapping"),
        None,
        "server must start without a Unode mapping"
    );

    let server = inarch_cli::spawn_http_server_with_config(
        server_engine,
        "127.0.0.1:0",
        inarch_cli::ServerAuthConfig::insecure_allow_anonymous(),
    )
    .expect("spawn anonymous in-memory server");
    let client = RemoteRpcClient::new(&server.base_url(), None).expect("build rpc client");

    Seeded {
        server,
        client,
        cs_id,
        true_fsnode,
        true_unode,
    }
}

fn put_mapping(seeded: &Seeded, kind: DerivedDataKind, derived_hash: ObjectHash) -> RpcResponse {
    seeded
        .client
        .call(&RpcRequest::PutDerivedMapping {
            cs_id: seeded.cs_id,
            kind,
            derived_hash,
        })
        .expect("PutDerivedMapping transport")
}

fn get_mapping(seeded: &Seeded, kind: DerivedDataKind) -> Option<ObjectHash> {
    match seeded
        .client
        .call(&RpcRequest::GetDerivedMapping {
            cs_id: seeded.cs_id,
            kind,
        })
        .expect("GetDerivedMapping transport")
    {
        RpcResponse::GetDerivedMapping { derived_hash } => derived_hash,
        other => panic!("unexpected GetDerivedMapping response: {other:?}"),
    }
}

fn assert_error_contains(response: &RpcResponse, needle: &str, context: &str) {
    match response {
        RpcResponse::Error { message } => assert!(
            message.contains(needle),
            "{context}: error message must contain `{needle}`, got: {message}"
        ),
        other => {
            panic!("{context}: expected RpcResponse::Error containing `{needle}`, got {other:?}")
        }
    }
}

/// The stored mapping must be absent or the server-computed truth; never the client's bogus value.
fn assert_stored_is_not_bogus(stored: Option<ObjectHash>, truth: ObjectHash, kind: &str) {
    assert_ne!(
        stored,
        Some(bogus_hash()),
        "{kind} mapping must never hold the client-supplied bogus hash"
    );
    if let Some(hash) = stored {
        assert_eq!(
            hash, truth,
            "{kind} mapping, when present, must be the server-computed root"
        );
    }
}

#[test]
fn bogus_fsnode_mapping_is_refused_and_not_stored() {
    let seeded = seed_server();

    let response = put_mapping(&seeded, DerivedDataKind::Fsnode, bogus_hash());
    assert_error_contains(
        &response,
        "derived mapping mismatch",
        "bogus Fsnode mapping",
    );

    let stored = get_mapping(&seeded, DerivedDataKind::Fsnode);
    assert_stored_is_not_bogus(stored, seeded.true_fsnode, "Fsnode");

    // A later correct submission for the same changeset is still accepted.
    let ok = put_mapping(&seeded, DerivedDataKind::Fsnode, seeded.true_fsnode);
    assert_eq!(
        ok,
        RpcResponse::PutDerivedMappingOk,
        "the true Fsnode root must be accepted after a refused bogus one"
    );
    assert_eq!(
        get_mapping(&seeded, DerivedDataKind::Fsnode),
        Some(seeded.true_fsnode),
        "the accepted Fsnode mapping must be the true root"
    );

    seeded.server.shutdown();
}

#[test]
fn correct_fsnode_mapping_is_accepted() {
    let seeded = seed_server();

    let response = put_mapping(&seeded, DerivedDataKind::Fsnode, seeded.true_fsnode);
    assert_eq!(
        response,
        RpcResponse::PutDerivedMappingOk,
        "the true Fsnode root must be accepted"
    );
    assert_eq!(
        get_mapping(&seeded, DerivedDataKind::Fsnode),
        Some(seeded.true_fsnode),
        "the stored Fsnode mapping must be the true root"
    );

    seeded.server.shutdown();
}

#[test]
fn bogus_unode_mapping_is_refused_and_not_stored() {
    let seeded = seed_server();

    let response = put_mapping(&seeded, DerivedDataKind::Unode, bogus_hash());
    assert_error_contains(&response, "derived mapping mismatch", "bogus Unode mapping");

    let stored = get_mapping(&seeded, DerivedDataKind::Unode);
    assert_stored_is_not_bogus(stored, seeded.true_unode, "Unode");

    let ok = put_mapping(&seeded, DerivedDataKind::Unode, seeded.true_unode);
    assert_eq!(
        ok,
        RpcResponse::PutDerivedMappingOk,
        "the true Unode root must be accepted after a refused bogus one"
    );
    assert_eq!(
        get_mapping(&seeded, DerivedDataKind::Unode),
        Some(seeded.true_unode),
        "the accepted Unode mapping must be the true root"
    );

    seeded.server.shutdown();
}

#[test]
fn blame_and_commit_graph_mappings_are_not_accepted_from_clients() {
    let seeded = seed_server();

    for (kind, label) in [
        (DerivedDataKind::BlameV2, "BlameV2"),
        (DerivedDataKind::CommitGraph, "CommitGraph"),
    ] {
        // Neither a bogus value nor a plausible-looking one (the true Fsnode root) may be stored.
        for candidate in [bogus_hash(), seeded.true_fsnode] {
            let response = put_mapping(&seeded, kind, candidate);
            assert_error_contains(
                &response,
                "derived mapping kind not accepted from clients",
                label,
            );
            assert_eq!(
                get_mapping(&seeded, kind),
                None,
                "{label} mapping must not be stored from a client request"
            );
        }
    }

    seeded.server.shutdown();
}
