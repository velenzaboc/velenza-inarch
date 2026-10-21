//! `CasRef` server-side policy tests (`inarch-cli`).
//!
//! The server must apply its own policy to every `CasRef` RPC, for every caller (including the
//! admin token):
//! - the new target must be a stored changeset;
//! - a move from `expected` to `new_target` must be a fast-forward (`expected` is an ancestor of,
//!   or equal to, `new_target`);
//! - a JIT lease may only move refs named in its `allowed_refs` (or any ref when it holds `"*"`);
//! - a caller with restricted write prefixes may only move a ref onto history whose new
//!   changesets (those reachable from `new_target` but not from `expected`) touch paths inside
//!   those prefixes.
//!
//! Each refusal is an `RpcResponse::Error` whose message contains a frozen substring, and the ref
//! must be unchanged afterwards (verified with `GetRef`).
//!
//! The fast-forward check must cost nothing proportional to the *bodies* of the changesets that
//! are already behind the ref: the policy reads only the parent headers of those ancestors and
//! fully decodes only the changesets new to the ref. The disk-backed tests below prove it by
//! truncating stored ancestor files to their canonical header (magic + parent list), which
//! makes any body decode fail while the parent pointers stay readable.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use inarch_cli::{HttpServerHandle, ServerAuthConfig, spawn_http_server_with_config};
use inarch_engine::ScionEngine;
use inarch_store::{
    FsMetadataStore, JitLeaseRecord, MemBlobStore, MemMetadataStore, MetadataStore,
    RemoteRpcClient, RpcRequest, RpcResponse, StoreError, derive_jit_signing_key,
};
use inarch_types::bonsai::{BonsaiChangeset, FileChange, FileType};
use inarch_types::hash::{BlobId, ChangesetId, ObjectDomain};
use inarch_types::path::MPath;

const ADMIN_TOKEN: &str = "cas-ref-policy-admin-token";
const JIT_KEY_MATERIAL: &str = "cas-ref-policy-test-jit-key-material";
const REPO: &str = "policy-repo";

/// A running token-protected server with a JIT signing key plus an admin client for `REPO`.
struct Fixture {
    server: HttpServerHandle,
    admin: RemoteRpcClient,
}

impl Fixture {
    fn start() -> Self {
        Self::start_with_meta(Arc::new(MemMetadataStore::new()))
    }

    /// Starts the server over the given metadata store (in memory or on disk).
    fn start_with_meta(meta: Arc<dyn MetadataStore>) -> Self {
        let engine = Arc::new(ScionEngine::from_dyn(Arc::new(MemBlobStore::new()), meta));
        let mut auth_cfg = ServerAuthConfig::new(Some(ADMIN_TOKEN.to_string()));
        auth_cfg.jit_signing_key = Some(derive_jit_signing_key(JIT_KEY_MATERIAL));
        let server = spawn_http_server_with_config(engine, "127.0.0.1:0", auth_cfg)
            .expect("spawn token-protected server with a JIT signing key");
        let admin = RemoteRpcClient::new(&server.base_url(), Some(ADMIN_TOKEN.to_string()))
            .expect("build admin rpc client")
            .with_repo_id(REPO);
        Fixture { server, admin }
    }

    fn client_with_token(&self, token: String) -> RemoteRpcClient {
        RemoteRpcClient::new(&self.server.base_url(), Some(token))
            .expect("build token rpc client")
            .with_repo_id(REPO)
    }

    /// Stores a changeset (and its content blobs) through the admin client.
    fn put_changeset(
        &self,
        parents: Vec<ChangesetId>,
        message: &str,
        secs: i64,
        files: &[(&str, &[u8])],
    ) -> ChangesetId {
        let mut file_changes = BTreeMap::new();
        let mut objects = Vec::new();
        for (path, content) in files {
            let blob_id = BlobId::from_content(content);
            objects.push((ObjectDomain::Blob, blob_id.0, content.to_vec()));
            file_changes.insert(
                MPath::new(path).expect("valid test path"),
                FileChange::Tracked {
                    blob_id,
                    size: content.len() as u64,
                    file_type: FileType::Regular,
                },
            );
        }
        if !objects.is_empty() {
            let response = self
                .admin
                .call(&RpcRequest::PutObjectsBatch { objects })
                .expect("PutObjectsBatch transport");
            assert_eq!(
                response,
                RpcResponse::PutObjectsBatchOk,
                "uploading blobs for `{message}` must succeed"
            );
        }
        let changeset = BonsaiChangeset::new(
            parents,
            "policy-dev@example.com".to_string(),
            secs,
            0,
            message.to_string(),
            BTreeMap::new(),
            file_changes,
        )
        .expect("construct changeset");
        let expected_id = changeset.changeset_id();
        let response = self
            .admin
            .call(&RpcRequest::PutChangeset { changeset })
            .expect("PutChangeset transport");
        match response {
            RpcResponse::PutChangeset { id } => {
                assert_eq!(id, expected_id, "server stored a different changeset id");
                id
            }
            other => panic!("unexpected PutChangeset response for `{message}`: {other:?}"),
        }
    }

    fn get_ref(&self, ref_name: &str) -> Option<ChangesetId> {
        match self
            .admin
            .call(&RpcRequest::GetRef {
                repo_id: REPO.to_string(),
                ref_name: ref_name.to_string(),
            })
            .expect("GetRef transport")
        {
            RpcResponse::GetRef { target } => target,
            other => panic!("unexpected GetRef response: {other:?}"),
        }
    }

    /// Checks out a lease through the admin client and returns the lease record and token.
    fn checkout_lease(
        &self,
        write_prefixes: &[&str],
        allowed_refs: &[&str],
    ) -> (JitLeaseRecord, String) {
        let response = self
            .admin
            .call(&RpcRequest::CheckoutLease {
                swarm_id: "swarm-policy".to_string(),
                task_id: "task-policy".to_string(),
                repo_id: REPO.to_string(),
                allowed_ops: vec!["read".to_string(), "land".to_string()],
                allowed_read_prefixes: Vec::new(),
                allowed_write_prefixes: write_prefixes.iter().map(|p| p.to_string()).collect(),
                ttl_secs: 600,
                allowed_refs: allowed_refs.iter().map(|r| r.to_string()).collect(),
            })
            .expect("CheckoutLease transport");
        match response {
            RpcResponse::CheckoutLease { lease, token } => (lease, token),
            other => panic!("expected CheckoutLease, got {other:?}"),
        }
    }
}

fn cas_ref(
    client: &RemoteRpcClient,
    ref_name: &str,
    expected: Option<ChangesetId>,
    new_target: ChangesetId,
) -> RpcResponse {
    client
        .call(&RpcRequest::CasRef {
            repo_id: REPO.to_string(),
            ref_name: ref_name.to_string(),
            expected,
            new_target,
        })
        .expect("CasRef transport")
}

fn assert_cas_ok(response: RpcResponse, context: &str) {
    assert_eq!(response, RpcResponse::CasRefOk, "{context}");
}

fn assert_cas_refused(response: RpcResponse, frozen_substring: &str, context: &str) {
    match response {
        RpcResponse::Error { message } => assert!(
            message.contains(frozen_substring),
            "{context}: expected an error containing `{frozen_substring}`, got `{message}`"
        ),
        other => {
            panic!("{context}: expected an Error containing `{frozen_substring}`, got {other:?}")
        }
    }
}

#[test]
fn non_fast_forward_cas_ref_is_refused_and_ref_does_not_move() {
    let fx = Fixture::start();
    let root = fx.put_changeset(
        Vec::new(),
        "root",
        1_761_400_001,
        &[("base.txt", b"base\n")],
    );
    let x = fx.put_changeset(vec![root], "child x", 1_761_400_002, &[("x.txt", b"x\n")]);
    let y = fx.put_changeset(vec![root], "child y", 1_761_400_003, &[("y.txt", b"y\n")]);
    assert_ne!(x, y, "diverging children must have distinct ids");

    assert_cas_ok(
        cas_ref(&fx.admin, "main", None, root),
        "creating main at the root must succeed",
    );
    assert_cas_ok(
        cas_ref(&fx.admin, "main", Some(root), x),
        "fast-forwarding main from root to x must succeed",
    );
    assert_eq!(fx.get_ref("main"), Some(x));

    // Y is a sibling of X: moving main from X to Y rewrites history, even for the admin token.
    assert_cas_refused(
        cas_ref(&fx.admin, "main", Some(x), y),
        "cas_ref refused: not a fast-forward",
        "admin move from x to diverging y",
    );
    assert_eq!(
        fx.get_ref("main"),
        Some(x),
        "a refused non-fast-forward must leave the ref unchanged"
    );

    fx.server.shutdown();
}

#[test]
fn cas_ref_to_an_unknown_changeset_is_refused_and_ref_does_not_move() {
    let fx = Fixture::start();
    let root = fx.put_changeset(
        Vec::new(),
        "root",
        1_761_400_101,
        &[("base.txt", b"base\n")],
    );
    let x = fx.put_changeset(vec![root], "child x", 1_761_400_102, &[("x.txt", b"x\n")]);
    assert_cas_ok(
        cas_ref(&fx.admin, "main", None, root),
        "creating main at the root must succeed",
    );
    assert_cas_ok(
        cas_ref(&fx.admin, "main", Some(root), x),
        "fast-forwarding main to x must succeed",
    );

    // An id that was never stored as a changeset.
    let never_stored = ChangesetId::from_canonical_bytes(b"cas-ref-policy-never-stored-changeset");
    assert_cas_refused(
        cas_ref(&fx.admin, "main", Some(x), never_stored),
        "cas_ref refused: unknown target changeset",
        "move onto a changeset that was never stored",
    );
    assert_eq!(
        fx.get_ref("main"),
        Some(x),
        "a refused unknown target must leave the ref unchanged"
    );

    // Creating a brand-new ref at an unknown changeset is refused too.
    assert_cas_refused(
        cas_ref(&fx.admin, "fresh", None, never_stored),
        "cas_ref refused: unknown target changeset",
        "create a ref at a changeset that was never stored",
    );
    assert_eq!(fx.get_ref("fresh"), None);

    fx.server.shutdown();
}

#[test]
fn fast_forward_cas_ref_is_accepted() {
    let fx = Fixture::start();
    let root = fx.put_changeset(
        Vec::new(),
        "root",
        1_761_400_201,
        &[("base.txt", b"base\n")],
    );
    let x = fx.put_changeset(vec![root], "child x", 1_761_400_202, &[("x.txt", b"x\n")]);
    let z = fx.put_changeset(vec![x], "child z of x", 1_761_400_203, &[("z.txt", b"z\n")]);

    assert_cas_ok(
        cas_ref(&fx.admin, "main", None, root),
        "creating main at the root must succeed",
    );
    assert_cas_ok(
        cas_ref(&fx.admin, "main", Some(root), x),
        "fast-forward root -> x must succeed",
    );
    assert_cas_ok(
        cas_ref(&fx.admin, "main", Some(x), z),
        "fast-forward x -> z must succeed",
    );
    assert_eq!(fx.get_ref("main"), Some(z));

    // A multi-step fast-forward (expected is an ancestor but not the parent) is also allowed.
    assert_cas_ok(
        cas_ref(&fx.admin, "topic", None, root),
        "creating topic at the root must succeed",
    );
    assert_cas_ok(
        cas_ref(&fx.admin, "topic", Some(root), z),
        "fast-forward root -> z across two changesets must succeed",
    );
    assert_eq!(fx.get_ref("topic"), Some(z));

    fx.server.shutdown();
}

#[test]
fn lease_cannot_move_a_ref_outside_its_allowed_refs() {
    let fx = Fixture::start();
    let root = fx.put_changeset(
        Vec::new(),
        "root",
        1_761_400_301,
        &[("base.txt", b"base\n")],
    );

    let (lease, token) = fx.checkout_lease(&[], &["main"]);
    assert_eq!(
        lease.allowed_refs,
        vec!["main".to_string()],
        "the minted lease must carry the requested allowed_refs"
    );
    let lease_client = fx.client_with_token(token);

    // `release` is not in allowed_refs: refused, and the ref is never created.
    assert_cas_refused(
        cas_ref(&lease_client, "release", None, root),
        "cas_ref refused: ref not allowed by lease",
        "lease moving a ref outside allowed_refs",
    );
    assert_eq!(
        fx.get_ref("release"),
        None,
        "a refused lease move must not create the ref"
    );

    // Positive control: the same lease may move `main`, so the refusal above is about the ref.
    assert_cas_ok(
        cas_ref(&lease_client, "main", None, root),
        "lease moving a ref listed in allowed_refs must succeed",
    );
    assert_eq!(fx.get_ref("main"), Some(root));

    fx.server.shutdown();
}

#[test]
fn lease_with_write_prefixes_cannot_move_a_ref_onto_changesets_outside_them() {
    let fx = Fixture::start();
    // The history below the lease's `expected` head may touch anything: only the new range counts.
    let head = fx.put_changeset(
        Vec::new(),
        "head",
        1_761_400_401,
        &[("src/other/base.txt", b"base\n")],
    );
    assert_cas_ok(
        cas_ref(&fx.admin, "main", None, head),
        "admin creating main at head must succeed",
    );

    // Both candidate changesets are pushed with the admin token (no write-prefix limit there).
    let outside = fx.put_changeset(
        vec![head],
        "touches outside the lease prefixes",
        1_761_400_402,
        &[("src/other/file.txt", b"outside\n")],
    );
    let inside = fx.put_changeset(
        vec![head],
        "touches only the lease prefixes",
        1_761_400_403,
        &[("src/allowed/ok.txt", b"inside\n")],
    );

    let (lease, token) = fx.checkout_lease(&["src/allowed"], &["main"]);
    assert_eq!(
        lease.allowed_write_prefixes,
        vec!["src/allowed".to_string()]
    );
    let lease_client = fx.client_with_token(token);

    assert_cas_refused(
        cas_ref(&lease_client, "main", Some(head), outside),
        "cas_ref refused: changeset outside write prefixes",
        "lease moving main onto a changeset that touches src/other",
    );
    assert_eq!(
        fx.get_ref("main"),
        Some(head),
        "a refused range check must leave the ref unchanged"
    );

    assert_cas_ok(
        cas_ref(&lease_client, "main", Some(head), inside),
        "lease moving main onto a changeset inside its write prefixes must succeed",
    );
    assert_eq!(fx.get_ref("main"), Some(inside));

    fx.server.shutdown();
}

// ============================================================================
// Ancestor cost: the policy reads parent headers, never ancestor bodies
// ============================================================================

/// A metadata store on disk under a per-test directory that is removed on drop.
struct DiskMeta {
    dir: PathBuf,
    meta: Arc<FsMetadataStore>,
}

impl DiskMeta {
    fn create(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "velenza-inarch-cas-ref-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let meta = Arc::new(FsMetadataStore::new(&dir).expect("create FsMetadataStore"));
        DiskMeta { dir, meta }
    }

    fn as_dyn(&self) -> Arc<dyn MetadataStore> {
        let meta: Arc<dyn MetadataStore> = self.meta.clone();
        meta
    }

    /// Stores a changeset with `files` tracked paths (one shared blob), as the benchmark's wide
    /// root does, directly in the store: the server is not involved.
    fn put_wide_root(&self, files: usize) -> ChangesetId {
        let blob = BlobId::from_content(b"module body\n");
        let mut changes = BTreeMap::new();
        for i in 0..files {
            changes.insert(
                MPath::new(&format!("services/svc-{:04}/mod_{:05}.rs", i % 1_000, i))
                    .expect("valid generated path"),
                FileChange::Tracked {
                    blob_id: blob,
                    size: 12,
                    file_type: FileType::Regular,
                },
            );
        }
        let root = BonsaiChangeset::new(
            Vec::new(),
            "wide@example.com".to_string(),
            1_761_400_500,
            0,
            "wide root".to_string(),
            BTreeMap::new(),
            changes,
        )
        .expect("wide root is a valid changeset");
        self.meta.put_changeset(&root).expect("store wide root")
    }

    /// Keeps only the canonical header (magic, parent count, parent ids) of a stored changeset
    /// so that decoding its body fails while its parent pointers remain readable.
    fn truncate_body(&self, id: &ChangesetId, parent_count: usize) {
        let hex = id.to_hex();
        let path = self.dir.join("changesets").join(&hex[0..2]).join(&hex);
        let bytes = std::fs::read(&path).expect("stored changeset file must exist");
        let header_len = 8 + 4 + 32 * parent_count;
        assert!(
            bytes.len() > header_len,
            "changeset {hex} must have a body beyond its {header_len}-byte header"
        );
        std::fs::write(&path, &bytes[..header_len]).expect("truncate changeset body");
        // Positive control: a full decode of this changeset now fails.
        assert!(
            matches!(
                self.meta.get_changeset(id),
                Err(StoreError::SnapshotCorrupted(_))
            ),
            "a truncated changeset body must be unreadable through get_changeset"
        );
    }
}

impl Drop for DiskMeta {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn fast_forward_over_ancestors_with_unreadable_bodies_succeeds() {
    let disk = DiskMeta::create("ff-linear");
    let root = disk.put_wide_root(5_000);
    let fx = Fixture::start_with_meta(disk.as_dyn());

    // Thirty linear changesets on top of the wide root, pushed through the server.
    let mut chain = Vec::new();
    let mut tip = root;
    for i in 0..30 {
        let path = format!("services/svc-0000/change_{i:02}.rs");
        tip = fx.put_changeset(
            vec![tip],
            &format!("linear change {i}"),
            1_761_400_600 + i,
            &[(path.as_str(), b"edit\n")],
        );
        chain.push(tip);
    }
    let head = chain[28];
    let next = chain[29];
    assert_cas_ok(
        cas_ref(&fx.admin, "main", None, head),
        "creating main at the 29th change must succeed while every body is readable",
    );

    // Everything strictly behind `head` keeps only its header.
    disk.truncate_body(&root, 0);
    for id in &chain[..28] {
        disk.truncate_body(id, 1);
    }

    assert_cas_ok(
        cas_ref(&fx.admin, "main", Some(head), next),
        "a fast-forward whose ancestors have unreadable bodies must succeed: the policy reads \
         only their parent headers",
    );
    assert_eq!(fx.get_ref("main"), Some(next));

    fx.server.shutdown();
}

#[test]
fn fast_forward_to_a_merge_reads_only_parent_headers_below_the_base() {
    let disk = DiskMeta::create("ff-merge");
    let root = disk.put_wide_root(5_000);
    let fx = Fixture::start_with_meta(disk.as_dyn());

    // main: root -> b1 -> b2.   topic: root -> a1.   merge m has parents [b2, a1].
    let b1 = fx.put_changeset(vec![root], "b1", 1_761_400_701, &[("b/one.txt", b"b1\n")]);
    let b2 = fx.put_changeset(vec![b1], "b2", 1_761_400_702, &[("b/two.txt", b"b2\n")]);
    let a1 = fx.put_changeset(vec![root], "a1", 1_761_400_703, &[("a/one.txt", b"a1\n")]);
    let merge = fx.put_changeset(
        vec![b2, a1],
        "merge a1 into b2",
        1_761_400_704,
        &[("merge.txt", b"m\n")],
    );
    assert_cas_ok(
        cas_ref(&fx.admin, "main", None, b2),
        "creating main at b2 must succeed while every body is readable",
    );

    // The history below b2 keeps only its headers; b2, a1 and the merge stay readable.
    disk.truncate_body(&root, 0);
    disk.truncate_body(&b1, 1);

    // b2 is an ancestor of the merge, so this is a fast-forward whose new changesets are the
    // merge and a1. The walk from a1 reaches the wide root, which is behind the base: its body
    // must never be decoded.
    assert_cas_ok(
        cas_ref(&fx.admin, "main", Some(b2), merge),
        "fast-forwarding main onto a merge must succeed when the shared history below the base \
         has unreadable bodies",
    );
    assert_eq!(fx.get_ref("main"), Some(merge));

    fx.server.shutdown();
}

#[test]
fn non_fast_forward_is_refused_through_parent_headers_with_unreadable_ancestor_bodies() {
    let disk = DiskMeta::create("nff");
    let root = disk.put_wide_root(5_000);
    let fx = Fixture::start_with_meta(disk.as_dyn());

    let b1 = fx.put_changeset(vec![root], "b1", 1_761_400_801, &[("b/one.txt", b"b1\n")]);
    let b2 = fx.put_changeset(vec![b1], "b2", 1_761_400_802, &[("b/two.txt", b"b2\n")]);
    let a1 = fx.put_changeset(vec![root], "a1", 1_761_400_803, &[("a/one.txt", b"a1\n")]);
    assert_cas_ok(
        cas_ref(&fx.admin, "main", None, b2),
        "creating main at b2 must succeed while every body is readable",
    );

    // The whole base side keeps only headers; the candidate a1 stays readable.
    disk.truncate_body(&root, 0);
    disk.truncate_body(&b1, 1);
    disk.truncate_body(&b2, 1);

    assert_cas_refused(
        cas_ref(&fx.admin, "main", Some(b2), a1),
        "cas_ref refused: not a fast-forward",
        "moving main from b2 onto the sibling a1 with unreadable ancestor bodies",
    );
    assert_eq!(
        fx.get_ref("main"),
        Some(b2),
        "a refused non-fast-forward must leave the ref unchanged"
    );

    fx.server.shutdown();
}

#[test]
fn write_prefix_check_still_decodes_the_new_changesets_over_unreadable_ancestors() {
    let disk = DiskMeta::create("prefix");
    let root = disk.put_wide_root(5_000);
    let fx = Fixture::start_with_meta(disk.as_dyn());

    let head = fx.put_changeset(
        vec![root],
        "head",
        1_761_400_901,
        &[("src/other/base.txt", b"base\n")],
    );
    assert_cas_ok(
        cas_ref(&fx.admin, "main", None, head),
        "admin creating main at head must succeed",
    );
    let outside = fx.put_changeset(
        vec![head],
        "touches outside the lease prefixes",
        1_761_400_902,
        &[("src/other/file.txt", b"outside\n")],
    );
    let inside = fx.put_changeset(
        vec![head],
        "touches only the lease prefixes",
        1_761_400_903,
        &[("src/allowed/ok.txt", b"inside\n")],
    );

    // The base and the wide root keep only headers; the candidates stay readable.
    disk.truncate_body(&root, 0);
    disk.truncate_body(&head, 1);

    let (_lease, token) = fx.checkout_lease(&["src/allowed"], &["main"]);
    let lease_client = fx.client_with_token(token);

    assert_cas_refused(
        cas_ref(&lease_client, "main", Some(head), outside),
        "cas_ref refused: changeset outside write prefixes",
        "lease moving main onto a readable changeset that touches src/other",
    );
    assert_eq!(fx.get_ref("main"), Some(head));

    assert_cas_ok(
        cas_ref(&lease_client, "main", Some(head), inside),
        "lease moving main onto a readable changeset inside its write prefixes must succeed",
    );
    assert_eq!(fx.get_ref("main"), Some(inside));

    fx.server.shutdown();
}

#[test]
fn write_prefix_check_decodes_every_changeset_new_to_the_ref_not_only_the_target() {
    let disk = DiskMeta::create("prefix-range");
    let root = disk.put_wide_root(5_000);
    let fx = Fixture::start_with_meta(disk.as_dyn());

    let head = fx.put_changeset(
        vec![root],
        "head",
        1_761_401_101,
        &[("src/other/base.txt", b"base\n")],
    );
    assert_cas_ok(
        cas_ref(&fx.admin, "main", None, head),
        "admin creating main at head must succeed",
    );

    // A two-changeset range whose first step leaves the lease prefixes while its target, the
    // only changeset a target-only check would look at, stays inside them.
    let n1 = fx.put_changeset(
        vec![head],
        "steps outside the lease prefixes",
        1_761_401_102,
        &[("src/other/file.txt", b"outside\n")],
    );
    let n2 = fx.put_changeset(
        vec![n1],
        "returns inside the lease prefixes",
        1_761_401_103,
        &[("src/allowed/ok.txt", b"inside\n")],
    );
    // A two-changeset range entirely inside the lease prefixes.
    let i1 = fx.put_changeset(
        vec![head],
        "inside one",
        1_761_401_104,
        &[("src/allowed/one.txt", b"one\n")],
    );
    let i2 = fx.put_changeset(
        vec![i1],
        "inside two",
        1_761_401_105,
        &[("src/allowed/two.txt", b"two\n")],
    );

    // The base and the wide root keep only headers; every candidate stays readable.
    disk.truncate_body(&root, 0);
    disk.truncate_body(&head, 1);

    let (_lease, token) = fx.checkout_lease(&["src/allowed"], &["main"]);
    let lease_client = fx.client_with_token(token);

    assert_cas_refused(
        cas_ref(&lease_client, "main", Some(head), n2),
        "cas_ref refused: changeset outside write prefixes",
        "lease moving main across a range whose non-target changeset touches src/other",
    );
    assert_eq!(
        fx.get_ref("main"),
        Some(head),
        "a refused range must leave the ref unchanged"
    );

    assert_cas_ok(
        cas_ref(&lease_client, "main", Some(head), i2),
        "lease moving main across a two-changeset range inside its write prefixes must succeed",
    );
    assert_eq!(fx.get_ref("main"), Some(i2));

    // With a base set, a non-target changeset new to the ref whose body is unreadable refuses
    // the move with the inspect error: every new changeset is fully decoded, not only the target.
    let u1 = fx.put_changeset(
        vec![i2],
        "unreadable step",
        1_761_401_106,
        &[("src/allowed/u1.txt", b"u1\n")],
    );
    let u2 = fx.put_changeset(
        vec![u1],
        "readable target",
        1_761_401_107,
        &[("src/allowed/u2.txt", b"u2\n")],
    );
    disk.truncate_body(&u1, 1);
    assert_cas_refused(
        cas_ref(&lease_client, "main", Some(i2), u2),
        "failed to inspect changeset",
        "moving main across a range whose non-target new changeset has an unreadable body",
    );
    assert_eq!(fx.get_ref("main"), Some(i2));

    fx.server.shutdown();
}

#[test]
fn creating_a_ref_fully_decodes_every_new_changeset_and_refuses_an_unreadable_one() {
    let disk = DiskMeta::create("unset-ref");
    let root = disk.put_wide_root(5_000);
    let fx = Fixture::start_with_meta(disk.as_dyn());

    let c1 = fx.put_changeset(vec![root], "c1", 1_761_401_001, &[("c/one.txt", b"c1\n")]);
    assert_cas_ok(
        cas_ref(&fx.admin, "early", None, c1),
        "creating a ref while every new changeset is readable must succeed",
    );

    // With no expected head and no current ref, every ancestor of the target is new to the
    // ref, so each one is fully decoded and an unreadable one refuses the move.
    disk.truncate_body(&root, 0);
    assert_cas_refused(
        cas_ref(&fx.admin, "fresh", None, c1),
        "failed to inspect changeset",
        "creating a ref over a new changeset whose body is unreadable",
    );
    assert_eq!(fx.get_ref("fresh"), None);

    fx.server.shutdown();
}
