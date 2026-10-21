//! End-to-End Networked Client/Server & Multi-Workstation Tests (`inarch-cli`).
//!
//! Validates:
//! 1. Stateless HTTP/1.1 keep-alive RPC server (`spawn_http_server`) with Bearer token auth.
//! 2. Multi-workstation collaboration: Workstation A ingests & commits a project over `remote_url`;
//!    Workstation B (cold local cache) reads files checkout-free, verifies 100% accuracy, and
//!    materializes a stateless tree-walk checkout.
//! 3. Multi-repository ref isolation (`repo_id = "service-alpha"` vs `repo_id = "service-beta"`)
//!    sharing a single server instance and global content-addressed store.
//! 4. High-concurrency lock-free speculative rebase across 8 concurrent remote agent clients.

#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use inarch_cli::{
    InarchConfig, checkout_stateless, ingest_directory, spawn_http_server, verify_codebase_accuracy,
};
use inarch_engine::{PatchFileEdit, PatchSubmission, ScionEngine};
use inarch_store::{FsBlobStore, FsMetadataStore, MemBlobStore, MemMetadataStore};
use inarch_types::bonsai::FileType;
use inarch_types::path::MPath;

fn unique_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "velenza-inarch-remote-test-{}-{}-{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn multi_workstation_remote_commit_checkout_and_repo_isolation() {
    let root = unique_temp_dir("multi-ws");
    let server_blobs_dir = root.join("server/blobs");
    let server_meta_dir = root.join("server/meta");
    let ws_a_dir = root.join("ws-a");
    let ws_b_dir = root.join("ws-b");
    let project_src = root.join("project-src");
    let ws_b_checkout = root.join("ws-b-checkout");

    fs::create_dir_all(&ws_a_dir).unwrap();
    fs::create_dir_all(&ws_b_dir).unwrap();
    fs::create_dir_all(project_src.join("src/nested")).unwrap();

    fs::write(
        project_src.join("Cargo.toml"),
        b"[package]\nname = \"networked-demo\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(
        project_src.join("src/lib.rs"),
        b"pub mod nested;\npub fn answer() -> u32 { nested::value() + 2 }\n",
    )
    .unwrap();
    fs::write(
        project_src.join("src/nested/mod.rs"),
        b"pub fn value() -> u32 { 40 }\n",
    )
    .unwrap();

    let server_blobs = Arc::new(FsBlobStore::new(&server_blobs_dir).unwrap());
    let server_meta = Arc::new(FsMetadataStore::new(&server_meta_dir).unwrap());
    let server_engine = Arc::new(ScionEngine::new(server_blobs, server_meta));
    let server = spawn_http_server(
        server_engine,
        "127.0.0.1:0",
        Some("test-secret-token".to_string()),
    )
    .expect("spawn Velenza Inarch HTTP server");

    let remote_url = format!("http://{}", server.local_addr());

    // Workstation A configuration (with local Tier-1 cache)
    let mut cfg_a = InarchConfig::default();
    cfg_a.repo_id = "service-alpha".to_string();
    cfg_a.remote_url = remote_url.clone();
    cfg_a.auth_token = "test-secret-token".to_string();
    cfg_a.tier1_cache_dir = ".inarch/cache-t1".to_string();

    let engine_a = cfg_a.open_engine(&ws_a_dir).expect("open ws-a engine");
    let ignore_a = cfg_a.ignore_slices();
    let receipt = ingest_directory(
        &engine_a,
        "main",
        "dev-a@example.com",
        1_761_100_000,
        "initial remote commit from workstation A",
        &project_src,
        &ignore_a,
    )
    .expect("ingest project from workstation A over HTTP");
    assert_eq!(receipt.files_scanned, 3);
    assert_eq!(receipt.files_upserted, 3);

    // Workstation B configuration (independent machine with cold cache)
    let mut cfg_b = InarchConfig::default();
    cfg_b.repo_id = "service-alpha".to_string();
    cfg_b.remote_url = remote_url.clone();
    cfg_b.auth_token = "test-secret-token".to_string();
    cfg_b.tier1_cache_dir = ".inarch/cache-t1".to_string();

    let engine_b = cfg_b.open_engine(&ws_b_dir).expect("open ws-b engine");
    let head_b = engine_b
        .resolve_ref("main")
        .expect("resolve main on ws-b")
        .expect("main exists on server");
    assert_eq!(head_b, receipt.changeset_id);

    // Checkout-free read on Workstation B
    let content = engine_b
        .read_file(head_b, &MPath::new("src/nested/mod.rs").unwrap())
        .expect("checkout-free read_file on ws-b");
    assert_eq!(content, b"pub fn value() -> u32 { 40 }\n");

    // 100% accuracy verification & stateless checkout on Workstation B
    let report = verify_codebase_accuracy(&engine_b, head_b, &project_src, &ignore_a)
        .expect("verify accuracy on ws-b");
    assert_eq!(report.files_verified, 3);

    let co = checkout_stateless(&engine_b, head_b, None, &ws_b_checkout)
        .expect("stateless checkout on ws-b");
    assert_eq!(co.files_materialized, 3);
    let co_verify = verify_codebase_accuracy(&engine_b, head_b, &ws_b_checkout, &ignore_a)
        .expect("verify materialized checkout on ws-b");
    assert_eq!(co_verify.bytes_verified, report.bytes_verified);

    // Verify multi-repository isolation (`service-beta` sees no `main` ref until committed)
    let mut cfg_beta = cfg_b.clone();
    cfg_beta.repo_id = "service-beta".to_string();
    let engine_beta = cfg_beta.open_engine(&ws_b_dir).expect("open beta engine");
    assert_eq!(engine_beta.resolve_ref("main").unwrap(), None);

    server.shutdown();
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn eight_concurrent_remote_agents_speculative_rebase_over_http() {
    let server_blobs = Arc::new(MemBlobStore::new());
    let server_meta = Arc::new(MemMetadataStore::new());
    let server_engine = Arc::new(ScionEngine::new(server_blobs, server_meta));
    let server = inarch_cli::spawn_http_server_with_config(
        server_engine,
        "127.0.0.1:0",
        inarch_cli::ServerAuthConfig::insecure_allow_anonymous(),
    )
    .expect("spawn in-memory HTTP server");
    let remote_url = format!("http://{}", server.local_addr());

    let root = unique_temp_dir("concurrent-agents");
    let mut base_cfg = InarchConfig::default();
    base_cfg.repo_id = "swarm-repo".to_string();
    base_cfg.remote_url = remote_url.clone();

    let seed_engine = base_cfg.open_engine(&root).unwrap();
    let base_out = seed_engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "coordinator@example.com".to_string(),
            timestamp: 1_761_200_000,
            tz_offset_secs: 0,
            message: "seed root".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("README.md").unwrap(),
                content: b"# Swarm Repo\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect("seed base changeset");

    let mut handles = Vec::new();
    for agent_id in 0..8 {
        let cfg = base_cfg.clone();
        let ws = root.join(format!("agent-{}", agent_id));
        fs::create_dir_all(&ws).unwrap();
        let base_cs = base_out.changeset_id;
        handles.push(std::thread::spawn(move || {
            let eng = cfg.open_engine(&ws).unwrap();
            eng.land_patch(PatchSubmission {
                target_ref: "main".to_string(),
                base_changeset: Some(base_cs),
                author: format!("agent-{}@example.com", agent_id),
                timestamp: 1_761_200_010 + agent_id as i64,
                tz_offset_secs: 0,
                message: format!("agent {} patch", agent_id),
                extra: BTreeMap::new(),
                edits: vec![PatchFileEdit::Upsert {
                    path: MPath::new(&format!("agents/a{}.rs", agent_id)).unwrap(),
                    content: format!("pub const ID: usize = {};\n", agent_id).into_bytes(),
                    file_type: FileType::Regular,
                }],
            })
            .expect("remote agent speculative rebase")
        }));
    }

    let mut max_rebased = 0usize;
    for h in handles {
        let res = h.join().unwrap();
        max_rebased = max_rebased.max(res.rebased_across);
    }
    assert!(max_rebased >= 1);

    let final_head = seed_engine.resolve_ref("main").unwrap().unwrap();
    let entries = seed_engine
        .list_directory(final_head, Some(&MPath::new("agents").unwrap()))
        .unwrap();
    assert_eq!(entries.len(), 8);

    server.shutdown();
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn workstation_oidc_principal_enrollment_and_jit_swarm_lease_enforcement() {
    use inarch_cli::{LocalJitLeaseFile, ServerAuthConfig, spawn_http_server_with_config};
    use inarch_store::{PrincipalRecord, RpcRequest, RpcResponse};
    use std::io::{Read, Write};

    // 1. Spawn a lightweight mock OIDC tokeninfo server on 127.0.0.1:0
    let oidc_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let oidc_addr = oidc_listener.local_addr().unwrap();
    let oidc_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let oidc_stop_clone = Arc::clone(&oidc_stop);

    std::thread::spawn(move || {
        for stream_res in oidc_listener.incoming() {
            if oidc_stop_clone.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let Ok(mut s) = stream_res else {
                continue;
            };
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]);
            let (status, body) = if req_str.contains("id_token=oidc-tok-ws-alpha") {
                (
                    "200 OK",
                    r#"{"email":"device-alpha@example.com","email_verified":"true","exp":"4102444800","aud":"https://inarch.example.com"}"#,
                )
            } else if req_str.contains("id_token=oidc-tok-ws-beta") {
                (
                    "200 OK",
                    r#"{"email":"device-beta@example.com","email_verified":"true","exp":"4102444800","aud":"https://inarch.example.com"}"#,
                )
            } else {
                (
                    "400 Bad Request",
                    r#"{"error":"invalid_token","error_description":"unknown test token"}"#,
                )
            };
            let resp = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.flush();
        }
    });

    // 2. Spawn Velenza Inarch HTTP server with admin bootstrap token, JIT signing key, and mock OIDC URL
    let server_blobs = Arc::new(MemBlobStore::new());
    let server_meta = Arc::new(MemMetadataStore::new());
    let server_engine = Arc::new(ScionEngine::new(server_blobs, server_meta));

    let mut auth_cfg = ServerAuthConfig::new(Some("bootstrap-admin-secret".to_string()));
    auth_cfg.jit_signing_key = Some(inarch_store::derive_jit_signing_key(
        "remote-server-test-jit-key-material",
    ));
    auth_cfg.oidc_audience = Some("https://inarch.example.com".to_string());
    auth_cfg.oidc_tokeninfo_url = Some(format!("http://{}/tokeninfo", oidc_addr));
    auth_cfg.require_auth = true;

    let server = spawn_http_server_with_config(server_engine, "127.0.0.1:0", auth_cfg)
        .expect("spawn Velenza Inarch server with OIDC + JIT auth");
    let remote_url = format!("http://{}", server.local_addr());

    let root = unique_temp_dir("oidc-jit");
    let admin_dir = root.join("admin");
    let ws_alpha_dir = root.join("ws-alpha");
    let ws_beta_dir = root.join("ws-beta");
    let swarm_dir = root.join("swarm-worktree");
    fs::create_dir_all(&admin_dir).unwrap();
    fs::create_dir_all(&ws_alpha_dir).unwrap();
    fs::create_dir_all(&ws_beta_dir).unwrap();
    fs::create_dir_all(&swarm_dir).unwrap();

    // 3. Admin enrolls workstation `device-alpha@example.com` for repo `repo-core`
    let mut admin_cfg = InarchConfig::default();
    admin_cfg.remote_url = remote_url.clone();
    admin_cfg.auth_token = "bootstrap-admin-secret".to_string();
    admin_cfg.repo_id = "repo-core".to_string();

    let admin_client = admin_cfg.open_remote_client(&admin_dir).unwrap();
    let enroll_resp = admin_client
        .call(&RpcRequest::EnrollPrincipal {
            record: PrincipalRecord {
                principal_email: "device-alpha@example.com".to_string(),
                principal_kind: "workstation".to_string(),
                host_label: "ws-alpha".to_string(),
                allowed_repos: vec!["repo-core".to_string()],
                allowed_ops: vec!["read".to_string(), "land".to_string()],
                status: "active".to_string(),
                enrolled_by: String::new(),
                created_at_unix: 1_761_300_000,
                revoked_at_unix: None,
                allowed_write_prefixes: vec!["*".to_string()],
            },
        })
        .unwrap();
    assert_eq!(enroll_resp, RpcResponse::EnrollPrincipalOk);

    // 4. Unenrolled workstation `device-beta@example.com` is rejected (401 Unauthorized)
    let mut beta_cfg = InarchConfig::default();
    beta_cfg.remote_url = remote_url.clone();
    beta_cfg.auth_token = "oidc-tok-ws-beta".to_string();
    beta_cfg.repo_id = "repo-core".to_string();
    let beta_client = beta_cfg.open_remote_client(&ws_beta_dir).unwrap();
    assert!(beta_client.call(&RpcRequest::WhoAmI).is_err());

    // 5. Enrolled workstation `device-alpha@example.com` authenticates via OIDC token & seeds `repo-core`
    let mut alpha_cfg = InarchConfig::default();
    alpha_cfg.remote_url = remote_url.clone();
    alpha_cfg.auth_token = "oidc-tok-ws-alpha".to_string();
    alpha_cfg.repo_id = "repo-core".to_string();

    let alpha_client = alpha_cfg.open_remote_client(&ws_alpha_dir).unwrap();
    match alpha_client.call(&RpcRequest::WhoAmI).unwrap() {
        RpcResponse::WhoAmI {
            principal_id,
            role,
            auth_method,
            lease,
        } => {
            assert_eq!(principal_id, "device-alpha@example.com");
            assert_eq!(role, "workstation");
            assert_eq!(auth_method, "gcp_oidc");
            assert!(lease.is_none());
        }
        other => panic!("unexpected WhoAmI response: {:?}", other),
    }

    // Workstation alpha cannot access `repo-secret`
    let mut alpha_other_repo = alpha_cfg.clone();
    alpha_other_repo.repo_id = "repo-secret".to_string();
    let alpha_other_engine = alpha_other_repo.open_engine(&ws_alpha_dir).unwrap();
    assert!(alpha_other_engine.resolve_ref("main").is_err());

    // Workstation alpha seeds initial files into `repo-core`
    let alpha_engine = alpha_cfg.open_engine(&ws_alpha_dir).unwrap();
    let seed_out = alpha_engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "device-alpha@example.com".to_string(),
            timestamp: 1_761_300_100,
            tz_offset_secs: 0,
            message: "seed repo-core".to_string(),
            extra: BTreeMap::new(),
            edits: vec![
                PatchFileEdit::Upsert {
                    path: MPath::new("crates/allowed/lib.rs").unwrap(),
                    content: b"pub fn allowed() -> u32 { 1 }\n".to_vec(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("crates/forbidden/secret.rs").unwrap(),
                    content: b"pub fn secret() -> u32 { 99 }\n".to_vec(),
                    file_type: FileType::Regular,
                },
            ],
        })
        .expect("seed repo-core from workstation alpha");

    // 6. Workstation alpha checks out a Just-In-Time (JIT) lease for a spawned swarm
    //    restricted to `repo-core` and write prefix `crates/allowed`
    let (jit_lease, jit_token) = match alpha_client
        .call(&RpcRequest::CheckoutLease {
            swarm_id: "swarm-07".to_string(),
            task_id: "TASK-404".to_string(),
            repo_id: "repo-core".to_string(),
            allowed_ops: vec!["read".to_string(), "land".to_string()],
            allowed_read_prefixes: Vec::new(),
            allowed_write_prefixes: vec!["crates/allowed".to_string()],
            ttl_secs: 600,
            allowed_refs: vec!["main".to_string()],
        })
        .unwrap()
    {
        RpcResponse::CheckoutLease { lease, token } => (lease, token),
        other => panic!("expected CheckoutLease, got {:?}", other),
    };
    assert_eq!(jit_lease.principal_email, "device-alpha@example.com");
    assert_eq!(jit_lease.repo_id, "repo-core");
    assert_eq!(jit_lease.allowed_refs, vec!["main".to_string()]);
    assert!(jit_lease.allowed_read_prefixes.is_empty());

    // Write `.inarch/jit_lease.json` into `swarm_dir`. Notice `swarm_cfg` has NO `auth_token` and NO `gcp_credentials_file`!
    let lease_file_path = LocalJitLeaseFile::resolve_path(&swarm_dir, "");
    LocalJitLeaseFile::from_lease_and_token(&jit_lease, jit_token)
        .write_to_file(&lease_file_path)
        .unwrap();

    let mut swarm_cfg = InarchConfig::default();
    swarm_cfg.remote_url = remote_url.clone();
    swarm_cfg.repo_id = "repo-core".to_string();

    let swarm_client = swarm_cfg.open_remote_client(&swarm_dir).unwrap();
    match swarm_client.call(&RpcRequest::WhoAmI).unwrap() {
        RpcResponse::WhoAmI {
            principal_id,
            role,
            auth_method,
            lease,
        } => {
            assert!(principal_id.starts_with("swarm:swarm-07:TASK-404:"));
            assert_eq!(role, "jit_swarm");
            assert_eq!(auth_method, "jit_lease");
            assert!(lease.is_some());
        }
        other => panic!("unexpected swarm WhoAmI: {:?}", other),
    }

    // 7. Swarm can read and land changes under `crates/allowed/...`
    let swarm_engine = swarm_cfg.open_engine(&swarm_dir).unwrap();
    let allowed_land = swarm_engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: Some(seed_out.changeset_id),
            author: "swarm-07@example.com".to_string(),
            timestamp: 1_761_300_200,
            tz_offset_secs: 0,
            message: "swarm edit inside allowed write prefix".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("crates/allowed/lib.rs").unwrap(),
                content: b"pub fn allowed() -> u32 { 2 }\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect("swarm land inside crates/allowed");

    // 8. Swarm is BLOCKED from modifying `crates/forbidden/secret.rs` (write-prefix violation)
    let forbidden_land = swarm_engine.land_patch(PatchSubmission {
        target_ref: "main".to_string(),
        base_changeset: Some(allowed_land.changeset_id),
        author: "swarm-07@example.com".to_string(),
        timestamp: 1_761_300_210,
        tz_offset_secs: 0,
        message: "attempt edit outside allowed_write_prefixes".to_string(),
        extra: BTreeMap::new(),
        edits: vec![PatchFileEdit::Upsert {
            path: MPath::new("crates/forbidden/secret.rs").unwrap(),
            content: b"pub fn hijacked() -> u32 { 0 }\n".to_vec(),
            file_type: FileType::Regular,
        }],
    });
    assert!(
        forbidden_land.is_err(),
        "swarm write outside allowed_write_prefixes must be rejected"
    );

    // 9. Swarm is BLOCKED from minting sub-leases or accessing another repo
    match swarm_client
        .call(&RpcRequest::CheckoutLease {
            swarm_id: "sub-swarm".to_string(),
            task_id: "sub-task".to_string(),
            repo_id: "repo-core".to_string(),
            allowed_ops: vec!["read".to_string()],
            allowed_read_prefixes: Vec::new(),
            allowed_write_prefixes: Vec::new(),
            ttl_secs: 60,
            allowed_refs: Vec::new(),
        })
        .unwrap()
    {
        RpcResponse::Error { message } => {
            assert!(message.contains("cannot mint sub-leases"));
        }
        other => panic!("expected sub-lease denial, got {:?}", other),
    }

    let mut swarm_wrong_repo = swarm_cfg.clone();
    swarm_wrong_repo.repo_id = "other-repo".to_string();
    let wrong_repo_engine = swarm_wrong_repo.open_engine(&swarm_dir).unwrap();
    assert!(wrong_repo_engine.resolve_ref("main").is_err());

    // 10. Swarm checks in its JIT lease (`RevokeLease`), immediately invalidating the token
    let checkin_resp = swarm_client
        .call(&RpcRequest::RevokeLease {
            lease_id: jit_lease.lease_id.clone(),
            revoked_at_unix: 1_761_300_300,
        })
        .unwrap();
    assert_eq!(checkin_resp, RpcResponse::RevokeLeaseOk);

    // Any subsequent request using that checked-in lease token fails with 401 Unauthorized
    assert!(swarm_client.call(&RpcRequest::WhoAmI).is_err());

    // 11. Admin revokes workstation `device-alpha@example.com`; subsequent workstation requests fail
    let revoke_ws = admin_client
        .call(&RpcRequest::RevokePrincipal {
            principal_id: "device-alpha@example.com".to_string(),
            revoked_at_unix: 1_761_300_350,
        })
        .unwrap();
    assert_eq!(revoke_ws, RpcResponse::RevokePrincipalOk);
    assert!(alpha_client.call(&RpcRequest::WhoAmI).is_err());

    oidc_stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = std::net::TcpStream::connect(oidc_addr);
    server.shutdown();
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_has_objects_batch_and_put_objects_batch_dedup_over_http() {
    use inarch_store::{BlobStore, RemoteBlobStore};
    use inarch_types::hash::{ObjectDomain, ObjectHash};

    let server_blobs = Arc::new(MemBlobStore::new());
    let server_meta = Arc::new(MemMetadataStore::new());
    let server_engine = Arc::new(ScionEngine::new(
        Arc::clone(&server_blobs),
        Arc::clone(&server_meta),
    ));
    let server = inarch_cli::spawn_http_server_with_config(
        server_engine,
        "127.0.0.1:0",
        inarch_cli::ServerAuthConfig::insecure_allow_anonymous(),
    )
    .expect("spawn in-memory HTTP server");
    let remote_url = format!("http://{}", server.local_addr());

    let remote_blobs = RemoteBlobStore::new(&remote_url, None).expect("create RemoteBlobStore");

    // Create two compressible 24 KiB source blobs and one 1 KiB blob
    let blob_a: Vec<u8> = "pub fn alpha_handler() -> Result<u64, Error> { Ok(42) }\n"
        .repeat(450)
        .into_bytes();
    let blob_b: Vec<u8> = "pub fn beta_handler() -> Result<u64, Error> { Ok(99) }\n"
        .repeat(450)
        .into_bytes();
    let blob_c: Vec<u8> = "pub fn gamma_new() -> u32 { 7 }\n".repeat(32).into_bytes();

    let hash_a = ObjectHash::from_domain(ObjectDomain::Blob, &blob_a);
    let hash_b = ObjectHash::from_domain(ObjectDomain::Blob, &blob_b);
    let hash_c = ObjectHash::from_domain(ObjectDomain::Blob, &blob_c);

    // 1. Seed blob_a and blob_b on the server and verify wire compression shrinks the HTTP payload
    remote_blobs.reset_wire_stats();
    remote_blobs
        .put_objects_batch(&[
            (ObjectDomain::Blob, hash_a, blob_a.clone()),
            (ObjectDomain::Blob, hash_b, blob_b.clone()),
        ])
        .expect("initial put_objects_batch");

    let initial_stats = remote_blobs.wire_stats();
    assert!(
        initial_stats.wire_bytes_sent < initial_stats.uncompressed_bytes_sent / 3,
        "wire compression must shrink initial 48 KiB upload below 1/3 of raw size (sent={} vs raw={})",
        initial_stats.wire_bytes_sent,
        initial_stats.uncompressed_bytes_sent
    );

    // 2. Verify HasObjectsBatch returns exact presence bitmap
    let present = remote_blobs
        .has_objects_batch(&[
            (ObjectDomain::Blob, hash_a),
            (ObjectDomain::Blob, hash_c),
            (ObjectDomain::Blob, hash_b),
        ])
        .expect("has_objects_batch over HTTP");
    assert_eq!(present, vec![true, false, true]);

    // 3. Re-uploading [blob_a, blob_b] when 100% already exist on the server must skip PutObjectsBatch completely
    remote_blobs.reset_wire_stats();
    remote_blobs
        .put_objects_batch(&[
            (ObjectDomain::Blob, hash_a, blob_a.clone()),
            (ObjectDomain::Blob, hash_b, blob_b.clone()),
        ])
        .expect("idempotent put_objects_batch when all exist");
    let skip_stats = remote_blobs.wire_stats();
    assert_eq!(
        skip_stats.requests_sent, 1,
        "100% duplicate batch should only send 1 HasObjectsBatch preflight RPC"
    );
    assert!(
        skip_stats.wire_bytes_sent < 256,
        "100% duplicate batch must not transmit the 48 KiB blob payloads (sent={})",
        skip_stats.wire_bytes_sent
    );

    // 4. Uploading [blob_a, blob_b, blob_c] where only blob_c (1 KiB) is missing must only upload blob_c
    remote_blobs.reset_wire_stats();
    remote_blobs
        .put_objects_batch(&[
            (ObjectDomain::Blob, hash_a, blob_a),
            (ObjectDomain::Blob, hash_b, blob_b),
            (ObjectDomain::Blob, hash_c, blob_c.clone()),
        ])
        .expect("partial dedup put_objects_batch");
    let partial_stats = remote_blobs.wire_stats();
    assert_eq!(partial_stats.requests_sent, 2);
    assert!(
        partial_stats.wire_bytes_sent < 1024,
        "partial duplicate batch must only transmit missing blob_c (sent={})",
        partial_stats.wire_bytes_sent
    );
    assert_eq!(
        server_blobs
            .get_object(ObjectDomain::Blob, &hash_c)
            .unwrap()
            .unwrap(),
        blob_c
    );

    server.shutdown();
}

#[test]
fn test_remote_mode_defaults_to_persistent_tier1_cache_and_serves_warm_reads_with_zero_egress() {
    use inarch_types::hash::{ObjectDomain, ObjectHash};

    let root = unique_temp_dir("persistent-t1-default");
    let ws_dir = root.join("workspace");
    fs::create_dir_all(&ws_dir).unwrap();

    // 1. Local mode with empty tier1_cache_dir does NOT enable a duplicate client cache dir
    let local_cfg = InarchConfig::default();
    assert_eq!(local_cfg.resolved_tier1_cache_dir(&ws_dir), None);

    // 2. Remote mode with empty tier1_cache_dir automatically resolves a persistent NVMe cache dir
    let mut remote_cfg = InarchConfig::default();
    remote_cfg.remote_url = "http://127.0.0.1:7331".to_string();
    let auto_t1 = remote_cfg
        .resolved_tier1_cache_dir(&ws_dir)
        .expect("remote_url mode must default to a persistent Tier-1 cache directory");
    assert_eq!(
        Some(auto_t1.clone()),
        InarchConfig::default_client_tier1_cache_dir()
    );
    assert!(
        auto_t1.to_string_lossy().contains("velenza-inarch"),
        "expected default tier1 cache path to include velenza-inarch, got: {}",
        auto_t1.display()
    );

    // 3. Explicit opt-out (`"none"` or `"memory"`) disables disk Tier-1 cache even in remote mode
    let mut opt_out_cfg = remote_cfg.clone();
    opt_out_cfg.tier1_cache_dir = "none".to_string();
    assert_eq!(opt_out_cfg.resolved_tier1_cache_dir(&ws_dir), None);
    opt_out_cfg.tier1_cache_dir = "memory".to_string();
    assert_eq!(opt_out_cfg.resolved_tier1_cache_dir(&ws_dir), None);

    // 4. End-to-end warm-cache persistence across separate engine instances with 0 server egress
    //    Notice `client_cfg.tier1_cache_dir` is left EMPTY ("") so `open_engine` uses the automatic remote default!
    let server_blobs = Arc::new(MemBlobStore::new());
    let server_meta = Arc::new(MemMetadataStore::new());
    let server_engine = Arc::new(ScionEngine::new(server_blobs, server_meta));
    let server = inarch_cli::spawn_http_server_with_config(
        server_engine,
        "127.0.0.1:0",
        inarch_cli::ServerAuthConfig::insecure_allow_anonymous(),
    )
    .expect("spawn in-memory HTTP server");
    let remote_url = format!("http://{}", server.local_addr());

    let unique_payload = format!(
        "pub const PERSISTED_IN_NVME_T1_NONCE: u128 = {};\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let file_bytes = unique_payload.repeat(64).into_bytes();
    let file_hash = ObjectHash::from_domain(ObjectDomain::Blob, &file_bytes);

    let mut client_cfg = InarchConfig::default();
    client_cfg.remote_url = remote_url;
    client_cfg.repo_id = "warm-cache-repo".to_string();
    assert!(client_cfg.tier1_cache_dir.is_empty());

    // Session 1: Land a file and read it back so the default persistent Tier-1 cache on disk is populated
    let engine_session_1 = client_cfg.open_engine(&ws_dir).unwrap();
    let land_out = engine_session_1
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "agent@example.com".to_string(),
            timestamp: 1_761_400_000,
            tz_offset_secs: 0,
            message: "seed warm cache file".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("src/warm.rs").unwrap(),
                content: file_bytes.clone(),
                file_type: FileType::Regular,
            }],
        })
        .unwrap();
    let read_1 = engine_session_1
        .read_file(land_out.changeset_id, &MPath::new("src/warm.rs").unwrap())
        .unwrap();
    assert_eq!(read_1, file_bytes);
    drop(engine_session_1);

    // Shut down the remote HTTP server completely!
    server.shutdown();

    // Session 2: A brand-new process/engine instance opens with `tier1_cache_dir = ""` (automatic persistent Tier-1 cache);
    // fetching the immutable blob by content hash succeeds from local NVMe with 0 network egress!
    let engine_session_2 = client_cfg.open_engine(&ws_dir).unwrap();
    let cached_bytes = engine_session_2
        .blobs()
        .get_object(ObjectDomain::Blob, &file_hash)
        .expect("read from persistent Tier-1 cache while remote server is offline")
        .expect("blob must be present in persistent Tier-1 cache");
    assert_eq!(cached_bytes, file_bytes);

    let _ = fs::remove_dir_all(&root);
}
