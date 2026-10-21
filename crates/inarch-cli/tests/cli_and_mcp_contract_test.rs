//! Comprehensive contract tests for `inarch-cli` (Iteration 6 — Slice 7):
//! - Checkout-free MCP (Model Context Protocol) JSON-RPC 2.0 server dispatcher (`McpServer`)
//!   exercising `tools/list` and `tools/call` (`inarch_commit_patch`, `inarch_read_file`,
//!   `inarch_list_dir`, `inarch_diff`, `inarch_log_path`, `inarch_blame`, `inarch_revert`).
//! - Stateless tree-walk checkout (`checkout_stateless`) with sparse prefix pruning and
//!   3-tier cache verification.

use std::collections::BTreeMap;
use std::sync::Arc;

use inarch_antique::AntiqueService;
use inarch_cli::{McpRequest, McpServer, checkout_stateless};
use inarch_engine::{PatchFileEdit, PatchSubmission, ScionEngine};
use inarch_store::{BlobStore, MemBlobStore, MemMetadataStore, TieredBlobStore};
use inarch_types::bonsai::FileType;
use inarch_types::hash::{BlobId, ObjectDomain};
use inarch_types::path::MPath;

#[test]
fn mcp_dispatcher_executes_end_to_end_checkout_free_agent_workflow() {
    let engine = Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ));
    let antique = Arc::new(AntiqueService::new(Arc::clone(&engine)));
    let mcp = McpServer::new(Arc::clone(&engine), Arc::clone(&antique));

    // 1. List tools
    let list_resp = mcp.handle(McpRequest::ListTools { id: 1 });
    assert!(list_resp.error.is_none());
    let tools_payload = list_resp.result.unwrap();
    assert!(tools_payload.contains("inarch_commit_patch"));
    assert!(tools_payload.contains("inarch_read_file"));
    assert!(tools_payload.contains("inarch_diff"));
    assert!(tools_payload.contains("inarch_log_path"));
    assert!(tools_payload.contains("inarch_blame"));
    assert!(tools_payload.contains("inarch_revert"));

    // 2. Commit initial patch on `main` via MCP
    let c1_resp = mcp.handle(McpRequest::CallTool {
        id: 2,
        name: "inarch_commit_patch".to_string(),
        args: BTreeMap::from([
            ("target_ref".to_string(), "main".to_string()),
            ("base_changeset".to_string(), "INITIAL".to_string()),
            ("author".to_string(), "alice@inarch.dev".to_string()),
            ("timestamp".to_string(), "1760600001".to_string()),
            ("message".to_string(), "initial commit".to_string()),
            ("path".to_string(), "src/lib.rs".to_string()),
            (
                "content".to_string(),
                "pub fn greet() -> &'static str {\n    \"v1\"\n}\n".to_string(),
            ),
        ]),
    });
    assert!(c1_resp.error.is_none());
    let c1_hex = engine.resolve_ref("main").unwrap().unwrap().to_hex();

    // 3. Commit second patch on `main` via MCP
    let c2_resp = mcp.handle(McpRequest::CallTool {
        id: 3,
        name: "inarch_commit_patch".to_string(),
        args: BTreeMap::from([
            ("target_ref".to_string(), "main".to_string()),
            ("base_changeset".to_string(), c1_hex.clone()),
            ("author".to_string(), "bob@inarch.dev".to_string()),
            ("timestamp".to_string(), "1760600002".to_string()),
            ("message".to_string(), "upgrade greet to v2".to_string()),
            ("path".to_string(), "src/lib.rs".to_string()),
            (
                "content".to_string(),
                "pub fn greet() -> &'static str {\n    \"v2\"\n}\n".to_string(),
            ),
        ]),
    });
    assert!(c2_resp.error.is_none());
    let c2_hex = engine.resolve_ref("main").unwrap().unwrap().to_hex();
    assert_ne!(c1_hex, c2_hex);

    // 4. Read file at `main` via MCP without a working tree
    let read_resp = mcp.handle(McpRequest::CallTool {
        id: 4,
        name: "inarch_read_file".to_string(),
        args: BTreeMap::from([
            ("rev".to_string(), "main".to_string()),
            ("path".to_string(), "src/lib.rs".to_string()),
        ]),
    });
    assert_eq!(
        read_resp.result.as_deref(),
        Some("pub fn greet() -> &'static str {\n    \"v2\"\n}\n")
    );

    // 5. Diff c1..c2 via MCP
    let diff_resp = mcp.handle(McpRequest::CallTool {
        id: 5,
        name: "inarch_diff".to_string(),
        args: BTreeMap::from([
            ("from".to_string(), c1_hex.clone()),
            ("to".to_string(), c2_hex.clone()),
        ]),
    });
    assert!(diff_resp.result.unwrap().contains("MODIFIED src/lib.rs"));

    // 6. Blame src/lib.rs at `main` via MCP
    let blame_resp = mcp.handle(McpRequest::CallTool {
        id: 6,
        name: "inarch_blame".to_string(),
        args: BTreeMap::from([
            ("rev".to_string(), "main".to_string()),
            ("path".to_string(), "src/lib.rs".to_string()),
        ]),
    });
    let blame_text = blame_resp.result.unwrap();
    assert!(blame_text.contains("alice@inarch.dev"));
    assert!(blame_text.contains("bob@inarch.dev"));

    // 7. Instant revert of c2 via MCP
    let revert_resp = mcp.handle(McpRequest::CallTool {
        id: 7,
        name: "inarch_revert".to_string(),
        args: BTreeMap::from([
            ("target_ref".to_string(), "main".to_string()),
            ("culprit".to_string(), c2_hex),
            ("author".to_string(), "autorevert@inarch.dev".to_string()),
            ("timestamp".to_string(), "1760600003".to_string()),
        ]),
    });
    assert!(revert_resp.error.is_none());

    // Verify `src/lib.rs` on `main` is restored to `"v1"`
    let read_after_revert = mcp.handle(McpRequest::CallTool {
        id: 8,
        name: "inarch_read_file".to_string(),
        args: BTreeMap::from([
            ("rev".to_string(), "main".to_string()),
            ("path".to_string(), "src/lib.rs".to_string()),
        ]),
    });
    assert_eq!(
        read_after_revert.result.as_deref(),
        Some("pub fn greet() -> &'static str {\n    \"v1\"\n}\n")
    );
}

#[test]
fn stateless_tree_walk_checkout_materializes_sparse_subtrees_and_prunes_unselected_blobs() {
    let tier1_daemon = Arc::new(MemBlobStore::new());
    let tier2_regional = Arc::new(MemBlobStore::new());
    let tier3_origin = Arc::new(MemBlobStore::new());

    // Authoritative server writes directly to `tier3_origin`
    let meta = Arc::new(MemMetadataStore::new());
    let origin_engine = ScionEngine::new(Arc::clone(&tier3_origin), Arc::clone(&meta));

    let core_code = b"pub fn run() -> bool { true }\n";
    let heavy_asset = vec![0xABu8; 32 * 1024];
    let heavy_blob_id = BlobId::from_content(&heavy_asset);

    let landed = origin_engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "builder@inarch.dev".to_string(),
            timestamp: 1_760_700_000,
            tz_offset_secs: 0,
            message: "add core and heavy asset".to_string(),
            extra: BTreeMap::new(),
            edits: vec![
                PatchFileEdit::Upsert {
                    path: MPath::new("crates/core/src/lib.rs").unwrap(),
                    content: core_code.to_vec(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("crates/heavy_assets/weights.bin").unwrap(),
                    content: heavy_asset,
                    file_type: FileType::Regular,
                },
            ],
        })
        .unwrap();

    // Ensure root Fsnode is derived on the server
    origin_engine
        .derived()
        .derive_fsnode(landed.changeset_id)
        .unwrap();

    // Client connects through the 3-tier `TieredBlobStore` with an initially cold `tier1_daemon`
    let tiered_store = Arc::new(TieredBlobStore::new(
        Arc::clone(&tier1_daemon),
        Arc::clone(&tier2_regional),
        Arc::clone(&tier3_origin),
    ));
    let client_engine = ScionEngine::new(Arc::clone(&tiered_store), Arc::clone(&meta));

    let checkout_dir = std::env::temp_dir().join(format!(
        "velenza-inarch-sparse-checkout-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&checkout_dir);

    let sparse_filter = vec![MPath::new("crates/core").unwrap()];
    let receipt = checkout_stateless(
        &client_engine,
        landed.changeset_id,
        Some(&sparse_filter),
        &checkout_dir,
    )
    .expect("stateless sparse checkout must succeed");

    assert_eq!(receipt.files_materialized, 1);
    assert_eq!(receipt.bytes_materialized, core_code.len() as u64);

    // Verify `crates/core/src/lib.rs` exists on disk with exact content
    let disk_bytes =
        std::fs::read(checkout_dir.join("crates/core/src/lib.rs")).expect("read materialized file");
    assert_eq!(disk_bytes, core_code);

    // Verify `crates/heavy_assets/weights.bin` was NOT materialized on disk
    assert!(
        !checkout_dir
            .join("crates/heavy_assets/weights.bin")
            .exists()
    );

    // Verify `tier1_daemon` NEVER fetched `heavy_blob_id` (sparse tree walk pruned the `crates/heavy_assets` subtree!)
    assert!(
        !tier1_daemon
            .has_object(ObjectDomain::Blob, &heavy_blob_id.0)
            .unwrap(),
        "sparse tree-walk checkout must never fetch blobs from pruned directory subtrees"
    );

    let _ = std::fs::remove_dir_all(&checkout_dir);
}

use inarch_cli::arbor;

#[test]
fn arbor_stack_report_discovers_all_four_layers_via_env_canonical_and_compat_aliases() {
    use arbor::{ArborLayerId, discover_arbor_stack};

    let tmp_root = std::env::temp_dir().join(format!(
        "velenza-arbor-discovery-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_root);
    let bin_dir_1 = tmp_root.join("bin1");
    let bin_dir_2 = tmp_root.join("bin2");
    let override_dir = tmp_root.join("override");
    std::fs::create_dir_all(&bin_dir_1).unwrap();
    std::fs::create_dir_all(&bin_dir_2).unwrap();
    std::fs::create_dir_all(&override_dir).unwrap();

    // Layer 0: canonical `velenza-inarch` in bin_dir_1 AND compat `inr` in bin_dir_2 -> must pick canonical `velenza-inarch`
    let inarch_canonical = bin_dir_1.join("velenza-inarch");
    let inarch_compat = bin_dir_2.join("inr");
    std::fs::write(&inarch_canonical, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::write(&inarch_compat, b"#!/bin/sh\nexit 0\n").unwrap();

    // Layer 1: env override `VELENZA_CAMBIUM_BIN` -> must take priority over bin_dir_1/code-graph
    let cambium_override = override_dir.join("custom-cambium");
    let cambium_compat = bin_dir_1.join("code-graph");
    std::fs::write(&cambium_override, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::write(&cambium_compat, b"#!/bin/sh\nexit 0\n").unwrap();

    // Layer 2: only compat alias `spec-graph` present in bin_dir_2 -> must fall back to compat alias
    let canon_compat = bin_dir_2.join("spec-graph");
    std::fs::write(&canon_compat, b"#!/bin/sh\nexit 0\n").unwrap();

    // Layer 3: neither env nor binary in search_dirs -> resolved_binary must be None
    let env_map = BTreeMap::from([(
        "VELENZA_CAMBIUM_BIN".to_string(),
        cambium_override.to_string_lossy().to_string(),
    )]);

    let report = discover_arbor_stack(&[bin_dir_1.clone(), bin_dir_2.clone()], &|k| {
        env_map.get(k).cloned()
    });

    assert_eq!(report.stack_name, "velenza-arbor");
    assert_eq!(report.umbrella_cli, "inr");
    assert_eq!(report.layers.len(), 4);

    let l0 = &report.layers[0];
    assert_eq!(l0.layer, 0);
    assert_eq!(l0.id, ArborLayerId::Inarch);
    assert_eq!(l0.canonical_name, "velenza-inarch");
    assert_eq!(l0.compat_alias, "inr");
    assert_eq!(l0.umbrella_subcommands, &["inr"]);
    assert_eq!(l0.config_env_vars, &["INARCH_CONFIG"]);
    assert_eq!(l0.resolved_binary.as_ref(), Some(&inarch_canonical));

    let l1 = &report.layers[1];
    assert_eq!(l1.layer, 1);
    assert_eq!(l1.id, ArborLayerId::Cambium);
    assert_eq!(l1.canonical_name, "velenza-cambium");
    assert_eq!(l1.compat_alias, "code-graph");
    assert_eq!(l1.umbrella_subcommands, &["inr cambium", "inr code"]);
    assert_eq!(
        l1.config_env_vars,
        &[
            "CODE_GRAPH_GCP_PROJECT",
            "CODE_GRAPH_SPANNER_INSTANCE",
            "CODE_GRAPH_SPANNER_DATABASE",
            "ARBOR_GCP_PROJECT",
            "ARBOR_SPANNER_INSTANCE",
        ]
    );
    assert_eq!(l1.resolved_binary.as_ref(), Some(&cambium_override));

    let l2 = &report.layers[2];
    assert_eq!(l2.layer, 2);
    assert_eq!(l2.id, ArborLayerId::Canon);
    assert_eq!(l2.canonical_name, "velenza-canon");
    assert_eq!(l2.compat_alias, "spec-graph");
    assert_eq!(l2.umbrella_subcommands, &["inr canon", "inr spec"]);
    assert_eq!(
        l2.config_env_vars,
        &[
            "VELENZA_CANON_CONFIG",
            "SPEC_GRAPH_CONFIG",
            "ARBOR_GCP_PROJECT",
            "ARBOR_SPANNER_INSTANCE",
        ]
    );
    assert_eq!(l2.resolved_binary.as_ref(), Some(&canon_compat));

    let l3 = &report.layers[3];
    assert_eq!(l3.layer, 3);
    assert_eq!(l3.id, ArborLayerId::Trellis);
    assert_eq!(l3.canonical_name, "velenza-trellis");
    assert_eq!(l3.compat_alias, "task-graph");
    assert_eq!(l3.umbrella_subcommands, &["inr trellis", "inr task"]);
    assert_eq!(
        l3.config_env_vars,
        &[
            "VELENZA_TRELLIS_CONFIG",
            "TASK_GRAPH_CONFIG",
            "ARBOR_GCP_PROJECT",
            "ARBOR_SPANNER_INSTANCE",
        ]
    );
    assert_eq!(l3.resolved_binary, None);

    let json = report.to_json_string();
    assert!(json.contains("\"stack_name\": \"velenza-arbor\""));
    assert!(json.contains("\"canonical_name\": \"velenza-cambium\""));
    assert!(json.contains("\"canonical_name\": \"velenza-canon\""));
    assert!(json.contains("\"canonical_name\": \"velenza-trellis\""));

    let table = report.to_text_table();
    assert!(table.contains("Velenza Arbor Stack"));
    assert!(table.contains("velenza-cambium"));
    assert!(table.contains("velenza-canon"));
    assert!(table.contains("velenza-trellis"));

    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[test]
fn arbor_umbrella_subcommand_resolution_and_delegation_forwards_args_and_exit_code() {
    use arbor::{ArborLayerId, delegate_arbor_subcommand, resolve_umbrella_subcommand};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    assert_eq!(
        resolve_umbrella_subcommand("cambium"),
        Some(ArborLayerId::Cambium)
    );
    assert_eq!(
        resolve_umbrella_subcommand("code"),
        Some(ArborLayerId::Cambium)
    );
    assert_eq!(
        resolve_umbrella_subcommand("code-graph"),
        Some(ArborLayerId::Cambium)
    );
    assert_eq!(
        resolve_umbrella_subcommand("canon"),
        Some(ArborLayerId::Canon)
    );
    assert_eq!(
        resolve_umbrella_subcommand("spec"),
        Some(ArborLayerId::Canon)
    );
    assert_eq!(
        resolve_umbrella_subcommand("spec-graph"),
        Some(ArborLayerId::Canon)
    );
    assert_eq!(
        resolve_umbrella_subcommand("trellis"),
        Some(ArborLayerId::Trellis)
    );
    assert_eq!(
        resolve_umbrella_subcommand("task"),
        Some(ArborLayerId::Trellis)
    );
    assert_eq!(
        resolve_umbrella_subcommand("task-graph"),
        Some(ArborLayerId::Trellis)
    );
    assert_eq!(resolve_umbrella_subcommand("status"), None);
    assert_eq!(resolve_umbrella_subcommand("stack"), None);

    let tmp_root = std::env::temp_dir().join(format!(
        "velenza-arbor-delegate-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_root);
    std::fs::create_dir_all(&tmp_root).unwrap();

    // Write a mock executable `velenza-cambium` script that echoes its arguments and exits 0
    let mock_cambium = tmp_root.join("velenza-cambium");
    std::fs::write(
        &mock_cambium,
        b"#!/bin/sh\necho \"cambium-exec:$*\"\nexit 0\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&mock_cambium, std::fs::Permissions::from_mode(0o755)).unwrap();

    let (code, stdout, stderr) = delegate_arbor_subcommand(
        ArborLayerId::Cambium,
        &["arbor-info".to_string(), "--json".to_string()],
        std::slice::from_ref(&tmp_root),
        &|_| None,
    )
    .expect("delegation to mock velenza-cambium must succeed");
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "cambium-exec:arbor-info --json");
    assert!(stderr.is_empty());

    // Missing layer binary returns an actionable error mentioning both canonical and compat names
    let err = delegate_arbor_subcommand(
        ArborLayerId::Trellis,
        &["arbor-info".to_string()],
        std::slice::from_ref(&tmp_root),
        &|_| None,
    )
    .expect_err("missing layer binary must return error");
    let msg = err.to_string();
    assert!(
        msg.contains("velenza-trellis") && msg.contains("task-graph"),
        "unexpected error message: {}",
        msg
    );

    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[test]
fn arbor_streaming_delegation_and_readme_arbor_stack_contract() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string()),
    );
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");

    // 1. REQ-INARCH-STREAMING-DELEGATION: verify `main.rs` delegates via inherited-stdio
    // `spawn_arbor_subcommand_inherited` rather than buffering stdout/stderr until exit,
    // and test end-to-end execution via `CARGO_BIN_EXE_inr`.
    let main_src = std::fs::read_to_string(manifest_dir.join("src/main.rs"))
        .expect("read crates/inarch-cli/src/main.rs");
    assert!(
        main_src.contains("spawn_arbor_subcommand_inherited("),
        "AssertionError: main.rs must use spawn_arbor_subcommand_inherited for streaming stdio delegation"
    );

    let tmp_root = std::env::temp_dir().join(format!(
        "velenza-arbor-streaming-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_root);
    std::fs::create_dir_all(&tmp_root).unwrap();

    let mock_canon = tmp_root.join("velenza-canon");
    std::fs::write(
        &mock_canon,
        b"#!/bin/sh\necho \"canon-stream:$*\"\nexit 42\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&mock_canon, std::fs::Permissions::from_mode(0o755)).unwrap();

    let inr_bin = env!("CARGO_BIN_EXE_inr");
    let out = Command::new(inr_bin)
        .env("VELENZA_CANON_BIN", &mock_canon)
        .args(["canon", "arbor-info", "--config", "spec-graph.config.json"])
        .output()
        .expect("execute inr canon");
    assert_eq!(out.status.code(), Some(42));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim(),
        "canon-stream:arbor-info --config spec-graph.config.json"
    );

    let _ = std::fs::remove_dir_all(&tmp_root);

    // 2. REQ-INARCH-README-ARBOR-STACK: verify `README.md` documents the 4-layer Velenza Arbor Stack.
    let readme = std::fs::read_to_string(repo_root.join("README.md")).expect("read root README.md");
    for required in [
        "Velenza Arbor Stack",
        "velenza-cambium",
        "velenza-canon",
        "velenza-trellis",
        "inr stack",
        "inr cambium",
        "inr canon",
        "inr trellis",
    ] {
        assert!(
            readme.contains(required),
            "README.md missing required Velenza Arbor Stack token: {}",
            required
        );
    }
}

#[test]
fn arbor_quickstart_and_clean_release_exporter_contract() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string()),
    );
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");

    // 1. REQ-ARBOR-QUICKSTART-COMPOSE: verify `quickstart/docker-compose.yml` configures
    // the local Cloud Spanner Emulator on ports 9010 (gRPC) and 9020 (REST).
    let compose_path = repo_root.join("quickstart/docker-compose.yml");
    assert!(
        compose_path.is_file(),
        "AssertionError: quickstart/docker-compose.yml must exist"
    );
    let compose_body =
        std::fs::read_to_string(&compose_path).expect("read quickstart/docker-compose.yml");
    for token in [
        "gcr.io/cloud-spanner-emulator/emulator",
        "9010:9010",
        "9020:9020",
    ] {
        assert!(
            compose_body.contains(token),
            "AssertionError: quickstart/docker-compose.yml missing token: {}",
            token
        );
    }

    // 2. REQ-ARBOR-QUICKSTART-SCRIPT: verify `quickstart/arbor-quickstart.sh` exists, is executable,
    // passes `sh -n`, and executes an end-to-end 4-layer Velenza Arbor Stack smoke run.
    let quickstart_script = repo_root.join("quickstart/arbor-quickstart.sh");
    assert!(
        quickstart_script.is_file(),
        "AssertionError: quickstart/arbor-quickstart.sh must exist"
    );
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&quickstart_script)
            .expect("stat quickstart/arbor-quickstart.sh")
            .permissions()
            .mode();
        assert_ne!(
            mode & 0o111,
            0,
            "AssertionError: quickstart/arbor-quickstart.sh must be executable"
        );
    }
    let syntax_check = Command::new("sh")
        .arg("-n")
        .arg(&quickstart_script)
        .output()
        .expect("sh -n quickstart/arbor-quickstart.sh");
    assert!(
        syntax_check.status.success(),
        "AssertionError: sh -n quickstart/arbor-quickstart.sh failed: {}",
        String::from_utf8_lossy(&syntax_check.stderr)
    );

    let inr_bin = env!("CARGO_BIN_EXE_inr");
    let smoke_out = Command::new("sh")
        .arg(&quickstart_script)
        .arg("--smoke")
        .env("INR_BIN", inr_bin)
        .output()
        .expect("run quickstart/arbor-quickstart.sh --smoke");
    assert!(
        smoke_out.status.success(),
        "AssertionError: quickstart/arbor-quickstart.sh --smoke failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&smoke_out.stdout),
        String::from_utf8_lossy(&smoke_out.stderr)
    );
    let smoke_stdout = String::from_utf8_lossy(&smoke_out.stdout);
    for stage in [
        "[Layer 0: velenza-inarch]",
        "[Layer 1: velenza-cambium]",
        "[Layer 2: velenza-canon]",
        "[Layer 3: velenza-trellis]",
        "ARBOR_QUICKSTART_OK",
    ] {
        assert!(
            smoke_stdout.contains(stage),
            "AssertionError: quickstart smoke output missing stage '{}': {}",
            stage,
            smoke_stdout
        );
    }

    // 3. REQ-ARBOR-CLEAN-RELEASE-EXPORT: verify `quickstart/export-clean-public-release.sh`
    // exports a clean single-root-commit (`v0.1.0`) git repository with zero history leaks.
    let export_script = repo_root.join("quickstart/export-clean-public-release.sh");
    assert!(
        export_script.is_file(),
        "AssertionError: quickstart/export-clean-public-release.sh must exist"
    );
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&export_script)
            .expect("stat quickstart/export-clean-public-release.sh")
            .permissions()
            .mode();
        assert_ne!(
            mode & 0o111,
            0,
            "AssertionError: quickstart/export-clean-public-release.sh must be executable"
        );
    }
    let export_syntax = Command::new("sh")
        .arg("-n")
        .arg(&export_script)
        .output()
        .expect("sh -n quickstart/export-clean-public-release.sh");
    assert!(
        export_syntax.status.success(),
        "AssertionError: sh -n quickstart/export-clean-public-release.sh failed: {}",
        String::from_utf8_lossy(&export_syntax.stderr)
    );

    let tmp_export = std::env::temp_dir().join(format!(
        "velenza-clean-release-export-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_export);
    std::fs::create_dir_all(&tmp_export).unwrap();

    let export_out = Command::new("sh")
        .arg(&export_script)
        .arg("--source-dir")
        .arg(repo_root)
        .arg("--output-dir")
        .arg(&tmp_export)
        .arg("--tag")
        .arg("v0.1.0")
        .output()
        .expect("run quickstart/export-clean-public-release.sh");
    assert!(
        export_out.status.success(),
        "AssertionError: export-clean-public-release.sh failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&export_out.stdout),
        String::from_utf8_lossy(&export_out.stderr)
    );

    let exported_repo = tmp_export.join("velenza-inarch");
    let rev_count = Command::new("git")
        .arg("-C")
        .arg(&exported_repo)
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .expect("git rev-list --count HEAD");
    assert_eq!(
        String::from_utf8_lossy(&rev_count.stdout).trim(),
        "1",
        "AssertionError: exported repository must contain exactly 1 root commit"
    );

    let author_out = Command::new("git")
        .arg("-C")
        .arg(&exported_repo)
        .args(["log", "-1", "--format=%an <%ae>"])
        .output()
        .expect("git log -1 author");
    assert_eq!(
        String::from_utf8_lossy(&author_out.stdout).trim(),
        "Velenza Open Source <open-source@velenzaboc.com>",
        "AssertionError: exported root commit must use clean open-source identity"
    );

    let tag_out = Command::new("git")
        .arg("-C")
        .arg(&exported_repo)
        .args(["tag", "-l", "v0.1.0"])
        .output()
        .expect("git tag -l v0.1.0");
    assert_eq!(
        String::from_utf8_lossy(&tag_out.stdout).trim(),
        "v0.1.0",
        "AssertionError: exported repository must be tagged v0.1.0"
    );

    let _ = std::fs::remove_dir_all(&tmp_export);

    let readme = std::fs::read_to_string(repo_root.join("README.md")).expect("read root README.md");
    assert!(
        readme.contains("quickstart/arbor-quickstart.sh"),
        "AssertionError: README.md must document quickstart/arbor-quickstart.sh"
    );
}

#[test]
fn review_882aaa34_c2_workspace_base_mcp_and_server_hardening() {
    use inarch_cli::{
        AclRuleConfig, InarchConfig, ServerAuthConfig, ingest_directory,
        load_workspace_base_changeset, spawn_http_server, spawn_http_server_with_config,
        validate_serve_bind_address,
    };
    use inarch_store::{PrincipalRecord, RemoteRpcClient, RpcRequest, RpcResponse};
    use inarch_types::bonsai::{BonsaiChangeset, FileChange};

    // 1. N4: Plaintext non-loopback bind guard
    assert!(validate_serve_bind_address("127.0.0.1:0", false).is_ok());
    assert!(validate_serve_bind_address("0.0.0.0:7331", false).is_err());
    assert!(validate_serve_bind_address("0.0.0.0:7331", true).is_ok());

    // 2. N8: ServerAuthConfig::new(None) requires auth by default (fails closed)
    let default_auth = ServerAuthConfig::new(None);
    assert!(default_auth.require_auth);
    let closed_engine = Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ));
    let closed_srv = spawn_http_server(closed_engine, "127.0.0.1:0", None).unwrap();
    let anon_client = RemoteRpcClient::new(&closed_srv.base_url(), None).unwrap();
    assert!(
        anon_client.call(&RpcRequest::WhoAmI).is_err(),
        "spawn_http_server(..., None) must reject unauthenticated RPCs with 401"
    );
    closed_srv.shutdown();

    // 3. B1: checkout_stateless persists .inarch/workspace_state.toml so ingest_directory
    //    uses the workspace's checkout base rather than blindly using remote ref tip
    let tmp = std::env::temp_dir().join(format!(
        "inarch-c2-b1-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let ws1 = tmp.join("ws1");
    let ws2 = tmp.join("ws2");
    std::fs::create_dir_all(&ws1).unwrap();
    std::fs::create_dir_all(&ws2).unwrap();

    let engine = Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ));
    let seed = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "seed@inarch.dev".to_string(),
            timestamp: 100,
            tz_offset_secs: 0,
            message: "seed".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("a.txt").unwrap(),
                content: b"a1\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .unwrap();

    checkout_stateless(&engine, seed.changeset_id, None, &ws1).unwrap();
    checkout_stateless(&engine, seed.changeset_id, None, &ws2).unwrap();
    assert_eq!(
        load_workspace_base_changeset(&ws1).unwrap(),
        Some(seed.changeset_id)
    );

    // Agent 1 adds b.txt and lands onto `main`
    std::fs::write(ws1.join("b.txt"), b"from-ws1\n").unwrap();
    let r1 = ingest_directory(&engine, "main", "a1@inarch.dev", 101, "add b", &ws1, &[]).unwrap();
    assert_eq!(
        load_workspace_base_changeset(&ws1).unwrap(),
        Some(r1.changeset_id)
    );

    // Agent 2 (still based at `seed`, without `b.txt` on disk) adds `c.txt` and ingests onto `main`.
    // Because `ws2` recorded `seed` in `.inarch/workspace_state.toml`, `ingest_directory` must NOT
    // delete `b.txt`—instead it computes delta against `seed` and speculatively rebases across `r1`!
    std::fs::write(ws2.join("c.txt"), b"from-ws2\n").unwrap();
    let r2 = ingest_directory(&engine, "main", "a2@inarch.dev", 102, "add c", &ws2, &[]).unwrap();
    assert_eq!(r2.files_deleted, 0, "must not silently delete b.txt");
    assert_eq!(
        engine
            .read_file(r2.changeset_id, &MPath::new("b.txt").unwrap())
            .unwrap(),
        b"from-ws1\n"
    );
    assert_eq!(
        engine
            .read_file(r2.changeset_id, &MPath::new("c.txt").unwrap())
            .unwrap(),
        b"from-ws2\n"
    );

    // 4. N3 & N5: MCP base_changeset required, explicit op='delete', file_type preserved,
    //    multi-file edits array, and merge revert guard
    let antique = Arc::new(AntiqueService::new(Arc::clone(&engine)));
    let mcp = McpServer::new(Arc::clone(&engine), antique);

    // Missing base_changeset is rejected
    let missing_base = mcp.handle(McpRequest::CallTool {
        id: 10,
        name: "inarch_commit_patch".to_string(),
        args: BTreeMap::from([
            ("target_ref".to_string(), "main".to_string()),
            ("author".to_string(), "bot@inarch.dev".to_string()),
            ("message".to_string(), "no base".to_string()),
            ("path".to_string(), "a.txt".to_string()),
            ("content".to_string(), "v2".to_string()),
        ]),
    });
    assert!(missing_base.error.is_some());

    // Missing content without op='delete' is rejected (no accidental deletion)
    let missing_content = mcp.handle(McpRequest::CallTool {
        id: 11,
        name: "inarch_commit_patch".to_string(),
        args: BTreeMap::from([
            ("target_ref".to_string(), "main".to_string()),
            ("base_changeset".to_string(), "HEAD".to_string()),
            ("author".to_string(), "bot@inarch.dev".to_string()),
            ("message".to_string(), "accidental delete".to_string()),
            ("path".to_string(), "a.txt".to_string()),
        ]),
    });
    assert!(missing_content.error.is_some());

    // Multi-file edits with executable file_type and op='delete'
    let multi_resp = mcp.handle(McpRequest::CallTool {
        id: 12,
        name: "inarch_commit_patch".to_string(),
        args: BTreeMap::from([
            ("target_ref".to_string(), "main".to_string()),
            ("base_changeset".to_string(), "HEAD".to_string()),
            ("author".to_string(), "bot@inarch.dev".to_string()),
            ("message".to_string(), "multi edit".to_string()),
            (
                "edits".to_string(),
                r##"[{"path":"bin/run.sh","content":"#!/bin/sh\necho 1\n","file_type":"executable"},{"path":"a.txt","op":"delete"}]"##.to_string(),
            ),
        ]),
    });
    assert!(multi_resp.error.is_none(), "got: {:?}", multi_resp.error);

    // Subsequent edit to bin/run.sh without specifying file_type preserves FileType::Executable
    let preserve_exec = mcp.handle(McpRequest::CallTool {
        id: 13,
        name: "inarch_commit_patch".to_string(),
        args: BTreeMap::from([
            ("target_ref".to_string(), "main".to_string()),
            ("base_changeset".to_string(), "HEAD".to_string()),
            ("author".to_string(), "bot@inarch.dev".to_string()),
            ("message".to_string(), "update script".to_string()),
            ("path".to_string(), "bin/run.sh".to_string()),
            ("content".to_string(), "#!/bin/sh\necho 2\n".to_string()),
        ]),
    });
    assert!(preserve_exec.error.is_none());
    let head_after_exec = engine.resolve_ref("main").unwrap().unwrap();
    let head_cs = engine
        .meta()
        .get_changeset(&head_after_exec)
        .unwrap()
        .unwrap();
    match head_cs
        .file_changes
        .get(&MPath::new("bin/run.sh").unwrap())
        .unwrap()
    {
        FileChange::Tracked { file_type, .. } => assert_eq!(*file_type, FileType::Executable),
        other => panic!("expected Tracked executable, got {:?}", other),
    }

    // N5: Reverting a merge changeset via MCP is refused with a clear error
    let merge_cs = BonsaiChangeset::new(
        vec![r1.changeset_id, r2.changeset_id],
        "merger@inarch.dev".to_string(),
        200,
        0,
        "merge commit".to_string(),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .unwrap();
    let merge_id = engine.meta().put_changeset(&merge_cs).unwrap();
    let revert_merge = mcp.handle(McpRequest::CallTool {
        id: 14,
        name: "inarch_revert".to_string(),
        args: BTreeMap::from([
            ("target_ref".to_string(), "main".to_string()),
            ("culprit".to_string(), merge_id.to_hex()),
            ("author".to_string(), "bot@inarch.dev".to_string()),
        ]),
    });
    assert!(
        revert_merge
            .error
            .as_deref()
            .unwrap_or("")
            .contains("cannot revert merge changeset"),
        "got: {:?}",
        revert_merge
    );

    // 5. N1, N6, N7: Config ACL wiring, cross-principal lease/principal isolation, and repo_id mismatch rejection
    let cfg = InarchConfig {
        repo_id: "repo-alpha".to_string(),
        acl_rules: vec![AclRuleConfig {
            prefix: "locked/".to_string(),
            allowed_actors: vec!["owner@example.com".to_string()],
            required_reviewers: Vec::new(),
        }],
        ..Default::default()
    };
    let acl_engine = cfg.open_engine(&ws1).unwrap();
    assert!(
        acl_engine
            .check_path_acl(
                "intruder@example.com",
                &MPath::new("locked/key.txt").unwrap()
            )
            .is_err(),
        "open_engine must wire config acl_rules into ScionEngine"
    );

    // Spawn OIDC mock for two workstation principals (ws1@example.com and ws2@example.com)
    let oidc_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let oidc_addr = oidc_listener.local_addr().unwrap();
    let oidc_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let oidc_stop_bg = Arc::clone(&oidc_stop);
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for s_res in oidc_listener.incoming() {
            if oidc_stop_bg.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            if let Ok(mut s) = s_res {
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let body = if req.contains("id_token=tok-ws1") {
                    r#"{"email":"ws1@example.com","email_verified":"true","exp":"4102444800","aud":"test-aud"}"#
                } else {
                    r#"{"email":"ws2@example.com","email_verified":"true","exp":"4102444800","aud":"test-aud"}"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        }
    });

    let mut auth_cfg = ServerAuthConfig::new(Some("admin-tok".to_string()));
    auth_cfg.jit_signing_key = Some(inarch_store::derive_jit_signing_key("c2-test-jit-key"));
    auth_cfg.oidc_audience = Some("test-aud".to_string());
    auth_cfg.oidc_tokeninfo_url = Some(format!("http://{}/tokeninfo", oidc_addr));
    let srv =
        spawn_http_server_with_config(Arc::clone(&acl_engine), "127.0.0.1:0", auth_cfg).unwrap();

    let admin_c = RemoteRpcClient::new(&srv.base_url(), Some("admin-tok".to_string()))
        .unwrap()
        .with_repo_id("repo-alpha");
    for email in ["ws1@example.com", "ws2@example.com"] {
        admin_c
            .call(&RpcRequest::EnrollPrincipal {
                record: PrincipalRecord {
                    principal_email: email.to_string(),
                    principal_kind: "workstation".to_string(),
                    host_label: "ws".to_string(),
                    allowed_repos: vec!["repo-alpha".to_string()],
                    allowed_ops: vec!["read".to_string(), "land".to_string()],
                    status: "active".to_string(),
                    enrolled_by: String::new(),
                    created_at_unix: 100,
                    revoked_at_unix: None,
                    allowed_write_prefixes: vec!["*".to_string()],
                },
            })
            .unwrap();
    }

    let ws1_c = RemoteRpcClient::new(&srv.base_url(), Some("tok-ws1".to_string()))
        .unwrap()
        .with_repo_id("repo-alpha");
    let ws2_c = RemoteRpcClient::new(&srv.base_url(), Some("tok-ws2".to_string()))
        .unwrap()
        .with_repo_id("repo-alpha");

    let (ws1_lease, _) = match ws1_c
        .call(&RpcRequest::CheckoutLease {
            swarm_id: "s1".to_string(),
            task_id: "t1".to_string(),
            repo_id: "repo-alpha".to_string(),
            allowed_ops: vec!["read".to_string()],
            allowed_read_prefixes: Vec::new(),
            allowed_write_prefixes: Vec::new(),
            ttl_secs: 300,
            allowed_refs: vec!["main".to_string()],
        })
        .unwrap()
    {
        RpcResponse::CheckoutLease { lease, token } => (lease, token),
        other => panic!("unexpected: {:?}", other),
    };

    // N6: ws2 cannot revoke or inspect ws1's lease, list all leases, list all principals, or inspect ws1's principal
    assert!(matches!(
        ws2_c
            .call(&RpcRequest::RevokeLease {
                lease_id: ws1_lease.lease_id.clone(),
                revoked_at_unix: 200,
            })
            .unwrap(),
        RpcResponse::Error { .. }
    ));
    assert!(matches!(
        ws2_c
            .call(&RpcRequest::ListLeases { repo_id: None })
            .unwrap(),
        RpcResponse::Error { .. }
    ));
    assert!(matches!(
        ws2_c.call(&RpcRequest::ListPrincipals).unwrap(),
        RpcResponse::Error { .. }
    ));
    assert!(matches!(
        ws2_c
            .call(&RpcRequest::GetPrincipal {
                principal_id: "ws1@example.com".to_string()
            })
            .unwrap(),
        RpcResponse::Error { .. }
    ));
    // ws2 CAN inspect its own principal record
    assert!(matches!(
        ws2_c
            .call(&RpcRequest::GetPrincipal {
                principal_id: "ws2@example.com".to_string()
            })
            .unwrap(),
        RpcResponse::GetPrincipal { record: Some(_) }
    ));

    // N7: repo_id in payload mismatching X-Inarch-Repo header is rejected
    assert!(matches!(
        ws1_c
            .call(&RpcRequest::GetRef {
                repo_id: "other-repo".to_string(),
                ref_name: "main".to_string(),
            })
            .unwrap(),
        RpcResponse::Error { .. }
    ));

    oidc_stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = std::net::TcpStream::connect(oidc_addr);
    srv.shutdown();
    let _ = std::fs::remove_dir_all(&tmp);
}
