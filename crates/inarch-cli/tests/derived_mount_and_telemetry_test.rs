use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use inarch_antique::AntiqueService;
use inarch_cli::{
    McpRequest, McpServer, hydrate_virtual_paths, ingest_directory, mount_virtual_workspace,
    spawn_webdav_virtual_mount, verify_codebase_accuracy,
};
use inarch_derived::CopyKind;
use inarch_engine::{PatchFileEdit, PatchSubmission, ScionEngine};
use inarch_store::telemetry::{
    GcpCloudLoggingSink, JsonlFileTelemetrySink, LogLevel, MemoryTelemetrySink, MultiTelemetrySink,
    TelemetrySink,
};
use inarch_store::{
    DerivedDataKind, FsBlobStore, MemBlobStore, MemMetadataStore, MetadataStore, TieredBlobStore,
};
use inarch_types::{FileType, MPath};

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "inarch_test_{}_{}_{}",
        label,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn test_structured_telemetry_jsonl_gcp_and_engine_events() {
    let tmp = unique_temp_dir("telemetry");
    let log_path = tmp.join("logs").join("inarch.jsonl");

    let mem_sink = Arc::new(MemoryTelemetrySink::new());
    let jsonl_sink = Arc::new(JsonlFileTelemetrySink::new(&log_path).expect("jsonl sink"));
    let gcp_sink = Arc::new(GcpCloudLoggingSink::new_buffer_only(
        "projects/example-proj/logs/inarch",
        "example-monorepo",
    ));

    let multi_sink: Arc<dyn TelemetrySink> = Arc::new(MultiTelemetrySink::new(vec![
        mem_sink.clone(),
        jsonl_sink.clone(),
        gcp_sink.clone(),
    ]));

    let blobs = Arc::new(TieredBlobStore::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemBlobStore::new()),
        Arc::new(MemBlobStore::new()),
    ));
    let meta = Arc::new(MemMetadataStore::new());

    let engine = ScionEngine::with_telemetry("telemetry-repo", blobs, meta, multi_sink);

    let outcome = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "telemetry-agent".to_string(),
            timestamp: 1_700_000_000,
            tz_offset_secs: 0,
            message: "Initial commit with telemetry".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("src/lib.rs").expect("mpath"),
                content: b"pub fn answer() -> u32 { 42 }\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect("land_patch");

    let bytes = engine
        .read_file(outcome.changeset_id, &MPath::new("src/lib.rs").unwrap())
        .expect("read_file");
    assert_eq!(bytes, b"pub fn answer() -> u32 { 42 }\n");

    let events = mem_sink.events();
    assert!(
        events
            .iter()
            .any(|e| e.operation == "land_patch" && e.level == LogLevel::Info),
        "expected land_patch telemetry event, got: {:?}",
        events
    );
    assert!(
        events.iter().any(|e| e.operation == "read_file"),
        "expected read_file telemetry event"
    );

    // Verify JSONL file on disk contains structured entries
    let on_disk = fs::read_to_string(&log_path).expect("read jsonl log");
    assert!(on_disk.contains("\"operation\":\"land_patch\""));
    assert!(on_disk.contains("\"repo_id\":\"telemetry-repo\""));
    assert!(on_disk.contains(&outcome.changeset_id.to_hex()));

    // Verify GCP Cloud Logging StructuredLogEntry format
    let gcp_entries = gcp_sink.formatted_entries();
    assert!(!gcp_entries.is_empty());
    let first_gcp = &gcp_entries[0];
    assert!(first_gcp.contains("\"severity\":\"INFO\""));
    assert!(first_gcp.contains("\"logging.googleapis.com/labels\""));
    assert!(first_gcp.contains("\"logging.googleapis.com/operation\""));
    assert!(first_gcp.contains("\"logName\":\"projects/example-proj/logs/inarch\""));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_inductive_path_search_and_copy_detection_with_mcp() {
    let blobs = Arc::new(TieredBlobStore::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemBlobStore::new()),
        Arc::new(MemBlobStore::new()),
    ));
    let meta = Arc::new(MemMetadataStore::new());
    let engine = Arc::new(ScionEngine::new(blobs, Arc::clone(&meta)));
    let antique = Arc::new(AntiqueService::new(Arc::clone(&engine)));

    // Commit 1: seed initial files
    let engine_code =
        b"pub struct Engine {\n    pub name: String,\n    pub workers: usize,\n    pub active: bool,\n}\n"
            .to_vec();
    let c1 = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "alice".to_string(),
            timestamp: 1_700_000_100,
            tz_offset_secs: 0,
            message: "c1: initial layout".to_string(),
            extra: BTreeMap::new(),
            edits: vec![
                PatchFileEdit::Upsert {
                    path: MPath::new("crates/core/src/engine.rs").unwrap(),
                    content: engine_code.clone(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("crates/core/src/utils.rs").unwrap(),
                    content: b"pub fn helper() -> &'static str { \"ok\" }\n".to_vec(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("docs/README.md").unwrap(),
                    content: b"# Architecture Overview\nLine 1\nLine 2\nLine 3\nLine 4\n".to_vec(),
                    file_type: FileType::Regular,
                },
            ],
        })
        .expect("land c1");

    // Commit 2:
    // - ExactRename: crates/core/src/utils.rs -> crates/core/src/helpers.rs
    // - ExactCopy: crates/core/src/engine.rs -> crates/core/src/engine_backup.rs
    // - SimilarRename: docs/README.md -> docs/GUIDE.md (75%+ identical lines)
    let c2 = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: Some(c1.changeset_id),
            author: "bob".to_string(),
            timestamp: 1_700_000_200,
            tz_offset_secs: 0,
            message: "c2: rename utils, copy engine, evolve guide".to_string(),
            extra: BTreeMap::new(),
            edits: vec![
                PatchFileEdit::Delete {
                    path: MPath::new("crates/core/src/utils.rs").unwrap(),
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("crates/core/src/helpers.rs").unwrap(),
                    content: b"pub fn helper() -> &'static str { \"ok\" }\n".to_vec(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("crates/core/src/engine_backup.rs").unwrap(),
                    content: engine_code,
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Delete {
                    path: MPath::new("docs/README.md").unwrap(),
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("docs/GUIDE.md").unwrap(),
                    content: b"# Architecture Overview\nLine 1\nLine 2\nLine 3\nLine 4 updated\n"
                        .to_vec(),
                    file_type: FileType::Regular,
                },
            ],
        })
        .expect("land c2");

    // 1. Test PathSearchIndex (glob & substring)
    let rs_hits = engine
        .search_paths(c2.changeset_id, "*.rs", 50)
        .expect("search *.rs");
    let rs_paths: Vec<String> = rs_hits
        .iter()
        .map(|e| e.path.as_str().to_string())
        .collect();
    assert_eq!(
        rs_paths,
        vec![
            "crates/core/src/engine.rs".to_string(),
            "crates/core/src/engine_backup.rs".to_string(),
            "crates/core/src/helpers.rs".to_string(),
        ]
    );

    // Ensure PathSearchIndex derived mapping is cached
    assert!(
        meta.get_derived_mapping(c2.changeset_id, DerivedDataKind::PathSearchIndex)
            .unwrap()
            .is_some()
    );

    let guide_hits = engine
        .search_paths(c2.changeset_id, "guide", 10)
        .expect("search guide");
    assert_eq!(guide_hits.len(), 1);
    assert_eq!(guide_hits[0].path.as_str(), "docs/GUIDE.md");

    // 2. Test CopyDetection
    let copy_report = engine
        .detect_copies(c2.changeset_id)
        .expect("detect_copies");
    assert_eq!(copy_report.records.len(), 3);

    let helpers_rec = copy_report
        .records
        .iter()
        .find(|r| r.dest_path.as_str() == "crates/core/src/helpers.rs")
        .expect("helpers copy record");
    assert_eq!(helpers_rec.source_path.as_str(), "crates/core/src/utils.rs");
    assert_eq!(helpers_rec.kind, CopyKind::ExactRename);
    assert_eq!(helpers_rec.similarity_bps, 10_000);

    let backup_rec = copy_report
        .records
        .iter()
        .find(|r| r.dest_path.as_str() == "crates/core/src/engine_backup.rs")
        .expect("engine_backup copy record");
    assert_eq!(backup_rec.source_path.as_str(), "crates/core/src/engine.rs");
    assert_eq!(backup_rec.kind, CopyKind::ExactCopy);
    assert_eq!(backup_rec.similarity_bps, 10_000);

    let guide_rec = copy_report
        .records
        .iter()
        .find(|r| r.dest_path.as_str() == "docs/GUIDE.md")
        .expect("guide rename record");
    assert_eq!(guide_rec.source_path.as_str(), "docs/README.md");
    assert_eq!(guide_rec.kind, CopyKind::SimilarRename);
    assert!(guide_rec.similarity_bps >= 7_000);

    // 3. Test MCP tools for inarch_search_paths and inarch_detect_copies
    let mcp = McpServer::new(engine, antique);
    let search_resp = mcp
        .handle(McpRequest::CallTool {
            id: 1,
            name: "inarch_search_paths".to_string(),
            args: BTreeMap::from([
                ("rev".to_string(), c2.changeset_id.to_hex()),
                ("query".to_string(), "*.rs".to_string()),
            ]),
        })
        .result
        .expect("mcp search resp");
    assert!(search_resp.contains("engine_backup.rs"));
    assert!(search_resp.contains("helpers.rs"));

    let copies_resp = mcp
        .handle(McpRequest::CallTool {
            id: 2,
            name: "inarch_detect_copies".to_string(),
            args: BTreeMap::from([("rev".to_string(), c2.changeset_id.to_hex())]),
        })
        .result
        .expect("mcp copies resp");
    assert!(copies_resp.contains("ExactRename"));
    assert!(copies_resp.contains("ExactCopy"));
    assert!(copies_resp.contains("SimilarRename"));
}

#[test]
fn test_virtual_mount_lazy_hydration_and_cow_commit_plus_webdav() {
    let tmp = unique_temp_dir("virtual_mount");
    let store_dir = tmp.join("store");
    let mount_dir = tmp.join("mnt");

    let disk = Arc::new(FsBlobStore::new(&store_dir).expect("fs store"));
    let blobs = Arc::new(TieredBlobStore::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemBlobStore::new()),
        disk,
    ));
    let meta = Arc::new(MemMetadataStore::new());
    let engine = Arc::new(ScionEngine::new(blobs, meta));

    // Seed a multi-directory repository
    let seed = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "mount-tester".to_string(),
            timestamp: 1_700_000_300,
            tz_offset_secs: 0,
            message: "Initial multi-service repo".to_string(),
            extra: BTreeMap::new(),
            edits: vec![
                PatchFileEdit::Upsert {
                    path: MPath::new("services/api/src/main.rs").unwrap(),
                    content: b"fn main() { println!(\"api v1\"); }\n".to_vec(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("services/worker/src/lib.rs").unwrap(),
                    content: b"pub fn run_worker() -> bool { true }\n".to_vec(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("docs/architecture.md").unwrap(),
                    content: b"# System Architecture\n".to_vec(),
                    file_type: FileType::Regular,
                },
            ],
        })
        .expect("seed commit");

    // 1. Mount virtual workspace: 0 files materialized upfront, directory skeleton created
    let mount_receipt =
        mount_virtual_workspace(&engine, seed.changeset_id, &[], &mount_dir).expect("mount");
    assert_eq!(mount_receipt.total_virtual_files, 3);
    assert_eq!(mount_receipt.hydrated_files, 0);
    assert!(mount_dir.join(".inarch/virtual_mount.toml").exists());
    assert!(mount_dir.join("services/api/src").is_dir());
    assert!(mount_dir.join("services/worker/src").is_dir());
    assert!(!mount_dir.join("services/api/src/main.rs").exists());
    assert!(!mount_dir.join("services/worker/src/lib.rs").exists());

    // 2. Hydrate only `services/api` on demand
    let hydrate_receipt =
        hydrate_virtual_paths(&engine, &mount_dir, &["services/api".to_string()]).expect("hydrate");
    assert_eq!(hydrate_receipt.newly_hydrated_files, 1);
    assert!(mount_dir.join("services/api/src/main.rs").is_file());
    assert!(!mount_dir.join("services/worker/src/lib.rs").exists());
    assert!(!mount_dir.join("docs/architecture.md").exists());

    // 3. Edit the hydrated file and add a new file inside the virtual mount, then ingest!
    // Unhydrated files (`services/worker/src/lib.rs` and `docs/architecture.md`) MUST be preserved!
    fs::write(
        mount_dir.join("services/api/src/main.rs"),
        b"fn main() { println!(\"api v2 updated in virtual mount\"); }\n",
    )
    .expect("write modified api main.rs");
    fs::write(mount_dir.join("services/api/README.md"), b"# API Service\n")
        .expect("write new file in virtual mount");

    let ingest_receipt = ingest_directory(
        &engine,
        "main",
        "mount-tester",
        1_700_000_400,
        "Edit hydrated file and add README from virtual mount",
        &mount_dir,
        &[".inarch"],
    )
    .expect("ingest from virtual mount");

    // Verify the new commit has all 4 files (2 untouched unhydrated + 1 modified + 1 added)
    let api_main = engine
        .read_file(
            ingest_receipt.changeset_id,
            &MPath::new("services/api/src/main.rs").unwrap(),
        )
        .expect("read updated api main");
    assert_eq!(
        api_main,
        b"fn main() { println!(\"api v2 updated in virtual mount\"); }\n"
    );
    let worker_lib = engine
        .read_file(
            ingest_receipt.changeset_id,
            &MPath::new("services/worker/src/lib.rs").unwrap(),
        )
        .expect("unhydrated worker lib preserved");
    assert_eq!(worker_lib, b"pub fn run_worker() -> bool { true }\n");
    let arch_doc = engine
        .read_file(
            ingest_receipt.changeset_id,
            &MPath::new("docs/architecture.md").unwrap(),
        )
        .expect("unhydrated docs preserved");
    assert_eq!(arch_doc, b"# System Architecture\n");

    // Verify codebase accuracy on virtual mount passes for hydrated + virtual files
    let verify_report = verify_codebase_accuracy(
        &engine,
        ingest_receipt.changeset_id,
        &mount_dir,
        &[".inarch"],
    )
    .expect("verify virtual mount");
    assert!(
        verify_report.is_clean(),
        "virtual mount verification should be clean, got: {:?}",
        verify_report
    );
    assert_eq!(verify_report.files_verified, 4);

    // 4. Test loopback WebDAV virtual filesystem server for on-demand GET and CoW PUT
    let webdav = spawn_webdav_virtual_mount(engine.clone(), "main".to_string(), "127.0.0.1:0")
        .expect("webdav");
    let addr = webdav.local_addr;
    let tok = webdav.auth_token.clone();

    // On-demand GET of an unhydrated file (`services/worker/src/lib.rs`)
    {
        let mut stream = TcpStream::connect(addr).expect("connect webdav GET");
        write!(
            stream,
            "GET /services/worker/src/lib.rs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            tok
        )
        .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {}", resp);
        assert!(resp.contains("pub fn run_worker() -> bool { true }"));
    }

    // PROPFIND on root directory
    {
        let mut stream = TcpStream::connect(addr).expect("connect webdav PROPFIND");
        write!(
            stream,
            "PROPFIND / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nDepth: 1\r\nConnection: close\r\n\r\n",
            tok
        )
        .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 207 Multi-Status"),
            "got: {}",
            resp
        );
        assert!(resp.contains("D:multistatus"));
    }

    // PROPFIND on a single file must return file metadata (<D:resourcetype/> and <D:getcontentlength>), not <D:collection/>
    {
        let mut stream = TcpStream::connect(addr).expect("connect webdav file PROPFIND");
        write!(
            stream,
            "PROPFIND /services/worker/src/lib.rs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nDepth: 0\r\nConnection: close\r\n\r\n",
            tok
        )
        .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 207 Multi-Status"),
            "got: {}",
            resp
        );
        assert!(resp.contains("<D:resourcetype/>"), "got: {}", resp);
        assert!(
            resp.contains("<D:getcontentlength>37</D:getcontentlength>"),
            "got: {}",
            resp
        );
    }

    // PROPFIND on a non-existent path must return 404 Not Found
    {
        let mut stream = TcpStream::connect(addr).expect("connect webdav missing PROPFIND");
        write!(
            stream,
            "PROPFIND /no/such/path.rs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nDepth: 0\r\nConnection: close\r\n\r\n",
            tok
        )
        .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"), "got: {}", resp);
    }

    webdav.shutdown();
    let _ = fs::remove_dir_all(&tmp);
}
