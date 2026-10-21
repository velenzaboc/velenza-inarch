// `inr` / `velenza-inarch` (`inr`) — Configuration-driven CLI for Velenza Inarch.
//
// All repository coordinates, storage paths, default branch names, author identities,
// ignore lists, and ACL policies are loaded from `InarchConfig` (`--config <path>`,
// `INARCH_CONFIG`, `./inarch.toml`, or `./.inarch/config.toml`).

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use inarch_antique::AntiqueService;
use inarch_cli::{
    BenchmarkConfig, GitImportOptions, InarchConfig, LocalJitLeaseFile, McpRequest, McpServer,
    ServerAuthConfig, checkout_stateless, default_arbor_search_dirs, discover_arbor_stack,
    export_git_revision, hydrate_virtual_paths, import_git_history, ingest_directory,
    mount_virtual_workspace, resolve_umbrella_subcommand, run_benchmark_suite,
    serve_http_blocking_with_config, spawn_arbor_subcommand_inherited, spawn_webdav_virtual_mount,
    verify_codebase_accuracy,
};
use inarch_engine::{PatchFileEdit, PatchSubmission, ScionEngine};
use inarch_store::{
    FsBlobStore, FsMetadataStore, MemBlobStore, MemMetadataStore, PrincipalRecord, RpcRequest,
    RpcResponse, TieredBlobStore,
};
use inarch_types::bonsai::FileType;
use inarch_types::hash::ChangesetId;
use inarch_types::path::MPath;

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();

    if let Some((layer_id, child_args)) = extract_umbrella_invocation(&raw_args) {
        let search_dirs = default_arbor_search_dirs();
        match spawn_arbor_subcommand_inherited(layer_id, child_args, &search_dirs, &|k| {
            env::var(k).ok()
        }) {
            Ok(code) => {
                std::process::exit(code);
            }
            Err(err) => {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
    }

    let (config_override, args) = extract_config_flag(&raw_args);
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let subcommand = args.first().map(|s| s.as_str()).unwrap_or("help");
    if subcommand == "stack" || subcommand == "arbor" {
        let search_dirs = default_arbor_search_dirs();
        let report = discover_arbor_stack(&search_dirs, &|k| env::var(k).ok());
        if args.iter().skip(1).any(|a| a == "--json") {
            print!("{}", report.to_json_string());
        } else {
            print!("{}", report.to_text_table());
        }
        return;
    }

    let cfg = match InarchConfig::discover(&cwd, config_override.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error loading configuration: {}", e);
            std::process::exit(1);
        }
    };

    match subcommand {
        "stack" | "arbor" => {
            let search_dirs = default_arbor_search_dirs();
            let report = discover_arbor_stack(&search_dirs, &|k| env::var(k).ok());
            if args.iter().skip(1).any(|a| a == "--json") {
                print!("{}", report.to_json_string());
            } else {
                print!("{}", report.to_text_table());
            }
        }
        "init" => {
            let target_dir = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| cwd.clone());
            run_init(&target_dir, &cfg);
        }
        "config" => {
            print!("{}", cfg.to_toml_string());
        }
        "serve" => {
            run_serve(&cwd, &cfg, &args[1..]);
        }
        "whoami" => {
            run_whoami(&cwd, &cfg);
        }
        "principal" => {
            run_principal(&cwd, &cfg, &args[1..]);
        }
        "lease" => {
            run_lease(&cwd, &cfg, &args[1..]);
        }
        "refs" => {
            run_refs(&cwd, &cfg);
        }
        "commit" => {
            run_commit(&cwd, &cfg, &args[1..]);
        }
        "checkout" => {
            run_checkout(&cwd, &cfg, &args[1..]);
        }
        "mount" => {
            run_mount(&cwd, &cfg, &args[1..]);
        }
        "hydrate" => {
            run_hydrate(&cwd, &cfg, &args[1..]);
        }
        "status" => {
            run_status(&cwd, &cfg, &args[1..]);
        }
        "log" => {
            run_log(&cwd, &cfg, &args[1..]);
        }
        "diff" => {
            run_diff(&cwd, &cfg, &args[1..]);
        }
        "cat" => {
            run_cat(&cwd, &cfg, &args[1..]);
        }
        "ls" => {
            run_ls(&cwd, &cfg, &args[1..]);
        }
        "blame" => {
            run_blame(&cwd, &cfg, &args[1..]);
        }
        "search" => {
            run_search(&cwd, &cfg, &args[1..]);
        }
        "copies" => {
            run_copies(&cwd, &cfg, &args[1..]);
        }
        "revert" => {
            run_revert(&cwd, &cfg, &args[1..]);
        }
        "bisect" => {
            run_bisect(&cwd, &cfg, &args[1..]);
        }
        "git-import" => {
            run_git_import(&cwd, &cfg, &args[1..]);
        }
        "git-export" => {
            run_git_export(&cwd, &cfg, &args[1..]);
        }
        "bench" => {
            run_bench(&cwd, &args[1..]);
        }
        "mcp-tools" => {
            println!("Velenza Inarch Checkout-Free MCP Tool Catalog:");
            for (name, desc) in McpServer::tool_catalog() {
                println!("  {:<20} {}", name, desc);
            }
        }
        "mcp-stdio" => {
            run_mcp_stdio(&cwd, &cfg);
        }
        "demo" => {
            run_demo(&cfg);
        }
        "verify-codebase" => {
            let dir = args.get(1).map(|s| s.as_str()).unwrap_or(".");
            run_verify_codebase(Path::new(dir), &cfg);
        }
        _ => {
            print_help();
        }
    }
}

fn extract_umbrella_invocation(
    raw_args: &[String],
) -> Option<(inarch_cli::ArborLayerId, &[String])> {
    let mut i = 0;
    while i < raw_args.len() {
        if raw_args[i] == "--config" {
            i += 2;
            continue;
        }
        if raw_args[i].starts_with("--config=") {
            i += 1;
            continue;
        }
        if let Some(layer_id) = resolve_umbrella_subcommand(&raw_args[i]) {
            return Some((layer_id, &raw_args[i + 1..]));
        }
        return None;
    }
    None
}

fn extract_config_flag(raw_args: &[String]) -> (Option<PathBuf>, Vec<String>) {
    let mut config_path = None;
    let mut filtered = Vec::new();
    let mut i = 0;
    while i < raw_args.len() {
        if raw_args[i] == "--config" {
            if let Some(val) = raw_args.get(i + 1) {
                config_path = Some(PathBuf::from(val));
                i += 2;
                continue;
            }
        } else if let Some(val) = raw_args[i].strip_prefix("--config=") {
            config_path = Some(PathBuf::from(val));
            i += 1;
            continue;
        }
        filtered.push(raw_args[i].clone());
        i += 1;
    }
    (config_path, filtered)
}

fn print_help() {
    println!(
        "Velenza Inarch (inr / velenza-inarch) — Server-Centric, Checkout-Free Version Control System"
    );
    println!();
    println!("GLOBAL OPTIONS:");
    println!("  --config <path>              Path to inarch.toml (or set INARCH_CONFIG)");
    println!();
    println!("COMMANDS:");
    println!("  inr init [dir]               Initialize local store and config.toml");
    println!("  inr config                   Print active resolved configuration (TOML)");
    println!("  inr serve [--listen <addr>]  Run stateless Velenza Inarch HTTP/RPC server");
    println!(
        "  inr whoami                   Verify caller identity & active JIT lease against server"
    );
    println!(
        "  inr principal <subcmd>       Manage workstation/service-account principals (enroll|list|get|revoke)"
    );
    println!(
        "  inr lease <subcmd>           Manage Just-In-Time (JIT) swarm access leases (checkout|checkin|renew|revoke|list)"
    );
    println!("  inr refs                     List repository branch/tag refs");
    println!("  inr commit -m <msg> [dir]    Ingest & land directory changes onto configured ref");
    println!(
        "  inr checkout <rev> <dest>    Stateless tree-walk checkout (--prefix p1,p2 --jit-ttl <secs>)"
    );
    println!(
        "  inr mount <rev> <dest>       Instant virtual workspace mount (0 blob writes; --serve-webdav <addr>)"
    );
    println!(
        "  inr hydrate <dest> <p1...>   Hydrate individual files or prefixes on demand in a virtual mount"
    );
    println!(
        "  inr git-import [git_dir]     Import Git commit history into tree-free BonsaiChangesets"
    );
    println!("  inr git-export <rev> <dest>  Export an Inarch revision to a Git repository branch");
    println!(
        "  inr bench [options]          Run scientific Git vs. Velenza Inarch benchmark suite"
    );
    println!("  inr status [dir]             Verify working tree against head revision");
    println!("  inr log [--path <p>]         Inspect changeset history or O(k) path history");
    println!(
        "  inr diff <base> <head>       Compute O(d) structural Merkle diff between revisions"
    );
    println!("  inr cat <rev> <path>         Checkout-free file read");
    println!(
        "  inr ls <rev> [path]          Checkout-free directory listing with recursive rollups"
    );
    println!("  inr blame <rev> <path>       Checkout-free inductive line-by-line blame");
    println!(
        "  inr search <rev> <query>     Checkout-free inductive path search (glob or substring)"
    );
    println!("  inr copies <rev>             Checkout-free inductive copy and rename detection");
    println!(
        "  inr revert <rev> [--ref <r>] Synthesize and land an instant server-side inverse commit"
    );
    println!(
        "  inr bisect --good <g> --bad <b> --run <cmd>  Automated O(log N) post-merge regression bisect"
    );
    println!(
        "  inr verify-codebase [dir]    Cold-disk round-trip & 100% byte-for-byte accuracy check"
    );
    println!(
        "  inr demo                     Run end-to-end 3-tier cache & speculative rebase showcase"
    );
    println!(
        "  inr mcp-tools                List checkout-free Model Context Protocol (MCP) tools"
    );
    println!("  inr mcp-stdio                Run checkout-free MCP JSON-RPC server over stdio");
    println!();
    println!("VELENZA ARBOR STACK (UMBRELLA CLI):");
    println!(
        "  inr stack [--json]           Inspect all 4 Velenza Arbor Stack layers and resolved binaries"
    );
    println!("  inr cambium|code <args...>   Delegate to Layer 1: velenza-cambium (code-graph)");
    println!("  inr canon|spec <args...>     Delegate to Layer 2: velenza-canon (spec-graph)");
    println!("  inr trellis|task <args...>   Delegate to Layer 3: velenza-trellis (task-graph)");
}

fn resolve_rev_or_ref(engine: &ScionEngine, rev_or_ref: &str) -> Result<ChangesetId, String> {
    match engine.resolve_ref(rev_or_ref) {
        Ok(Some(cs_id)) => return Ok(cs_id),
        Ok(None) => {}
        Err(e) => return Err(format!("failed to resolve ref '{}': {}", rev_or_ref, e)),
    }
    if rev_or_ref.len() == 64 {
        if let Ok(cs_id) = ChangesetId::from_hex(rev_or_ref) {
            return Ok(cs_id);
        }
    }
    Err(format!("unknown revision or ref: {}", rev_or_ref))
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(1_760_000_000)
}

fn run_init(target_dir: &Path, cfg: &InarchConfig) {
    let engine = cfg
        .open_engine(target_dir)
        .expect("initialize Velenza Inarch storage");
    drop(engine);
    let config_file = target_dir.join(".inarch/config.toml");
    if !config_file.exists() {
        cfg.write_to_file(&config_file)
            .expect("write .inarch/config.toml");
    }
    println!(
        "Initialized Velenza Inarch repository in {} (config: {})",
        target_dir.join(".inarch").display(),
        config_file.display()
    );
}

fn run_serve(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let mut listen_addr = cfg.listen_addr.clone();
    let mut allow_plaintext_non_loopback = false;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--listen" {
            if let Some(a) = args.get(i + 1) {
                listen_addr = a.clone();
                i += 2;
                continue;
            }
        } else if args[i] == "--allow-plaintext-non-loopback" {
            allow_plaintext_non_loopback = true;
        }
        i += 1;
    }

    if let Err(e) =
        inarch_cli::validate_serve_bind_address(&listen_addr, allow_plaintext_non_loopback)
    {
        eprintln!("server bind error: {}", e);
        std::process::exit(1);
    }

    let (blobs, meta) = cfg
        .open_server_stores(cwd)
        .expect("open server storage backends");
    let telemetry = cfg
        .build_telemetry_sink(cwd)
        .unwrap_or_else(|_| Arc::new(inarch_store::telemetry::NoopTelemetrySink));
    let engine = ScionEngine::with_telemetry(&cfg.repo_id, blobs, meta, telemetry);
    if !cfg.acl_rules.is_empty() {
        let rules = cfg
            .acl_rules
            .iter()
            .map(|r| inarch_engine::EnginePathAclRule {
                prefix: r.prefix.clone(),
                allowed_actors: r.allowed_actors.clone(),
            })
            .collect();
        engine.set_acl_rules(rules);
    }
    let engine = Arc::new(engine);
    let mut auth_cfg = ServerAuthConfig::from_inarch_config(cfg).unwrap_or_else(|e| {
        eprintln!("server auth configuration error: {}", e);
        std::process::exit(1);
    });
    if !cfg.auth_token.is_empty() && auth_cfg.admin_token.is_none() {
        auth_cfg.admin_token = Some(cfg.auth_token.clone());
        auth_cfg.require_auth = true;
    }
    println!(
        "Velenza Inarch server listening on http://{} (blob_backend={}, meta_backend={}, require_auth={})",
        listen_addr, cfg.blob_backend, cfg.meta_backend, auth_cfg.require_auth
    );
    serve_http_blocking_with_config(engine, &listen_addr, auth_cfg)
        .expect("run Velenza Inarch HTTP server");
}

fn parse_csv_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn run_whoami(cwd: &Path, cfg: &InarchConfig) {
    let client = cfg.open_remote_client(cwd).unwrap_or_else(|e| {
        eprintln!("error opening remote client: {}", e);
        std::process::exit(1);
    });
    match client.call(&RpcRequest::WhoAmI) {
        Ok(RpcResponse::WhoAmI {
            principal_id,
            role,
            auth_method,
            lease,
        }) => {
            println!("principal_id: {}", principal_id);
            println!("role:         {}", role);
            println!("auth_method:  {}", auth_method);
            println!("repo_id:      {}", cfg.repo_id);
            if let Some(l) = lease {
                println!(
                    "active_lease: {} (swarm={}, task={}, expires_at={})",
                    l.lease_id, l.swarm_id, l.task_id, l.expires_at_unix
                );
            } else {
                let lease_path = LocalJitLeaseFile::resolve_path(cwd, &cfg.jit_lease_file);
                if let Ok(local_lease) = LocalJitLeaseFile::load_from_file(&lease_path) {
                    println!(
                        "active_lease: {} (swarm={}, task={}, expires_at={})",
                        local_lease.lease_id,
                        local_lease.swarm_id,
                        local_lease.task_id,
                        local_lease.expires_at_unix
                    );
                }
            }
        }
        Ok(RpcResponse::Error { message }) => {
            eprintln!("server error: {}", message);
            std::process::exit(1);
        }
        Ok(other) => {
            eprintln!("unexpected response: {:?}", other);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("whoami RPC failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_principal(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("list");
    let client = cfg.open_remote_client(cwd).unwrap_or_else(|e| {
        eprintln!("error opening remote client: {}", e);
        std::process::exit(1);
    });

    match sub {
        "enroll" => {
            let Some(email) = args.get(1).cloned() else {
                eprintln!(
                    "usage: inr principal enroll <email> --host <label> [--kind workstation|admin] [--repos *] [--ops read,land] [--write-prefixes *]"
                );
                std::process::exit(1);
            };
            let mut host_label = String::from("workstation");
            let mut kind = String::from("workstation");
            let mut repos = vec![String::from("*")];
            let mut ops = vec![String::from("read"), String::from("land")];
            let mut write_prefixes = vec![String::from("*")];

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--host" => {
                        if let Some(v) = args.get(i + 1) {
                            host_label = v.clone();
                            i += 2;
                            continue;
                        }
                    }
                    "--kind" => {
                        if let Some(v) = args.get(i + 1) {
                            kind = v.clone();
                            i += 2;
                            continue;
                        }
                    }
                    "--repos" => {
                        if let Some(v) = args.get(i + 1) {
                            repos = parse_csv_list(v);
                            i += 2;
                            continue;
                        }
                    }
                    "--ops" => {
                        if let Some(v) = args.get(i + 1) {
                            ops = parse_csv_list(v);
                            i += 2;
                            continue;
                        }
                    }
                    "--write-prefixes" | "--write-prefix" => {
                        if let Some(v) = args.get(i + 1) {
                            write_prefixes = parse_csv_list(v);
                            i += 2;
                            continue;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }

            let record = PrincipalRecord {
                principal_email: email.clone(),
                principal_kind: kind,
                host_label,
                allowed_repos: repos,
                allowed_ops: ops,
                status: String::from("active"),
                enrolled_by: String::new(),
                created_at_unix: now_unix_secs(),
                revoked_at_unix: None,
                allowed_write_prefixes: write_prefixes,
            };

            match client.call(&RpcRequest::EnrollPrincipal { record }) {
                Ok(RpcResponse::EnrollPrincipalOk) => {
                    println!("Enrolled principal {}", email);
                }
                Ok(RpcResponse::Error { message }) => {
                    eprintln!("enroll failed: {}", message);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("RPC error: {}", e);
                    std::process::exit(1);
                }
                _ => {}
            }
        }
        "list" => match client.call(&RpcRequest::ListPrincipals) {
            Ok(RpcResponse::ListPrincipals { principals }) => {
                for p in principals {
                    println!(
                        "{}\tkind={}\thost={}\tstatus={}\trepos={}\tops={}\twrite_prefixes={}",
                        p.principal_email,
                        p.principal_kind,
                        p.host_label,
                        p.status,
                        p.allowed_repos.join(","),
                        p.allowed_ops.join(","),
                        p.allowed_write_prefixes.join(",")
                    );
                }
            }
            Ok(RpcResponse::Error { message }) => {
                eprintln!("list principals failed: {}", message);
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("RPC error: {}", e);
                std::process::exit(1);
            }
            _ => {}
        },
        "get" => {
            let Some(email) = args.get(1).cloned() else {
                eprintln!("usage: inr principal get <email>");
                std::process::exit(1);
            };
            match client.call(&RpcRequest::GetPrincipal {
                principal_id: email.clone(),
            }) {
                Ok(RpcResponse::GetPrincipal { record: Some(p) }) => {
                    println!(
                        "{}\tkind={}\thost={}\tstatus={}\trepos={}\tops={}\twrite_prefixes={}\tenrolled_by={}",
                        p.principal_email,
                        p.principal_kind,
                        p.host_label,
                        p.status,
                        p.allowed_repos.join(","),
                        p.allowed_ops.join(","),
                        p.allowed_write_prefixes.join(","),
                        p.enrolled_by
                    );
                }
                Ok(RpcResponse::GetPrincipal { record: None }) => {
                    eprintln!("principal not found: {}", email);
                    std::process::exit(1);
                }
                Ok(RpcResponse::Error { message }) => {
                    eprintln!("get principal failed: {}", message);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("RPC error: {}", e);
                    std::process::exit(1);
                }
                _ => {}
            }
        }
        "revoke" => {
            let Some(email) = args.get(1).cloned() else {
                eprintln!("usage: inr principal revoke <email>");
                std::process::exit(1);
            };
            match client.call(&RpcRequest::RevokePrincipal {
                principal_id: email.clone(),
                revoked_at_unix: now_unix_secs(),
            }) {
                Ok(RpcResponse::RevokePrincipalOk) => {
                    println!("Revoked principal {}", email);
                }
                Ok(RpcResponse::Error { message }) => {
                    eprintln!("revoke failed: {}", message);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("RPC error: {}", e);
                    std::process::exit(1);
                }
                _ => {}
            }
        }
        other => {
            eprintln!(
                "unknown principal subcommand '{}': expected enroll|list|get|revoke",
                other
            );
            std::process::exit(1);
        }
    }
}

fn run_lease(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("list");

    match sub {
        "checkout" => {
            let mut repo_id = cfg.repo_id.clone();
            let mut swarm_id = String::from("swarm-default");
            let mut task_id = String::from("task-default");
            let mut ttl_secs = 3600u64;
            let mut ops = vec![String::from("read"), String::from("land")];
            let mut write_prefixes: Vec<String> = Vec::new();
            let mut allowed_refs: Vec<String> = vec![String::from("*")];
            let mut dest_dir = cwd.to_path_buf();

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--repo" => {
                        if let Some(v) = args.get(i + 1) {
                            repo_id = v.clone();
                            i += 2;
                            continue;
                        }
                    }
                    "--swarm" | "--swarm-id" => {
                        if let Some(v) = args.get(i + 1) {
                            swarm_id = v.clone();
                            i += 2;
                            continue;
                        }
                    }
                    "--task" | "--task-id" => {
                        if let Some(v) = args.get(i + 1) {
                            task_id = v.clone();
                            i += 2;
                            continue;
                        }
                    }
                    "--ttl" | "--ttl-secs" => {
                        if let Some(v) = args.get(i + 1).and_then(|s| s.parse().ok()) {
                            ttl_secs = v;
                            i += 2;
                            continue;
                        }
                    }
                    "--ops" => {
                        if let Some(v) = args.get(i + 1) {
                            ops = parse_csv_list(v);
                            i += 2;
                            continue;
                        }
                    }
                    "--read-prefix" | "--read-prefixes" => {
                        eprintln!(
                            "error: read prefixes are not enforced; use --write-prefix to restrict writes"
                        );
                        std::process::exit(1);
                    }
                    "--write-prefix" | "--write-prefixes" => {
                        if let Some(v) = args.get(i + 1) {
                            write_prefixes = parse_csv_list(v);
                            i += 2;
                            continue;
                        }
                    }
                    "--refs" | "--allowed-refs" => {
                        if let Some(v) = args.get(i + 1) {
                            allowed_refs = parse_csv_list(v);
                            i += 2;
                            continue;
                        }
                    }
                    "--dest" => {
                        if let Some(v) = args.get(i + 1) {
                            dest_dir = PathBuf::from(v);
                            i += 2;
                            continue;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }

            let client = cfg.open_remote_client(cwd).unwrap_or_else(|e| {
                eprintln!("error opening remote client: {}", e);
                std::process::exit(1);
            });
            match client.call(&RpcRequest::CheckoutLease {
                swarm_id,
                task_id,
                repo_id,
                allowed_ops: ops,
                allowed_read_prefixes: Vec::new(),
                allowed_write_prefixes: write_prefixes,
                ttl_secs,
                allowed_refs,
            }) {
                Ok(RpcResponse::CheckoutLease { lease, token }) => {
                    let lease_file_path =
                        LocalJitLeaseFile::resolve_path(&dest_dir, &cfg.jit_lease_file);
                    let local_file = LocalJitLeaseFile::from_lease_and_token(&lease, token);
                    local_file
                        .write_to_file(&lease_file_path)
                        .expect("write .inarch/jit_lease.json");
                    println!(
                        "Checked out JIT lease {} for repo '{}' (swarm={}, task={}, expires_at={}, file={})",
                        lease.lease_id,
                        lease.repo_id,
                        lease.swarm_id,
                        lease.task_id,
                        lease.expires_at_unix,
                        lease_file_path.display()
                    );
                }
                Ok(RpcResponse::Error { message }) => {
                    eprintln!("lease checkout failed: {}", message);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("RPC error: {}", e);
                    std::process::exit(1);
                }
                _ => {}
            }
        }
        "checkin" => {
            let mut lease_id_opt: Option<String> = None;
            let mut target_dir = cwd.to_path_buf();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--lease-id" => {
                        if let Some(v) = args.get(i + 1) {
                            lease_id_opt = Some(v.clone());
                            i += 2;
                            continue;
                        }
                    }
                    "--dir" => {
                        if let Some(v) = args.get(i + 1) {
                            target_dir = PathBuf::from(v);
                            i += 2;
                            continue;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }

            let lease_file_path = LocalJitLeaseFile::resolve_path(&target_dir, &cfg.jit_lease_file);
            if lease_id_opt.is_none() {
                if let Ok(local) = LocalJitLeaseFile::load_from_file(&lease_file_path) {
                    lease_id_opt = Some(local.lease_id);
                }
            }
            let Some(lease_id) = lease_id_opt else {
                eprintln!(
                    "no active JIT lease found in {} and no --lease-id specified",
                    lease_file_path.display()
                );
                std::process::exit(1);
            };

            let client = cfg.open_remote_client(&target_dir).unwrap_or_else(|e| {
                eprintln!("error opening remote client: {}", e);
                std::process::exit(1);
            });
            match client.call(&RpcRequest::RevokeLease {
                lease_id: lease_id.clone(),
                revoked_at_unix: now_unix_secs(),
            }) {
                Ok(RpcResponse::RevokeLeaseOk) => {
                    let _ = std::fs::remove_file(&lease_file_path);
                    println!("Checked in and revoked JIT lease {}", lease_id);
                }
                Ok(RpcResponse::Error { message }) => {
                    eprintln!("lease checkin failed: {}", message);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("RPC error: {}", e);
                    std::process::exit(1);
                }
                _ => {}
            }
        }
        "renew" => {
            let mut lease_id_opt: Option<String> = None;
            let mut ttl_secs = 3600u64;
            let mut target_dir = cwd.to_path_buf();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--lease-id" => {
                        if let Some(v) = args.get(i + 1) {
                            lease_id_opt = Some(v.clone());
                            i += 2;
                            continue;
                        }
                    }
                    "--ttl" => {
                        if let Some(v) = args.get(i + 1).and_then(|s| s.parse().ok()) {
                            ttl_secs = v;
                            i += 2;
                            continue;
                        }
                    }
                    "--dir" => {
                        if let Some(v) = args.get(i + 1) {
                            target_dir = PathBuf::from(v);
                            i += 2;
                            continue;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }

            let lease_file_path = LocalJitLeaseFile::resolve_path(&target_dir, &cfg.jit_lease_file);
            if lease_id_opt.is_none() {
                if let Ok(local) = LocalJitLeaseFile::load_from_file(&lease_file_path) {
                    lease_id_opt = Some(local.lease_id);
                }
            }
            let Some(lease_id) = lease_id_opt else {
                eprintln!("no active JIT lease found and no --lease-id specified");
                std::process::exit(1);
            };

            let client = cfg.open_remote_client(&target_dir).unwrap_or_else(|e| {
                eprintln!("error opening remote client: {}", e);
                std::process::exit(1);
            });
            match client.call(&RpcRequest::RenewLease { lease_id, ttl_secs }) {
                Ok(RpcResponse::RenewLease { lease, token }) => {
                    if lease_file_path.exists() {
                        let updated = LocalJitLeaseFile::from_lease_and_token(&lease, token);
                        let _ = updated.write_to_file(&lease_file_path);
                    }
                    println!(
                        "Renewed JIT lease {} (new expires_at={})",
                        lease.lease_id, lease.expires_at_unix
                    );
                }
                Ok(RpcResponse::Error { message }) => {
                    eprintln!("lease renew failed: {}", message);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("RPC error: {}", e);
                    std::process::exit(1);
                }
                _ => {}
            }
        }
        "revoke" => {
            let Some(lease_id) = args.get(1).cloned() else {
                eprintln!("usage: inr lease revoke <lease_id>");
                std::process::exit(1);
            };
            let client = cfg.open_remote_client(cwd).unwrap_or_else(|e| {
                eprintln!("error opening remote client: {}", e);
                std::process::exit(1);
            });
            match client.call(&RpcRequest::RevokeLease {
                lease_id: lease_id.clone(),
                revoked_at_unix: now_unix_secs(),
            }) {
                Ok(RpcResponse::RevokeLeaseOk) => {
                    println!("Revoked JIT lease {}", lease_id);
                }
                Ok(RpcResponse::Error { message }) => {
                    eprintln!("lease revoke failed: {}", message);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("RPC error: {}", e);
                    std::process::exit(1);
                }
                _ => {}
            }
        }
        "list" => {
            let mut repo_id: Option<String> = None;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--repo" {
                    if let Some(v) = args.get(i + 1) {
                        repo_id = Some(v.clone());
                        i += 2;
                        continue;
                    }
                }
                i += 1;
            }
            let client = cfg.open_remote_client(cwd).unwrap_or_else(|e| {
                eprintln!("error opening remote client: {}", e);
                std::process::exit(1);
            });
            match client.call(&RpcRequest::ListLeases { repo_id }) {
                Ok(RpcResponse::ListLeases { leases }) => {
                    for l in leases {
                        println!(
                            "{}\trepo={}\tswarm={}\ttask={}\tprincipal={}\texpires_at={}\trevoked={}\twrite_prefixes={}",
                            l.lease_id,
                            l.repo_id,
                            l.swarm_id,
                            l.task_id,
                            l.principal_email,
                            l.expires_at_unix,
                            l.revoked,
                            l.allowed_write_prefixes.join(",")
                        );
                    }
                }
                Ok(RpcResponse::Error { message }) => {
                    eprintln!("list leases failed: {}", message);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("RPC error: {}", e);
                    std::process::exit(1);
                }
                _ => {}
            }
        }
        other => {
            eprintln!(
                "unknown lease subcommand '{}': expected checkout|checkin|renew|revoke|list",
                other
            );
            std::process::exit(1);
        }
    }
}

fn run_refs(cwd: &Path, cfg: &InarchConfig) {
    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let refs = engine.meta().list_refs().expect("list refs");
    for (name, cs_id) in refs {
        println!("{}\t{}", cs_id.to_hex(), name);
    }
}

fn run_commit(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let mut message = None;
    let mut target_ref = cfg.default_ref.clone();
    let mut author = cfg.default_author.clone();
    let mut source_dir = cwd.to_path_buf();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-m" | "--message" => {
                if let Some(m) = args.get(i + 1) {
                    message = Some(m.clone());
                    i += 2;
                    continue;
                }
            }
            "--ref" => {
                if let Some(r) = args.get(i + 1) {
                    target_ref = r.clone();
                    i += 2;
                    continue;
                }
            }
            "--author" => {
                if let Some(a) = args.get(i + 1) {
                    author = a.clone();
                    i += 2;
                    continue;
                }
            }
            other if !other.starts_with('-') => {
                source_dir = PathBuf::from(other);
            }
            _ => {}
        }
        i += 1;
    }

    let msg = message.unwrap_or_else(|| "inr commit".to_string());
    let engine = cfg
        .open_engine(&source_dir)
        .expect("open configured engine");
    let ignore_refs = cfg.ignore_slices();
    let receipt = match ingest_directory(
        &engine,
        &target_ref,
        &author,
        now_unix_secs(),
        &msg,
        &source_dir,
        &ignore_refs,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("commit failed: {}", e);
            std::process::exit(1);
        }
    };

    println!(
        "[{}] {} ({} files scanned, {} upserted, {} deleted, {} bytes)",
        target_ref,
        receipt.changeset_id.to_hex(),
        receipt.files_scanned,
        receipt.files_upserted,
        receipt.files_deleted,
        receipt.bytes_ingested
    );
}

fn run_checkout(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let mut prefixes: Option<Vec<MPath>> = None;
    let mut raw_prefixes: Vec<String> = Vec::new();
    let mut jit_ttl_opt: Option<u64> = None;
    let mut swarm_id = String::from("swarm-checkout");
    let mut task_id = String::from("task-checkout");
    let mut write_prefixes: Option<Vec<String>> = None;
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--prefix" => {
                if let Some(val) = args.get(i + 1) {
                    raw_prefixes = parse_csv_list(val);
                    prefixes = Some(
                        raw_prefixes
                            .iter()
                            .map(|s| MPath::new(s).expect("valid sparse prefix MPath"))
                            .collect(),
                    );
                    i += 2;
                    continue;
                }
            }
            "--jit-ttl" => {
                if let Some(val) = args.get(i + 1).and_then(|s| s.parse().ok()) {
                    jit_ttl_opt = Some(val);
                    i += 2;
                    continue;
                }
            }
            "--swarm-id" => {
                if let Some(val) = args.get(i + 1) {
                    swarm_id = val.clone();
                    i += 2;
                    continue;
                }
            }
            "--task-id" => {
                if let Some(val) = args.get(i + 1) {
                    task_id = val.clone();
                    i += 2;
                    continue;
                }
            }
            "--write-prefix" | "--write-prefixes" => {
                if let Some(val) = args.get(i + 1) {
                    write_prefixes = Some(parse_csv_list(val));
                    i += 2;
                    continue;
                }
            }
            "--read-prefix" | "--read-prefixes" => {
                eprintln!(
                    "error: read prefixes are not enforced; use --write-prefix to restrict writes"
                );
                std::process::exit(1);
            }
            _ => {}
        }
        positional.push(args[i].clone());
        i += 1;
    }

    let rev = positional
        .first()
        .map(|s| s.as_str())
        .unwrap_or(&cfg.default_ref);
    let dest = positional
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| cwd.to_path_buf());

    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let cs_id = resolve_rev_or_ref(&engine, rev).expect("resolve checkout revision");
    let report = checkout_stateless(&engine, cs_id, prefixes.as_deref(), &dest)
        .expect("stateless tree-walk checkout");
    let sp_file = dest.join(".inarch").join("sparse_prefixes");
    if !raw_prefixes.is_empty() {
        let _ = std::fs::create_dir_all(dest.join(".inarch"));
        let _ = std::fs::write(&sp_file, format!("{}\n", raw_prefixes.join("\n")));
    } else {
        let _ = std::fs::remove_file(&sp_file);
    }
    println!(
        "Checked out {} to {} ({} files materialized, {} bytes, root_fsnode={})",
        cs_id.to_hex(),
        dest.display(),
        report.files_materialized,
        report.bytes_materialized,
        report.root_fsnode_id.to_hex()
    );

    if let Some(ttl_secs) = jit_ttl_opt {
        let client = cfg
            .open_remote_client(cwd)
            .expect("open remote client for JIT lease checkout");
        let eff_write = write_prefixes.unwrap_or_else(|| raw_prefixes.clone());
        match client.call(&RpcRequest::CheckoutLease {
            swarm_id,
            task_id,
            repo_id: cfg.repo_id.clone(),
            allowed_ops: vec![String::from("read"), String::from("land")],
            allowed_read_prefixes: Vec::new(),
            allowed_write_prefixes: eff_write,
            ttl_secs,
            allowed_refs: vec![String::from("*")],
        }) {
            Ok(RpcResponse::CheckoutLease { lease, token }) => {
                let lease_file_path = LocalJitLeaseFile::resolve_path(&dest, &cfg.jit_lease_file);
                let local_file = LocalJitLeaseFile::from_lease_and_token(&lease, token);
                local_file
                    .write_to_file(&lease_file_path)
                    .expect("write .inarch/jit_lease.json");
                println!(
                    "Bound JIT lease {} to {} (repo={}, expires_at={})",
                    lease.lease_id,
                    lease_file_path.display(),
                    lease.repo_id,
                    lease.expires_at_unix
                );
            }
            Ok(RpcResponse::Error { message }) => {
                eprintln!("JIT lease checkout failed: {}", message);
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("JIT lease RPC error: {}", e);
                std::process::exit(1);
            }
            _ => {}
        }
    }
}

fn run_status(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let mut rev = cfg.default_ref.clone();
    let mut dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        if (args[i] == "--rev" || args[i] == "--ref")
            && let Some(r) = args.get(i + 1)
        {
            rev = r.clone();
            i += 2;
            continue;
        } else if !args[i].starts_with('-') && dir.is_none() {
            dir = Some(PathBuf::from(&args[i]));
        }
        i += 1;
    }
    let dir = dir.unwrap_or_else(|| cwd.to_path_buf());
    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let cs_id = resolve_rev_or_ref(&engine, &rev).expect("resolve status revision");
    let ignore_refs = cfg.ignore_slices();
    match verify_codebase_accuracy(&engine, cs_id, &dir, &ignore_refs) {
        Ok(report) => {
            println!(
                "Clean against {} ({}): {} files ({} bytes) verified 100% exact",
                rev,
                &cs_id.to_hex()[..16],
                report.files_verified,
                report.bytes_verified
            );
        }
        Err(e) => {
            println!("Working tree differs from {}: {}", rev, e);
            std::process::exit(1);
        }
    }
}

fn run_log(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let mut rev = cfg.default_ref.clone();
    let mut path_filter: Option<String> = None;
    let mut limit = 20usize;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rev" => {
                if let Some(r) = args.get(i + 1) {
                    rev = r.clone();
                    i += 2;
                    continue;
                }
            }
            "--path" => {
                if let Some(p) = args.get(i + 1) {
                    path_filter = Some(p.clone());
                    i += 2;
                    continue;
                }
            }
            "--limit" | "-n" => {
                if let Some(n) = args.get(i + 1).and_then(|s| s.parse().ok()) {
                    limit = n;
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let head_id = resolve_rev_or_ref(&engine, &rev).expect("resolve revision");

    if let Some(p_str) = path_filter {
        let mpath = MPath::new(&p_str).expect("valid MPath");
        let summaries = engine
            .log_path(head_id, &mpath)
            .expect("query O(k) path log");
        for s in summaries.into_iter().take(limit) {
            println!(
                "{} | {} | {} | {}",
                s.changeset_id.to_hex(),
                s.author,
                s.timestamp,
                s.message
            );
        }
    } else {
        let mut cursor = Some(head_id);
        let mut count = 0;
        while let Some(id) = cursor {
            if count >= limit {
                break;
            }
            let cs = engine
                .meta()
                .get_changeset(&id)
                .expect("load changeset")
                .expect("changeset exists");
            println!(
                "{} | {} | {} | {}",
                id.to_hex(),
                cs.author,
                cs.author_date_secs,
                cs.message
            );
            cursor = cs.parents.first().copied();
            count += 1;
        }
    }
}

fn run_diff(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    if args.len() < 2 {
        eprintln!("usage: inr diff <base_rev> <head_rev>");
        std::process::exit(1);
    }
    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let base_id = resolve_rev_or_ref(&engine, &args[0]).expect("resolve base_rev");
    let head_id = resolve_rev_or_ref(&engine, &args[1]).expect("resolve head_rev");
    let diffs = engine
        .diff_changesets(base_id, head_id)
        .expect("diff changesets");
    for d in diffs {
        println!("{:?} {}", d.kind, d.path);
    }
}

fn run_cat(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    if args.len() < 2 {
        eprintln!("usage: inr cat <rev> <path>");
        std::process::exit(1);
    }
    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let cs_id = resolve_rev_or_ref(&engine, &args[0]).expect("resolve revision");
    let mpath = MPath::new(&args[1]).expect("valid MPath");
    let bytes = engine.read_file(cs_id, &mpath).expect("read file");
    print!("{}", String::from_utf8_lossy(&bytes));
}

fn run_ls(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let rev = args.first().map(|s| s.as_str()).unwrap_or(&cfg.default_ref);
    let path_opt = args.get(1).map(|p| MPath::new(p).expect("valid MPath"));
    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let cs_id = resolve_rev_or_ref(&engine, rev).expect("resolve revision");
    let entries = engine
        .list_directory(cs_id, path_opt.as_ref())
        .expect("list directory");
    for entry in entries {
        match entry {
            inarch_engine::DirectoryListingEntry::File {
                name,
                blob_id,
                file_type,
                size,
            } => {
                println!(
                    "file {:<10} {:>10}B  {}  {}",
                    format!("{:?}", file_type),
                    size,
                    blob_id.to_hex(),
                    name
                );
            }
            inarch_engine::DirectoryListingEntry::Directory {
                name,
                fsnode_id,
                summary,
            } => {
                println!(
                    "dir  ({} files, {}B)  {}  {}/",
                    summary.descendant_files_count,
                    summary.descendant_files_total_size,
                    fsnode_id.to_hex(),
                    name
                );
            }
        }
    }
}

fn run_blame(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    if args.len() < 2 {
        eprintln!("usage: inr blame <rev> <path>");
        std::process::exit(1);
    }
    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let cs_id = resolve_rev_or_ref(&engine, &args[0]).expect("resolve revision");
    let mpath = MPath::new(&args[1]).expect("valid MPath");
    let blame = engine.blame(cs_id, &mpath).expect("compute blame");
    for line in blame.lines {
        println!(
            "L{:<4} | {} (orig L{}) | {}",
            line.line_number,
            &line.changeset_id.to_hex()[..12],
            line.origin_line,
            line.content
        );
    }
}

fn run_search(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    if args.len() < 2 {
        eprintln!("usage: inr search <rev> <query> [--limit <n>]");
        std::process::exit(1);
    }
    let mut limit = 100usize;
    let mut i = 2;
    while i < args.len() {
        if (args[i] == "--limit" || args[i] == "-n")
            && let Some(n) = args.get(i + 1).and_then(|s| s.parse().ok())
        {
            limit = n;
            i += 2;
            continue;
        }
        i += 1;
    }
    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let cs_id = resolve_rev_or_ref(&engine, &args[0]).expect("resolve revision");
    let matches = engine
        .search_paths(cs_id, &args[1], limit)
        .expect("search paths");
    for entry in matches {
        println!(
            "{}  ({}B, {:?}, {})",
            entry.path,
            entry.size,
            entry.file_type,
            &entry.blob_id.to_hex()[..16]
        );
    }
}

fn run_copies(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let rev = args.first().map(|s| s.as_str()).unwrap_or(&cfg.default_ref);
    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let cs_id = resolve_rev_or_ref(&engine, rev).expect("resolve revision");
    let report = engine.detect_copies(cs_id).expect("detect copies");
    if report.records.is_empty() {
        println!(
            "No copies or renames detected at {} ({})",
            rev,
            &cs_id.to_hex()[..16]
        );
        return;
    }
    for rec in report.records {
        println!(
            "{:?}  {} <- {}  (similarity={:.2}%)",
            rec.kind,
            rec.dest_path,
            rec.source_path,
            rec.similarity_bps as f64 / 100.0
        );
    }
}

fn run_revert(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let mut culprit_rev: Option<String> = None;
    let mut target_ref = cfg.default_ref.clone();
    let mut author = cfg.default_author.clone();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ref" | "--target-ref" => {
                if let Some(r) = args.get(i + 1) {
                    target_ref = r.clone();
                    i += 2;
                    continue;
                }
            }
            "--author" => {
                if let Some(a) = args.get(i + 1) {
                    author = a.clone();
                    i += 2;
                    continue;
                }
            }
            "--culprit" => {
                if let Some(c) = args.get(i + 1) {
                    culprit_rev = Some(c.clone());
                    i += 2;
                    continue;
                }
            }
            other if !other.starts_with('-') && culprit_rev.is_none() => {
                culprit_rev = Some(other.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let Some(culprit_str) = culprit_rev else {
        eprintln!("usage: inr revert <changeset_id> [--ref <r>] [--author <a>]");
        std::process::exit(1);
    };

    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let culprit_id = resolve_rev_or_ref(&engine, &culprit_str).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });
    if let Ok(Some(cs)) = engine.meta().get_changeset(&culprit_id) {
        if cs.parents.len() > 1 {
            eprintln!(
                "revert failed: cannot revert merge changeset {} with {} parents",
                culprit_id.to_hex(),
                cs.parents.len()
            );
            std::process::exit(1);
        }
    }
    let antique = AntiqueService::new(engine);
    let outcome = antique
        .revert_changeset(&target_ref, culprit_id, &author, now_unix_secs())
        .unwrap_or_else(|e| {
            eprintln!("revert failed: {}", e);
            std::process::exit(1);
        });
    println!(
        "Reverted {} on ref '{}' -> {} (rebased_across={})",
        culprit_id.to_hex(),
        target_ref,
        outcome.changeset_id.to_hex(),
        outcome.rebased_across
    );
}

fn run_bisect(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let mut good_rev: Option<String> = None;
    let mut bad_rev: Option<String> = None;
    let mut run_cmd: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--good" => {
                if let Some(v) = args.get(i + 1) {
                    good_rev = Some(v.clone());
                    i += 2;
                    continue;
                }
            }
            "--bad" => {
                if let Some(v) = args.get(i + 1) {
                    bad_rev = Some(v.clone());
                    i += 2;
                    continue;
                }
            }
            "--run" | "--cmd" => {
                if let Some(v) = args.get(i + 1) {
                    run_cmd = Some(v.clone());
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let (Some(good_str), Some(bad_str), Some(cmd_str)) = (good_rev, bad_rev, run_cmd) else {
        eprintln!("usage: inr bisect --good <id> --bad <id> --run <cmd>");
        std::process::exit(1);
    };

    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let good_id = resolve_rev_or_ref(&engine, &good_str).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });
    let bad_id = resolve_rev_or_ref(&engine, &bad_str).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });
    let antique = AntiqueService::new(Arc::clone(&engine));
    let outcome = antique
        .bisect_regression(good_id, bad_id, |candidate_id| {
            let probe_dir = std::env::temp_dir().join(format!(
                "inarch-bisect-{}-{}",
                std::process::id(),
                &candidate_id.to_hex()[..12]
            ));
            let _ = std::fs::remove_dir_all(&probe_dir);
            checkout_stateless(&engine, candidate_id, None, &probe_dir).map_err(|e| {
                format!("failed to materialize bisect probe {}: {}", candidate_id, e)
            })?;
            #[cfg(windows)]
            let status_res = std::process::Command::new("cmd")
                .args(["/C", &cmd_str])
                .current_dir(&probe_dir)
                .env("INARCH_BISECT_CHANGESET", candidate_id.to_hex())
                .status();
            #[cfg(not(windows))]
            let status_res = std::process::Command::new("sh")
                .args(["-c", &cmd_str])
                .current_dir(&probe_dir)
                .env("INARCH_BISECT_CHANGESET", candidate_id.to_hex())
                .status();
            let _ = std::fs::remove_dir_all(&probe_dir);
            status_res
                .map(|s| s.success())
                .map_err(|e| format!("failed to execute bisect command '{}': {}", cmd_str, e))
        })
        .unwrap_or_else(|e| {
            eprintln!("bisect failed: {}", e);
            std::process::exit(1);
        });

    println!(
        "Culprit changeset: {} (probes_executed={})",
        outcome.culprit.to_hex(),
        outcome.probes_executed
    );
}

fn run_mcp_stdio(cwd: &Path, cfg: &InarchConfig) {
    use std::io::{BufRead, Write};

    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let antique = Arc::new(AntiqueService::new(Arc::clone(&engine)));
    let mcp = McpServer::new(engine, antique);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line_res in stdin.lock().lines() {
        let Ok(line) = line_res else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("\"notifications/") {
            continue;
        }
        let id = extract_json_rpc_id(trimmed).unwrap_or(1);
        if trimmed.contains("\"initialize\"") {
            let resp = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":\"velenza-inarch\",\"version\":\"0.1.0\"}}}}}}\n",
                id
            );
            let _ = stdout.write_all(resp.as_bytes());
            let _ = stdout.flush();
        } else if trimmed.contains("\"tools/list\"") || trimmed.eq_ignore_ascii_case("list") {
            let mut tools_json = String::from("[");
            for (idx, (name, desc)) in McpServer::tool_catalog().iter().enumerate() {
                if idx > 0 {
                    tools_json.push(',');
                }
                tools_json.push_str(&format!(
                    "{{\"name\":{:?},\"description\":{:?}}}",
                    name, desc
                ));
            }
            tools_json.push(']');
            let resp = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"tools\":{}}}}}\n",
                id, tools_json
            );
            let _ = stdout.write_all(resp.as_bytes());
            let _ = stdout.flush();
        } else if let Some(tool_name) = extract_json_str_after(trimmed, "\"name\"") {
            let args = extract_mcp_tool_args(trimmed);
            let mcp_resp = mcp.handle(McpRequest::CallTool {
                id,
                name: tool_name,
                args,
            });
            let resp = match (mcp_resp.result, mcp_resp.error) {
                (Some(text), _) => format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":{:?}}}]}}}}\n",
                    id, text
                ),
                (_, Some(err)) => format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":-32000,\"message\":{:?}}}}}\n",
                    id, err
                ),
                _ => format!("{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{}}}}\n", id),
            };
            let _ = stdout.write_all(resp.as_bytes());
            let _ = stdout.flush();
        }
    }
}

fn extract_json_rpc_id(json: &str) -> Option<u64> {
    let idx = json.find("\"id\"")?;
    let after = &json[idx + 4..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start().trim_start_matches('"');
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u64>().ok()
}

fn extract_json_str_after(json: &str, key_lit: &str) -> Option<String> {
    let idx = json.find(key_lit)?;
    let after = &json[idx + key_lit.len()..];
    let colon = after.find(':')?;
    let val = after[colon + 1..].trim_start().strip_prefix('"')?;
    let mut out = String::new();
    let mut esc = false;
    for ch in val.chars() {
        if esc {
            out.push(ch);
            esc = false;
        } else if ch == '\\' {
            esc = true;
        } else if ch == '"' {
            return Some(out);
        } else {
            out.push(ch);
        }
    }
    None
}

fn extract_mcp_tool_args(json: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let scope = if let Some(idx) = json.find("\"arguments\"") {
        &json[idx + 11..]
    } else {
        json
    };
    for key in [
        "ref",
        "target_ref",
        "base_changeset",
        "author",
        "timestamp",
        "message",
        "path",
        "content",
        "op",
        "file_type",
        "rev",
        "changeset_id",
        "from",
        "to",
        "limit",
        "culprit",
        "query",
    ] {
        let needle = format!("\"{}\"", key);
        if let Some(val) = extract_json_str_after(scope, &needle) {
            out.insert(key.to_string(), val);
        }
    }
    if let Some(idx) = scope.find("\"edits\"") {
        let after = &scope[idx + 7..];
        if let Some(colon) = after.find(':') {
            let val = after[colon + 1..].trim_start();
            if val.starts_with('[') {
                let mut depth = 0usize;
                let mut in_str = false;
                let mut esc = false;
                for (byte_idx, ch) in val.char_indices() {
                    if in_str {
                        if esc {
                            esc = false;
                        } else if ch == '\\' {
                            esc = true;
                        } else if ch == '"' {
                            in_str = false;
                        }
                    } else if ch == '"' {
                        in_str = true;
                    } else if ch == '[' {
                        depth += 1;
                    } else if ch == ']' {
                        depth -= 1;
                        if depth == 0 {
                            out.insert(
                                "edits".to_string(),
                                val[..byte_idx + ch.len_utf8()].to_string(),
                            );
                            break;
                        }
                    }
                }
            }
        }
    }
    out
}

fn run_mount(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    if args.is_empty() {
        eprintln!(
            "usage: inr mount <rev> [dest_dir] [--prefix <p1,p2>] [--serve-webdav <127.0.0.1:port>]"
        );
        std::process::exit(1);
    }
    let rev = &args[0];
    let mut dest_dir: Option<PathBuf> = None;
    let mut serve_webdav: Option<String> = None;
    let mut prefixes: Vec<MPath> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--serve-webdav" {
            if let Some(addr) = args.get(i + 1) {
                serve_webdav = Some(addr.clone());
                i += 2;
                continue;
            }
        } else if args[i] == "--prefix" {
            if let Some(val) = args.get(i + 1) {
                prefixes = parse_csv_list(val)
                    .iter()
                    .map(|s| MPath::new(s).expect("valid sparse prefix MPath"))
                    .collect();
                i += 2;
                continue;
            }
        } else if !args[i].starts_with('-') && dest_dir.is_none() {
            dest_dir = Some(PathBuf::from(&args[i]));
        }
        i += 1;
    }

    if dest_dir.is_none() && serve_webdav.is_none() {
        dest_dir = Some(cwd.to_path_buf());
    }

    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let cs_id = resolve_rev_or_ref(&engine, rev).expect("resolve revision");

    if let Some(dest) = dest_dir {
        let receipt = mount_virtual_workspace(&engine, cs_id, &prefixes, &dest)
            .expect("mount virtual workspace");
        println!(
            "Mounted virtual workspace at {} for {} ({}): {} virtual files ({} directories created), {} blobs written upfront",
            dest.display(),
            rev,
            &cs_id.to_hex()[..16],
            receipt.total_virtual_files,
            receipt.created_directories,
            receipt.hydrated_files
        );
    }

    if let Some(bind_addr) = serve_webdav {
        let handle = spawn_webdav_virtual_mount(Arc::clone(&engine), rev.clone(), &bind_addr)
            .expect("spawn WebDAV virtual filesystem mount");
        println!(
            "Serving on-demand WebDAV virtual filesystem for {} ({}) at http://{}/ (Bearer token: {}, Ctrl+C to stop)",
            rev,
            &cs_id.to_hex()[..16],
            handle.local_addr,
            handle.auth_token
        );
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
}

fn run_hydrate(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    if args.len() < 2 {
        eprintln!("usage: inr hydrate <mount_dir> <path_or_prefix...>");
        std::process::exit(1);
    }
    let mount_dir = PathBuf::from(&args[0]);
    let selectors: Vec<String> = args[1..].to_vec();
    let engine = cfg.open_engine(cwd).expect("open configured engine");
    let receipt =
        hydrate_virtual_paths(&engine, &mount_dir, &selectors).expect("hydrate virtual paths");
    println!(
        "Hydrated {} files ({} bytes) in {} (total hydrated: {})",
        receipt.newly_hydrated_files,
        receipt.bytes_written,
        mount_dir.display(),
        receipt.total_hydrated_files
    );
}

fn run_verify_codebase(source_dir: &Path, cfg: &InarchConfig) {
    let canonical = std::fs::canonicalize(source_dir).expect("resolve source directory");
    println!(
        "=== Velenza Inarch Real-Codebase Round-Trip Verification: {} ===",
        canonical.display()
    );

    let scratch = std::env::temp_dir().join(format!("inarch-cli-verify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let blobs_dir = scratch.join("store/blobs");
    let meta_dir = scratch.join("store/meta");
    let checkout_dir = scratch.join("checkout");
    let ignore = cfg.ignore_slices();

    let receipt = {
        let blobs = Arc::new(FsBlobStore::new(&blobs_dir).expect("create FsBlobStore"));
        let meta = Arc::new(FsMetadataStore::new(&meta_dir).expect("create FsMetadataStore"));
        let engine = ScionEngine::new(blobs, meta);
        ingest_directory(
            &engine,
            &cfg.default_ref,
            &cfg.default_author,
            1_760_950_000,
            "verify real codebase round-trip",
            &canonical,
            &ignore,
        )
        .expect("ingest codebase")
    };
    println!(
        "[1] Ingested {} files ({} bytes) -> ChangesetId {}",
        receipt.files_scanned,
        receipt.bytes_ingested,
        receipt.changeset_id.to_hex()
    );

    // Cold reopen with 3-tier cache
    let tier1 = Arc::new(MemBlobStore::new());
    let tier2 = Arc::new(MemBlobStore::new());
    let tier3 = Arc::new(FsBlobStore::new(&blobs_dir).expect("reopen FsBlobStore"));
    let tiered = Arc::new(TieredBlobStore::new(tier1, tier2, tier3));
    let meta = Arc::new(FsMetadataStore::new(&meta_dir).expect("reopen FsMetadataStore"));
    let engine = ScionEngine::new(tiered, meta);

    let report = verify_codebase_accuracy(&engine, receipt.changeset_id, &canonical, &ignore)
        .expect("verify checkout-free read accuracy");
    println!(
        "[2] Cold-reopen checkout-free read_file & Fsnode verification: {}/{} files ({} bytes) 100% EXACT (Root Fsnode {})",
        report.files_verified,
        receipt.files_scanned,
        report.bytes_verified,
        report.root_fsnode_id.to_hex()
    );

    let co = checkout_stateless(&engine, receipt.changeset_id, None, &checkout_dir)
        .expect("stateless tree-walk checkout");
    let co_report = verify_codebase_accuracy(&engine, receipt.changeset_id, &checkout_dir, &ignore)
        .expect("verify materialized checkout directory");
    println!(
        "[3] Stateless tree-walk checkout materialization: {}/{} files ({} bytes) 100% EXACT on disk",
        co_report.files_verified, co.files_materialized, co_report.bytes_verified
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

fn run_demo(cfg: &InarchConfig) {
    println!("=== Velenza Inarch End-to-End Architecture Showcase ===");

    let tier1_daemon = Arc::new(MemBlobStore::new());
    let tier2_regional = Arc::new(MemBlobStore::new());
    let tier3_origin = Arc::new(MemBlobStore::new());
    let tiered_blobs = Arc::new(TieredBlobStore::new(
        tier1_daemon,
        tier2_regional,
        tier3_origin,
    ));
    let meta = Arc::new(MemMetadataStore::new());
    let engine = Arc::new(ScionEngine::new(tiered_blobs, meta));
    let antique = Arc::new(AntiqueService::new(Arc::clone(&engine)));
    let mcp = McpServer::new(Arc::clone(&engine), Arc::clone(&antique));

    let base = engine
        .land_patch(PatchSubmission {
            target_ref: cfg.default_ref.clone(),
            base_changeset: None,
            author: cfg.default_author.clone(),
            timestamp: 1_760_600_000,
            tz_offset_secs: 0,
            message: "seed monorepo root".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("README.md").unwrap(),
                content: b"# Velenza Inarch Monorepo\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect("seed base commit");
    println!(
        "[1] Seeded base commit on {}: {}",
        cfg.default_ref,
        &base.changeset_id.to_hex()[..16]
    );

    let mut handles = Vec::new();
    for agent_id in 0..8 {
        let eng = Arc::clone(&engine);
        let base_id = base.changeset_id;
        let target_ref = cfg.default_ref.clone();
        handles.push(std::thread::spawn(move || {
            eng.land_patch(PatchSubmission {
                target_ref,
                base_changeset: Some(base_id),
                author: format!("agent-{}@inarch.dev", agent_id),
                timestamp: 1_760_600_010 + agent_id as i64,
                tz_offset_secs: 0,
                message: format!("agent-{} autonomous module", agent_id),
                extra: BTreeMap::new(),
                edits: vec![PatchFileEdit::Upsert {
                    path: MPath::new(&format!("agents/agent_{}/mod.rs", agent_id)).unwrap(),
                    content: format!("pub const AGENT_ID: usize = {};\n", agent_id).into_bytes(),
                    file_type: FileType::Regular,
                }],
            })
            .expect("agent lock-free speculative rebase")
        }));
    }

    let mut max_rebased = 0usize;
    for h in handles {
        let out = h.join().unwrap();
        max_rebased = max_rebased.max(out.rebased_across);
    }
    let head = engine.resolve_ref(&cfg.default_ref).unwrap().unwrap();
    println!(
        "[2] 8 concurrent agents landed on {} (head={}, max_speculative_rebase_hops={})",
        cfg.default_ref,
        &head.to_hex()[..16],
        max_rebased
    );

    let list_resp = mcp.handle(McpRequest::CallTool {
        id: 1,
        name: "inarch_list_dir".to_string(),
        args: BTreeMap::from([("rev".to_string(), cfg.default_ref.clone())]),
    });
    println!(
        "[3] Checkout-free root directory listing via MCP:\n{}",
        list_resp.result.unwrap().trim_end()
    );
}

fn run_git_import(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let mut git_repo_dir = cwd.to_path_buf();
    let mut store_dir = cwd.to_path_buf();
    let mut explicit_store = false;
    let mut verify_tip = false;
    let mut opts = GitImportOptions {
        git_ref: "HEAD".to_string(),
        target_ref: cfg.default_ref.clone(),
        max_commits: None,
        ignore_names: cfg.ignore_names.clone(),
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--git-repo" | "--git-dir" => {
                if let Some(v) = args.get(i + 1) {
                    git_repo_dir = PathBuf::from(v);
                    i += 2;
                    continue;
                }
            }
            "--store" => {
                if let Some(v) = args.get(i + 1) {
                    store_dir = PathBuf::from(v);
                    explicit_store = true;
                    i += 2;
                    continue;
                }
            }
            "--verify-tip" => {
                verify_tip = true;
                i += 1;
                continue;
            }
            "--branch" | "--git-ref" => {
                if let Some(v) = args.get(i + 1) {
                    opts.git_ref = v.clone();
                    i += 2;
                    continue;
                }
            }
            "--ref" | "--target-ref" => {
                if let Some(v) = args.get(i + 1) {
                    opts.target_ref = v.clone();
                    i += 2;
                    continue;
                }
            }
            "--limit" | "-n" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse().ok()) {
                    opts.max_commits = Some(v);
                    i += 2;
                    continue;
                }
            }
            other if !other.starts_with('-') => {
                git_repo_dir = PathBuf::from(other);
            }
            _ => {}
        }
        i += 1;
    }

    let mut eff_cfg = cfg.clone();
    if explicit_store {
        eff_cfg.blob_backend = "local".to_string();
        eff_cfg.meta_backend = "local".to_string();
        eff_cfg.remote_url.clear();
    }
    let engine = eff_cfg
        .open_engine(&store_dir)
        .expect("open configured engine");
    let receipt = import_git_history(&engine, &git_repo_dir, &opts).unwrap_or_else(|e| {
        eprintln!("git-import failed: {}", e);
        std::process::exit(1);
    });
    let head_hex = receipt
        .head_changeset
        .map(|id| id.to_hex())
        .unwrap_or_else(|| "none".to_string());
    println!(
        "Imported {} Git commit(s) (examined={}, skipped_existing={}, file_changes={}, bytes_ingested={}) onto ref '{}' -> {}",
        receipt.commits_imported,
        receipt.commits_examined,
        receipt.commits_skipped_existing,
        receipt.total_file_changes,
        receipt.total_bytes_ingested,
        receipt.target_ref,
        head_hex
    );

    if verify_tip {
        if let Some(head_id) = receipt.head_changeset {
            let verify_tmp = std::env::temp_dir().join(format!(
                "inarch-verify-tip-{}-{}",
                std::process::id(),
                now_unix_secs()
            ));
            let _ = std::fs::remove_dir_all(&verify_tmp);
            let clone_ok = std::process::Command::new("git")
                .args([
                    "clone",
                    "-q",
                    "--no-checkout",
                    &git_repo_dir.to_string_lossy(),
                    &verify_tmp.to_string_lossy(),
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
                && std::process::Command::new("git")
                    .current_dir(&verify_tmp)
                    .args(["checkout", "-q", &opts.git_ref])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);

            let check_dir = if clone_ok { &verify_tmp } else { &git_repo_dir };
            let ignore_refs = eff_cfg.ignore_slices();
            let res = verify_codebase_accuracy(&engine, head_id, check_dir, &ignore_refs);
            let _ = std::fs::remove_dir_all(&verify_tmp);
            match res {
                Ok(report) => {
                    println!(
                        "Verified imported tip {} against Git commit tree: {} files ({} bytes) 100% byte-for-byte accurate",
                        &head_id.to_hex()[..16],
                        report.files_verified,
                        report.bytes_verified
                    );
                }
                Err(e) => {
                    eprintln!("verify-tip failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

fn run_git_export(cwd: &Path, cfg: &InarchConfig, args: &[String]) {
    let mut store_dir = cwd.to_path_buf();
    let mut explicit_store = false;
    let mut branch = cfg.default_ref.clone();
    let mut flag_ref: Option<String> = None;
    let mut flag_git_repo: Option<String> = None;
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--branch" => {
                if let Some(b) = args.get(i + 1) {
                    branch = b.clone();
                    i += 2;
                    continue;
                }
            }
            "--ref" | "--rev" => {
                if let Some(r) = args.get(i + 1) {
                    flag_ref = Some(r.clone());
                    i += 2;
                    continue;
                }
            }
            "--git-repo" | "--dest" => {
                if let Some(d) = args.get(i + 1) {
                    flag_git_repo = Some(d.clone());
                    i += 2;
                    continue;
                }
            }
            "--author" | "--message" => {
                if args.get(i + 1).is_some() {
                    i += 2;
                    continue;
                }
            }
            "--store" => {
                if let Some(s) = args.get(i + 1) {
                    store_dir = PathBuf::from(s);
                    explicit_store = true;
                    i += 2;
                    continue;
                }
            }
            other if !other.starts_with('-') => {
                positional.push(other.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let rev_str = flag_ref
        .or_else(|| positional.first().cloned())
        .unwrap_or_else(|| cfg.default_ref.clone());
    let Some(dest_str) = flag_git_repo.or_else(|| positional.get(1).cloned()) else {
        eprintln!(
            "usage: inr git-export <rev_or_ref> <dest_git_dir> [--branch <name>] [--store <dir>]"
        );
        std::process::exit(1);
    };

    let mut eff_cfg = cfg.clone();
    if explicit_store {
        eff_cfg.blob_backend = "local".to_string();
        eff_cfg.meta_backend = "local".to_string();
        eff_cfg.remote_url.clear();
    }
    let engine = eff_cfg
        .open_engine(&store_dir)
        .expect("open configured engine");
    let cs_id = resolve_rev_or_ref(&engine, &rev_str).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });

    let receipt = export_git_revision(&engine, cs_id, Path::new(&dest_str), &branch)
        .unwrap_or_else(|e| {
            eprintln!("git-export failed: {}", e);
            std::process::exit(1);
        });
    println!(
        "Exported Velenza Inarch changeset {} to Git commit {} on branch '{}' ({} files, {} bytes)",
        receipt.changeset_id.to_hex(),
        receipt.git_commit_sha,
        receipt.branch,
        receipt.files_exported,
        receipt.bytes_exported
    );
}

fn run_bench(_cwd: &Path, args: &[String]) {
    let mut bcfg = BenchmarkConfig::default();
    let mut csv_out: Option<PathBuf> = None;
    let mut json_out: Option<PathBuf> = None;
    let mut md_out: Option<PathBuf> = None;
    let mut output_dir: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--corpus" => {
                if let Some(v) = args.get(i + 1) {
                    bcfg.corpus_label = v.clone();
                    i += 2;
                    continue;
                }
            }
            "--host" => {
                if let Some(v) = args.get(i + 1) {
                    bcfg.host_label = v.clone();
                    i += 2;
                    continue;
                }
            }
            "--source" | "--source-dir" | "--git-repo" => {
                if let Some(v) = args.get(i + 1) {
                    bcfg.source_dir = Some(PathBuf::from(v));
                    i += 2;
                    continue;
                }
            }
            "--files" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse().ok()) {
                    bcfg.file_count = v;
                    i += 2;
                    continue;
                }
            }
            "--agents" | "--concurrency" | "--swarm-counts" => {
                if let Some(v) = args.get(i + 1) {
                    let parsed: Vec<usize> =
                        v.split(',').filter_map(|s| s.trim().parse().ok()).collect();
                    if !parsed.is_empty() {
                        bcfg.concurrency_levels = parsed;
                    }
                    i += 2;
                    continue;
                }
            }
            "--trials" | "--iterations" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse().ok()) {
                    bcfg.trials = v;
                    i += 2;
                    continue;
                }
            }
            "--warmup" => {
                if args.get(i + 1).is_some() {
                    i += 2;
                    continue;
                }
            }
            "--large-file-mb" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse().ok()) {
                    bcfg.large_file_mb = v;
                    i += 2;
                    continue;
                }
            }
            "--output-dir" => {
                if let Some(v) = args.get(i + 1) {
                    output_dir = Some(PathBuf::from(v));
                    i += 2;
                    continue;
                }
            }
            "--csv-out" => {
                if let Some(v) = args.get(i + 1) {
                    csv_out = Some(PathBuf::from(v));
                    i += 2;
                    continue;
                }
            }
            "--json-out" => {
                if let Some(v) = args.get(i + 1) {
                    json_out = Some(PathBuf::from(v));
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let report = run_benchmark_suite(&bcfg).unwrap_or_else(|e| {
        eprintln!("benchmark suite failed: {}", e);
        std::process::exit(1);
    });

    if let Some(dir) = output_dir {
        std::fs::create_dir_all(&dir).expect("create benchmark output directory");
        if csv_out.is_none() {
            csv_out = Some(dir.join("benchmark_summary.csv"));
        }
        if json_out.is_none() {
            json_out = Some(dir.join("benchmark_report.json"));
        }
        if md_out.is_none() {
            md_out = Some(dir.join("summary.md"));
        }
    }

    if let Some(path) = csv_out {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&path, report.to_csv_string()).expect("write CSV benchmark report");
    }
    if let Some(path) = json_out {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&path, report.to_json_string()).expect("write JSON benchmark report");
    }
    if let Some(path) = md_out {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&path, report.to_markdown_string())
            .expect("write Markdown benchmark report");
    }
    print!("{}", report.to_csv_string());
}
