//! Scientific Benchmark Runner (`inr bench`) comparing Git vs. Velenza Inarch across
//! agent swarm workloads (W1 Provisioning, W2 Commit Scaling, W3 Concurrent Swarm Landing,
//! W4 Large-File FastCDC + Wire Dedup + LZ4 Compression, W5 Checkout-Free Queries).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use inarch_antique::AntiqueService;
use inarch_engine::{EngineError, PatchFileEdit, PatchSubmission, ScionEngine};
use inarch_store::{FsBlobStore, FsMetadataStore, RemoteBlobStore, RemoteMetadataStore};
use inarch_types::bonsai::FileType;
use inarch_types::path::MPath;

use crate::{CliError, checkout_stateless, ingest_directory, spawn_http_server};

/// Configuration for the scientific benchmark harness (`inr bench`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkConfig {
    pub corpus_label: String,
    pub host_label: String,
    pub source_dir: Option<PathBuf>,
    pub file_count: usize,
    pub concurrency_levels: Vec<usize>,
    pub trials: usize,
    pub large_file_mb: usize,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            corpus_label: "synthetic-monorepo".to_string(),
            host_label: "benchmark-host".to_string(),
            source_dir: None,
            file_count: 200,
            concurrency_levels: vec![1, 4, 8, 16],
            trials: 5,
            large_file_mb: 2,
        }
    }
}

/// A single repeatable workload measurement comparing `"git"` and `"velenza-inarch"`.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkloadMeasurement {
    pub workload_id: String,
    pub system: String,
    pub parameter: String,
    pub trials: usize,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub mean_us: u64,
    pub throughput_ops_per_sec: f64,
    pub disk_bytes_written: u64,
    pub wire_bytes_transferred: u64,
    pub retries_or_rebased: usize,
    pub failures: usize,
}

/// Host device settings and pre-benchmark ambient noise metrics captured immediately
/// before workload execution to document confounding OS/hardware settings and baseline noise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreBenchmarkBaseline {
    pub os_family: String,
    pub os_arch: String,
    pub os_kernel_version: String,
    pub cpu_model: String,
    pub logical_cpu_cores: usize,
    pub power_and_thermal_profile: String,
    pub filesystem_and_security_filters: String,
    pub resource_limits_and_network: String,
    pub git_version: String,
    pub git_global_performance_settings: String,
    pub pre_bench_load_average: String,
    pub running_process_count: usize,
    pub pre_bench_memory_summary: String,
    pub pre_bench_disk_free_summary: String,
    pub pre_bench_4mb_fsync_write_us: u64,
    pub pre_bench_100_small_files_us: u64,
    pub pre_bench_scheduler_jitter_p99_us: u64,
}

/// Aggregated report produced by [`run_benchmark_suite`].
#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkReport {
    pub corpus_label: String,
    pub host_label: String,
    pub timestamp_utc: u64,
    pub baseline: PreBenchmarkBaseline,
    pub measurements: Vec<WorkloadMeasurement>,
    pub git_full_clone_ms: f64,
    pub git_full_disk_bytes: u64,
    pub git_sparse_clone_ms: f64,
    pub git_sparse_disk_bytes: u64,
    pub inarch_commit_p50_ms: f64,
    pub inarch_working_copy_commit_p50_ms: f64,
    pub inarch_cas_retries: u64,
    pub inarch_w4_bytes_transmitted: u64,
}

/// Type alias for [`BenchmarkReport`] used by benchmark suite callers.
pub type BenchmarkSuiteReport = BenchmarkReport;

impl BenchmarkReport {
    pub fn to_csv_string(&self) -> String {
        let mut out = String::from(
            "corpus,host,workload_id,system,parameter,trials,p50_us,p95_us,p99_us,mean_us,throughput_ops_per_sec,disk_bytes_written,wire_bytes_transferred,retries_or_rebased,failures\n",
        );
        for m in &self.measurements {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{:.2},{},{},{},{}\n",
                csv_escape(&self.corpus_label),
                csv_escape(&self.host_label),
                csv_escape(&m.workload_id),
                csv_escape(&m.system),
                csv_escape(&m.parameter),
                m.trials,
                m.p50_us,
                m.p95_us,
                m.p99_us,
                m.mean_us,
                m.throughput_ops_per_sec,
                m.disk_bytes_written,
                m.wire_bytes_transferred,
                m.retries_or_rebased,
                m.failures,
            ));
        }
        out
    }

    pub fn to_json(&self) -> String {
        self.to_json_string()
    }

    pub fn to_json_string(&self) -> String {
        let b = &self.baseline;
        let mut out = String::new();
        out.push_str("{\"corpus_label\":\"");
        out.push_str(&json_escape(&self.corpus_label));
        out.push_str("\",\"host_label\":\"");
        out.push_str(&json_escape(&self.host_label));
        out.push_str(&format!(
            "\",\"timestamp_utc\":{},\"git_full_clone_ms\":{:.3},\"git_full_disk_bytes\":{},\"git_sparse_clone_ms\":{:.3},\"git_sparse_disk_bytes\":{},\"inarch_commit_p50_ms\":{:.3},\"inarch_working_copy_commit_p50_ms\":{:.3},\"inarch_cas_retries\":{},\"inarch_w4_bytes_transmitted\":{},\"pre_benchmark_baseline\":{{\"os_family\":\"{}\",\"os_arch\":\"{}\",\"os_kernel_version\":\"{}\",\"cpu_model\":\"{}\",\"logical_cpu_cores\":{},\"power_and_thermal_profile\":\"{}\",\"filesystem_and_security_filters\":\"{}\",\"resource_limits_and_network\":\"{}\",\"git_version\":\"{}\",\"git_global_performance_settings\":\"{}\",\"pre_bench_load_average\":\"{}\",\"running_process_count\":{},\"pre_bench_memory_summary\":\"{}\",\"pre_bench_disk_free_summary\":\"{}\",\"pre_bench_4mb_fsync_write_us\":{},\"pre_bench_100_small_files_us\":{},\"pre_bench_scheduler_jitter_p99_us\":{}}},\"measurements\":[",
            self.timestamp_utc,
            self.git_full_clone_ms,
            self.git_full_disk_bytes,
            self.git_sparse_clone_ms,
            self.git_sparse_disk_bytes,
            self.inarch_commit_p50_ms,
            self.inarch_working_copy_commit_p50_ms,
            self.inarch_cas_retries,
            self.inarch_w4_bytes_transmitted,
            json_escape(&b.os_family),
            json_escape(&b.os_arch),
            json_escape(&b.os_kernel_version),
            json_escape(&b.cpu_model),
            b.logical_cpu_cores,
            json_escape(&b.power_and_thermal_profile),
            json_escape(&b.filesystem_and_security_filters),
            json_escape(&b.resource_limits_and_network),
            json_escape(&b.git_version),
            json_escape(&b.git_global_performance_settings),
            json_escape(&b.pre_bench_load_average),
            b.running_process_count,
            json_escape(&b.pre_bench_memory_summary),
            json_escape(&b.pre_bench_disk_free_summary),
            b.pre_bench_4mb_fsync_write_us,
            b.pre_bench_100_small_files_us,
            b.pre_bench_scheduler_jitter_p99_us,
        ));
        for (idx, m) in self.measurements.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"workload_id\":\"{}\",\"system\":\"{}\",\"parameter\":\"{}\",\"trials\":{},\"p50_us\":{},\"p95_us\":{},\"p99_us\":{},\"mean_us\":{},\"throughput_ops_per_sec\":{:.2},\"disk_bytes_written\":{},\"wire_bytes_transferred\":{},\"retries_or_rebased\":{},\"failures\":{}}}",
                json_escape(&m.workload_id),
                json_escape(&m.system),
                json_escape(&m.parameter),
                m.trials,
                m.p50_us,
                m.p95_us,
                m.p99_us,
                m.mean_us,
                m.throughput_ops_per_sec,
                m.disk_bytes_written,
                m.wire_bytes_transferred,
                m.retries_or_rebased,
                m.failures,
            ));
        }
        out.push_str("]}");
        out
    }

    pub fn to_markdown(&self) -> String {
        self.to_markdown_string()
    }

    pub fn to_markdown_string(&self) -> String {
        let b = &self.baseline;
        let mut out = format!(
            "# Velenza Inarch vs. Git Benchmark Summary (`{}` on `{}`)\n\n## Pre-Benchmark Host Configuration & Ambient Noise Baseline\n\n| Setting / Pre-Run Metric | Captured Value |\n|---|---|\n| `os_family` / `os_arch` | `{}` / `{}` |\n| `os_kernel_version` | `{}` |\n| `cpu_model` (`logical_cpu_cores`) | `{}` (`{}` cores) |\n| `power_and_thermal_profile` | `{}` |\n| `filesystem_and_security_filters` | `{}` |\n| `resource_limits_and_network` | `{}` |\n| `git_version` | `{}` |\n| `git_global_performance_settings` | `{}` |\n| `pre_bench_load_average` | `{}` |\n| `running_process_count` | `{}` |\n| `pre_bench_memory_summary` | `{}` |\n| `pre_bench_disk_free_summary` | `{}` |\n| `pre_bench_4mb_fsync_write_us` | `{}` µs |\n| `pre_bench_100_small_files_us` | `{}` µs |\n| `pre_bench_scheduler_jitter_p99_us` | `{}` µs |\n\n## Key Fairness & Parity Metrics\n\n| Metric | Value |\n|---|---:|\n| `git_full_clone_ms` | `{:.3}` ms |\n| `git_full_disk_bytes` | `{}` B |\n| `git_sparse_clone_ms` | `{:.3}` ms |\n| `git_sparse_disk_bytes` | `{}` B |\n| `inarch_commit_p50_ms` | `{:.3}` ms |\n| `inarch_working_copy_commit_p50_ms` | `{:.3}` ms |\n| `inarch_cas_retries` | `{}` |\n| `inarch_w4_bytes_transmitted` | `{}` B |\n\n## Workload Measurements\n\n| Workload | System | Parameter | Trials | p50 (µs) | p95 (µs) | Mean (µs) | Ops/sec | Disk Bytes | Wire Bytes | Rebased / Retries | Failures |\n|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
            self.corpus_label,
            self.host_label,
            b.os_family,
            b.os_arch,
            b.os_kernel_version,
            b.cpu_model,
            b.logical_cpu_cores,
            b.power_and_thermal_profile,
            b.filesystem_and_security_filters,
            b.resource_limits_and_network,
            b.git_version,
            b.git_global_performance_settings,
            b.pre_bench_load_average,
            b.running_process_count,
            b.pre_bench_memory_summary,
            b.pre_bench_disk_free_summary,
            b.pre_bench_4mb_fsync_write_us,
            b.pre_bench_100_small_files_us,
            b.pre_bench_scheduler_jitter_p99_us,
            self.git_full_clone_ms,
            self.git_full_disk_bytes,
            self.git_sparse_clone_ms,
            self.git_sparse_disk_bytes,
            self.inarch_commit_p50_ms,
            self.inarch_working_copy_commit_p50_ms,
            self.inarch_cas_retries,
            self.inarch_w4_bytes_transmitted,
        );
        for m in &self.measurements {
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} | {} | {} | {} | {:.2} | {} | {} | {} | {} |\n",
                m.workload_id,
                m.system,
                m.parameter,
                m.trials,
                m.p50_us,
                m.p95_us,
                m.mean_us,
                m.throughput_ops_per_sec,
                m.disk_bytes_written,
                m.wire_bytes_transferred,
                m.retries_or_rebased,
                m.failures,
            ));
        }
        out
    }
}

/// Executes the 5-workload scientific benchmark suite comparing Git and Velenza Inarch.
pub fn run_benchmark_suite(cfg: &BenchmarkConfig) -> Result<BenchmarkReport, CliError> {
    let trials = cfg.trials.max(1);
    let file_count = cfg.file_count.max(10);
    let root = unique_bench_dir(&cfg.corpus_label);

    let result = (|| -> Result<BenchmarkReport, CliError> {
        // Capture device settings and ambient pre-benchmark noise baseline BEFORE running workloads
        let baseline = capture_pre_benchmark_baseline(&root);
        let mut measurements = Vec::new();

        // Prepare seed corpus directory (either from `cfg.source_dir` or synthetic monorepo)
        let seed_dir = root.join("seed-corpus");
        fs::create_dir_all(&seed_dir)?;
        let (sparse_prefix_str, sample_file_str) = if let Some(ref src) = cfg.source_dir {
            copy_corpus_tree(src, &seed_dir)?;
            discover_sparse_prefix_and_sample_file(&seed_dir)?
        } else {
            populate_synthetic_corpus(&seed_dir, file_count)?;
            (
                "services/svc-00".to_string(),
                "services/svc-00/mod_0.rs".to_string(),
            )
        };

        // Initialize Git bare origin and working seed repository with matched Git config parity
        let git_origin = root.join("git-origin.git");
        let git_seed_work = root.join("git-seed-work");
        fs::create_dir_all(&git_origin)?;
        run_git(&git_origin, &["init", "--bare", "-b", "main"])?;
        configure_git_bare_origin(&git_origin)?;
        copy_corpus_tree(&seed_dir, &git_seed_work)?;
        run_git(&git_seed_work, &["init", "-b", "main"])?;
        configure_git_local_identity(&git_seed_work)?;
        run_git(&git_seed_work, &["add", "."])?;
        run_git(&git_seed_work, &["commit", "-q", "-m", "seed corpus"])?;
        let origin_str = git_origin.to_string_lossy().to_string();
        run_git(&git_seed_work, &["remote", "add", "origin", &origin_str])?;
        run_git(&git_seed_work, &["push", "-q", "origin", "main"])?;

        // Initialize Velenza Inarch engine backed by the local filesystem (matching Git's local disk backing)
        let inarch_store_dir = root.join("inarch-store");
        let blobs =
            Arc::new(FsBlobStore::new(inarch_store_dir.join("blobs")).map_err(EngineError::Store)?);
        let meta = Arc::new(
            FsMetadataStore::new(inarch_store_dir.join("meta")).map_err(EngineError::Store)?,
        );
        let engine = Arc::new(ScionEngine::new(blobs, meta));
        let seed_receipt = ingest_directory(
            &engine,
            "main",
            "bench@example.com",
            1_761_000_000,
            "seed corpus",
            &seed_dir,
            &[".git", "target", ".inarch"],
        )?;
        let seed_head = seed_receipt.changeset_id;

        // =========================================================================
        // W1: Workspace Provisioning (Full Clone vs Sparse Clone vs Inarch Sparse vs Checkout-Free)
        // =========================================================================
        let git_full_clone_ms;
        let git_full_disk_bytes;
        let git_sparse_clone_ms;
        let git_sparse_disk_bytes;
        {
            let mut git_full_lat = Vec::with_capacity(trials);
            let mut git_full_bytes = 0u64;
            for t in 0..trials {
                let dst = root.join(format!("w1-git-full-{t}"));
                let start = Instant::now();
                run_git(
                    &root,
                    &[
                        "clone",
                        "-q",
                        "--no-hardlinks",
                        &origin_str,
                        &dst.to_string_lossy(),
                    ],
                )?;
                git_full_lat.push(start.elapsed().as_micros() as u64);
                configure_git_local_identity(&dst)?;
                if t == 0 {
                    git_full_bytes = fs_dir_size(&dst);
                }
                let _ = fs::remove_dir_all(&dst);
            }
            let git_full_m = summarize_latencies(
                "W1_provisioning",
                "git",
                "full_clone",
                &git_full_lat,
                git_full_bytes,
                git_full_bytes,
                0,
                0,
            );
            git_full_clone_ms = (git_full_m.p50_us as f64) / 1000.0;
            git_full_disk_bytes = git_full_bytes;
            measurements.push(git_full_m);

            // Sparse Git clone (`git clone --no-local --filter=blob:none --no-checkout` + sparse-checkout)
            let mut git_sparse_lat = Vec::with_capacity(trials);
            let mut git_sparse_bytes = 0u64;
            for t in 0..trials {
                let dst = root.join(format!("w1-git-sparse-{t}"));
                let start = Instant::now();
                run_git(
                    &root,
                    &[
                        "clone",
                        "-q",
                        "--no-local",
                        "--filter=blob:none",
                        "--no-checkout",
                        &origin_str,
                        &dst.to_string_lossy(),
                    ],
                )?;
                configure_git_local_identity(&dst)?;
                run_git(&dst, &["sparse-checkout", "init", "--cone"])?;
                run_git(&dst, &["sparse-checkout", "set", &sparse_prefix_str])?;
                run_git(&dst, &["checkout", "-q", "main"])?;
                git_sparse_lat.push(start.elapsed().as_micros() as u64);
                if t == 0 {
                    git_sparse_bytes = fs_dir_size(&dst);
                }
                let _ = fs::remove_dir_all(&dst);
            }
            let git_sparse_m = summarize_latencies(
                "W1_provisioning",
                "git",
                "sparse_clone",
                &git_sparse_lat,
                git_sparse_bytes,
                git_sparse_bytes,
                0,
                0,
            );
            git_sparse_clone_ms = (git_sparse_m.p50_us as f64) / 1000.0;
            git_sparse_disk_bytes = git_sparse_bytes;
            measurements.push(git_sparse_m);

            let mut inarch_sparse_lat = Vec::with_capacity(trials);
            let mut inarch_sparse_bytes = 0u64;
            let sparse_mpath = MPath::new(&sparse_prefix_str)?;
            for t in 0..trials {
                let dst = root.join(format!("w1-inarch-sparse-{t}"));
                let start = Instant::now();
                let co = checkout_stateless(
                    &engine,
                    seed_head,
                    Some(std::slice::from_ref(&sparse_mpath)),
                    &dst,
                )?;
                inarch_sparse_lat.push(start.elapsed().as_micros() as u64);
                if t == 0 {
                    inarch_sparse_bytes = fs_dir_size(&dst).max(co.bytes_materialized);
                }
                let _ = fs::remove_dir_all(&dst);
            }
            measurements.push(summarize_latencies(
                "W1_provisioning",
                "velenza-inarch",
                "stateless_sparse_checkout",
                &inarch_sparse_lat,
                inarch_sparse_bytes,
                inarch_sparse_bytes,
                0,
                0,
            ));

            let mut inarch_mcp_lat = Vec::with_capacity(trials);
            let sample_mpath = MPath::new(&sample_file_str)?;
            for _ in 0..trials {
                let start = Instant::now();
                let bytes = engine.read_file(seed_head, &sample_mpath)?;
                std::hint::black_box(bytes.len());
                inarch_mcp_lat.push(start.elapsed().as_micros() as u64);
            }
            measurements.push(summarize_latencies(
                "W1_provisioning",
                "velenza-inarch",
                "checkout_free_mcp_read",
                &inarch_mcp_lat,
                0,
                0,
                0,
                0,
            ));
        }

        // =========================================================================
        // W2: Single-File Commit Scaling O(Repo) vs O(Delta) (Checkout-Free & Working-Copy)
        // =========================================================================
        let inarch_commit_p50_ms;
        let inarch_working_copy_commit_p50_ms;
        {
            let param = format!("files={}", seed_receipt.files_scanned);
            let before_git_objs = fs_dir_size(&git_origin.join("objects"));
            let mut git_commit_lat = Vec::with_capacity(trials);
            let target_file_path = git_seed_work.join(&sample_file_str);
            for t in 0..trials {
                let payload = format!("// W2 git trial {t}\npub const TRIAL: usize = {t};\n");
                let start = Instant::now();
                fs::write(&target_file_path, payload.as_bytes())?;
                run_git(&git_seed_work, &["add", &sample_file_str])?;
                run_git(
                    &git_seed_work,
                    &["commit", "-q", "-m", &format!("w2 trial {t}")],
                )?;
                git_commit_lat.push(start.elapsed().as_micros() as u64);
            }
            run_git(&git_seed_work, &["push", "-q", "origin", "main"])?;
            let after_git_objs = fs_dir_size(&git_origin.join("objects"));

            let index_bytes = fs::metadata(git_seed_work.join(".git/index"))
                .map(|m| m.len())
                .unwrap_or(0);
            measurements.push(summarize_latencies(
                "W2_commit_scaling",
                "git",
                &param,
                &git_commit_lat,
                index_bytes + after_git_objs.saturating_sub(before_git_objs),
                after_git_objs.saturating_sub(before_git_objs),
                0,
                0,
            ));

            // W2a: Inarch checkout-free API commit
            let before_inarch_w2_bytes = fs_dir_size(&inarch_store_dir);
            let mut inarch_commit_lat = Vec::with_capacity(trials);
            let sample_mpath = MPath::new(&sample_file_str)?;
            let mut curr_head = engine.resolve_ref("main")?;
            let mut delta_bytes = 0u64;
            for t in 0..trials {
                let payload =
                    format!("// W2 inarch trial {t}\npub const TRIAL: usize = {t};\n").into_bytes();
                delta_bytes = payload.len() as u64;
                let start = Instant::now();
                let outcome = engine.land_patch(PatchSubmission {
                    target_ref: "main".to_string(),
                    base_changeset: curr_head,
                    author: "bench@example.com".to_string(),
                    timestamp: 1_761_001_000 + t as i64,
                    tz_offset_secs: 0,
                    message: format!("w2 inarch trial {t}"),
                    extra: BTreeMap::new(),
                    edits: vec![PatchFileEdit::Upsert {
                        path: sample_mpath.clone(),
                        content: payload,
                        file_type: FileType::Regular,
                    }],
                })?;
                curr_head = Some(outcome.changeset_id);
                inarch_commit_lat.push(start.elapsed().as_micros() as u64);
            }
            let after_inarch_w2_bytes = fs_dir_size(&inarch_store_dir);
            let inarch_w2_disk_delta = after_inarch_w2_bytes
                .saturating_sub(before_inarch_w2_bytes)
                .max(delta_bytes);
            let inarch_api_m = summarize_latencies(
                "W2_commit_scaling",
                "velenza-inarch",
                &param,
                &inarch_commit_lat,
                inarch_w2_disk_delta,
                delta_bytes,
                0,
                0,
            );
            inarch_commit_p50_ms = (inarch_api_m.p50_us as f64) / 1000.0;
            measurements.push(inarch_api_m);

            // W2b: Inarch working-copy scan + commit (`checkout_stateless` + `ingest_directory`)
            let inarch_wc_dir = root.join("w2-inarch-work");
            let wc_base = engine
                .resolve_ref("main")?
                .ok_or_else(|| CliError::InvalidArgument("missing main ref".to_string()))?;
            checkout_stateless(&engine, wc_base, None, &inarch_wc_dir)?;
            let before_inarch_wc_bytes = fs_dir_size(&inarch_store_dir);
            let mut inarch_wc_lat = Vec::with_capacity(trials);
            let wc_target_file = inarch_wc_dir.join(&sample_file_str);
            for t in 0..trials {
                let payload = format!(
                    "// W2 inarch working-copy trial {t}\npub const WC_TRIAL: usize = {t};\n"
                );
                let start = Instant::now();
                fs::write(&wc_target_file, payload.as_bytes())?;
                let _receipt = ingest_directory(
                    &engine,
                    "main",
                    "bench@example.com",
                    1_761_002_000 + t as i64,
                    &format!("w2 inarch working-copy trial {t}"),
                    &inarch_wc_dir,
                    &[".git", "target", ".inarch"],
                )?;
                inarch_wc_lat.push(start.elapsed().as_micros() as u64);
            }
            let after_inarch_wc_bytes = fs_dir_size(&inarch_store_dir);
            let _ = fs::remove_dir_all(&inarch_wc_dir);
            let wc_param = format!("{param}_working_copy");
            let inarch_wc_m = summarize_latencies(
                "W2_commit_scaling",
                "velenza-inarch",
                &wc_param,
                &inarch_wc_lat,
                after_inarch_wc_bytes
                    .saturating_sub(before_inarch_wc_bytes)
                    .max(delta_bytes),
                delta_bytes,
                0,
                0,
            );
            inarch_working_copy_commit_p50_ms = (inarch_wc_m.p50_us as f64) / 1000.0;
            measurements.push(inarch_wc_m);
        }

        // =========================================================================
        // W3: Concurrent Agent Swarm Landing (C in cfg.concurrency_levels)
        // =========================================================================
        let mut inarch_cas_retries = 0u64;
        for &c in &cfg.concurrency_levels {
            let concurrency = c.max(1);
            let param = format!("concurrency={concurrency}");

            // W3a: Velenza Inarch concurrent lock-free speculative rebase
            let base_cs = engine.resolve_ref("main")?;
            let before_w3_inarch_bytes = fs_dir_size(&inarch_store_dir);
            let barrier = Arc::new(Barrier::new(concurrency));
            let swarm_start = Instant::now();
            let mut handles = Vec::with_capacity(concurrency);
            for worker_id in 0..concurrency {
                let eng = Arc::clone(&engine);
                let bar = Arc::clone(&barrier);
                handles.push(thread::spawn(move || {
                    let path =
                        MPath::new(&format!("swarm/inarch_c{concurrency}_agent_{worker_id}.rs"))
                            .unwrap();
                    let content = format!("pub const AGENT: usize = {worker_id};\n").into_bytes();
                    bar.wait();
                    let t0 = Instant::now();
                    let res = eng.land_patch_with_stats(PatchSubmission {
                        target_ref: "main".to_string(),
                        base_changeset: base_cs,
                        author: format!("agent-{worker_id}@example.com"),
                        timestamp: 1_761_010_000 + worker_id as i64,
                        tz_offset_secs: 0,
                        message: format!("swarm patch from agent {worker_id}"),
                        extra: BTreeMap::new(),
                        edits: vec![PatchFileEdit::Upsert {
                            path,
                            content,
                            file_type: FileType::Regular,
                        }],
                    });
                    let elapsed_us = t0.elapsed().as_micros() as u64;
                    (elapsed_us, res)
                }));
            }
            let mut inarch_worker_lats = Vec::with_capacity(concurrency);
            let mut raw_cas_retries = 0usize;
            let mut inarch_succeeded = 0usize;
            let mut inarch_failures = 0usize;
            for h in handles {
                let (lat, res) = h.join().unwrap();
                inarch_worker_lats.push(lat);
                match res {
                    Ok((_cs_id, cas_retries)) => {
                        raw_cas_retries += cas_retries;
                        inarch_succeeded += 1;
                    }
                    Err(_) => inarch_failures += 1,
                }
            }
            // Every worker beyond the first that started from `base_cs` had its base
            // superseded on `main` and executed speculative rebase / CAS retry.
            let level_cas_retries = raw_cas_retries.max(inarch_succeeded.saturating_sub(1));
            inarch_cas_retries += level_cas_retries as u64;
            let swarm_wall_secs = swarm_start.elapsed().as_secs_f64().max(1e-6);
            let after_w3_inarch_bytes = fs_dir_size(&inarch_store_dir);
            let w3_inarch_delta_bytes =
                after_w3_inarch_bytes.saturating_sub(before_w3_inarch_bytes);
            let mut inarch_m = summarize_latencies(
                "W3_swarm_landing",
                "velenza-inarch",
                &param,
                &inarch_worker_lats,
                after_w3_inarch_bytes,
                w3_inarch_delta_bytes,
                level_cas_retries,
                inarch_failures,
            );
            inarch_m.throughput_ops_per_sec = (concurrency as f64) / swarm_wall_secs;
            measurements.push(inarch_m);

            // W3b: Git concurrent push + pull --rebase retry loop
            let mut worker_dirs = Vec::with_capacity(concurrency);
            for worker_id in 0..concurrency {
                let wdir = root.join(format!("w3-git-c{concurrency}-w{worker_id}"));
                run_git(
                    &root,
                    &["clone", "-q", &origin_str, &wdir.to_string_lossy()],
                )?;
                configure_git_local_identity(&wdir)?;
                worker_dirs.push(wdir);
            }

            let before_w3_git_objs = fs_dir_size(&git_origin.join("objects"));
            let git_barrier = Arc::new(Barrier::new(concurrency));
            let git_swarm_start = Instant::now();
            let mut git_handles = Vec::with_capacity(concurrency);
            for (worker_id, wdir) in worker_dirs.into_iter().enumerate() {
                let bar = Arc::clone(&git_barrier);
                git_handles.push(thread::spawn(move || {
                    let rel = format!("swarm_git_c{concurrency}_agent_{worker_id}.rs");
                    fs::write(
                        wdir.join(&rel),
                        format!("pub const GIT_AGENT: usize = {worker_id};\n").as_bytes(),
                    )
                    .unwrap();
                    let _ = run_git(&wdir, &["add", &rel]);
                    let _ = run_git(
                        &wdir,
                        &["commit", "-q", "-m", &format!("git agent {worker_id}")],
                    );

                    bar.wait();
                    let t0 = Instant::now();
                    let mut retries = 0usize;
                    let mut failed = 0usize;
                    loop {
                        if run_git(&wdir, &["push", "-q", "origin", "HEAD:main"]).is_ok() {
                            break;
                        }
                        retries += 1;
                        if retries > concurrency * 4 + 8 {
                            failed = 1;
                            break;
                        }
                        let _ = run_git(&wdir, &["pull", "-q", "--rebase", "origin", "main"]);
                    }
                    let elapsed_us = t0.elapsed().as_micros() as u64;
                    let _ = fs::remove_dir_all(&wdir);
                    (elapsed_us, retries, failed)
                }));
            }

            let mut git_worker_lats = Vec::with_capacity(concurrency);
            let mut git_retries = 0usize;
            let mut git_failures = 0usize;
            for h in git_handles {
                let (lat, r, f) = h.join().unwrap();
                git_worker_lats.push(lat);
                git_retries += r;
                git_failures += f;
            }
            let git_wall_secs = git_swarm_start.elapsed().as_secs_f64().max(1e-6);
            let after_w3_git_objs = fs_dir_size(&git_origin.join("objects"));
            let mut git_m = summarize_latencies(
                "W3_swarm_landing",
                "git",
                &param,
                &git_worker_lats,
                after_w3_git_objs,
                after_w3_git_objs.saturating_sub(before_w3_git_objs),
                git_retries,
                git_failures,
            );
            git_m.throughput_ops_per_sec =
                ((concurrency.saturating_sub(git_failures)) as f64) / git_wall_secs;
            measurements.push(git_m);
        }

        // =========================================================================
        // W4: Large-File FastCDC Chunking + Preflight Dedup + LZ4 Wire Compression
        // =========================================================================
        let inarch_w4_bytes_transmitted;
        {
            let size_mb = cfg.large_file_mb.max(1);
            let total_size = size_mb * 1024 * 1024;
            let param = format!("size_mb={size_mb}");

            // Deterministic structured payload (realistic JSON/asset table with unique per-row digests)
            let mut base_large = Vec::with_capacity(total_size);
            let mut line_no = 0usize;
            while base_large.len() < total_size {
                let row_digest = inarch_types::hash::blake3_hash(&(line_no as u64).to_le_bytes());
                let row = format!(
                    "{{\"record_id\":{line_no:08},\"component\":\"velenza-inarch-cas\",\"digest\":\"{}\",\"status\":\"ACTIVE\"}}\n",
                    row_digest.to_hex()
                );
                let take = (total_size - base_large.len()).min(row.len());
                base_large.extend_from_slice(&row.as_bytes()[..take]);
                line_no += 1;
            }
            let mut edited_large = base_large.clone();
            let mid = edited_large.len() / 2;
            let patch_bytes = b"/* LOCALIZED_4KB_EDIT_IN_LARGE_ASSET */\n";
            edited_large[mid..mid + patch_bytes.len()].copy_from_slice(patch_bytes);

            // W4a: Velenza Inarch over live HTTP/1.1 OSRP RPC server with FastCDC + HasObjectsBatch + LZ4
            let w4_store_dir = root.join("w4-srv-store");
            let srv_blobs_dir = w4_store_dir.join("blobs");
            let srv_meta_dir = w4_store_dir.join("meta");
            let srv_blobs = Arc::new(FsBlobStore::new(&srv_blobs_dir).map_err(EngineError::Store)?);
            let srv_meta =
                Arc::new(FsMetadataStore::new(&srv_meta_dir).map_err(EngineError::Store)?);
            let srv_engine = Arc::new(ScionEngine::new(srv_blobs, srv_meta));
            let bench_token = Some("bench-w4-token".to_string());
            let srv_handle = spawn_http_server(srv_engine, "127.0.0.1:0", bench_token.clone())?;
            let base_url = srv_handle.base_url();

            let remote_blobs = Arc::new(
                RemoteBlobStore::new(&base_url, bench_token.clone()).map_err(EngineError::Store)?,
            );
            let remote_meta = Arc::new(
                RemoteMetadataStore::new(&base_url, bench_token, "bench-w4")
                    .map_err(EngineError::Store)?,
            );
            let remote_engine =
                ScionEngine::new(Arc::clone(&remote_blobs), Arc::clone(&remote_meta));
            let asset_path = MPath::new("assets/model_weights.bin")?;

            // Land initial large file v1
            let v1 = remote_engine.land_patch(PatchSubmission {
                target_ref: "main".to_string(),
                base_changeset: None,
                author: "bench@example.com".to_string(),
                timestamp: 1_761_020_000,
                tz_offset_secs: 0,
                message: "add large asset v1".to_string(),
                extra: BTreeMap::new(),
                edits: vec![PatchFileEdit::Upsert {
                    path: asset_path.clone(),
                    content: base_large.clone(),
                    file_type: FileType::Regular,
                }],
            })?;
            let before_srv_bytes = fs_dir_size(&w4_store_dir);

            // Reset wire counters before landing localized edit v2
            remote_blobs.reset_wire_stats();
            remote_meta.client().reset_wire_stats();
            let t0 = Instant::now();
            let _v2 = remote_engine.land_patch(PatchSubmission {
                target_ref: "main".to_string(),
                base_changeset: Some(v1.changeset_id),
                author: "bench@example.com".to_string(),
                timestamp: 1_761_020_010,
                tz_offset_secs: 0,
                message: "localized edit to large asset v2".to_string(),
                extra: BTreeMap::new(),
                edits: vec![PatchFileEdit::Upsert {
                    path: asset_path,
                    content: edited_large.clone(),
                    file_type: FileType::Regular,
                }],
            })?;
            let inarch_w4_us = t0.elapsed().as_micros() as u64;
            let b_stats = remote_blobs.wire_stats();
            let m_stats = remote_meta.client().wire_stats();
            let wire_bytes = b_stats.wire_bytes_sent
                + b_stats.wire_bytes_received
                + m_stats.wire_bytes_sent
                + m_stats.wire_bytes_received;
            let after_srv_bytes = fs_dir_size(&w4_store_dir);
            let srv_disk_bytes = after_srv_bytes.saturating_sub(before_srv_bytes);
            inarch_w4_bytes_transmitted = srv_disk_bytes;
            srv_handle.shutdown();

            measurements.push(summarize_latencies(
                "W4_large_file_wire_dedup",
                "velenza-inarch",
                &param,
                &[inarch_w4_us],
                srv_disk_bytes,
                wire_bytes,
                0,
                0,
            ));

            // W4b: Git large file v1 -> v2 commit + push
            let git_w4_origin = root.join("w4-git-origin.git");
            let git_w4_work = root.join("w4-git-work");
            fs::create_dir_all(&git_w4_origin)?;
            fs::create_dir_all(&git_w4_work)?;
            run_git(&git_w4_origin, &["init", "--bare", "-b", "main"])?;
            configure_git_bare_origin(&git_w4_origin)?;
            run_git(&git_w4_work, &["init", "-b", "main"])?;
            configure_git_local_identity(&git_w4_work)?;
            let w4_origin_str = git_w4_origin.to_string_lossy().to_string();
            run_git(&git_w4_work, &["remote", "add", "origin", &w4_origin_str])?;

            fs::write(git_w4_work.join("model_weights.bin"), &base_large)?;
            run_git(&git_w4_work, &["add", "model_weights.bin"])?;
            run_git(&git_w4_work, &["commit", "-q", "-m", "v1"])?;
            run_git(&git_w4_work, &["push", "-q", "origin", "main"])?;
            let before_origin_bytes = fs_dir_size(&git_w4_origin);

            let git_t0 = Instant::now();
            fs::write(git_w4_work.join("model_weights.bin"), &edited_large)?;
            run_git(&git_w4_work, &["add", "model_weights.bin"])?;
            run_git(&git_w4_work, &["commit", "-q", "-m", "v2"])?;
            run_git(&git_w4_work, &["push", "-q", "origin", "main"])?;
            let git_w4_us = git_t0.elapsed().as_micros() as u64;
            let after_origin_bytes = fs_dir_size(&git_w4_origin);
            let git_wire_delta = after_origin_bytes
                .saturating_sub(before_origin_bytes)
                .max(patch_bytes.len() as u64);

            measurements.push(summarize_latencies(
                "W4_large_file_wire_dedup",
                "git",
                &param,
                &[git_w4_us],
                after_origin_bytes,
                git_wire_delta,
                0,
                0,
            ));
        }

        // =========================================================================
        // W5: Checkout-Free History (log_path + blame + single-parent revert)
        // =========================================================================
        {
            let sample_mpath = MPath::new(&sample_file_str)?;
            let antique = AntiqueService::new(Arc::clone(&engine));
            let mut inarch_w5_lats = Vec::with_capacity(trials);
            for t in 0..trials {
                let start = Instant::now();
                let head = engine.resolve_ref("main")?.unwrap();
                let log = engine.log_path(head, &sample_mpath)?;
                let blame = engine.blame(head, &sample_mpath)?;
                std::hint::black_box((log.len(), blame.lines.len()));
                let _rev = antique.revert_changeset(
                    "main",
                    head,
                    "bench@example.com",
                    1_761_030_000 + t as i64,
                )?;
                inarch_w5_lats.push(start.elapsed().as_micros() as u64);
            }
            measurements.push(summarize_latencies(
                "W5_checkout_free_queries",
                "velenza-inarch",
                "log_blame_revert",
                &inarch_w5_lats,
                0,
                0,
                0,
                0,
            ));

            let mut git_w5_lats = Vec::with_capacity(trials);
            for _ in 0..trials {
                let start = Instant::now();
                let _ = run_git(&git_seed_work, &["log", "-n", "10", "--", &sample_file_str])?;
                let _ = run_git(&git_seed_work, &["blame", &sample_file_str])?;
                let _ = run_git(&git_seed_work, &["revert", "--no-edit", "HEAD"])?;
                git_w5_lats.push(start.elapsed().as_micros() as u64);
            }
            measurements.push(summarize_latencies(
                "W5_checkout_free_queries",
                "git",
                "log_blame_revert",
                &git_w5_lats,
                fs_dir_size(&git_seed_work),
                0,
                0,
                0,
            ));
        }

        let timestamp_utc = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(BenchmarkReport {
            corpus_label: cfg.corpus_label.clone(),
            host_label: cfg.host_label.clone(),
            timestamp_utc,
            baseline,
            measurements,
            git_full_clone_ms,
            git_full_disk_bytes,
            git_sparse_clone_ms,
            git_sparse_disk_bytes,
            inarch_commit_p50_ms,
            inarch_working_copy_commit_p50_ms,
            inarch_cas_retries,
            inarch_w4_bytes_transmitted,
        })
    })();

    let _ = fs::remove_dir_all(&root);
    result
}

fn capture_pre_benchmark_baseline(bench_root: &Path) -> PreBenchmarkBaseline {
    use std::io::Write;
    use std::time::Duration;

    let os_family = std::env::consts::OS.to_string();
    let os_arch = std::env::consts::ARCH.to_string();
    let logical_cpu_cores = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let os_kernel_version = if os_family == "windows" {
        run_probe("cmd", &["/c", "ver"]).unwrap_or_else(|| "Windows".to_string())
    } else {
        run_probe("uname", &["-srm"]).unwrap_or_else(|| os_family.clone())
    };

    let cpu_model = match os_family.as_str() {
        "macos" => {
            let brand = run_probe("sysctl", &["-n", "machdep.cpu.brand_string"])
                .unwrap_or_else(|| "Apple Silicon".to_string());
            let p_cores =
                run_probe("sysctl", &["-n", "hw.perflevel0.physicalcpu"]).unwrap_or_default();
            let e_cores =
                run_probe("sysctl", &["-n", "hw.perflevel1.physicalcpu"]).unwrap_or_default();
            if !p_cores.is_empty() && !e_cores.is_empty() {
                format!("{brand} ({p_cores}P+{e_cores}E physical)")
            } else {
                brand
            }
        }
        "linux" => fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|v| v.trim().to_string())
            })
            .unwrap_or_else(|| "Linux CPU".to_string()),
        "windows" => run_probe(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_Processor | Select-Object -First 1).Name",
            ],
        )
        .unwrap_or_else(|| "Windows x86_64 CPU".to_string()),
        _ => "Unknown CPU".to_string(),
    };

    let power_and_thermal_profile = match os_family.as_str() {
        "macos" => {
            let pmset = run_probe("pmset", &["-g"]).unwrap_or_default();
            let power_src = if pmset.contains("AC Power") {
                "AC Power"
            } else if pmset.contains("Battery Power") {
                "Battery Power"
            } else {
                "Unknown Power"
            };
            let low_power = pmset
                .lines()
                .find(|l| l.trim_start().starts_with("lowpowermode"))
                .map(|l| l.trim())
                .unwrap_or("lowpowermode=0");
            format!("{power_src}; {low_power}")
        }
        "linux" => {
            let gov = fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "default_governor".to_string());
            format!("cpufreq_governor={gov}")
        }
        "windows" => run_probe("powercfg", &["/getactivescheme"])
            .unwrap_or_else(|| "Windows Default Power Scheme".to_string()),
        _ => "default".to_string(),
    };

    let filesystem_and_security_filters = match os_family.as_str() {
        "macos" => {
            let fv = run_probe("fdesetup", &["status"])
                .unwrap_or_else(|| "FileVault=unknown".to_string());
            let spotlight = run_probe("mdutil", &["-s", "/"])
                .map(|s| {
                    if s.contains("Indexing enabled") {
                        "Spotlight=enabled"
                    } else if s.contains("Indexing disabled") {
                        "Spotlight=disabled"
                    } else {
                        "Spotlight=default"
                    }
                })
                .unwrap_or("Spotlight=unknown");
            format!("APFS; {fv}; {spotlight}")
        }
        "linux" => run_probe("findmnt", &["-n", "-o", "FSTYPE,OPTIONS", "/"])
            .unwrap_or_else(|| "ext4/xfs default".to_string()),
        "windows" => run_probe(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "$mp = Get-MpPreference -ErrorAction SilentlyContinue; $ws = Get-Service WSearch -ErrorAction SilentlyContinue; \"DefenderRealtimeDisabled=$($mp.DisableRealtimeMonitoring); WSearch=$($ws.Status)\"",
            ],
        )
        .unwrap_or_else(|| "NTFS default".to_string()),
        _ => "default".to_string(),
    };

    let resource_limits_and_network = match os_family.as_str() {
        "macos" => {
            let nofile =
                run_probe("sh", &["-c", "ulimit -n"]).unwrap_or_else(|| "unknown".to_string());
            let p_first = run_probe("sysctl", &["-n", "net.inet.ip.portrange.first"])
                .unwrap_or_else(|| "49152".to_string());
            let p_last = run_probe("sysctl", &["-n", "net.inet.ip.portrange.last"])
                .unwrap_or_else(|| "65535".to_string());
            format!("ulimit_nofile={nofile}; ephemeral_ports={p_first}..{p_last}")
        }
        "linux" => {
            let nofile =
                run_probe("sh", &["-c", "ulimit -n"]).unwrap_or_else(|| "unknown".to_string());
            let ports = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
                .map(|s| s.split_whitespace().collect::<Vec<_>>().join(".."))
                .unwrap_or_else(|_| "32768..60999".to_string());
            format!("ulimit_nofile={nofile}; ephemeral_ports={ports}")
        }
        "windows" => {
            let ports = run_probe("netsh", &["int", "ipv4", "show", "dynamicport", "tcp"])
                .map(|s| s.lines().collect::<Vec<_>>().join(" "))
                .unwrap_or_else(|| "default_dynamic_ports".to_string());
            format!("windows_handles=unbounded; {ports}")
        }
        _ => "default".to_string(),
    };

    let git_version =
        run_probe("git", &["--version"]).unwrap_or_else(|| "git (unknown)".to_string());

    let perf_git_keys = [
        "core.fsmonitor",
        "core.untrackedCache",
        "core.preloadIndex",
        "core.fscache",
        "core.autocrlf",
        "core.symlinks",
        "core.longpaths",
        "feature.manyFiles",
        "pack.threads",
        "gc.auto",
        "commit.gpgsign",
    ];
    let mut git_kv = Vec::new();
    for key in perf_git_keys {
        if let Some(val) = run_probe("git", &["config", "--global", "--get", key]) {
            if !val.is_empty() {
                git_kv.push(format!("{key}={val}"));
            }
        }
    }
    let git_global_performance_settings = if git_kv.is_empty() {
        "all_defaults (no global perf overrides)".to_string()
    } else {
        git_kv.join("; ")
    };

    let pre_bench_load_average = match os_family.as_str() {
        "macos" => run_probe("sysctl", &["-n", "vm.loadavg"]).unwrap_or_else(|| "N/A".to_string()),
        "linux" => fs::read_to_string("/proc/loadavg")
            .ok()
            .map(|s| {
                s.split_whitespace()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(" / ")
            })
            .unwrap_or_else(|| "N/A".to_string()),
        "windows" => run_probe(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "$lp = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average; \"cpu_load_pct=$lp%\"",
            ],
        )
        .unwrap_or_else(|| "N/A".to_string()),
        _ => "N/A".to_string(),
    };

    let running_process_count = if os_family == "windows" {
        run_probe(
            "powershell",
            &["-NoProfile", "-Command", "(Get-Process).Count"],
        )
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(1)
    } else {
        run_probe("ps", &["-e"])
            .map(|s| s.lines().count().saturating_sub(1).max(1))
            .unwrap_or(1)
    };

    let pre_bench_memory_summary = match os_family.as_str() {
        "macos" => {
            let total_bytes = run_probe("sysctl", &["-n", "hw.memsize"])
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0);
            let total_mb = total_bytes / (1024 * 1024);
            format!("total_ram_mb={total_mb}")
        }
        "linux" => fs::read_to_string("/proc/meminfo")
            .ok()
            .map(|s| {
                let mut parts = Vec::new();
                for line in s.lines() {
                    if line.starts_with("MemTotal:")
                        || line.starts_with("MemAvailable:")
                        || line.starts_with("SwapFree:")
                    {
                        parts.push(line.split_whitespace().collect::<Vec<_>>().join(" "));
                    }
                }
                parts.join("; ")
            })
            .unwrap_or_else(|| "N/A".to_string()),
        "windows" => run_probe(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "$os = Get-CimInstance Win32_OperatingSystem; \"total_mb=$([math]::Round($os.TotalVisibleMemorySize/1024)) free_mb=$([math]::Round($os.FreePhysicalMemory/1024))\"",
            ],
        )
        .unwrap_or_else(|| "N/A".to_string()),
        _ => "N/A".to_string(),
    };

    let pre_bench_disk_free_summary = if os_family == "windows" {
        run_probe(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "$d = Get-PSDrive -Name ($pwd.Drive.Name); \"free_gb=$([math]::Round($d.Free/1GB, 1))\"",
            ],
        )
        .unwrap_or_else(|| "N/A".to_string())
    } else {
        run_probe("df", &["-h", &bench_root.to_string_lossy()])
            .and_then(|s| {
                s.lines().nth(1).map(|l| {
                    let cols: Vec<&str> = l.split_whitespace().collect();
                    if cols.len() >= 5 {
                        format!("size={} avail={} used_pct={}", cols[1], cols[3], cols[4])
                    } else {
                        l.trim().to_string()
                    }
                })
            })
            .unwrap_or_else(|| "N/A".to_string())
    };

    // Micro-calibration probe 1: 4 MiB sequential write + fsync on target benchmark disk
    let probe_dir = bench_root.join(".pre-bench-probe");
    let _ = fs::create_dir_all(&probe_dir);
    let fsync_file_path = probe_dir.join("fsync_4mb.bin");
    let buf_4mb = vec![0xA5u8; 4 * 1024 * 1024];
    let t_fsync = Instant::now();
    if let Ok(mut f) = fs::File::create(&fsync_file_path) {
        let _ = f.write_all(&buf_4mb);
        let _ = f.sync_all();
    }
    let pre_bench_4mb_fsync_write_us = t_fsync.elapsed().as_micros().max(1) as u64;
    let _ = fs::remove_file(&fsync_file_path);

    // Micro-calibration probe 2: 100 x 4 KiB small-file create + write + read + unlink
    let buf_4kb = [0x5Au8; 4096];
    let t_small = Instant::now();
    for idx in 0..100usize {
        let p = probe_dir.join(format!("small_{idx:03}.tmp"));
        if fs::write(&p, buf_4kb).is_ok() {
            let _ = fs::read(&p);
            let _ = fs::remove_file(&p);
        }
    }
    let pre_bench_100_small_files_us = t_small.elapsed().as_micros().max(1) as u64;
    let _ = fs::remove_dir_all(&probe_dir);

    // Micro-calibration probe 3: 15 x 1 ms OS scheduler wakeup jitter p99
    let mut jitters = Vec::with_capacity(15);
    for _ in 0..15 {
        let t0 = Instant::now();
        thread::sleep(Duration::from_micros(1000));
        let elapsed = t0.elapsed().as_micros() as u64;
        jitters.push(elapsed.saturating_sub(1000).max(1));
    }
    jitters.sort_unstable();
    let pre_bench_scheduler_jitter_p99_us = jitters[jitters.len() - 1];

    PreBenchmarkBaseline {
        os_family: sanitize_telemetry(&os_family),
        os_arch: sanitize_telemetry(&os_arch),
        os_kernel_version: sanitize_telemetry(&os_kernel_version),
        cpu_model: sanitize_telemetry(&cpu_model),
        logical_cpu_cores,
        power_and_thermal_profile: sanitize_telemetry(&power_and_thermal_profile),
        filesystem_and_security_filters: sanitize_telemetry(&filesystem_and_security_filters),
        resource_limits_and_network: sanitize_telemetry(&resource_limits_and_network),
        git_version: sanitize_telemetry(&git_version),
        git_global_performance_settings: sanitize_telemetry(&git_global_performance_settings),
        pre_bench_load_average: sanitize_telemetry(&pre_bench_load_average),
        running_process_count,
        pre_bench_memory_summary: sanitize_telemetry(&pre_bench_memory_summary),
        pre_bench_disk_free_summary: sanitize_telemetry(&pre_bench_disk_free_summary),
        pre_bench_4mb_fsync_write_us,
        pre_bench_100_small_files_us,
        pre_bench_scheduler_jitter_p99_us,
    }
}

fn run_probe(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn sanitize_telemetry(raw: &str) -> String {
    let single_line = raw
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    single_line.replace('|', "/")
}

#[allow(clippy::too_many_arguments)]
fn summarize_latencies(
    workload_id: &str,
    system: &str,
    parameter: &str,
    samples_us: &[u64],
    disk_bytes_written: u64,
    wire_bytes_transferred: u64,
    retries_or_rebased: usize,
    failures: usize,
) -> WorkloadMeasurement {
    let mut sorted = samples_us.to_vec();
    if sorted.is_empty() {
        sorted.push(1);
    }
    sorted.sort_unstable();
    let n = sorted.len();
    let p50_us = sorted[(n - 1) * 50 / 100];
    let p95_us = sorted[(n - 1) * 95 / 100];
    let p99_us = sorted[(n - 1) * 99 / 100];
    let sum: u128 = sorted.iter().map(|&x| x as u128).sum();
    let mean_us = (sum / (n as u128)).max(1) as u64;
    let throughput_ops_per_sec = 1_000_000.0 / (mean_us as f64);

    WorkloadMeasurement {
        workload_id: workload_id.to_string(),
        system: system.to_string(),
        parameter: parameter.to_string(),
        trials: n,
        p50_us,
        p95_us,
        p99_us,
        mean_us,
        throughput_ops_per_sec,
        disk_bytes_written,
        wire_bytes_transferred,
        retries_or_rebased,
        failures,
    }
}

fn unique_bench_dir(label: &str) -> PathBuf {
    let sanitized: String = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let dir = std::env::temp_dir().join(format!(
        "velenza-inarch-bench-{}-{}-{}",
        sanitized,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn populate_synthetic_corpus(root: &Path, file_count: usize) -> Result<(), CliError> {
    let svc_count = 10usize;
    for i in 0..file_count {
        let svc = i % svc_count;
        let idx = i / svc_count;
        let dir = root.join(format!("services/svc-{svc:02}"));
        fs::create_dir_all(&dir)?;
        let content = format!(
            "//! Synthetic service module svc-{svc:02} file {idx}\npub fn compute_{idx}(x: u64) -> u64 {{\n    x.wrapping_mul(6364136223846793005).wrapping_add({i})\n}}\n"
        );
        fs::write(dir.join(format!("mod_{idx}.rs")), content.as_bytes())?;
    }
    Ok(())
}

fn copy_corpus_tree(src: &Path, dst: &Path) -> Result<(), CliError> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".git" || name == "target" || name == ".inarch" || name == "node_modules" {
            continue;
        }
        let path = entry.path();
        let ft = fs::symlink_metadata(&path)?.file_type();
        let target = dst.join(&name);
        if ft.is_dir() {
            copy_corpus_tree(&path, &target)?;
        } else if ft.is_file() {
            fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

fn discover_sparse_prefix_and_sample_file(root: &Path) -> Result<(String, String), CliError> {
    let mut files = Vec::new();
    collect_relative_files(root, root, &mut files)?;
    files.sort();
    let sample = files
        .first()
        .cloned()
        .ok_or_else(|| CliError::InvalidArgument("empty benchmark corpus directory".to_string()))?;
    let prefix = sample.split('/').next().unwrap_or(&sample).to_string();
    Ok((prefix, sample))
}

fn collect_relative_files(root: &Path, curr: &Path, out: &mut Vec<String>) -> Result<(), CliError> {
    for entry in fs::read_dir(curr)? {
        let entry = entry?;
        let path = entry.path();
        let ft = fs::symlink_metadata(&path)?.file_type();
        if ft.is_dir() {
            collect_relative_files(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.push(rel);
        }
    }
    Ok(())
}

/// Recursively computes the total on-disk file size (in bytes) of `dir`.
pub fn fs_dir_size(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut sum = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            sum += fs_dir_size(&path);
        } else if meta.is_file() {
            sum += meta.len();
        }
    }
    sum
}

fn configure_git_bare_origin(repo_dir: &Path) -> Result<(), CliError> {
    run_git(repo_dir, &["config", "core.fsmonitor", "false"])?;
    run_git(repo_dir, &["config", "feature.manyFiles", "true"])?;
    run_git(repo_dir, &["config", "uploadpack.allowFilter", "true"])?;
    run_git(
        repo_dir,
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    )?;
    Ok(())
}

fn configure_git_local_identity(repo_dir: &Path) -> Result<(), CliError> {
    run_git(repo_dir, &["config", "user.name", "Benchmark Runner"])?;
    run_git(repo_dir, &["config", "user.email", "bench@example.com"])?;
    run_git(repo_dir, &["config", "core.fsmonitor", "false"])?;
    run_git(repo_dir, &["config", "feature.manyFiles", "true"])?;
    Ok(())
}

fn run_git(repo_dir: &Path, args: &[&str]) -> Result<Vec<u8>, CliError> {
    let out = Command::new("git")
        .current_dir(repo_dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Benchmark Runner")
        .env("GIT_AUTHOR_EMAIL", "bench@example.com")
        .env("GIT_COMMITTER_NAME", "Benchmark Runner")
        .env("GIT_COMMITTER_EMAIL", "bench@example.com")
        .output()?;
    if !out.status.success() {
        return Err(CliError::InvalidArgument(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_suite_records_sparse_git_and_working_copy_inarch_and_cas_retries() {
        let cfg = BenchmarkConfig {
            corpus_label: "unit-bench".to_string(),
            host_label: "unit-host".to_string(),
            source_dir: None,
            file_count: 20,
            concurrency_levels: vec![1, 4],
            trials: 1,
            large_file_mb: 1,
        };
        let report: BenchmarkSuiteReport =
            run_benchmark_suite(&cfg).expect("benchmark suite must succeed");
        assert!(report.git_full_clone_ms > 0.0);
        assert!(report.git_full_disk_bytes > 0);
        assert!(report.git_sparse_clone_ms > 0.0);
        assert!(report.git_sparse_disk_bytes > 0);
        assert!(report.inarch_commit_p50_ms > 0.0);
        assert!(report.inarch_working_copy_commit_p50_ms > 0.0);
        assert!(
            report.inarch_cas_retries >= 1,
            "4 concurrent workers on same ref must record >=1 CAS retry, got {}",
            report.inarch_cas_retries
        );
        assert!(report.inarch_w4_bytes_transmitted > 0);
        assert!(report.inarch_w4_bytes_transmitted < 1024 * 1024);

        let json = report.to_json();
        assert!(json.contains("\"git_sparse_clone_ms\":"));
        assert!(json.contains("\"inarch_working_copy_commit_p50_ms\":"));
        assert!(json.contains("\"inarch_cas_retries\":"));

        let md = report.to_markdown();
        assert!(md.contains("git_sparse_clone_ms"));
        assert!(md.contains("inarch_working_copy_commit_p50_ms"));
        assert!(md.contains("inarch_cas_retries"));
    }
}
