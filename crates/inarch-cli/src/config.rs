//! Externalized Configuration System (`InarchConfig`) for Velenza Inarch.
//!
//! Enforces Velenza Inarch's zero-hardcoded-environment rule: all storage roots, cache tiers,
//! default references, author identities, timezone offsets, directory ignore patterns,
//! FastCDC chunking parameters, and Antique directory ACL policies are loaded from a
//! TOML configuration file (`inarch.toml` or `.inarch/config.toml`) and optional
//! `INARCH_*` environment variable overrides.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use inarch_antique::{PathAclPolicy, PathAclRule};
use inarch_engine::ScionEngine;
use inarch_store::{
    BlobStore, FsBlobStore, FsMetadataStore, GcsBlobStore, MemBlobStore, MetadataStore,
    RemoteBlobStore, RemoteMetadataStore, RemoteRpcClient, ScopedMetadataStore,
    SpannerMetadataStore,
    TieredBlobStore,
};
use inarch_types::path::MPath;

use crate::CliError;

/// A single directory ACL rule loaded from `[[acl_rules]]` in `inarch.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRuleConfig {
    /// Directory prefix (empty `""` or `"/"` for the repository root rule).
    pub prefix: String,
    /// Actors permitted to modify paths under `prefix` (`"*"` allows any actor).
    pub allowed_actors: Vec<String>,
    /// Reviewers required before landing changes under `prefix`.
    pub required_reviewers: Vec<String>,
}

/// Complete runtime configuration for an Velenza Inarch workspace or server node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InarchConfig {
    /// Logical repository identifier for multi-repo ref scoping (`"default"` if unscoped).
    /// Overridable via `INARCH_REPO_ID`.
    pub repo_id: String,
    /// Default target ref (e.g. `"main"`). Overridable via `INARCH_DEFAULT_REF`.
    pub default_ref: String,
    /// Default commit/patch author identity. Overridable via `INARCH_AUTHOR`.
    pub default_author: String,
    /// Default timezone offset in seconds from UTC. Overridable via `INARCH_TZ_OFFSET_SECS`.
    pub tz_offset_secs: i32,
    /// Directory and file names ignored when scanning or verifying working trees on disk.
    pub ignore_names: Vec<String>,
    /// Bind address for `inr serve` (e.g. `"127.0.0.1:7331"` or `"0.0.0.0:7331"`).
    /// Overridable via `INARCH_LISTEN_ADDR`.
    pub listen_addr: String,
    /// Remote `inarch-server` base URL (e.g. `"http://127.0.0.1:7331"`).
    /// Overridable via `INARCH_REMOTE_URL`.
    pub remote_url: String,
    /// Optional shared bearer token for authenticating with `inarch-server`.
    /// Overridable via `INARCH_AUTH_TOKEN`.
    pub auth_token: String,
    /// Optional path to a Google Cloud service account JSON key file used to mint
    /// short-lived OIDC `id_token` bearer tokens for workstation authentication.
    /// Overridable via `INARCH_GCP_CREDENTIALS_FILE`.
    pub gcp_credentials_file: String,
    /// Optional path to a checked-out Just-In-Time (JIT) swarm lease JSON file
    /// (defaults to `<workspace_root>/.inarch/jit_lease.json` when present).
    /// Overridable via `INARCH_JIT_LEASE_FILE`.
    pub jit_lease_file: String,
    /// Server-side secret seed or 64-hex key used by `inr serve` to sign and verify
    /// quantum-safe BLAKE3 keyed-MAC JIT lease tokens (`inarch_jit_v1_...`).
    /// Overridable via `INARCH_JIT_SIGNING_KEY`.
    pub jit_signing_key: String,
    /// OIDC tokeninfo verification endpoint used by `inr serve` to validate workstation
    /// service account `id_token`s. Overridable via `INARCH_OIDC_TOKENINFO_URL`.
    pub oidc_tokeninfo_url: String,
    /// Optional override for the OAuth2 `token_uri` used when minting workstation OIDC tokens.
    /// Overridable via `INARCH_OIDC_TOKEN_URI`.
    pub oidc_token_uri: String,
    /// Expected OIDC audience (`aud` claim) required by `inr serve` and requested by workstation
    /// service-account token minting. Overridable via `INARCH_OIDC_AUDIENCE`.
    pub oidc_audience: String,
    /// Root directory for persistent Velenza Inarch stores (relative to workspace root or absolute).
    /// Overridable via `INARCH_STORE_DIR`.
    pub store_dir: String,
    /// Subdirectory under `store_dir` for content-addressed blobs and derived objects.
    pub blobs_subdir: String,
    /// Subdirectory under `store_dir` for `BonsaiChangeset`s, refs, and derived mappings.
    pub meta_subdir: String,
    /// Optional filesystem directory for Tier-1 (`inarch-daemon`) persistent NVMe cache.
    /// When empty, an in-memory `MemBlobStore` cache is used.
    /// Overridable via `INARCH_TIER1_CACHE_DIR`.
    pub tier1_cache_dir: String,
    /// Optional filesystem directory for Tier-2 (`inarch-cache`) regional cache.
    /// When empty, an in-memory `MemBlobStore` cache is used.
    /// Overridable via `INARCH_TIER2_CACHE_DIR`.
    pub tier2_cache_dir: String,
    /// Authoritative Tier-3 blob storage backend (`"local" | "gcs" | "remote"`).
    /// Overridable via `INARCH_BLOB_BACKEND`.
    pub blob_backend: String,
    /// Google Cloud Storage bucket name when `blob_backend = "gcs"`.
    /// Overridable via `INARCH_GCS_BUCKET`.
    pub gcs_bucket: String,
    /// Optional object key prefix inside `gcs_bucket`.
    /// Overridable via `INARCH_GCS_PREFIX`.
    pub gcs_prefix: String,
    /// Authoritative metadata & CAS ref backend (`"local" | "spanner" | "remote"`).
    /// Overridable via `INARCH_META_BACKEND`.
    pub meta_backend: String,
    /// Cloud Spanner database resource path (`projects/<p>/instances/<i>/databases/<d>`)
    /// when `meta_backend = "spanner"`. Overridable via `INARCH_SPANNER_DATABASE`.
    pub spanner_database: String,
    /// FastCDC minimum chunk size in bytes.
    pub chunk_min_size: usize,
    /// FastCDC target average chunk size in bytes.
    pub chunk_avg_size: usize,
    /// FastCDC maximum chunk size in bytes.
    pub chunk_max_size: usize,
    /// Structured telemetry & audit log backend (`"none" | "local" | "jsonl" | "stderr" | "gcp"`).
    /// Overridable via `INARCH_LOG_BACKEND`.
    pub log_backend: String,
    /// Minimum telemetry severity level (`"debug" | "info" | "warn" | "error"`).
    /// Overridable via `INARCH_LOG_LEVEL`.
    pub log_level: String,
    /// Local JSONL telemetry log file path when `log_backend = "local"` or `"jsonl"`.
    /// Overridable via `INARCH_LOG_FILE`.
    pub log_file: String,
    /// Google Cloud Logging resource logName (`projects/<p>/logs/<id>`) when `log_backend = "gcp"`.
    /// Overridable via `INARCH_GCP_LOG_NAME`.
    pub gcp_log_name: String,
    /// Longest-prefix Antique directory ACL rules.
    pub acl_rules: Vec<AclRuleConfig>,
}

impl Default for InarchConfig {
    fn default() -> Self {
        Self {
            repo_id: "default".to_string(),
            default_ref: "main".to_string(),
            default_author: "developer@inarch.local".to_string(),
            tz_offset_secs: 0,
            ignore_names: vec![
                ".git".to_string(),
                ".inarch".to_string(),
                "target".to_string(),
                "node_modules".to_string(),
            ],
            listen_addr: "127.0.0.1:7331".to_string(),
            remote_url: String::new(),
            auth_token: String::new(),
            gcp_credentials_file: String::new(),
            jit_lease_file: String::new(),
            jit_signing_key: String::new(),
            oidc_tokeninfo_url: "https://oauth2.googleapis.com/tokeninfo".to_string(),
            oidc_token_uri: String::new(),
            oidc_audience: String::new(),
            store_dir: ".inarch/store".to_string(),
            blobs_subdir: "blobs".to_string(),
            meta_subdir: "meta".to_string(),
            tier1_cache_dir: String::new(),
            tier2_cache_dir: String::new(),
            blob_backend: "local".to_string(),
            gcs_bucket: String::new(),
            gcs_prefix: String::new(),
            meta_backend: "local".to_string(),
            spanner_database: String::new(),
            chunk_min_size: 16 * 1024,
            chunk_avg_size: 64 * 1024,
            chunk_max_size: 256 * 1024,
            log_backend: "none".to_string(),
            log_level: "info".to_string(),
            log_file: ".inarch/logs/inarch.jsonl".to_string(),
            gcp_log_name: String::new(),
            acl_rules: Vec::new(),
        }
    }
}

/// Receipt stored at `<workspace_root>/.inarch/jit_lease.json` when a swarm checks out a JIT lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalJitLeaseFile {
    pub lease_id: String,
    pub lease_token: String,
    pub repo_id: String,
    pub swarm_id: String,
    pub task_id: String,
    pub allowed_ops: Vec<String>,
    pub allowed_read_prefixes: Vec<String>,
    pub allowed_write_prefixes: Vec<String>,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

impl LocalJitLeaseFile {
    pub fn to_toml_string(&self) -> String {
        let mut out = String::new();
        out.push_str("# Velenza Inarch Just-In-Time (JIT) Swarm Lease (.inarch/jit_lease.json)\n");
        out.push_str("[lease]\n");
        out.push_str(&format!("lease_id = {}\n", quote_toml_str(&self.lease_id)));
        out.push_str(&format!(
            "lease_token = {}\n",
            quote_toml_str(&self.lease_token)
        ));
        out.push_str(&format!("repo_id = {}\n", quote_toml_str(&self.repo_id)));
        out.push_str(&format!("swarm_id = {}\n", quote_toml_str(&self.swarm_id)));
        out.push_str(&format!("task_id = {}\n", quote_toml_str(&self.task_id)));
        out.push_str(&format!(
            "allowed_ops = {}\n",
            format_toml_str_array(&self.allowed_ops)
        ));
        out.push_str(&format!(
            "allowed_read_prefixes = {}\n",
            format_toml_str_array(&self.allowed_read_prefixes)
        ));
        out.push_str(&format!(
            "allowed_write_prefixes = {}\n",
            format_toml_str_array(&self.allowed_write_prefixes)
        ));
        out.push_str(&format!("issued_at_unix = {}\n", self.issued_at_unix));
        out.push_str(&format!("expires_at_unix = {}\n", self.expires_at_unix));
        out
    }

    pub fn from_toml_str(input: &str) -> Result<Self, CliError> {
        let mut rec = Self {
            lease_id: String::new(),
            lease_token: String::new(),
            repo_id: "default".to_string(),
            swarm_id: String::new(),
            task_id: String::new(),
            allowed_ops: Vec::new(),
            allowed_read_prefixes: Vec::new(),
            allowed_write_prefixes: Vec::new(),
            issued_at_unix: 0,
            expires_at_unix: 0,
        };
        for (idx, raw_line) in input.lines().enumerate() {
            let line = strip_toml_comment(raw_line).trim();
            if line.is_empty() || (line.starts_with('[') && line.ends_with(']')) {
                continue;
            }
            let Some((raw_k, raw_v)) = line.split_once('=') else {
                continue;
            };
            let k = raw_k.trim();
            let v = raw_v.trim();
            match k {
                "lease_id" => rec.lease_id = parse_toml_str(v, idx + 1)?,
                "lease_token" => rec.lease_token = parse_toml_str(v, idx + 1)?,
                "repo_id" => rec.repo_id = parse_toml_str(v, idx + 1)?,
                "swarm_id" => rec.swarm_id = parse_toml_str(v, idx + 1)?,
                "task_id" => rec.task_id = parse_toml_str(v, idx + 1)?,
                "allowed_ops" => rec.allowed_ops = parse_toml_str_array(v, idx + 1)?,
                "allowed_read_prefixes" => {
                    rec.allowed_read_prefixes = parse_toml_str_array(v, idx + 1)?
                }
                "allowed_write_prefixes" => {
                    rec.allowed_write_prefixes = parse_toml_str_array(v, idx + 1)?
                }
                "issued_at_unix" => {
                    rec.issued_at_unix = v.parse::<i64>().unwrap_or(0);
                }
                "expires_at_unix" => {
                    rec.expires_at_unix = v.parse::<i64>().unwrap_or(0);
                }
                _ => {}
            }
        }
        if rec.lease_id.is_empty() || rec.lease_token.is_empty() {
            return Err(CliError::InvalidArgument(
                "invalid JIT lease file: missing lease_id or lease_token".to_string(),
            ));
        }
        Ok(rec)
    }

    pub fn from_lease_and_token(lease: &inarch_store::JitLeaseRecord, lease_token: String) -> Self {
        Self {
            lease_id: lease.lease_id.clone(),
            lease_token,
            repo_id: lease.repo_id.clone(),
            swarm_id: lease.swarm_id.clone(),
            task_id: lease.task_id.clone(),
            allowed_ops: lease.allowed_ops.clone(),
            allowed_read_prefixes: lease.allowed_read_prefixes.clone(),
            allowed_write_prefixes: lease.allowed_write_prefixes.clone(),
            issued_at_unix: lease.issued_at_unix,
            expires_at_unix: lease.expires_at_unix,
        }
    }

    pub fn resolve_path(workspace_dir: &Path, configured_jit_lease_file: &str) -> PathBuf {
        let trimmed = configured_jit_lease_file.trim();
        if trimmed.is_empty() {
            workspace_dir.join(".inarch/jit_lease.json")
        } else {
            resolve_maybe_relative(workspace_dir, trimmed)
        }
    }

    pub fn load_from_file(path: &Path) -> Result<Self, CliError> {
        let raw = fs::read_to_string(path).map_err(|e| {
            CliError::Io(format!(
                "failed to read JIT lease file '{}': {}",
                path.display(),
                e
            ))
        })?;
        Self::from_toml_str(&raw)
    }

    pub fn read_from_file(path: &Path) -> Result<Self, CliError> {
        Self::load_from_file(path)
    }

    pub fn write_to_file(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, self.to_toml_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

impl InarchConfig {
    /// Returns the user-global configuration file path (`~/.config/velenza-inarch/inarch.toml`), if `HOME` or `USERPROFILE` is set.
    pub fn user_global_config_path() -> Option<PathBuf> {
        if let Ok(explicit_global) = env::var("INARCH_USER_CONFIG") {
            let trimmed = explicit_global.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed));
            }
        }
        let home = env::var("HOME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                env::var("USERPROFILE")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
            })?;
        Some(
            PathBuf::from(home)
                .join(".config")
                .join("velenza-inarch")
                .join("inarch.toml"),
        )
    }

    /// Discovers configuration in order of precedence:
    /// 1. Explicit `explicit_path` (`--config <path>`)
    /// 2. `INARCH_CONFIG` environment variable
    /// 3. `<workspace_root>/inarch.toml`
    /// 4. `<workspace_root>/.inarch/config.toml`
    /// 5. `~/.config/velenza-inarch/inarch.toml` (when present)
    /// 6. `InarchConfig::default()`, with `INARCH_*` environment variable overrides applied.
    pub fn discover(workspace_root: &Path, explicit_path: Option<&Path>) -> Result<Self, CliError> {
        let env_cfg_path = env::var("INARCH_CONFIG")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let mut cfg = if let Some(path) = explicit_path {
            Self::load_from_file(path)?
        } else if let Some(env_path) = env_cfg_path {
            Self::load_from_file(Path::new(&env_path))?
        } else if workspace_root.join("inarch.toml").is_file() {
            Self::load_from_file(&workspace_root.join("inarch.toml"))?
        } else if workspace_root.join(".inarch/config.toml").is_file() {
            Self::load_from_file(&workspace_root.join(".inarch/config.toml"))?
        } else if let Some(global_path) = Self::user_global_config_path() {
            if global_path.is_file() {
                Self::load_from_file(&global_path)?
            } else {
                Self::default()
            }
        } else {
            Self::default()
        };

        cfg.apply_env_overrides();
        Ok(cfg)
    }

    /// Loads an [`InarchConfig`] from a TOML file on disk.
    pub fn load_from_file(path: &Path) -> Result<Self, CliError> {
        let text = fs::read_to_string(path).map_err(|e| {
            CliError::Io(format!("failed to read config '{}': {}", path.display(), e))
        })?;
        let mut cfg = Self::from_toml_str(&text)?;
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    /// Writes this configuration as TOML to `path`, creating parent directories if needed.
    pub fn write_to_file(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, self.to_toml_string())?;
        Ok(())
    }

    /// Returns `ignore_names` as a borrowed `&str` slice vector for directory ingestion/verification.
    pub fn ignore_slices(&self) -> Vec<&str> {
        self.ignore_names.iter().map(|s| s.as_str()).collect()
    }

    /// Applies `INARCH_*` environment variable overrides on top of the loaded configuration.
    pub fn apply_env_overrides(&mut self) {
        fn read_env(key: &str) -> Option<String> {
            env::var(key)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        }

        if let Some(val) = read_env("INARCH_REPO_ID") {
            self.repo_id = val;
        }
        if let Some(val) = read_env("INARCH_DEFAULT_REF") {
            self.default_ref = val;
        }
        if let Some(val) = read_env("INARCH_AUTHOR").or_else(|| read_env("INARCH_DEFAULT_AUTHOR")) {
            self.default_author = val;
        }
        if let Some(val) = read_env("INARCH_TZ_OFFSET_SECS") {
            if let Ok(parsed) = val.parse::<i32>() {
                self.tz_offset_secs = parsed;
            }
        }
        if let Some(val) = read_env("INARCH_LISTEN_ADDR") {
            self.listen_addr = val;
        }
        if let Some(val) = read_env("INARCH_REMOTE_URL") {
            self.remote_url = val;
        }
        if let Some(val) = read_env("INARCH_AUTH_TOKEN") {
            self.auth_token = val;
        }
        if let Some(val) =
            read_env("INARCH_GCP_CREDENTIALS_FILE").or_else(|| read_env("INARCH_GCP_CREDENTIALS"))
        {
            self.gcp_credentials_file = val;
        }
        if let Some(val) = read_env("INARCH_JIT_LEASE_FILE") {
            self.jit_lease_file = val;
        }
        if let Some(val) = read_env("INARCH_JIT_SIGNING_KEY") {
            self.jit_signing_key = val;
        }
        if let Some(val) = read_env("INARCH_OIDC_TOKENINFO_URL") {
            self.oidc_tokeninfo_url = val;
        }
        if let Some(val) = read_env("INARCH_OIDC_TOKEN_URI") {
            self.oidc_token_uri = val;
        }
        if let Some(val) = read_env("INARCH_OIDC_AUDIENCE") {
            self.oidc_audience = val;
        }
        if let Some(val) = read_env("INARCH_STORE_DIR") {
            self.store_dir = val;
        }
        if let Some(val) = read_env("INARCH_TIER1_CACHE_DIR") {
            self.tier1_cache_dir = val;
        }
        if let Some(val) = read_env("INARCH_TIER2_CACHE_DIR") {
            self.tier2_cache_dir = val;
        }
        if let Some(val) = read_env("INARCH_BLOB_BACKEND") {
            self.blob_backend = val;
        }
        if let Some(val) = read_env("INARCH_GCS_BUCKET") {
            self.gcs_bucket = val;
        }
        if let Some(val) = read_env("INARCH_GCS_PREFIX") {
            self.gcs_prefix = val;
        }
        if let Some(val) = read_env("INARCH_META_BACKEND") {
            self.meta_backend = val;
        }
        if let Some(val) = read_env("INARCH_SPANNER_DATABASE") {
            self.spanner_database = val;
        } else if self.spanner_database.trim().is_empty() {
            if let (Some(proj), Some(inst)) = (
                read_env("ARBOR_GCP_PROJECT"),
                read_env("ARBOR_SPANNER_INSTANCE"),
            ) {
                let db = read_env("ARBOR_INARCH_DATABASE")
                    .or_else(|| read_env("VELENZA_INARCH_SPANNER_DATABASE"))
                    .unwrap_or_else(|| "inarch-meta".to_string());
                self.spanner_database =
                    format!("projects/{}/instances/{}/databases/{}", proj, inst, db);
            }
        }
        if let Some(val) = read_env("INARCH_LOG_BACKEND") {
            self.log_backend = val;
        }
        if let Some(val) = read_env("INARCH_LOG_LEVEL") {
            self.log_level = val;
        }
        if let Some(val) = read_env("INARCH_LOG_FILE") {
            self.log_file = val;
        }
        if let Some(val) = read_env("INARCH_GCP_LOG_NAME") {
            self.gcp_log_name = val;
        }
    }

    /// Builds the configured [`inarch_store::TelemetrySink`] (`"none"`, `"local"` / `"jsonl"`, `"stderr"`, or `"gcp"`).
    pub fn build_telemetry_sink(
        &self,
        workspace_root: &Path,
    ) -> Result<Arc<dyn inarch_store::TelemetrySink>, CliError> {
        let level = inarch_store::LogLevel::from_str_name(&self.log_level)
            .unwrap_or(inarch_store::LogLevel::Info);
        match self.log_backend.trim().to_ascii_lowercase().as_str() {
            "" | "none" | "off" => Ok(Arc::new(inarch_store::NoopTelemetrySink)),
            "local" | "jsonl" | "file" => {
                let rel = if self.log_file.trim().is_empty() {
                    ".inarch/logs/inarch.jsonl"
                } else {
                    self.log_file.trim()
                };
                let log_path = resolve_maybe_relative(workspace_root, rel);
                let sink = inarch_store::JsonlFileTelemetrySink::with_min_level(&log_path, level)
                    .map_err(inarch_engine::EngineError::Store)?;
                Ok(Arc::new(sink))
            }
            "stderr" => Ok(Arc::new(inarch_store::StderrTelemetrySink::new(level))),
            "gcp" | "cloud-logging" => {
                let log_name = if self.gcp_log_name.trim().is_empty() {
                    format!("projects/default/logs/velenza-inarch-{}", self.repo_id)
                } else {
                    self.gcp_log_name.trim().to_string()
                };
                let mirror_path = if self.log_file.trim().is_empty() {
                    None
                } else {
                    Some(resolve_maybe_relative(workspace_root, self.log_file.trim()))
                };
                let sink = inarch_store::GcpCloudLoggingSink::new(
                    log_name,
                    "global",
                    level,
                    false,
                    mirror_path.as_deref(),
                    std::env::var("INARCH_GCP_ACCESS_TOKEN")
                        .ok()
                        .filter(|v| !v.is_empty()),
                )
                .map_err(inarch_engine::EngineError::Store)?;
                Ok(Arc::new(sink))
            }
            other => Err(CliError::InvalidArgument(format!(
                "unsupported log_backend '{}' (expected \"none\", \"local\", \"jsonl\", \"stderr\", or \"gcp\")",
                other
            ))),
        }
    }

    /// Resolves the storage root path relative to `workspace_root` (unless `store_dir` is absolute).
    pub fn resolved_store_dir(&self, workspace_root: &Path) -> PathBuf {
        let p = Path::new(&self.store_dir);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            workspace_root.join(p)
        }
    }

    /// Resolves the content-addressed blobs directory path.
    pub fn resolved_blobs_dir(&self, workspace_root: &Path) -> PathBuf {
        self.resolved_store_dir(workspace_root)
            .join(&self.blobs_subdir)
    }

    /// Resolves the metadata store directory path.
    pub fn resolved_meta_dir(&self, workspace_root: &Path) -> PathBuf {
        self.resolved_store_dir(workspace_root)
            .join(&self.meta_subdir)
    }

    /// Resolves the active authentication bearer token and effective `repo_id` for client operations.
    ///
    /// Precedence:
    /// 1. Active checked-out JIT swarm lease file (`jit_lease_file` or `<workspace_root>/.inarch/jit_lease.json`)
    /// 2. Explicit `auth_token` (`INARCH_AUTH_TOKEN`)
    /// 3. Workstation service account OIDC `id_token` minted from `gcp_credentials_file` (`INARCH_GCP_CREDENTIALS_FILE`)
    pub fn resolve_effective_auth(
        &self,
        workspace_root: &Path,
    ) -> Result<(Option<String>, String), CliError> {
        let lease_path = if !self.jit_lease_file.trim().is_empty() {
            Some(resolve_maybe_relative(
                workspace_root,
                self.jit_lease_file.trim(),
            ))
        } else {
            let default_lease_path = workspace_root.join(".inarch/jit_lease.json");
            if default_lease_path.is_file() {
                Some(default_lease_path)
            } else {
                None
            }
        };

        if let Some(lp) = lease_path {
            if lp.is_file() {
                let lease = LocalJitLeaseFile::load_from_file(&lp)?;
                let effective_repo =
                    if self.repo_id.trim().is_empty() || self.repo_id.trim() == "default" {
                        lease.repo_id
                    } else {
                        self.repo_id.trim().to_string()
                    };
                return Ok((Some(lease.lease_token), effective_repo));
            }
        }

        let effective_repo = self.repo_id.trim().to_string();

        if !self.auth_token.trim().is_empty() {
            return Ok((Some(self.auth_token.trim().to_string()), effective_repo));
        }

        if !self.gcp_credentials_file.trim().is_empty() {
            let cred_path =
                resolve_maybe_relative(workspace_root, self.gcp_credentials_file.trim());
            let token_uri_opt = if self.oidc_token_uri.trim().is_empty() {
                None
            } else {
                Some(self.oidc_token_uri.trim())
            };
            let target_aud = if !self.oidc_audience.trim().is_empty() {
                self.oidc_audience.trim()
            } else {
                self.remote_url.trim().trim_end_matches('/')
            };
            let id_token =
                inarch_store::mint_service_account_id_token(&cred_path, token_uri_opt, target_aud)
                    .map_err(inarch_engine::EngineError::Store)?;
            return Ok((Some(id_token), effective_repo));
        }

        Ok((None, effective_repo))
    }

    /// Opens a [`inarch_store::RemoteRpcClient`] connected to `remote_url` with the active bearer token and `repo_id`.
    /// If `remote_url` is empty in the current directory's config, falls back to the user-global config
    /// (`~/.config/velenza-inarch/inarch.toml`) when present.
    pub fn open_remote_client(
        &self,
        workspace_root: &Path,
    ) -> Result<inarch_store::RemoteRpcClient, CliError> {
        let mut effective_cfg = self.clone();
        if effective_cfg.remote_url.trim().is_empty() {
            if let Some(global_path) = Self::user_global_config_path() {
                if global_path.is_file() {
                    if let Ok(global_cfg) = Self::load_from_file(&global_path) {
                        if !global_cfg.remote_url.trim().is_empty() {
                            effective_cfg.remote_url = global_cfg.remote_url;
                        }
                        if effective_cfg.auth_token.trim().is_empty()
                            && effective_cfg.gcp_credentials_file.trim().is_empty()
                        {
                            effective_cfg.auth_token = global_cfg.auth_token;
                            effective_cfg.gcp_credentials_file = global_cfg.gcp_credentials_file;
                            effective_cfg.oidc_token_uri = global_cfg.oidc_token_uri;
                        }
                        if effective_cfg.oidc_audience.trim().is_empty() {
                            effective_cfg.oidc_audience = global_cfg.oidc_audience;
                        }
                    }
                }
            }
        }

        if effective_cfg.remote_url.trim().is_empty() {
            return Err(CliError::InvalidArgument(
                "remote_url must be configured for remote Velenza Inarch commands".to_string(),
            ));
        }

        let (opt_token, effective_repo_id) =
            effective_cfg.resolve_effective_auth(workspace_root)?;
        inarch_store::RemoteRpcClient::new(effective_cfg.remote_url.trim(), opt_token)
            .map(|c| c.with_repo_id(&effective_repo_id))
            .map_err(|e| CliError::Engine(inarch_engine::EngineError::Store(e)))
    }

    /// Returns the default persistent client-side NVMe Tier-1 cache directory
    /// (`$INARCH_CACHE_DIR/t1`, `~/.cache/velenza-inarch/t1`, or `%LOCALAPPDATA%\velenza-inarch\cache\t1`).
    pub fn default_client_tier1_cache_dir() -> Option<PathBuf> {
        if let Ok(custom) = env::var("INARCH_CACHE_DIR") {
            let trimmed = custom.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed).join("t1"));
            }
        }
        #[cfg(windows)]
        {
            if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
                if !local_app_data.trim().is_empty() {
                    return Some(
                        PathBuf::from(local_app_data)
                            .join("velenza-inarch")
                            .join("cache")
                            .join("t1"),
                    );
                }
            }
            if let Ok(userprofile) = env::var("USERPROFILE") {
                if !userprofile.trim().is_empty() {
                    return Some(
                        PathBuf::from(userprofile)
                            .join(".cache")
                            .join("velenza-inarch")
                            .join("t1"),
                    );
                }
            }
        }
        #[cfg(not(windows))]
        {
            if let Ok(xdg) = env::var("XDG_CACHE_HOME") {
                if !xdg.trim().is_empty() {
                    return Some(PathBuf::from(xdg).join("velenza-inarch").join("t1"));
                }
            }
            if let Ok(home) = env::var("HOME") {
                if !home.trim().is_empty() {
                    return Some(
                        PathBuf::from(home)
                            .join(".cache")
                            .join("velenza-inarch")
                            .join("t1"),
                    );
                }
            }
        }
        None
    }

    /// Resolves the effective Tier-1 cache directory for client engines.
    ///
    /// - If `tier1_cache_dir` is `"none"` or `"memory"` (case-insensitive), returns `None` (in-memory only).
    /// - If `tier1_cache_dir` is explicitly set, resolves it relative to `workspace_root`.
    /// - If `tier1_cache_dir` is empty and the client is operating in remote mode (`!remote_url.is_empty()`
    ///   or `blob_backend == "remote"`), defaults to [`Self::default_client_tier1_cache_dir`] so immutable
    ///   blobs are persisted on local NVMe across CLI/MCP invocations with zero repeat GCP egress.
    /// - Otherwise (local mode with empty `tier1_cache_dir`), returns `None` to avoid duplicating local blobs.
    pub fn resolved_tier1_cache_dir(&self, workspace_root: &Path) -> Option<PathBuf> {
        let trimmed = self.tier1_cache_dir.trim();
        if trimmed.eq_ignore_ascii_case("none") || trimmed.eq_ignore_ascii_case("memory") {
            return None;
        }
        if !trimmed.is_empty() {
            return Some(resolve_maybe_relative(workspace_root, trimmed));
        }
        if !self.remote_url.trim().is_empty() || self.blob_backend.trim() == "remote" {
            return Self::default_client_tier1_cache_dir();
        }
        None
    }

    /// Opens a persistent [`ScionEngine`] backed by the configured 3-tier blob store and metadata store.
    pub fn open_engine(&self, workspace_root: &Path) -> Result<Arc<ScionEngine>, CliError> {
        self.validate_supported_acl_policy()?;
        let tier1: Arc<dyn BlobStore> = match self.resolved_tier1_cache_dir(workspace_root) {
            None => Arc::new(MemBlobStore::new()),
            Some(p) => Arc::new(FsBlobStore::new(p).map_err(inarch_engine::EngineError::Store)?),
        };

        let tier2: Arc<dyn BlobStore> = if self.tier2_cache_dir.trim().is_empty() {
            Arc::new(MemBlobStore::new())
        } else {
            let p = resolve_maybe_relative(workspace_root, &self.tier2_cache_dir);
            Arc::new(FsBlobStore::new(p).map_err(inarch_engine::EngineError::Store)?)
        };

        let effective_blob_backend = if (self.blob_backend == "local" || self.blob_backend == "fs")
            && !self.remote_url.trim().is_empty()
        {
            "remote"
        } else {
            self.blob_backend.trim()
        };

        let effective_meta_backend = if (self.meta_backend == "local" || self.meta_backend == "fs")
            && !self.remote_url.trim().is_empty()
        {
            "remote"
        } else {
            self.meta_backend.trim()
        };

        if effective_blob_backend == "remote" || effective_meta_backend == "remote" {
            RemoteRpcClient::validate_remote_url(self.remote_url.trim())
                .map_err(inarch_engine::EngineError::Store)?;
        }

        let (opt_token, effective_repo_id) =
            if effective_blob_backend == "remote" || effective_meta_backend == "remote" {
                self.resolve_effective_auth(workspace_root)?
            } else {
                let tok = if self.auth_token.trim().is_empty() {
                    None
                } else {
                    Some(self.auth_token.trim().to_string())
                };
                (tok, self.repo_id.trim().to_string())
            };

        let tier3: Arc<dyn BlobStore> = match effective_blob_backend {
            "local" | "fs" | "" => {
                let blobs_dir = self.resolved_blobs_dir(workspace_root);
                Arc::new(FsBlobStore::new(&blobs_dir).map_err(inarch_engine::EngineError::Store)?)
            }
            "gcs" => {
                if self.gcs_bucket.trim().is_empty() {
                    return Err(CliError::InvalidArgument(
                        "gcs_bucket must be configured when blob_backend = \"gcs\"".to_string(),
                    ));
                }
                Arc::new(
                    GcsBlobStore::new(self.gcs_bucket.trim(), self.gcs_prefix.trim())
                        .map_err(inarch_engine::EngineError::Store)?,
                )
            }
            "remote" => {
                if self.remote_url.trim().is_empty() {
                    return Err(CliError::InvalidArgument(
                        "remote_url must be configured when blob_backend = \"remote\"".to_string(),
                    ));
                }
                Arc::new(
                    RemoteBlobStore::new(self.remote_url.trim(), opt_token.clone())
                        .map(|b| b.with_repo_id(&effective_repo_id))
                        .map_err(inarch_engine::EngineError::Store)?,
                )
            }
            other => {
                return Err(CliError::InvalidArgument(format!(
                    "unsupported blob_backend '{}' (expected \"local\", \"fs\", \"gcs\", or \"remote\")",
                    other
                )));
            }
        };

        let tiered_blobs: Arc<dyn BlobStore> =
            Arc::new(TieredBlobStore::from_dyn(tier1, tier2, tier3));

        let meta: Arc<dyn MetadataStore> = match effective_meta_backend {
            "local" | "fs" | "" => {
                let meta_dir = self.resolved_meta_dir(workspace_root);
                let base: Arc<dyn MetadataStore> = Arc::new(
                    FsMetadataStore::new(&meta_dir).map_err(inarch_engine::EngineError::Store)?,
                );
                if effective_repo_id.is_empty() || effective_repo_id == "default" {
                    base
                } else {
                    Arc::new(ScopedMetadataStore::new(base, &effective_repo_id))
                }
            }
            "spanner" => {
                if self.spanner_database.trim().is_empty() {
                    return Err(CliError::InvalidArgument(
                        "spanner_database must be configured when meta_backend = \"spanner\""
                            .to_string(),
                    ));
                }
                Arc::new(
                    SpannerMetadataStore::new(self.spanner_database.trim(), &effective_repo_id)
                        .map_err(inarch_engine::EngineError::Store)?,
                )
            }
            "remote" => {
                if self.remote_url.trim().is_empty() {
                    return Err(CliError::InvalidArgument(
                        "remote_url must be configured when meta_backend = \"remote\"".to_string(),
                    ));
                }
                Arc::new(
                    RemoteMetadataStore::new(self.remote_url.trim(), opt_token, &effective_repo_id)
                        .map_err(inarch_engine::EngineError::Store)?,
                )
            }
            other => {
                return Err(CliError::InvalidArgument(format!(
                    "unsupported meta_backend '{}' (expected \"local\", \"fs\", \"spanner\", or \"remote\")",
                    other
                )));
            }
        };

        let telemetry = self.build_telemetry_sink(workspace_root)?;
        let engine = ScionEngine::with_telemetry(effective_repo_id, tiered_blobs, meta, telemetry);
        if !self.acl_rules.is_empty() {
            let rules = self
                .acl_rules
                .iter()
                .map(|r| inarch_engine::EnginePathAclRule {
                    prefix: r.prefix.clone(),
                    allowed_actors: r.allowed_actors.clone(),
                })
                .collect();
            engine.set_acl_rules(rules);
        }
        Ok(Arc::new(engine))
    }

    /// Opens the server-side [`BlobStore`] (wrapped in Tier-1/Tier-2 caches) and [`MetadataStore`]
    /// for `inr serve`.
    pub fn open_server_stores(
        &self,
        workspace_root: &Path,
    ) -> Result<(Arc<dyn BlobStore>, Arc<dyn MetadataStore>), CliError> {
        self.validate_supported_acl_policy()?;
        let tier1: Arc<dyn BlobStore> = if self.tier1_cache_dir.trim().is_empty() {
            Arc::new(MemBlobStore::new())
        } else {
            let p = resolve_maybe_relative(workspace_root, &self.tier1_cache_dir);
            Arc::new(FsBlobStore::new(p).map_err(inarch_engine::EngineError::Store)?)
        };

        let tier2: Arc<dyn BlobStore> = if self.tier2_cache_dir.trim().is_empty() {
            Arc::new(MemBlobStore::new())
        } else {
            let p = resolve_maybe_relative(workspace_root, &self.tier2_cache_dir);
            Arc::new(FsBlobStore::new(p).map_err(inarch_engine::EngineError::Store)?)
        };

        let tier3: Arc<dyn BlobStore> = match self.blob_backend.trim() {
            "local" | "fs" | "" => {
                let blobs_dir = self.resolved_blobs_dir(workspace_root);
                Arc::new(FsBlobStore::new(&blobs_dir).map_err(inarch_engine::EngineError::Store)?)
            }
            "gcs" => {
                if self.gcs_bucket.trim().is_empty() {
                    return Err(CliError::InvalidArgument(
                        "gcs_bucket must be configured when blob_backend = \"gcs\"".to_string(),
                    ));
                }
                Arc::new(
                    GcsBlobStore::new(self.gcs_bucket.trim(), self.gcs_prefix.trim())
                        .map_err(inarch_engine::EngineError::Store)?,
                )
            }
            other => {
                return Err(CliError::InvalidArgument(format!(
                    "unsupported server blob_backend '{}' (expected \"local\", \"fs\", or \"gcs\")",
                    other
                )));
            }
        };

        let blobs: Arc<dyn BlobStore> = Arc::new(TieredBlobStore::from_dyn(tier1, tier2, tier3));

        let meta: Arc<dyn MetadataStore> = match self.meta_backend.trim() {
            "local" | "fs" | "" => {
                let meta_dir = self.resolved_meta_dir(workspace_root);
                Arc::new(
                    FsMetadataStore::new(&meta_dir).map_err(inarch_engine::EngineError::Store)?,
                )
            }
            "spanner" => {
                if self.spanner_database.trim().is_empty() {
                    return Err(CliError::InvalidArgument(
                        "spanner_database must be configured when meta_backend = \"spanner\""
                            .to_string(),
                    ));
                }
                Arc::new(
                    SpannerMetadataStore::new(self.spanner_database.trim(), "default")
                        .map_err(inarch_engine::EngineError::Store)?,
                )
            }
            other => {
                return Err(CliError::InvalidArgument(format!(
                    "unsupported server meta_backend '{}' (expected \"local\", \"fs\", or \"spanner\")",
                    other
                )));
            }
        };

        Ok((blobs, meta))
    }

    /// Builds an Antique [`PathAclPolicy`] from the configured `[[acl_rules]]`.
    pub fn build_acl_policy(&self) -> Result<PathAclPolicy, CliError> {
        self.validate_supported_acl_policy()?;
        let mut policy = PathAclPolicy::new();
        for rule in &self.acl_rules {
            let trimmed = rule.prefix.trim().trim_matches('/');
            let prefix = if trimmed.is_empty() {
                None
            } else {
                Some(MPath::new(trimmed)?)
            };
            let allowed_actors: BTreeSet<String> = rule.allowed_actors.iter().cloned().collect();
            let required_reviewers: BTreeSet<String> =
                rule.required_reviewers.iter().cloned().collect();
            policy.add_rule(PathAclRule {
                prefix,
                allowed_actors,
                required_reviewers,
            });
        }
        Ok(policy)
    }

    fn validate_supported_acl_policy(&self) -> Result<(), CliError> {
        if let Some(rule) = self
            .acl_rules
            .iter()
            .find(|rule| !rule.required_reviewers.is_empty())
        {
            return Err(CliError::InvalidArgument(format!(
                "required_reviewers is unsupported because reviewer evidence enforcement is not implemented (ACL prefix {:?})",
                rule.prefix
            )));
        }
        Ok(())
    }

    /// Serializes this configuration into a documented TOML string.
    pub fn to_toml_string(&self) -> String {
        let mut out = String::new();
        out.push_str("# Velenza Inarch Configuration File (inarch.toml / .inarch/config.toml)\n");
        out.push_str(
            "# All environment-specific paths, identities, ignore lists, and ACL policies\n",
        );
        out.push_str("# are configured here rather than hardcoded in source code.\n\n");

        out.push_str("[repository]\n");
        out.push_str(&format!("repo_id = {}\n", quote_toml_str(&self.repo_id)));
        out.push_str(&format!(
            "default_ref = {}\n",
            quote_toml_str(&self.default_ref)
        ));
        out.push_str(&format!(
            "default_author = {}\n",
            quote_toml_str(&self.default_author)
        ));
        out.push_str(&format!("tz_offset_secs = {}\n", self.tz_offset_secs));
        out.push_str(&format!(
            "ignore_names = {}\n\n",
            format_toml_str_array(&self.ignore_names)
        ));

        out.push_str("[network]\n");
        out.push_str(&format!(
            "listen_addr = {}\n",
            quote_toml_str(&self.listen_addr)
        ));
        out.push_str(&format!(
            "remote_url = {}\n",
            quote_toml_str(&self.remote_url)
        ));
        out.push_str(&format!(
            "auth_token = {}\n",
            quote_toml_str(&self.auth_token)
        ));
        out.push_str(&format!(
            "gcp_credentials_file = {}\n",
            quote_toml_str(&self.gcp_credentials_file)
        ));
        out.push_str(&format!(
            "jit_lease_file = {}\n",
            quote_toml_str(&self.jit_lease_file)
        ));
        out.push_str(&format!(
            "jit_signing_key = {}\n",
            quote_toml_str(&self.jit_signing_key)
        ));
        out.push_str(&format!(
            "oidc_tokeninfo_url = {}\n",
            quote_toml_str(&self.oidc_tokeninfo_url)
        ));
        out.push_str(&format!(
            "oidc_token_uri = {}\n",
            quote_toml_str(&self.oidc_token_uri)
        ));
        out.push_str(&format!(
            "oidc_audience = {}\n\n",
            quote_toml_str(&self.oidc_audience)
        ));

        out.push_str("[storage]\n");
        out.push_str(&format!(
            "store_dir = {}\n",
            quote_toml_str(&self.store_dir)
        ));
        out.push_str(&format!(
            "blobs_subdir = {}\n",
            quote_toml_str(&self.blobs_subdir)
        ));
        out.push_str(&format!(
            "meta_subdir = {}\n",
            quote_toml_str(&self.meta_subdir)
        ));
        out.push_str(&format!(
            "tier1_cache_dir = {}\n",
            quote_toml_str(&self.tier1_cache_dir)
        ));
        out.push_str(&format!(
            "tier2_cache_dir = {}\n",
            quote_toml_str(&self.tier2_cache_dir)
        ));
        out.push_str(&format!(
            "blob_backend = {}\n",
            quote_toml_str(&self.blob_backend)
        ));
        out.push_str(&format!(
            "gcs_bucket = {}\n",
            quote_toml_str(&self.gcs_bucket)
        ));
        out.push_str(&format!(
            "gcs_prefix = {}\n",
            quote_toml_str(&self.gcs_prefix)
        ));
        out.push_str(&format!(
            "meta_backend = {}\n",
            quote_toml_str(&self.meta_backend)
        ));
        out.push_str(&format!(
            "spanner_database = {}\n\n",
            quote_toml_str(&self.spanner_database)
        ));

        out.push_str("[chunking]\n");
        out.push_str(&format!("min_size = {}\n", self.chunk_min_size));
        out.push_str(&format!("avg_size = {}\n", self.chunk_avg_size));
        out.push_str(&format!("max_size = {}\n\n", self.chunk_max_size));

        out.push_str("[telemetry]\n");
        out.push_str(&format!(
            "log_backend = {}\n",
            quote_toml_str(&self.log_backend)
        ));
        out.push_str(&format!(
            "log_level = {}\n",
            quote_toml_str(&self.log_level)
        ));
        out.push_str(&format!("log_file = {}\n", quote_toml_str(&self.log_file)));
        out.push_str(&format!(
            "gcp_log_name = {}\n",
            quote_toml_str(&self.gcp_log_name)
        ));

        for rule in &self.acl_rules {
            out.push_str("\n[[acl_rules]]\n");
            out.push_str(&format!("prefix = {}\n", quote_toml_str(&rule.prefix)));
            out.push_str(&format!(
                "allowed_actors = {}\n",
                format_toml_str_array(&rule.allowed_actors)
            ));
            out.push_str(&format!(
                "required_reviewers = {}\n",
                format_toml_str_array(&rule.required_reviewers)
            ));
        }

        out
    }

    /// Parses an [`InarchConfig`] from a TOML string.
    pub fn from_toml_str(input: &str) -> Result<Self, CliError> {
        let mut cfg = Self::default();
        let mut current_section = String::new();
        let mut current_acl: Option<AclRuleConfig> = None;

        for (line_idx, raw_line) in input.lines().enumerate() {
            let line = strip_toml_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            if line == "[[acl_rules]]" {
                if let Some(prev) = current_acl.take() {
                    cfg.acl_rules.push(prev);
                }
                current_section = "acl_rules".to_string();
                current_acl = Some(AclRuleConfig {
                    prefix: String::new(),
                    allowed_actors: Vec::new(),
                    required_reviewers: Vec::new(),
                });
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                if let Some(prev) = current_acl.take() {
                    cfg.acl_rules.push(prev);
                }
                current_section = line[1..line.len() - 1].trim().to_string();
                continue;
            }

            let Some((raw_key, raw_val)) = line.split_once('=') else {
                return Err(CliError::InvalidArgument(format!(
                    "config syntax error on line {}: expected `key = value`",
                    line_idx + 1
                )));
            };
            let key = raw_key.trim();
            let val = raw_val.trim();

            match (current_section.as_str(), key) {
                ("repository" | "", "repo_id") => {
                    cfg.repo_id = parse_toml_str(val, line_idx + 1)?;
                }
                ("repository" | "", "default_ref") => {
                    cfg.default_ref = parse_toml_str(val, line_idx + 1)?;
                }
                ("repository" | "", "default_author") => {
                    cfg.default_author = parse_toml_str(val, line_idx + 1)?;
                }
                ("repository" | "", "tz_offset_secs") => {
                    cfg.tz_offset_secs = val.parse::<i32>().map_err(|_| {
                        CliError::InvalidArgument(format!(
                            "invalid integer for tz_offset_secs on line {}",
                            line_idx + 1
                        ))
                    })?;
                }
                ("repository" | "", "ignore_names") => {
                    cfg.ignore_names = parse_toml_str_array(val, line_idx + 1)?;
                }
                ("network" | "auth" | "", "listen_addr") => {
                    cfg.listen_addr = parse_toml_str(val, line_idx + 1)?;
                }
                ("network" | "auth" | "", "remote_url") => {
                    cfg.remote_url = parse_toml_str(val, line_idx + 1)?;
                }
                ("network" | "auth" | "", "auth_token") => {
                    cfg.auth_token = parse_toml_str(val, line_idx + 1)?;
                }
                ("network" | "auth" | "", "gcp_credentials_file") => {
                    cfg.gcp_credentials_file = parse_toml_str(val, line_idx + 1)?;
                }
                ("network" | "auth" | "", "jit_lease_file") => {
                    cfg.jit_lease_file = parse_toml_str(val, line_idx + 1)?;
                }
                ("network" | "auth" | "", "jit_signing_key") => {
                    cfg.jit_signing_key = parse_toml_str(val, line_idx + 1)?;
                }
                ("network" | "auth" | "", "oidc_tokeninfo_url") => {
                    cfg.oidc_tokeninfo_url = parse_toml_str(val, line_idx + 1)?;
                }
                ("network" | "auth" | "", "oidc_token_uri") => {
                    cfg.oidc_token_uri = parse_toml_str(val, line_idx + 1)?;
                }
                ("network" | "auth" | "", "oidc_audience") => {
                    cfg.oidc_audience = parse_toml_str(val, line_idx + 1)?;
                }
                ("storage" | "", "store_dir") => {
                    cfg.store_dir = parse_toml_str(val, line_idx + 1)?;
                }
                ("storage" | "", "blobs_subdir") => {
                    cfg.blobs_subdir = parse_toml_str(val, line_idx + 1)?;
                }
                ("storage" | "", "meta_subdir") => {
                    cfg.meta_subdir = parse_toml_str(val, line_idx + 1)?;
                }
                ("storage" | "", "tier1_cache_dir") => {
                    cfg.tier1_cache_dir = parse_toml_str(val, line_idx + 1)?;
                }
                ("storage" | "", "tier2_cache_dir") => {
                    cfg.tier2_cache_dir = parse_toml_str(val, line_idx + 1)?;
                }
                ("storage" | "", "blob_backend") => {
                    cfg.blob_backend = parse_toml_str(val, line_idx + 1)?;
                }
                ("storage" | "", "gcs_bucket") => {
                    cfg.gcs_bucket = parse_toml_str(val, line_idx + 1)?;
                }
                ("storage" | "", "gcs_prefix") => {
                    cfg.gcs_prefix = parse_toml_str(val, line_idx + 1)?;
                }
                ("storage" | "", "meta_backend") => {
                    cfg.meta_backend = parse_toml_str(val, line_idx + 1)?;
                }
                ("storage" | "", "spanner_database") => {
                    cfg.spanner_database = parse_toml_str(val, line_idx + 1)?;
                }
                ("chunking" | "", "min_size") => {
                    cfg.chunk_min_size = val.parse::<usize>().map_err(|_| {
                        CliError::InvalidArgument(format!(
                            "invalid integer for min_size on line {}",
                            line_idx + 1
                        ))
                    })?;
                }
                ("chunking" | "", "avg_size") => {
                    cfg.chunk_avg_size = val.parse::<usize>().map_err(|_| {
                        CliError::InvalidArgument(format!(
                            "invalid integer for avg_size on line {}",
                            line_idx + 1
                        ))
                    })?;
                }
                ("chunking" | "", "max_size") => {
                    cfg.chunk_max_size = val.parse::<usize>().map_err(|_| {
                        CliError::InvalidArgument(format!(
                            "invalid integer for max_size on line {}",
                            line_idx + 1
                        ))
                    })?;
                }
                ("telemetry" | "", "log_backend") => {
                    cfg.log_backend = parse_toml_str(val, line_idx + 1)?;
                }
                ("telemetry" | "", "log_level") => {
                    cfg.log_level = parse_toml_str(val, line_idx + 1)?;
                }
                ("telemetry" | "", "log_file") => {
                    cfg.log_file = parse_toml_str(val, line_idx + 1)?;
                }
                ("telemetry" | "", "gcp_log_name") => {
                    cfg.gcp_log_name = parse_toml_str(val, line_idx + 1)?;
                }
                ("acl_rules", "prefix") => {
                    if let Some(rule) = current_acl.as_mut() {
                        rule.prefix = parse_toml_str(val, line_idx + 1)?;
                    }
                }
                ("acl_rules", "allowed_actors") => {
                    if let Some(rule) = current_acl.as_mut() {
                        rule.allowed_actors = parse_toml_str_array(val, line_idx + 1)?;
                    }
                }
                ("acl_rules", "required_reviewers") => {
                    if let Some(rule) = current_acl.as_mut() {
                        rule.required_reviewers = parse_toml_str_array(val, line_idx + 1)?;
                    }
                }
                (sec, k) => {
                    return Err(CliError::InvalidArgument(format!(
                        "unknown config key '{}' in section '[{}]' on line {}",
                        k,
                        sec,
                        line_idx + 1
                    )));
                }
            }
        }

        if let Some(prev) = current_acl.take() {
            cfg.acl_rules.push(prev);
        }

        cfg.validate_supported_acl_policy()?;
        Ok(cfg)
    }
}

fn resolve_maybe_relative(workspace_root: &Path, path_str: &str) -> PathBuf {
    if let Some(rest) = path_str
        .strip_prefix("~/")
        .or_else(|| path_str.strip_prefix("~\\"))
    {
        if let Some(home) = env::var("HOME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                env::var("USERPROFILE")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
            })
        {
            return PathBuf::from(home).join(rest);
        }
    }
    let p = Path::new(path_str);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        workspace_root.join(p)
    }
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if ch == '#' && !in_quotes {
            return &line[..i];
        }
    }
    line
}

fn quote_toml_str(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

fn format_toml_str_array(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| quote_toml_str(s)).collect();
    format!("[{}]", quoted.join(", "))
}

fn parse_toml_str(val: &str, line_num: usize) -> Result<String, CliError> {
    let v = val.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        let inner = &v[1..v.len() - 1];
        Ok(inner.replace("\\\"", "\"").replace("\\\\", "\\"))
    } else {
        Err(CliError::InvalidArgument(format!(
            "expected quoted string on line {}, found '{}'",
            line_num, val
        )))
    }
}

fn parse_toml_str_array(val: &str, line_num: usize) -> Result<Vec<String>, CliError> {
    let v = val.trim();
    if !v.starts_with('[') || !v.ends_with(']') {
        return Err(CliError::InvalidArgument(format!(
            "expected '[...]' array on line {}, found '{}'",
            line_num, val
        )));
    }
    let inner = v[1..v.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            current.push(ch);
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            current.push(ch);
            continue;
        }
        if ch == ',' && !in_quotes {
            let trimmed = current.trim();
            if !trimmed.is_empty() {
                out.push(parse_toml_str(trimmed, line_num)?);
            }
            current.clear();
        } else {
            current.push(ch);
        }
    }
    let tail = current.trim();
    if !tail.is_empty() {
        out.push(parse_toml_str(tail, line_num)?);
    }
    Ok(out)
}
