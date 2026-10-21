//! Structured logging and telemetry subsystem for Velenza Inarch.
//!
//! Provides zero-dependency structured telemetry sinks for:
//! - Local JSON Lines (`.inarch/logs/inarch.jsonl`) via [`JsonlFileTelemetrySink`]
//! - Standard error stream via [`StderrTelemetrySink`]
//! - Google Cloud Logging (`StructuredLogEntry` JSON + optional Cloud Logging REST API) via [`GcpCloudLoggingSink`]
//! - In-memory event capture for diagnostics and testing via [`MemoryTelemetrySink`]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::StoreError;

/// Maximum number of formatted audit/telemetry entries retained in memory by [`GcpCloudLoggingSink`].
pub const MAX_BUFFERED_AUDIT_EVENTS: usize = 256;

/// Dynamic token provider callback used by [`GcpCloudLoggingSink`] to resolve fresh bearer tokens.
pub type TokenProviderFn = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// Severity level for structured telemetry events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    /// Google Cloud Logging `LogSeverity` canonical string.
    pub const fn gcp_severity(self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARNING",
            LogLevel::Error => "ERROR",
        }
    }

    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "warn" | "warning" => Some(LogLevel::Warn),
            "error" | "err" => Some(LogLevel::Error),
            _ => None,
        }
    }
}

/// Returns current UNIX epoch timestamp in milliseconds.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A structured telemetry / audit event emitted by Inarch subsystems.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryEvent {
    pub timestamp_unix_ms: u64,
    pub level: LogLevel,
    pub component: String,
    pub operation: String,
    pub repo_id: String,
    pub changeset_id: Option<String>,
    pub duration_us: Option<u64>,
    pub message: String,
    pub attributes: BTreeMap<String, String>,
}

impl TelemetryEvent {
    pub fn new(
        level: LogLevel,
        component: impl Into<String>,
        operation: impl Into<String>,
        repo_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_unix_ms: now_unix_ms(),
            level,
            component: component.into(),
            operation: operation.into(),
            repo_id: repo_id.into(),
            changeset_id: None,
            duration_us: None,
            message: message.into(),
            attributes: BTreeMap::new(),
        }
    }

    pub fn info(
        component: impl Into<String>,
        operation: impl Into<String>,
        repo_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(LogLevel::Info, component, operation, repo_id, message)
    }

    pub fn with_changeset(mut self, changeset_id: impl Into<String>) -> Self {
        self.changeset_id = Some(changeset_id.into());
        self
    }

    pub fn with_duration_us(mut self, duration_us: u64) -> Self {
        self.duration_us = Some(duration_us);
        self
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Formats this event as a single-line JSON object suitable for `.inarch/logs/inarch.jsonl`.
    pub fn to_json_line(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');
        out.push_str(&format!(
            "\"timestamp_unix_ms\":{},\"level\":\"{}\",\"component\":\"{}\",\"operation\":\"{}\",\"repo_id\":\"{}\"",
            self.timestamp_unix_ms,
            self.level.as_str(),
            escape_json(&self.component),
            escape_json(&self.operation),
            escape_json(&self.repo_id),
        ));
        if let Some(cs) = &self.changeset_id {
            out.push_str(&format!(",\"changeset_id\":\"{}\"", escape_json(cs)));
        }
        if let Some(dur) = self.duration_us {
            out.push_str(&format!(",\"duration_us\":{dur}"));
        }
        out.push_str(&format!(",\"message\":\"{}\"", escape_json(&self.message)));
        if !self.attributes.is_empty() {
            out.push_str(",\"attributes\":{");
            for (idx, (k, v)) in self.attributes.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&format!("\"{}\":\"{}\"", escape_json(k), escape_json(v)));
            }
            out.push('}');
        }
        out.push('}');
        out
    }

    /// Formats this event as a Google Cloud Logging `StructuredLogEntry` JSON line.
    ///
    /// Includes `severity`, `logName`, `resource`, `logging.googleapis.com/labels`,
    /// `logging.googleapis.com/operation`, `message`, and `jsonPayload`.
    pub fn to_gcp_structured_entry(&self, log_name: &str, resource_type: &str) -> String {
        let secs = self.timestamp_unix_ms / 1000;
        let nanos = (self.timestamp_unix_ms % 1000) * 1_000_000;
        let mut out = String::with_capacity(384);
        out.push('{');
        out.push_str(&format!(
            "\"severity\":\"{}\",\"logName\":\"{}\",\"timestamp\":{{\"seconds\":{},\"nanos\":{}}}",
            self.level.gcp_severity(),
            escape_json(log_name),
            secs,
            nanos,
        ));
        out.push_str(&format!(
            ",\"resource\":{{\"type\":\"{}\",\"labels\":{{\"repo_id\":\"{}\"}}}}",
            escape_json(resource_type),
            escape_json(&self.repo_id),
        ));
        out.push_str(&format!(
            ",\"logging.googleapis.com/labels\":{{\"component\":\"{}\",\"operation\":\"{}\",\"repo_id\":\"{}\"",
            escape_json(&self.component),
            escape_json(&self.operation),
            escape_json(&self.repo_id),
        ));
        if let Some(cs) = &self.changeset_id {
            out.push_str(&format!(",\"changeset_id\":\"{}\"", escape_json(cs)));
        }
        out.push('}');
        out.push_str(&format!(
            ",\"logging.googleapis.com/operation\":{{\"id\":\"{}\",\"producer\":\"velenza-inarch/{}\"}}",
            escape_json(self.changeset_id.as_deref().unwrap_or(&self.operation)),
            escape_json(&self.component),
        ));
        out.push_str(&format!(",\"message\":\"{}\"", escape_json(&self.message)));
        out.push_str(",\"jsonPayload\":{");
        out.push_str(&format!(
            "\"component\":\"{}\",\"operation\":\"{}\",\"repo_id\":\"{}\"",
            escape_json(&self.component),
            escape_json(&self.operation),
            escape_json(&self.repo_id),
        ));
        if let Some(cs) = &self.changeset_id {
            out.push_str(&format!(",\"changeset_id\":\"{}\"", escape_json(cs)));
        }
        if let Some(dur) = self.duration_us {
            out.push_str(&format!(",\"duration_us\":{dur}"));
        }
        if !self.attributes.is_empty() {
            out.push_str(",\"attributes\":{");
            for (idx, (k, v)) in self.attributes.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&format!("\"{}\":\"{}\"", escape_json(k), escape_json(v)));
            }
            out.push('}');
        }
        out.push_str("}}");
        out
    }
}

/// Pluggable sink for structured telemetry events.
pub trait TelemetrySink: Send + Sync {
    fn emit(&self, event: &TelemetryEvent);
}

/// No-op telemetry sink with zero runtime overhead.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTelemetrySink;

impl TelemetrySink for NoopTelemetrySink {
    #[inline]
    fn emit(&self, _event: &TelemetryEvent) {}
}

/// In-memory telemetry sink for diagnostics and unit/integration testing.
#[derive(Debug, Default)]
pub struct MemoryTelemetrySink {
    events: Mutex<Vec<TelemetryEvent>>,
}

impl MemoryTelemetrySink {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn events(&self) -> Vec<TelemetryEvent> {
        self.events.lock().expect("telemetry mutex").clone()
    }
}

impl TelemetrySink for MemoryTelemetrySink {
    fn emit(&self, event: &TelemetryEvent) {
        self.events
            .lock()
            .expect("telemetry mutex")
            .push(event.clone());
    }
}

/// Appends structured JSON Lines events to a local file (e.g. `.inarch/logs/inarch.jsonl`).
pub struct JsonlFileTelemetrySink {
    path: PathBuf,
    min_level: LogLevel,
    file: Mutex<File>,
}

impl JsonlFileTelemetrySink {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::with_min_level(path, LogLevel::Info)
    }

    pub fn with_min_level(path: impl AsRef<Path>, min_level: LogLevel) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|e| StoreError::Io(format!("create log dir {parent:?}: {e}")))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| StoreError::Io(format!("open log file {path:?}: {e}")))?;
        Ok(Self {
            path,
            min_level,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl TelemetrySink for JsonlFileTelemetrySink {
    fn emit(&self, event: &TelemetryEvent) {
        if event.level < self.min_level {
            return;
        }
        let mut line = event.to_json_line();
        line.push('\n');
        if let Ok(mut guard) = self.file.lock() {
            let _ = guard.write_all(line.as_bytes());
            let _ = guard.flush();
        }
    }
}

/// Writes structured JSON Lines events to standard error (`stderr`).
#[derive(Debug, Clone)]
pub struct StderrTelemetrySink {
    pub min_level: LogLevel,
}

impl StderrTelemetrySink {
    pub fn new(min_level: LogLevel) -> Self {
        Self { min_level }
    }
}

impl TelemetrySink for StderrTelemetrySink {
    fn emit(&self, event: &TelemetryEvent) {
        if event.level < self.min_level {
            return;
        }
        eprintln!("{}", event.to_json_line());
    }
}

/// Google Cloud Logging structured telemetry sink.
///
/// Formats events into canonical `StructuredLogEntry` JSON compatible with:
/// - Cloud Run / GKE / Cloud Logging structured JSON agent collection
/// - Optional direct REST API shipping (`https://logging.googleapis.com/v2/entries:write`)
///   when `bearer_token` or a dynamic `token_provider` is supplied.
pub struct GcpCloudLoggingSink {
    pub log_name: String,
    pub resource_type: String,
    pub min_level: LogLevel,
    pub emit_to_stderr: bool,
    pub bearer_token: Option<String>,
    pub token_provider: Option<TokenProviderFn>,
    pub api_endpoint: String,
    pub local_mirror_file: Option<Mutex<File>>,
    buffer: Mutex<Vec<String>>,
}

impl GcpCloudLoggingSink {
    /// Validates that `log_name` is a canonical Cloud Logging resource path of the form
    /// `projects/<project>/logs/<log>` where neither `<project>` nor `<log>` is empty,
    /// `"default"`, or a `"REPLACE_WITH..."` placeholder.
    pub fn validate_log_name(log_name: &str) -> Result<(), String> {
        let trimmed = log_name.trim();
        let Some(rest) = trimmed.strip_prefix("projects/") else {
            return Err(format!(
                "invalid Cloud Logging log_name {:?}: must match 'projects/<project>/logs/<log>'",
                log_name
            ));
        };
        let Some((project, log_id)) = rest.split_once("/logs/") else {
            return Err(format!(
                "invalid Cloud Logging log_name {:?}: missing '/logs/<log>' segment",
                log_name
            ));
        };
        if project.is_empty() || project.contains('/') {
            return Err(format!(
                "invalid Cloud Logging log_name {:?}: project segment must be non-empty",
                log_name
            ));
        }
        if project.eq_ignore_ascii_case("default")
            || project.starts_with("REPLACE_WITH")
            || project.contains("REPLACE_WITH")
        {
            return Err(format!(
                "invalid Cloud Logging log_name {:?}: placeholder project {:?} is not allowed",
                log_name, project
            ));
        }
        if log_id.is_empty()
            || log_id.starts_with('/')
            || log_id.ends_with('/')
            || log_id.starts_with("REPLACE_WITH")
        {
            return Err(format!(
                "invalid Cloud Logging log_name {:?}: log segment must be non-empty and not a placeholder",
                log_name
            ));
        }
        Ok(())
    }

    fn extract_project_id(log_name: &str) -> &str {
        log_name
            .trim()
            .strip_prefix("projects/")
            .and_then(|rest| rest.split_once("/logs/"))
            .map(|(proj, _)| proj)
            .unwrap_or("")
    }

    /// Creates a GCP Cloud Logging sink that buffers formatted entries in memory (for testing/inspection).
    pub fn new_buffer_only(log_name: impl Into<String>, resource_type: impl Into<String>) -> Self {
        Self {
            log_name: log_name.into(),
            resource_type: resource_type.into(),
            min_level: LogLevel::Info,
            emit_to_stderr: false,
            bearer_token: None,
            token_provider: None,
            api_endpoint: "https://logging.googleapis.com/v2/entries:write".to_string(),
            local_mirror_file: None,
            buffer: Mutex::new(Vec::new()),
        }
    }

    /// Creates a production GCP Cloud Logging sink with optional local JSONL mirror and REST API token.
    pub fn new(
        log_name: impl Into<String>,
        resource_type: impl Into<String>,
        min_level: LogLevel,
        emit_to_stderr: bool,
        local_mirror_path: Option<&Path>,
        bearer_token: Option<String>,
    ) -> Result<Self, StoreError> {
        let local_mirror_file = if let Some(path) = local_mirror_path {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)
                    .map_err(|e| StoreError::Io(format!("create gcp log mirror dir: {e}")))?;
            }
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| StoreError::Io(format!("open gcp log mirror file: {e}")))?;
            Some(Mutex::new(f))
        } else {
            None
        };
        Ok(Self {
            log_name: log_name.into(),
            resource_type: resource_type.into(),
            min_level,
            emit_to_stderr,
            bearer_token,
            token_provider: None,
            api_endpoint: "https://logging.googleapis.com/v2/entries:write".to_string(),
            local_mirror_file,
            buffer: Mutex::new(Vec::new()),
        })
    }

    /// Configures a dynamic bearer token provider callback so rotated/refreshed tokens are used on each write.
    pub fn with_token_provider(mut self, provider: TokenProviderFn) -> Self {
        self.token_provider = Some(provider);
        self
    }

    /// Overrides the Cloud Logging `entries:write` endpoint (useful for local mock testing).
    pub fn with_api_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.api_endpoint = endpoint.into();
        self
    }

    /// Resolves the active bearer token from the dynamic `token_provider` (if configured) or static `bearer_token`.
    pub fn resolve_bearer_token(&self) -> Option<String> {
        if let Some(ref provider) = self.token_provider
            && let Some(tok) = provider()
            && !tok.trim().is_empty()
        {
            return Some(tok);
        }
        self.bearer_token
            .as_ref()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    }

    /// Formats an event as a canonical Cloud Logging v2 `entries:write` request payload (`LogEntry`).
    pub fn format_cloud_logging_payload(&self, event: &TelemetryEvent) -> String {
        let project_id = Self::extract_project_id(&self.log_name);
        let mut json_payload = String::with_capacity(256);
        json_payload.push('{');
        json_payload.push_str(&format!("\"message\":\"{}\",", escape_json(&event.message)));
        json_payload.push_str(&format!(
            "\"component\":\"{}\",",
            escape_json(&event.component)
        ));
        json_payload.push_str(&format!(
            "\"operation\":\"{}\",",
            escape_json(&event.operation)
        ));
        json_payload.push_str(&format!("\"repo_id\":\"{}\"", escape_json(&event.repo_id)));
        if let Some(d) = event.duration_us {
            json_payload.push_str(&format!(",\"duration_us\":{}", d));
        }
        if let Some(ref cs) = event.changeset_id {
            json_payload.push_str(&format!(",\"changeset_id\":\"{}\"", escape_json(cs)));
        }
        if !event.attributes.is_empty() {
            json_payload.push_str(",\"attributes\":{");
            let mut first = true;
            for (k, v) in &event.attributes {
                if !first {
                    json_payload.push(',');
                }
                first = false;
                json_payload.push_str(&format!("\"{}\":\"{}\"", escape_json(k), escape_json(v)));
            }
            json_payload.push('}');
        }
        json_payload.push('}');

        let mut labels_json = String::with_capacity(128);
        labels_json.push_str(&format!(
            "{{\"repo_id\":\"{}\",\"component\":\"{}\",\"operation\":\"{}\"",
            escape_json(&event.repo_id),
            escape_json(&event.component),
            escape_json(&event.operation)
        ));
        for (k, v) in &event.attributes {
            labels_json.push_str(&format!(",\"{}\":\"{}\"", escape_json(k), escape_json(v)));
        }
        labels_json.push('}');

        let secs = event.timestamp_unix_ms / 1000;
        let nanos = (event.timestamp_unix_ms % 1000) * 1_000_000;
        let timestamp = format!("{secs}.{nanos:09}Z");

        format!(
            "{{\"logName\":\"{}\",\"resource\":{{\"type\":\"{}\",\"labels\":{{\"project_id\":\"{}\"}}}},\"entries\":[{{\"severity\":\"{}\",\"timestamp\":\"{}\",\"labels\":{},\"jsonPayload\":{}}}]}}",
            escape_json(&self.log_name),
            escape_json(&self.resource_type),
            escape_json(project_id),
            event.level.gcp_severity(),
            timestamp,
            labels_json,
            json_payload
        )
    }

    /// Builds the `curl` argv and `--config -` stdin payload so the bearer token is never exposed in process arguments (`ps aux`).
    pub fn build_curl_write_args_and_stdin(
        &self,
        token: &str,
        body: &str,
    ) -> (Vec<String>, String) {
        let args = vec![
            "-sS".to_string(),
            "--max-time".to_string(),
            "5".to_string(),
            "--config".to_string(),
            "-".to_string(),
        ];
        let mut cfg = String::with_capacity(body.len() + 256);
        cfg.push_str(&format!(
            "url = \"{}\"\n",
            escape_curl_config_line(&self.api_endpoint)
        ));
        cfg.push_str("request = \"POST\"\n");
        cfg.push_str(&format!(
            "header = \"Authorization: Bearer {}\"\n",
            escape_curl_config_line(token)
        ));
        cfg.push_str("header = \"Content-Type: application/json\"\n");
        cfg.push_str(&format!("data = \"{}\"\n", escape_curl_config_line(body)));
        (args, cfg)
    }

    /// Returns all formatted `StructuredLogEntry` payloads captured in memory (up to [`MAX_BUFFERED_AUDIT_EVENTS`]).
    pub fn formatted_entries(&self) -> Vec<String> {
        self.buffer.lock().expect("gcp buffer mutex").clone()
    }
}

impl TelemetrySink for GcpCloudLoggingSink {
    fn emit(&self, event: &TelemetryEvent) {
        if event.level < self.min_level {
            return;
        }
        let structured = event.to_gcp_structured_entry(&self.log_name, &self.resource_type);
        if let Ok(mut buf) = self.buffer.lock() {
            while buf.len() >= MAX_BUFFERED_AUDIT_EVENTS {
                buf.remove(0);
            }
            buf.push(structured.clone());
        }
        if self.emit_to_stderr {
            eprintln!("{structured}");
        }
        if let Some(file_mutex) = &self.local_mirror_file
            && let Ok(mut f) = file_mutex.lock()
        {
            let _ = writeln!(f, "{structured}");
            let _ = f.flush();
        }
        if let Some(token) = self.resolve_bearer_token()
            && Self::validate_log_name(&self.log_name).is_ok()
        {
            let body = self.format_cloud_logging_payload(event);
            let (args, stdin_cfg) = self.build_curl_write_args_and_stdin(&token, &body);
            if let Ok(mut child) = Command::new("curl")
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(stdin_cfg.as_bytes());
                }
                let _ = child.wait();
            }
        }
    }
}

/// Multiplexes telemetry events across multiple sinks.
#[derive(Default)]
pub struct MultiTelemetrySink {
    sinks: Vec<Arc<dyn TelemetrySink>>,
}

impl MultiTelemetrySink {
    pub fn new(sinks: Vec<Arc<dyn TelemetrySink>>) -> Self {
        Self { sinks }
    }
}

impl TelemetrySink for MultiTelemetrySink {
    fn emit(&self, event: &TelemetryEvent) {
        for sink in &self.sinks {
            sink.emit(event);
        }
    }
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn escape_curl_config_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_gcp_cloud_logging_sink_bounded_buffer_cap() {
        let sink =
            GcpCloudLoggingSink::new_buffer_only("projects/velenza-audit/logs/inarch", "global");
        for i in 0..300 {
            let ev = TelemetryEvent::new(
                LogLevel::Info,
                "inarch-store",
                "audit_event",
                "repo-a",
                format!("event-{i}"),
            );
            sink.emit(&ev);
        }
        let entries = sink.formatted_entries();
        assert_eq!(entries.len(), MAX_BUFFERED_AUDIT_EVENTS);
        // Oldest 44 entries (0..44) were evicted; entry[0] is event-44 and last is event-299.
        assert!(entries[0].contains("\"message\":\"event-44\""));
        assert!(entries[MAX_BUFFERED_AUDIT_EVENTS - 1].contains("\"message\":\"event-299\""));
    }

    #[test]
    fn test_validate_log_name_rejects_invalid_and_placeholder_names() {
        assert!(
            GcpCloudLoggingSink::validate_log_name("projects/velenza-audit/logs/inarch-events")
                .is_ok()
        );
        assert!(GcpCloudLoggingSink::validate_log_name("").is_err());
        assert!(GcpCloudLoggingSink::validate_log_name("velenza-audit/logs/inarch").is_err());
        assert!(GcpCloudLoggingSink::validate_log_name("projects//logs/inarch").is_err());
        assert!(GcpCloudLoggingSink::validate_log_name("projects/velenza-audit/logs/").is_err());
        assert!(
            GcpCloudLoggingSink::validate_log_name("projects/default/logs/inarch-events").is_err()
        );
        assert!(
            GcpCloudLoggingSink::validate_log_name(
                "projects/REPLACE_WITH_GCP_PROJECT/logs/inarch-events"
            )
            .is_err()
        );
    }

    #[test]
    fn test_format_cloud_logging_payload_and_curl_config_hide_bearer_token() {
        let counter = Arc::new(AtomicUsize::new(1));
        let counter_clone = counter.clone();
        let sink = GcpCloudLoggingSink::new_buffer_only(
            "projects/velenza-audit/logs/inarch-security",
            "global",
        )
        .with_token_provider(Arc::new(move || {
            let n = counter_clone.fetch_add(1, Ordering::SeqCst);
            Some(format!("dynamic-secret-token-{n}"))
        }));

        // Verify dynamic token provider resolves fresh tokens on each call.
        assert_eq!(
            sink.resolve_bearer_token().as_deref(),
            Some("dynamic-secret-token-1")
        );
        assert_eq!(
            sink.resolve_bearer_token().as_deref(),
            Some("dynamic-secret-token-2")
        );

        let ev = TelemetryEvent::new(
            LogLevel::Warn,
            "inarch-rpc",
            "revoke_lease",
            "repo-sec",
            "lease revoked by admin",
        )
        .with_attr("lease_id", "lease-42");

        let payload = sink.format_cloud_logging_payload(&ev);
        assert!(payload.contains("\"logName\":\"projects/velenza-audit/logs/inarch-security\""));
        assert!(payload.contains(
            "\"resource\":{\"type\":\"global\",\"labels\":{\"project_id\":\"velenza-audit\"}}"
        ));
        assert!(payload.contains("\"severity\":\"WARNING\""));
        assert!(payload.contains("\"jsonPayload\":{\"message\":\"lease revoked by admin\""));
        assert!(payload.contains("\"lease_id\":\"lease-42\""));

        let (args, stdin_cfg) =
            sink.build_curl_write_args_and_stdin("super-secret-bearer-xyz", &payload);
        for arg in &args {
            assert!(
                !arg.contains("super-secret-bearer-xyz") && !arg.contains("Authorization"),
                "curl argv must never contain bearer token or Authorization header, got arg: {arg}"
            );
        }
        assert_eq!(args, vec!["-sS", "--max-time", "5", "--config", "-"]);
        assert!(stdin_cfg.contains("header = \"Authorization: Bearer super-secret-bearer-xyz\""));
        assert!(stdin_cfg.contains("url = \"https://logging.googleapis.com/v2/entries:write\""));
    }
}
