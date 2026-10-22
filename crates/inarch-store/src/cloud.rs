//! Generic Cloud Storage (`GcsBlobStore`) and Cloud Spanner (`SpannerMetadataStore`)
//! backends for Velenza Inarch.
//!
//! 100% open-source and vendor-clean: all project, instance, database, and bucket
//! coordinates are supplied dynamically via `InarchConfig` (`inarch.toml` or `INARCH_*`).
//! Passes OAuth2 Bearer tokens to `curl --config -` via `stdin` so credentials are
//! never exposed in process arguments (`ps`).

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use inarch_types::bonsai::BonsaiChangeset;
use inarch_types::hash::{ChangesetId, ObjectDomain, ObjectHash};

use crate::{
    BlobStore, DerivedDataKind, JitLeaseRecord, MetadataStore, PrincipalRecord, StoreError,
    verify_object_integrity,
};

static SA_ID_TOKEN_CACHE: std::sync::OnceLock<Mutex<HashMap<String, (String, Instant)>>> =
    std::sync::OnceLock::new();

struct StagedTempFile {
    path: PathBuf,
}

#[cfg(unix)]
fn create_private_staged_file(path: &Path) -> Result<std::fs::File, StoreError> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            StoreError::Io(format!(
                "failed to create exclusive private staged file: {e}"
            ))
        })
}

#[cfg(windows)]
fn create_private_staged_file(path: &Path) -> Result<std::fs::File, StoreError> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::ptr::null_mut;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *const SecurityAttributes,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut c_void,
        ) -> *mut c_void;
        fn GetVolumeInformationByHandleW(
            file: *mut c_void,
            volume_name_buffer: *mut u16,
            volume_name_size: u32,
            volume_serial_number: *mut u32,
            maximum_component_length: *mut u32,
            file_system_flags: *mut u32,
            file_system_name_buffer: *mut u16,
            file_system_name_size: u32,
        ) -> i32;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    const SDDL_REVISION_1: u32 = 1;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
    const FILE_PERSISTENT_ACLS: u32 = 0x0000_0008;
    const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

    // Protect the DACL from inheritance and grant access only to the file owner,
    // Local System, and the local Administrators group. The descriptor is supplied
    // to CreateFileW so the file is private from the instant it becomes visible.
    let sddl: Vec<u16> = "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)\0"
        .encode_utf16()
        .collect();
    let mut descriptor = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(StoreError::Io(format!(
            "failed to create private Windows staged-file ACL: {}",
            std::io::Error::last_os_error()
        )));
    }

    let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let attributes = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        security_descriptor: descriptor,
        inherit_handle: 0,
    };
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    let create_error = (handle == INVALID_HANDLE_VALUE).then(std::io::Error::last_os_error);
    unsafe {
        LocalFree(descriptor);
    }
    if let Some(error) = create_error {
        return Err(StoreError::Io(format!(
            "failed to create exclusive private Windows staged file: {error}"
        )));
    }

    let file = unsafe { std::fs::File::from_raw_handle(handle) };
    let mut file_system_flags = 0;
    let volume_info_ok = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut file_system_flags,
            null_mut(),
            0,
        )
    };
    if volume_info_ok == 0 || file_system_flags & FILE_PERSISTENT_ACLS == 0 {
        let detail = if volume_info_ok == 0 {
            format!(": {}", std::io::Error::last_os_error())
        } else {
            String::new()
        };
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(StoreError::Io(format!(
            "private Windows staged-file ACLs are unavailable on this filesystem{detail}"
        )));
    }

    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn create_private_staged_file(_path: &Path) -> Result<std::fs::File, StoreError> {
    Err(StoreError::Io(
        "private staged-file creation is unsupported on this platform".to_string(),
    ))
}

impl StagedTempFile {
    fn create(prefix: &str, suffix: &str, data: &[u8]) -> Result<Self, StoreError> {
        let unique = format!(
            "{prefix}_{}_{}{suffix}",
            std::process::id(),
            NEXT_REQ_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        let mut file = create_private_staged_file(&path)?;
        if let Err(error) = file.write_all(data) {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return Err(StoreError::Io(format!("failed to write staged file: {error}")));
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagedTempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Mints an OIDC `id_token` from a Google Cloud Service Account JSON key file
/// using `openssl` (RS256 JWT assertion) and `curl --config -` (OAuth2 token exchange),
/// without requiring the `gcloud` SDK to be installed on the workstation.
/// Caches tokens in memory for 45 minutes.
pub fn mint_service_account_id_token(
    credentials_file: &std::path::Path,
    token_uri_override: Option<&str>,
    target_audience: &str,
) -> Result<String, StoreError> {
    let cache_key = format!(
        "{}::{}::{}",
        credentials_file.to_string_lossy(),
        token_uri_override.unwrap_or(""),
        target_audience
    );
    let cache = SA_ID_TOKEN_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock()
        && let Some((tok, expires_at)) = guard.get(&cache_key)
        && Instant::now() < *expires_at
    {
        return Ok(tok.clone());
    }

    let raw = std::fs::read_to_string(credentials_file).map_err(|e| {
        StoreError::Io(format!(
            "failed to read gcp_credentials_file {}: {}",
            credentials_file.display(),
            e
        ))
    })?;
    let client_email = extract_json_string(&raw, "client_email")
        .ok_or_else(|| StoreError::Io("missing client_email in gcp_credentials_file".into()))?;
    let private_key = extract_json_string(&raw, "private_key")
        .ok_or_else(|| StoreError::Io("missing private_key in gcp_credentials_file".into()))?;
    let token_uri = match token_uri_override {
        Some(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => extract_json_string(&raw, "token_uri")
            .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string()),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let exp = now + 3600;

    let header_json = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    let claims_json = format!(
        "{{\"iss\":{:?},\"sub\":{:?},\"aud\":{:?},\"target_audience\":{:?},\"iat\":{},\"exp\":{}}}",
        client_email, client_email, token_uri, target_audience, now, exp
    );
    let signing_input = format!(
        "{}.{}",
        base64url_encode(header_json.as_bytes()),
        base64url_encode(claims_json.as_bytes())
    );

    let key_file = StagedTempFile::create("inarch_sakey", ".pem", private_key.as_bytes())?;
    let key_path = key_file.path().to_path_buf();

    let sign_res = (|| -> Result<Vec<u8>, StoreError> {
        let spawn_openssl = |bin: &str| {
            Command::new(bin)
                .args(["dgst", "-sha256", "-sign"])
                .arg(&key_path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        };
        let mut child = match spawn_openssl("openssl") {
            Ok(c) => c,
            Err(e) => {
                #[cfg(windows)]
                {
                    spawn_openssl("C:\\Program Files\\Git\\usr\\bin\\openssl.exe")
                        .map_err(|_| StoreError::Io(format!("failed to invoke openssl: {}", e)))?
                }
                #[cfg(not(windows))]
                {
                    return Err(StoreError::Io(format!("failed to invoke openssl: {}", e)));
                }
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(signing_input.as_bytes())
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        if !out.status.success() {
            return Err(StoreError::Io(format!(
                "openssl sign failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out.stdout)
    })();

    drop(key_file);
    let sig_bytes = sign_res?;
    let assertion = format!("{}.{}", signing_input, base64url_encode(&sig_bytes));

    let form_body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
        assertion
    );
    let mut cfg = String::new();
    cfg.push_str(&format!("url = \"{}\"\n", escape_curl_config(&token_uri)));
    cfg.push_str("request = \"POST\"\n");
    cfg.push_str("header = \"Content-Type: application/x-www-form-urlencoded\"\n");
    cfg.push_str(&format!("data = \"{}\"\n", escape_curl_config(&form_body)));
    cfg.push_str("silent\nshow-error\nfail\n");

    let mut child = Command::new("curl")
        .args(["--config", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| StoreError::Io(format!("failed to spawn curl for OIDC token: {}", e)))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(cfg.as_bytes());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| StoreError::Io(e.to_string()))?;
    if !out.status.success() {
        return Err(StoreError::Io(format!(
            "OIDC token exchange failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let resp_str = String::from_utf8_lossy(&out.stdout);
    let id_token = extract_json_string(&resp_str, "id_token")
        .or_else(|| extract_json_string(&resp_str, "access_token"))
        .ok_or_else(|| StoreError::Io("missing id_token in OAuth2 token response".into()))?;

    if let Ok(mut guard) = cache.lock() {
        guard.insert(
            cache_key,
            (
                id_token.clone(),
                Instant::now() + Duration::from_secs(45 * 60),
            ),
        );
    }
    Ok(id_token)
}

pub fn base64url_encode(data: &[u8]) -> String {
    base64_encode(data)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// Caches OAuth2 access tokens retrieved from `INARCH_GCP_ACCESS_TOKEN`,
/// the GCE Metadata Server, or `gcloud auth print-access-token`.
#[derive(Clone, Default)]
pub struct GcpTokenProvider {
    cached: Arc<Mutex<Option<(String, Instant)>>>,
}

impl GcpTokenProvider {
    pub fn new() -> Self {
        Self {
            cached: Arc::new(Mutex::new(None)),
        }
    }

    pub fn get_token(&self) -> Result<String, StoreError> {
        if let Ok(tok) = std::env::var("INARCH_GCP_ACCESS_TOKEN") {
            let trimmed = tok.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }

        let mut guard = self
            .cached
            .lock()
            .map_err(|_| StoreError::Io("token lock poisoned".into()))?;
        if let Some((ref tok, expires_at)) = *guard
            && Instant::now() < expires_at
        {
            return Ok(tok.clone());
        }

        // 1. Try GCE Metadata Server first (fast on GCP VMs).
        if let Ok(tok) = Self::fetch_from_metadata_server() {
            *guard = Some((tok.clone(), Instant::now() + Duration::from_secs(4 * 60)));
            return Ok(tok);
        }

        // 2. Fallback to `gcloud auth print-access-token`.
        let out = Command::new("gcloud")
            .args(["auth", "print-access-token", "--quiet"])
            .output()
            .map_err(|e| StoreError::Io(format!("failed to invoke gcloud for token: {}", e)))?;
        if !out.status.success() {
            return Err(StoreError::Io(format!(
                "gcloud auth print-access-token failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let tok = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if tok.is_empty() {
            return Err(StoreError::Io("empty access token from gcloud".into()));
        }
        *guard = Some((tok.clone(), Instant::now() + Duration::from_secs(4 * 60)));
        Ok(tok)
    }

    pub fn invalidate(&self) {
        if let Ok(mut guard) = self.cached.lock() {
            *guard = None;
        }
    }

    fn fetch_from_metadata_server() -> Result<String, StoreError> {
        let cfg = "url = \"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\"\nheader = \"Metadata-Flavor: Google\"\nconnect-timeout = 1\nmax-time = 2\nsilent\nfail\n";
        let mut child = Command::new("curl")
            .args(["--config", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(cfg.as_bytes());
        }
        let out = child
            .wait_with_output()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        if !out.status.success() {
            return Err(StoreError::Io("metadata server unavailable".into()));
        }
        let body = String::from_utf8_lossy(&out.stdout);
        extract_json_string(&body, "access_token")
            .ok_or_else(|| StoreError::Io("missing access_token in metadata response".into()))
    }
}

/// Executes an HTTP request via `curl --config -` passing headers over `stdin`
/// so Bearer tokens never appear in process arguments (`ps`).
/// Automatically retries transient HTTP `429`, `500`, `502`, `503`, `504` responses
/// and transient curl transport errors with exponential backoff.
/// Returns `(http_status_code, response_body_bytes)`.
fn curl_request(
    method: &str,
    url: &str,
    token: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), StoreError> {
    let mut last_err = None;
    for attempt in 0..4u32 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(150 * (1 << (attempt - 1))));
        }
        match curl_request_once(method, url, token, content_type, body) {
            Ok((code, payload)) if matches!(code, 429 | 500 | 502 | 503 | 504) && attempt < 3 => {
                last_err = Some(Ok((code, payload)));
                continue;
            }
            Ok(res) => return Ok(res),
            Err(e) if attempt < 3 => {
                last_err = Some(Err(e));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    last_err.unwrap()
}

fn curl_request_once(
    method: &str,
    url: &str,
    token: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), StoreError> {
    let mut cfg = String::new();
    cfg.push_str(&format!("url = \"{}\"\n", escape_curl_config(url)));
    cfg.push_str(&format!("request = \"{}\"\n", method));
    if !token.is_empty() {
        cfg.push_str(&format!(
            "header = \"Authorization: Bearer {}\"\n",
            escape_curl_config(token)
        ));
    }
    if let Some(ct) = content_type {
        cfg.push_str(&format!(
            "header = \"Content-Type: {}\"\n",
            escape_curl_config(ct)
        ));
    }
    cfg.push_str("silent\nshow-error\nwrite-out = \"\\n__HTTP_STATUS__:%{http_code}\"\n");

    let mut cmd = Command::new("curl");
    cmd.args(["--config", "-"]);

    let _temp_body = if let Some(b) = body {
        let staged = StagedTempFile::create("inarch_req", ".tmp", b)?;
        cfg.push_str(&format!(
            "data-binary = \"@{}\"\n",
            escape_curl_config(&staged.path().to_string_lossy())
        ));
        Some(staged)
    } else {
        None
    };

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| StoreError::Io(format!("failed to spawn curl: {}", e)))?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(cfg.as_bytes());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| StoreError::Io(format!("curl wait error: {}", e)))?;

    if !out.status.success() && out.stdout.is_empty() {
        return Err(StoreError::Io(format!(
            "curl transport error: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    let marker = b"\n__HTTP_STATUS__:";
    if let Some(idx) = find_subslice_rev(&out.stdout, marker) {
        let status_str = String::from_utf8_lossy(&out.stdout[idx + marker.len()..]);
        let code: u16 = status_str.trim().parse().unwrap_or(500);
        let payload = out.stdout[..idx].to_vec();
        Ok((code, payload))
    } else {
        Err(StoreError::Io(
            "missing HTTP status marker from curl".into(),
        ))
    }
}

static NEXT_REQ_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn find_subslice_rev(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    for i in (0..=haystack.len() - needle.len()).rev() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

fn escape_curl_config(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn url_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

type ObjectCacheMap = BTreeMap<(u8, ObjectHash), Vec<u8>>;

/// Google Cloud Storage (`gs://...`) implementation of `BlobStore`.
#[derive(Clone)]
pub struct GcsBlobStore {
    bucket: String,
    prefix: String,
    api_endpoint: String,
    tokens: GcpTokenProvider,
    cache: Arc<RwLock<ObjectCacheMap>>,
}

impl GcsBlobStore {
    pub fn new(bucket: impl Into<String>, prefix: impl Into<String>) -> Result<Self, StoreError> {
        Self::with_endpoint(bucket, prefix, "https://storage.googleapis.com")
    }

    pub fn with_endpoint(
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        api_endpoint: impl Into<String>,
    ) -> Result<Self, StoreError> {
        let b = bucket.into();
        let clean_bucket = b
            .trim()
            .strip_prefix("gs://")
            .unwrap_or(b.trim())
            .trim_matches('/')
            .to_string();
        if clean_bucket.is_empty() {
            return Err(StoreError::Io("GcsBlobStore bucket cannot be empty".into()));
        }
        let p = prefix.into().trim_matches('/').to_string();
        Ok(Self {
            bucket: clean_bucket,
            prefix: p,
            api_endpoint: api_endpoint.into().trim_end_matches('/').to_string(),
            tokens: GcpTokenProvider::new(),
            cache: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }

    fn domain_code(domain: ObjectDomain) -> u8 {
        match domain {
            ObjectDomain::Blob => 1,
            ObjectDomain::Chunk => 2,
            ObjectDomain::Changeset => 3,
            ObjectDomain::Fsnode => 4,
            ObjectDomain::UnodeFile => 5,
            ObjectDomain::UnodeManifest => 6,
            ObjectDomain::PathSearchIndex => 7,
            ObjectDomain::CopyInfo => 8,
        }
    }

    fn domain_dir(domain: ObjectDomain) -> &'static str {
        match domain {
            ObjectDomain::Blob => "blob",
            ObjectDomain::Chunk => "chunk",
            ObjectDomain::Changeset => "changeset",
            ObjectDomain::Fsnode => "fsnode",
            ObjectDomain::UnodeFile => "unode_file",
            ObjectDomain::UnodeManifest => "unode_manifest",
            ObjectDomain::PathSearchIndex => "path_search_index",
            ObjectDomain::CopyInfo => "copy_info",
        }
    }

    fn object_key(&self, domain: ObjectDomain, hash: &ObjectHash) -> String {
        let hex = hash.to_hex();
        if self.prefix.is_empty() {
            format!(
                "{}/{}/{}/{}",
                Self::domain_dir(domain),
                &hex[0..2],
                &hex[2..4],
                hex
            )
        } else {
            format!(
                "{}/{}/{}/{}/{}",
                self.prefix,
                Self::domain_dir(domain),
                &hex[0..2],
                &hex[2..4],
                hex
            )
        }
    }
}

impl BlobStore for GcsBlobStore {
    fn put_object(
        &self,
        domain: ObjectDomain,
        hash: ObjectHash,
        data: &[u8],
    ) -> Result<(), StoreError> {
        verify_object_integrity(domain, hash, data)?;
        let cache_key = (Self::domain_code(domain), hash);
        if self
            .cache
            .read()
            .expect("GcsBlobStore cache poisoned")
            .contains_key(&cache_key)
        {
            return Ok(());
        }
        let key = self.object_key(domain, &hash);
        let encoded_key = url_encode_path(&key);
        let url = format!(
            "{}/upload/storage/v1/b/{}/o?uploadType=media&name={}",
            self.api_endpoint, self.bucket, encoded_key
        );
        let token = self.tokens.get_token()?;
        let (mut status, mut resp) = curl_request(
            "POST",
            &url,
            &token,
            Some("application/octet-stream"),
            Some(data),
        )?;
        if status == 401 {
            self.tokens.invalidate();
            let fresh_token = self.tokens.get_token()?;
            let retry = curl_request(
                "POST",
                &url,
                &fresh_token,
                Some("application/octet-stream"),
                Some(data),
            )?;
            status = retry.0;
            resp = retry.1;
        }
        if (200..300).contains(&status) {
            self.cache
                .write()
                .expect("GcsBlobStore cache poisoned")
                .insert(cache_key, data.to_vec());
            Ok(())
        } else {
            Err(StoreError::Io(format!(
                "GCS put_object HTTP {}: {}",
                status,
                String::from_utf8_lossy(&resp)
            )))
        }
    }

    fn get_object(
        &self,
        domain: ObjectDomain,
        hash: &ObjectHash,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let cache_key = (Self::domain_code(domain), *hash);
        if let Some(cached) = self
            .cache
            .read()
            .expect("GcsBlobStore cache poisoned")
            .get(&cache_key)
            .cloned()
        {
            return Ok(Some(cached));
        }
        let key = self.object_key(domain, hash);
        let encoded_key = url_encode_path(&key);
        let url = format!(
            "{}/storage/v1/b/{}/o/{}?alt=media",
            self.api_endpoint, self.bucket, encoded_key
        );
        let token = self.tokens.get_token()?;
        let (mut status, mut resp) = curl_request("GET", &url, &token, None, None)?;
        if status == 401 {
            self.tokens.invalidate();
            let fresh_token = self.tokens.get_token()?;
            let retry = curl_request("GET", &url, &fresh_token, None, None)?;
            status = retry.0;
            resp = retry.1;
        }
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(StoreError::Io(format!(
                "GCS get_object HTTP {}: {}",
                status,
                String::from_utf8_lossy(&resp)
            )));
        }
        verify_object_integrity(domain, *hash, &resp)?;
        self.cache
            .write()
            .expect("GcsBlobStore cache poisoned")
            .insert(cache_key, resp.clone());
        Ok(Some(resp))
    }

    fn put_objects_batch(
        &self,
        objects: &[(ObjectDomain, ObjectHash, Vec<u8>)],
    ) -> Result<(), StoreError> {
        if objects.is_empty() {
            return Ok(());
        }
        if objects.len() <= 2 {
            for (domain, hash, data) in objects {
                self.put_object(*domain, *hash, data)?;
            }
            return Ok(());
        }
        // Pre-warm token once before spawning parallel upload workers
        let _ = self.tokens.get_token()?;
        let workers = objects.len().min(16);
        let chunk_size = objects.len().div_ceil(workers);
        std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(workers);
            for slice in objects.chunks(chunk_size) {
                handles.push(s.spawn(move || -> Result<(), StoreError> {
                    for (domain, hash, data) in slice {
                        self.put_object(*domain, *hash, data)?;
                    }
                    Ok(())
                }));
            }
            for h in handles {
                h.join()
                    .map_err(|_| StoreError::Io("GCS batch worker panicked".into()))??;
            }
            Ok(())
        })
    }

    fn get_objects_batch(
        &self,
        keys: &[(ObjectDomain, ObjectHash)],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        if keys.len() <= 2 {
            let mut out = Vec::with_capacity(keys.len());
            for (domain, hash) in keys {
                out.push(self.get_object(*domain, hash)?);
            }
            return Ok(out);
        }
        let _ = self.tokens.get_token()?;
        let workers = keys.len().min(8);
        let chunk_size = keys.len().div_ceil(workers);
        std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(workers);
            for slice in keys.chunks(chunk_size) {
                handles.push(
                    s.spawn(move || -> Result<Vec<Option<Vec<u8>>>, StoreError> {
                        let mut part = Vec::with_capacity(slice.len());
                        for (domain, hash) in slice {
                            part.push(self.get_object(*domain, hash)?);
                        }
                        Ok(part)
                    }),
                );
            }
            let mut out = Vec::with_capacity(keys.len());
            for h in handles {
                let part = h
                    .join()
                    .map_err(|_| StoreError::Io("GCS batch worker panicked".into()))??;
                out.extend(part);
            }
            Ok(out)
        })
    }

    fn has_object(&self, domain: ObjectDomain, hash: &ObjectHash) -> Result<bool, StoreError> {
        let cache_key = (Self::domain_code(domain), *hash);
        if self
            .cache
            .read()
            .expect("GcsBlobStore cache poisoned")
            .contains_key(&cache_key)
        {
            return Ok(true);
        }
        let key = self.object_key(domain, hash);
        let encoded_key = url_encode_path(&key);
        let url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.api_endpoint, self.bucket, encoded_key
        );
        for attempt in 0..2 {
            let token = self.tokens.get_token()?;
            let (status, _) = curl_request("GET", &url, &token, None, None)?;
            if status == 401 && attempt == 0 {
                self.tokens.invalidate();
                continue;
            }
            return if status == 404 {
                Ok(false)
            } else if (200..300).contains(&status) {
                Ok(true)
            } else {
                Err(StoreError::Io(format!("GCS has_object HTTP {}", status)))
            };
        }
        Err(StoreError::Io("GCS has_object auth retry exhausted".into()))
    }
}

/// Google Cloud Spanner implementation of `MetadataStore`.
///
/// Maximum number of idle Spanner sessions retained in the session pool.
pub const MAX_IDLE_SPANNER_SESSIONS: usize = 64;

/// Maximum number of retry attempts when Cloud Spanner aborts a read-write transaction (`HTTP 409 ABORTED`).
pub const MAX_SPANNER_ABORT_RETRIES: u32 = 16;

/// Returns `true` when a Cloud Spanner REST response indicates a retryable transaction abort
/// (`HTTP 409`, `"status": "ABORTED"`, or `"Transaction was aborted"`).
pub fn is_spanner_aborted(status: u16, body: &str) -> bool {
    status == 409 || body.contains("\"ABORTED\"") || body.contains("Transaction was aborted")
}

fn spanner_abort_backoff_delay(attempt: u32) -> Duration {
    let shift = attempt.min(6);
    let base_ms = 5u64.saturating_mul(1u64 << shift);
    let jitter_ms = (u64::from(attempt).wrapping_mul(7).wrapping_add(3)) % 5;
    Duration::from_millis(base_ms + jitter_ms)
}

fn normalize_spanner_endpoint(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    let without_v1 = trimmed
        .strip_suffix("/v1")
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    if without_v1.starts_with("http://") || without_v1.starts_with("https://") {
        without_v1.to_string()
    } else {
        format!("http://{}", without_v1)
    }
}

/// Uses serializable read-write transactions (`:beginTransaction`, `:executeSql`, `:commit`)
/// for lock-free atomic `cas_ref`, a multi-session pool so concurrent threads never share a
/// Spanner session concurrently, bounded retry on `HTTP 409 ABORTED`, and in-memory caches for
/// immutable `BonsaiChangeset` and `DerivedMappings`.
#[derive(Clone)]
pub struct SpannerMetadataStore {
    database: String,
    repo_id: String,
    api_endpoint: String,
    emulator_mode: bool,
    tokens: GcpTokenProvider,
    session_pool: Arc<Mutex<Vec<String>>>,
    changeset_cache: Arc<RwLock<HashMap<ChangesetId, BonsaiChangeset>>>,
    derived_cache: Arc<RwLock<HashMap<(ChangesetId, DerivedDataKind), ObjectHash>>>,
    principal_cache: Arc<RwLock<HashMap<String, PrincipalRecord>>>,
    lease_cache: Arc<RwLock<HashMap<String, JitLeaseRecord>>>,
}

impl SpannerMetadataStore {
    pub fn new(
        database: impl Into<String>,
        repo_id: impl Into<String>,
    ) -> Result<Self, StoreError> {
        if let Ok(emulator_host) = std::env::var("SPANNER_EMULATOR_HOST")
            && !emulator_host.trim().is_empty()
        {
            return Self::with_emulator_host(database, repo_id, emulator_host);
        }
        Self::with_endpoint(database, repo_id, "https://spanner.googleapis.com")
    }

    pub fn with_emulator_host(
        database: impl Into<String>,
        repo_id: impl Into<String>,
        emulator_host: impl Into<String>,
    ) -> Result<Self, StoreError> {
        let host = emulator_host.into();
        let endpoint = normalize_spanner_endpoint(&host);
        Self::build_store(database, repo_id, endpoint, true)
    }

    pub fn with_endpoint(
        database: impl Into<String>,
        repo_id: impl Into<String>,
        api_endpoint: impl Into<String>,
    ) -> Result<Self, StoreError> {
        let raw_endpoint = api_endpoint.into();
        let trimmed = raw_endpoint.trim().trim_end_matches('/');
        if let Ok(emulator_host) = std::env::var("SPANNER_EMULATOR_HOST") {
            let emu_trimmed = emulator_host.trim();
            if !emu_trimmed.is_empty() {
                let effective_endpoint =
                    if trimmed.is_empty() || trimmed == "https://spanner.googleapis.com" {
                        normalize_spanner_endpoint(emu_trimmed)
                    } else {
                        normalize_spanner_endpoint(trimmed)
                    };
                return Self::build_store(database, repo_id, effective_endpoint, true);
            }
        }
        Self::build_store(
            database,
            repo_id,
            normalize_spanner_endpoint(trimmed),
            false,
        )
    }

    fn build_store(
        database: impl Into<String>,
        repo_id: impl Into<String>,
        api_endpoint: String,
        emulator_mode: bool,
    ) -> Result<Self, StoreError> {
        let db = database.into().trim().trim_matches('/').to_string();
        if db.is_empty() {
            return Err(StoreError::Io(
                "SpannerMetadataStore database resource path cannot be empty".into(),
            ));
        }
        let r = repo_id.into();
        let clean_repo = if r.trim().is_empty() {
            "default".to_string()
        } else {
            r.trim().to_string()
        };
        Ok(Self {
            database: db,
            repo_id: clean_repo,
            api_endpoint,
            emulator_mode,
            tokens: GcpTokenProvider::new(),
            session_pool: Arc::new(Mutex::new(Vec::new())),
            changeset_cache: Arc::new(RwLock::new(HashMap::new())),
            derived_cache: Arc::new(RwLock::new(HashMap::new())),
            principal_cache: Arc::new(RwLock::new(HashMap::new())),
            lease_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Returns the base Spanner v1 REST URL (e.g. `https://spanner.googleapis.com/v1` or `http://127.0.0.1:9010/v1`).
    pub fn api_base_url(&self) -> String {
        format!("{}/v1", self.api_endpoint)
    }

    /// Returns `true` when this store is configured to talk to the Cloud Spanner emulator without GCP bearer tokens.
    pub fn is_emulator_mode(&self) -> bool {
        self.emulator_mode
    }

    /// Returns the number of idle sessions currently available in the session pool.
    pub fn idle_session_count(&self) -> usize {
        self.session_pool.lock().map(|pool| pool.len()).unwrap_or(0)
    }

    fn auth_token(&self) -> Result<String, StoreError> {
        if self.emulator_mode {
            Ok(String::new())
        } else {
            self.tokens.get_token()
        }
    }

    fn create_session(&self) -> Result<String, StoreError> {
        let url = format!("{}/v1/{}/sessions", self.api_endpoint, self.database);
        for attempt in 0..2 {
            let token = self.auth_token()?;
            let (status, resp) =
                curl_request("POST", &url, &token, Some("application/json"), Some(b"{}"))?;
            if status == 401 && !self.emulator_mode && attempt == 0 {
                self.tokens.invalidate();
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(StoreError::Io(format!(
                    "Spanner createSession HTTP {}: {}",
                    status,
                    String::from_utf8_lossy(&resp)
                )));
            }
            let body = String::from_utf8_lossy(&resp);
            let name = extract_json_string(&body, "name")
                .ok_or_else(|| StoreError::Io("missing session name in Spanner response".into()))?;
            return Ok(name);
        }
        Err(StoreError::Io(
            "Spanner createSession auth retry exhausted".into(),
        ))
    }

    /// Checks out an exclusive Spanner session from the idle pool, or creates a new session if the pool is empty.
    pub fn acquire_session(&self) -> Result<String, StoreError> {
        {
            let mut guard = self
                .session_pool
                .lock()
                .map_err(|_| StoreError::Io("spanner session pool lock poisoned".into()))?;
            if let Some(session) = guard.pop() {
                return Ok(session);
            }
        }
        self.create_session()
    }

    /// Returns a Spanner session to the idle pool (capped at [`MAX_IDLE_SPANNER_SESSIONS`]).
    pub fn release_session(&self, session: String) {
        if session.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.session_pool.lock()
            && guard.len() < MAX_IDLE_SPANNER_SESSIONS
            && !guard.contains(&session)
        {
            guard.push(session);
        }
    }

    fn spanner_post_in_session(
        &self,
        session: &mut String,
        action_suffix: &str,
        json_body: &str,
    ) -> Result<(u16, String), StoreError> {
        for attempt in 0..3 {
            let url = format!("{}/v1/{}{}", self.api_endpoint, *session, action_suffix);
            let token = self.auth_token()?;
            let (status, resp) = curl_request(
                "POST",
                &url,
                &token,
                Some("application/json"),
                Some(json_body.as_bytes()),
            )?;
            let resp_str = String::from_utf8_lossy(&resp).to_string();
            if status == 401 && !self.emulator_mode && attempt < 2 {
                self.tokens.invalidate();
                continue;
            }
            if status == 404 && resp_str.contains("Session not found") && attempt < 2 {
                *session = self.create_session()?;
                continue;
            }
            return Ok((status, resp_str));
        }
        Err(StoreError::Io("Spanner request retry exhausted".into()))
    }

    fn spanner_post(&self, action_suffix: &str, json_body: &str) -> Result<String, StoreError> {
        let mut session = self.acquire_session()?;
        let result = self.spanner_post_in_session(&mut session, action_suffix, json_body);
        self.release_session(session);
        let (status, resp_str) = result?;
        if !(200..300).contains(&status) {
            return Err(StoreError::Io(format!(
                "Spanner {} HTTP {}: {}",
                action_suffix, status, resp_str
            )));
        }
        Ok(resp_str)
    }

    fn spanner_commit_with_retry(&self, commit_body: &str) -> Result<String, StoreError> {
        let mut session = self.acquire_session()?;
        for attempt in 0..MAX_SPANNER_ABORT_RETRIES {
            let result = self.spanner_post_in_session(&mut session, ":commit", commit_body);
            match result {
                Ok((status, resp_str)) if (200..300).contains(&status) => {
                    self.release_session(session);
                    return Ok(resp_str);
                }
                Ok((status, resp_str))
                    if is_spanner_aborted(status, &resp_str)
                        && attempt + 1 < MAX_SPANNER_ABORT_RETRIES =>
                {
                    std::thread::sleep(spanner_abort_backoff_delay(attempt));
                    continue;
                }
                Ok((status, resp_str)) => {
                    self.release_session(session);
                    return Err(StoreError::Io(format!(
                        "Spanner :commit HTTP {}: {}",
                        status, resp_str
                    )));
                }
                Err(e) => {
                    self.release_session(session);
                    return Err(e);
                }
            }
        }
        self.release_session(session);
        Err(StoreError::Io(
            "Spanner :commit retry budget exhausted on ABORTED".into(),
        ))
    }

    fn split_scoped_ref<'a>(&'a self, ref_name: &'a str) -> (&'a str, &'a str) {
        if let Some((repo, unscoped)) = ref_name.split_once("::") {
            (repo, unscoped)
        } else {
            (self.repo_id.as_str(), ref_name)
        }
    }

    fn derived_kind_num(kind: DerivedDataKind) -> u8 {
        match kind {
            DerivedDataKind::Fsnode => 1,
            DerivedDataKind::Unode => 2,
            DerivedDataKind::BlameV2 => 3,
            DerivedDataKind::CommitGraph => 4,
            DerivedDataKind::PathSearchIndex => 5,
            DerivedDataKind::CopyDetection => 6,
        }
    }

    fn parse_principal_row(row: &[String]) -> Result<PrincipalRecord, StoreError> {
        if row.len() < 8 {
            return Err(StoreError::SnapshotCorrupted(
                "ScionPrincipals row has fewer than 8 columns".into(),
            ));
        }
        let allowed_repos: Vec<String> = row[2]
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let allowed_ops: Vec<String> = row[3]
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let created_at_unix: i64 = row[6]
            .parse()
            .map_err(|_| StoreError::SnapshotCorrupted("invalid CreatedAtUnix".into()))?;
        let revoked_at_unix: Option<i64> = if row[7].trim().is_empty() {
            None
        } else {
            Some(
                row[7]
                    .trim()
                    .parse()
                    .map_err(|_| StoreError::SnapshotCorrupted("invalid RevokedAtUnix".into()))?,
            )
        };
        let (allowed_write_prefixes, enrolled_by) = if row.len() >= 10 {
            let wp: Vec<String> = row[8]
                .split('\n')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            let eb = if row[9].is_empty() {
                "admin".to_string()
            } else {
                row[9].clone()
            };
            (wp, eb)
        } else {
            (
                Vec::new(),
                row.get(8).cloned().unwrap_or_else(|| "admin".to_string()),
            )
        };
        Ok(PrincipalRecord {
            principal_email: row[0].clone(),
            principal_kind: row[1].clone(),
            host_label: row[5].clone(),
            allowed_repos,
            allowed_ops,
            allowed_write_prefixes,
            status: row[4].clone(),
            enrolled_by,
            created_at_unix,
            revoked_at_unix,
        })
    }

    fn parse_lease_row(row: &[String]) -> Result<JitLeaseRecord, StoreError> {
        if row.len() < 11 {
            return Err(StoreError::SnapshotCorrupted(
                "ScionLeases row has fewer than 11 columns".into(),
            ));
        }
        let allowed_ops: Vec<String> = row[5]
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let allowed_read_prefixes: Vec<String> = row[6]
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let allowed_write_prefixes: Vec<String> = row[7]
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let issued_at_unix: i64 = row[8]
            .parse()
            .map_err(|_| StoreError::SnapshotCorrupted("invalid IssuedAtUnix".into()))?;
        let expires_at_unix: i64 = row[9]
            .parse()
            .map_err(|_| StoreError::SnapshotCorrupted("invalid ExpiresAtUnix".into()))?;
        let revoked = row[10].trim().eq_ignore_ascii_case("true") || row[10].trim() == "1";
        let allowed_refs: Vec<String> = row
            .get(12)
            .map(|s| {
                s.split('\n')
                    .filter(|p| !p.is_empty())
                    .map(|p| p.to_string())
                    .collect()
            })
            .unwrap_or_default();
        Ok(JitLeaseRecord {
            lease_id: row[0].clone(),
            principal_email: row[1].clone(),
            swarm_id: row[2].clone(),
            task_id: row[3].clone(),
            repo_id: row[4].clone(),
            allowed_ops,
            allowed_read_prefixes,
            allowed_write_prefixes,
            allowed_refs,
            issued_at_unix,
            expires_at_unix,
            revoked,
        })
    }
}

impl MetadataStore for SpannerMetadataStore {
    fn put_changeset(&self, cs: &BonsaiChangeset) -> Result<ChangesetId, StoreError> {
        // Verify parents exist first (preserving MetadataStore invariant)
        for parent in &cs.parents {
            if self.get_changeset(parent)?.is_none() {
                return Err(StoreError::UnknownChangeset(*parent));
            }
        }

        let id = cs.changeset_id();
        let hex_id = id.to_hex();
        let canonical = cs.to_canonical_bytes();
        let b64_payload = base64_encode(&canonical);

        let parents_json: Vec<String> = cs
            .parents
            .iter()
            .map(|p| format!("\"{}\"", json_escape(&p.to_hex())))
            .collect();

        let commit_body = format!(
            "{{\"singleUseTransaction\":{{\"readWrite\":{{}}}},\"mutations\":[{{\"insertOrUpdate\":{{\"table\":\"ScionChangesets\",\"columns\":[\"ChangesetId\",\"Author\",\"Message\",\"TimestampUnix\",\"Parents\",\"Payload\",\"CreatedAt\"],\"values\":[[{:?},{:?},{:?},{:?},[{}],{:?},\"spanner.commit_timestamp()\"]]}}}}]}}",
            hex_id,
            cs.author,
            cs.message,
            cs.author_date_secs.to_string(),
            parents_json.join(","),
            b64_payload
        );

        let _ = self.spanner_commit_with_retry(&commit_body)?;
        if let Ok(mut cache) = self.changeset_cache.write() {
            cache.insert(id, cs.clone());
        }
        Ok(id)
    }

    fn get_changeset(&self, id: &ChangesetId) -> Result<Option<BonsaiChangeset>, StoreError> {
        if let Ok(cache) = self.changeset_cache.read()
            && let Some(cs) = cache.get(id)
        {
            return Ok(Some(cs.clone()));
        }
        let hex_id = id.to_hex();
        let sql_body = format!(
            "{{\"sql\":\"SELECT Payload FROM ScionChangesets WHERE ChangesetId = @id\",\"params\":{{\"id\":{:?}}},\"paramTypes\":{{\"id\":{{\"code\":\"STRING\"}}}}}}",
            hex_id
        );
        let resp = self.spanner_post(":executeSql", &sql_body)?;
        let rows = extract_spanner_rows(&resp);
        if let Some(first_row) = rows.first()
            && let Some(b64) = first_row.first()
        {
            let bytes = base64_decode(b64)?;
            let cs = BonsaiChangeset::from_canonical_bytes(&bytes)
                .map_err(|e| StoreError::SnapshotCorrupted(e.to_string()))?;
            if let Ok(mut cache) = self.changeset_cache.write() {
                cache.insert(*id, cs.clone());
            }
            return Ok(Some(cs));
        }
        Ok(None)
    }

    /// Reads the `Parents` column alone; the canonical payload stays in Spanner, so an
    /// ancestry walk never transfers or decodes the bodies of the changesets it crosses.
    fn get_changeset_parents(
        &self,
        id: &ChangesetId,
    ) -> Result<Option<Vec<ChangesetId>>, StoreError> {
        if let Ok(cache) = self.changeset_cache.read()
            && let Some(cs) = cache.get(id)
        {
            return Ok(Some(cs.parents.clone()));
        }
        let hex_id = id.to_hex();
        let sql_body = format!(
            "{{\"sql\":\"SELECT ARRAY_TO_STRING(Parents, '\\\\n') FROM ScionChangesets WHERE ChangesetId = @id\",\"params\":{{\"id\":{:?}}},\"paramTypes\":{{\"id\":{{\"code\":\"STRING\"}}}}}}",
            hex_id
        );
        let resp = self.spanner_post(":executeSql", &sql_body)?;
        let rows = extract_spanner_rows(&resp);
        let Some(first_row) = rows.first() else {
            return Ok(None);
        };
        let joined = first_row.first().map(String::as_str).unwrap_or("");
        let mut parents = Vec::new();
        for hex in joined.split('\n').filter(|s| !s.is_empty()) {
            let hash = ObjectHash::from_hex(hex)
                .map_err(|e| StoreError::SnapshotCorrupted(e.to_string()))?;
            parents.push(ChangesetId(hash));
        }
        Ok(Some(parents))
    }

    fn get_ref(&self, ref_name: &str) -> Result<Option<ChangesetId>, StoreError> {
        let (repo, unscoped) = self.split_scoped_ref(ref_name);
        let sql_body = format!(
            "{{\"sql\":\"SELECT ChangesetId FROM ScionRefs WHERE RepoId = @repo AND RefName = @ref\",\"params\":{{\"repo\":{:?},\"ref\":{:?}}},\"paramTypes\":{{\"repo\":{{\"code\":\"STRING\"}},\"ref\":{{\"code\":\"STRING\"}}}}}}",
            repo, unscoped
        );
        let resp = self.spanner_post(":executeSql", &sql_body)?;
        let rows = extract_spanner_rows(&resp);
        if let Some(first_row) = rows.first()
            && let Some(hex_cs) = first_row.first()
        {
            let hash = ObjectHash::from_hex(hex_cs)
                .map_err(|e| StoreError::SnapshotCorrupted(e.to_string()))?;
            return Ok(Some(ChangesetId(hash)));
        }
        Ok(None)
    }

    fn list_refs(&self) -> Result<BTreeMap<String, ChangesetId>, StoreError> {
        let sql_body = "{\"sql\":\"SELECT RepoId, RefName, ChangesetId FROM ScionRefs ORDER BY RepoId, RefName\"}";
        let resp = self.spanner_post(":executeSql", sql_body)?;
        let rows = extract_spanner_rows(&resp);
        let mut out = BTreeMap::new();
        for row in rows {
            if row.len() >= 3 {
                let repo = &row[0];
                let name = &row[1];
                let hex_cs = &row[2];
                let hash = ObjectHash::from_hex(hex_cs)
                    .map_err(|e| StoreError::SnapshotCorrupted(e.to_string()))?;
                let key = if repo == "default" {
                    name.clone()
                } else {
                    format!("{}::{}", repo, name)
                };
                out.insert(key, ChangesetId(hash));
            }
        }
        Ok(out)
    }

    fn cas_ref(
        &self,
        ref_name: &str,
        expected: Option<ChangesetId>,
        new_target: ChangesetId,
    ) -> Result<(), StoreError> {
        if self.get_changeset(&new_target)?.is_none() {
            return Err(StoreError::UnknownChangeset(new_target));
        }

        let (repo, unscoped) = self.split_scoped_ref(ref_name);
        let mut session = self.acquire_session()?;

        for attempt in 0..MAX_SPANNER_ABORT_RETRIES {
            // 1. Begin a serializable read-write transaction in Cloud Spanner on our dedicated session.
            let (begin_status, begin_resp) = match self.spanner_post_in_session(
                &mut session,
                ":beginTransaction",
                "{\"options\":{\"readWrite\":{}}}",
            ) {
                Ok(res) => res,
                Err(e) => {
                    self.release_session(session);
                    return Err(e);
                }
            };
            if is_spanner_aborted(begin_status, &begin_resp)
                && attempt + 1 < MAX_SPANNER_ABORT_RETRIES
            {
                std::thread::sleep(spanner_abort_backoff_delay(attempt));
                continue;
            }
            if !(200..300).contains(&begin_status) {
                self.release_session(session);
                return Err(StoreError::Io(format!(
                    "Spanner :beginTransaction HTTP {}: {}",
                    begin_status, begin_resp
                )));
            }
            let Some(tx_id) = extract_json_string(&begin_resp, "id") else {
                self.release_session(session);
                return Err(StoreError::Io("missing transaction id from Spanner".into()));
            };

            // 2. Read current ref inside the serializable transaction.
            let sql_body = format!(
                "{{\"transaction\":{{\"id\":{:?}}},\"sql\":\"SELECT ChangesetId FROM ScionRefs WHERE RepoId = @repo AND RefName = @ref\",\"params\":{{\"repo\":{:?},\"ref\":{:?}}},\"paramTypes\":{{\"repo\":{{\"code\":\"STRING\"}},\"ref\":{{\"code\":\"STRING\"}}}}}}",
                tx_id, repo, unscoped
            );
            let (query_status, query_resp) =
                match self.spanner_post_in_session(&mut session, ":executeSql", &sql_body) {
                    Ok(res) => res,
                    Err(e) => {
                        self.release_session(session);
                        return Err(e);
                    }
                };
            if is_spanner_aborted(query_status, &query_resp)
                && attempt + 1 < MAX_SPANNER_ABORT_RETRIES
            {
                std::thread::sleep(spanner_abort_backoff_delay(attempt));
                continue;
            }
            if !(200..300).contains(&query_status) {
                let rollback_body = format!("{{\"transactionId\":{:?}}}", tx_id);
                let _ = self.spanner_post_in_session(&mut session, ":rollback", &rollback_body);
                self.release_session(session);
                return Err(StoreError::Io(format!(
                    "Spanner :executeSql HTTP {}: {}",
                    query_status, query_resp
                )));
            }
            let rows = extract_spanner_rows(&query_resp);
            let actual: Option<ChangesetId> = if let Some(first_row) = rows.first() {
                if let Some(hex_cs) = first_row.first() {
                    match ObjectHash::from_hex(hex_cs) {
                        Ok(h) => Some(ChangesetId(h)),
                        Err(e) => {
                            let rollback_body = format!("{{\"transactionId\":{:?}}}", tx_id);
                            let _ = self.spanner_post_in_session(
                                &mut session,
                                ":rollback",
                                &rollback_body,
                            );
                            self.release_session(session);
                            return Err(StoreError::SnapshotCorrupted(e.to_string()));
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if actual != expected {
                let rollback_body = format!("{{\"transactionId\":{:?}}}", tx_id);
                let _ = self.spanner_post_in_session(&mut session, ":rollback", &rollback_body);
                self.release_session(session);
                return Err(StoreError::CasMismatch {
                    ref_name: ref_name.to_string(),
                    expected,
                    actual,
                });
            }

            // 3. Commit the atomic ref update within the same transaction.
            let commit_body = format!(
                "{{\"transactionId\":{:?},\"mutations\":[{{\"insertOrUpdate\":{{\"table\":\"ScionRefs\",\"columns\":[\"RepoId\",\"RefName\",\"ChangesetId\",\"UpdatedAt\"],\"values\":[[{:?},{:?},{:?},\"spanner.commit_timestamp()\"]]}}}}]}}",
                tx_id,
                repo,
                unscoped,
                new_target.to_hex()
            );
            let (commit_status, commit_resp) =
                match self.spanner_post_in_session(&mut session, ":commit", &commit_body) {
                    Ok(res) => res,
                    Err(e) => {
                        self.release_session(session);
                        return Err(e);
                    }
                };
            if (200..300).contains(&commit_status) {
                self.release_session(session);
                return Ok(());
            }
            if is_spanner_aborted(commit_status, &commit_resp)
                && attempt + 1 < MAX_SPANNER_ABORT_RETRIES
            {
                std::thread::sleep(spanner_abort_backoff_delay(attempt));
                continue;
            }
            self.release_session(session);
            return Err(StoreError::Io(format!(
                "Spanner :commit HTTP {}: {}",
                commit_status, commit_resp
            )));
        }

        self.release_session(session);
        Err(StoreError::Io(
            "Spanner cas_ref retry budget exhausted on ABORTED".into(),
        ))
    }

    fn put_derived_mapping(
        &self,
        cs_id: ChangesetId,
        kind: DerivedDataKind,
        derived_hash: ObjectHash,
    ) -> Result<(), StoreError> {
        if let Some(existing) = self.get_derived_mapping(cs_id, kind)? {
            if existing != derived_hash {
                return Err(StoreError::ConflictingDerivedMapping {
                    changeset_id: cs_id,
                    kind,
                    existing,
                    attempted: derived_hash,
                });
            }
            return Ok(());
        }

        let kind_num = Self::derived_kind_num(kind);
        let commit_body = format!(
            "{{\"singleUseTransaction\":{{\"readWrite\":{{}}}},\"mutations\":[{{\"insertOrUpdate\":{{\"table\":\"ScionDerivedMappings\",\"columns\":[\"ChangesetId\",\"DerivedKind\",\"RootHash\",\"CreatedAt\"],\"values\":[[{:?},{:?},{:?},\"spanner.commit_timestamp()\"]]}}}}]}}",
            cs_id.to_hex(),
            kind_num.to_string(),
            derived_hash.to_hex()
        );
        let _ = self.spanner_commit_with_retry(&commit_body)?;
        if let Ok(mut cache) = self.derived_cache.write() {
            cache.insert((cs_id, kind), derived_hash);
        }
        Ok(())
    }

    fn get_derived_mapping(
        &self,
        cs_id: ChangesetId,
        kind: DerivedDataKind,
    ) -> Result<Option<ObjectHash>, StoreError> {
        if let Ok(cache) = self.derived_cache.read()
            && let Some(h) = cache.get(&(cs_id, kind))
        {
            return Ok(Some(*h));
        }
        let kind_num = Self::derived_kind_num(kind);
        let sql_body = format!(
            "{{\"sql\":\"SELECT RootHash FROM ScionDerivedMappings WHERE ChangesetId = @cs AND DerivedKind = @kind\",\"params\":{{\"cs\":{:?},\"kind\":{:?}}},\"paramTypes\":{{\"cs\":{{\"code\":\"STRING\"}},\"kind\":{{\"code\":\"INT64\"}}}}}}",
            cs_id.to_hex(),
            kind_num.to_string()
        );
        let resp = self.spanner_post(":executeSql", &sql_body)?;
        let rows = extract_spanner_rows(&resp);
        if let Some(first_row) = rows.first()
            && let Some(hex_h) = first_row.first()
        {
            let h = ObjectHash::from_hex(hex_h)
                .map_err(|e| StoreError::SnapshotCorrupted(e.to_string()))?;
            if let Ok(mut cache) = self.derived_cache.write() {
                cache.insert((cs_id, kind), h);
            }
            return Ok(Some(h));
        }
        Ok(None)
    }

    fn put_principal(&self, record: &PrincipalRecord) -> Result<(), StoreError> {
        let repos_json: Vec<String> = record
            .allowed_repos
            .iter()
            .map(|r| format!("{:?}", r))
            .collect();
        let ops_json: Vec<String> = record
            .allowed_ops
            .iter()
            .map(|o| format!("{:?}", o))
            .collect();
        let write_json: Vec<String> = record
            .allowed_write_prefixes
            .iter()
            .map(|p| format!("{:?}", p))
            .collect();
        let revoked_json = match record.revoked_at_unix {
            Some(ts) => format!("{:?}", ts.to_string()),
            None => "null".to_string(),
        };
        let commit_body = format!(
            "{{\"singleUseTransaction\":{{\"readWrite\":{{}}}},\"mutations\":[{{\"insertOrUpdate\":{{\"table\":\"ScionPrincipals\",\"columns\":[\"PrincipalId\",\"Role\",\"AllowedRepos\",\"AllowedOps\",\"AllowedWritePrefixes\",\"Status\",\"HostLabel\",\"EnrolledBy\",\"CreatedAtUnix\",\"RevokedAtUnix\",\"UpdatedAt\"],\"values\":[[{:?},{:?},[{}],[{}],[{}],{:?},{:?},{:?},{:?},{},\"spanner.commit_timestamp()\"]]}}}}]}}",
            record.principal_email,
            record.principal_kind,
            repos_json.join(","),
            ops_json.join(","),
            write_json.join(","),
            record.status,
            record.host_label,
            record.enrolled_by,
            record.created_at_unix.to_string(),
            revoked_json
        );
        let _ = self.spanner_commit_with_retry(&commit_body)?;
        if let Ok(mut cache) = self.principal_cache.write() {
            cache.insert(record.principal_email.clone(), record.clone());
        }
        Ok(())
    }

    fn get_principal(&self, principal_id: &str) -> Result<Option<PrincipalRecord>, StoreError> {
        if let Ok(cache) = self.principal_cache.read()
            && let Some(p) = cache.get(principal_id)
        {
            return Ok(Some(p.clone()));
        }
        let sql_body = format!(
            "{{\"sql\":\"SELECT PrincipalId, Role, ARRAY_TO_STRING(AllowedRepos, '\\\\n'), ARRAY_TO_STRING(AllowedOps, '\\\\n'), Status, HostLabel, CAST(CreatedAtUnix AS STRING), IFNULL(CAST(RevokedAtUnix AS STRING), ''), ARRAY_TO_STRING(AllowedWritePrefixes, '\\\\n'), EnrolledBy FROM ScionPrincipals WHERE PrincipalId = @id\",\"params\":{{\"id\":{:?}}},\"paramTypes\":{{\"id\":{{\"code\":\"STRING\"}}}}}}",
            principal_id
        );
        let resp = self.spanner_post(":executeSql", &sql_body)?;
        let rows = extract_spanner_rows(&resp);
        if let Some(first_row) = rows.first() {
            let rec = Self::parse_principal_row(first_row)?;
            if let Ok(mut cache) = self.principal_cache.write() {
                cache.insert(principal_id.to_string(), rec.clone());
            }
            return Ok(Some(rec));
        }
        Ok(None)
    }

    fn list_principals(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        let sql_body = "{\"sql\":\"SELECT PrincipalId, Role, ARRAY_TO_STRING(AllowedRepos, '\\\\n'), ARRAY_TO_STRING(AllowedOps, '\\\\n'), Status, HostLabel, CAST(CreatedAtUnix AS STRING), IFNULL(CAST(RevokedAtUnix AS STRING), ''), ARRAY_TO_STRING(AllowedWritePrefixes, '\\\\n'), EnrolledBy FROM ScionPrincipals ORDER BY PrincipalId\"}";
        let resp = self.spanner_post(":executeSql", sql_body)?;
        let rows = extract_spanner_rows(&resp);
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(Self::parse_principal_row(&row)?);
        }
        Ok(out)
    }

    fn put_lease(&self, record: &JitLeaseRecord) -> Result<(), StoreError> {
        let ops_json: Vec<String> = record
            .allowed_ops
            .iter()
            .map(|o| format!("{:?}", o))
            .collect();
        let read_json: Vec<String> = record
            .allowed_read_prefixes
            .iter()
            .map(|p| format!("{:?}", p))
            .collect();
        let write_json: Vec<String> = record
            .allowed_write_prefixes
            .iter()
            .map(|p| format!("{:?}", p))
            .collect();
        let refs_json: Vec<String> = record
            .allowed_refs
            .iter()
            .map(|r| format!("{:?}", r))
            .collect();
        let revoked_bool = if record.revoked { "true" } else { "false" };
        let commit_body = format!(
            "{{\"singleUseTransaction\":{{\"readWrite\":{{}}}},\"mutations\":[{{\"insertOrUpdate\":{{\"table\":\"ScionLeases\",\"columns\":[\"LeaseId\",\"PrincipalId\",\"SwarmId\",\"TaskId\",\"RepoId\",\"AllowedOps\",\"AllowedReadPrefixes\",\"AllowedWritePrefixes\",\"AllowedRefs\",\"IssuedAtUnix\",\"ExpiresAtUnix\",\"Revoked\",\"UpdatedAt\"],\"values\":[[{:?},{:?},{:?},{:?},{:?},[{}],[{}],[{}],[{}],{:?},{:?},{},\"spanner.commit_timestamp()\"]]}}}}]}}",
            record.lease_id,
            record.principal_email,
            record.swarm_id,
            record.task_id,
            record.repo_id,
            ops_json.join(","),
            read_json.join(","),
            write_json.join(","),
            refs_json.join(","),
            record.issued_at_unix.to_string(),
            record.expires_at_unix.to_string(),
            revoked_bool
        );
        let _ = self.spanner_commit_with_retry(&commit_body)?;
        if let Ok(mut cache) = self.lease_cache.write() {
            cache.insert(record.lease_id.clone(), record.clone());
        }
        Ok(())
    }

    fn get_lease(&self, lease_id: &str) -> Result<Option<JitLeaseRecord>, StoreError> {
        if let Ok(cache) = self.lease_cache.read()
            && let Some(l) = cache.get(lease_id)
        {
            return Ok(Some(l.clone()));
        }
        let sql_body = format!(
            "{{\"sql\":\"SELECT LeaseId, PrincipalId, SwarmId, TaskId, RepoId, ARRAY_TO_STRING(AllowedOps, '\\\\n'), ARRAY_TO_STRING(AllowedReadPrefixes, '\\\\n'), ARRAY_TO_STRING(AllowedWritePrefixes, '\\\\n'), CAST(IssuedAtUnix AS STRING), CAST(ExpiresAtUnix AS STRING), IF(Revoked, 'true', 'false'), IFNULL(CAST(RevokedAtUnix AS STRING), ''), ARRAY_TO_STRING(AllowedRefs, '\\\\n') FROM ScionLeases WHERE LeaseId = @id\",\"params\":{{\"id\":{:?}}},\"paramTypes\":{{\"id\":{{\"code\":\"STRING\"}}}}}}",
            lease_id
        );
        let resp = self.spanner_post(":executeSql", &sql_body)?;
        let rows = extract_spanner_rows(&resp);
        if let Some(first_row) = rows.first() {
            let rec = Self::parse_lease_row(first_row)?;
            if let Ok(mut cache) = self.lease_cache.write() {
                cache.insert(lease_id.to_string(), rec.clone());
            }
            return Ok(Some(rec));
        }
        Ok(None)
    }

    fn list_leases(&self, repo_id: Option<&str>) -> Result<Vec<JitLeaseRecord>, StoreError> {
        let sql_body = match repo_id {
            Some(repo) => format!(
                "{{\"sql\":\"SELECT LeaseId, PrincipalId, SwarmId, TaskId, RepoId, ARRAY_TO_STRING(AllowedOps, '\\\\n'), ARRAY_TO_STRING(AllowedReadPrefixes, '\\\\n'), ARRAY_TO_STRING(AllowedWritePrefixes, '\\\\n'), CAST(IssuedAtUnix AS STRING), CAST(ExpiresAtUnix AS STRING), IF(Revoked, 'true', 'false'), IFNULL(CAST(RevokedAtUnix AS STRING), ''), ARRAY_TO_STRING(AllowedRefs, '\\\\n') FROM ScionLeases WHERE RepoId = @repo ORDER BY LeaseId\",\"params\":{{\"repo\":{:?}}},\"paramTypes\":{{\"repo\":{{\"code\":\"STRING\"}}}}}}",
                repo
            ),
            None => "{\"sql\":\"SELECT LeaseId, PrincipalId, SwarmId, TaskId, RepoId, ARRAY_TO_STRING(AllowedOps, '\\\\n'), ARRAY_TO_STRING(AllowedReadPrefixes, '\\\\n'), ARRAY_TO_STRING(AllowedWritePrefixes, '\\\\n'), CAST(IssuedAtUnix AS STRING), CAST(ExpiresAtUnix AS STRING), IF(Revoked, 'true', 'false'), IFNULL(CAST(RevokedAtUnix AS STRING), ''), ARRAY_TO_STRING(AllowedRefs, '\\\\n') FROM ScionLeases ORDER BY LeaseId\"}".to_string(),
        };
        let resp = self.spanner_post(":executeSql", &sql_body)?;
        let rows = extract_spanner_rows(&resp);
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(Self::parse_lease_row(&row)?);
        }
        Ok(out)
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Extracts the string value of `"key": "value"` from a JSON object string.
pub fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let mut search_from = 0;
    while let Some(rel_idx) = json[search_from..].find(&pattern) {
        let after_key = search_from + rel_idx + pattern.len();
        let rest = json[after_key..].trim_start();
        if let Some(after_colon) = rest.strip_prefix(':') {
            let val_rest = after_colon.trim_start();
            if val_rest.starts_with('"')
                && let Some((parsed, _)) = parse_json_quoted_string(val_rest)
            {
                return Some(parsed);
            }
        }
        search_from = after_key;
    }
    None
}

fn parse_json_quoted_string(s: &str) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                i += 1;
                if i >= bytes.len() {
                    return None;
                }
                match bytes[i] {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    other => out.push(other as char),
                }
                i += 1;
            }
            b => {
                let ch = s[i..].chars().next()?;
                out.push(ch);
                i += ch.len_utf8();
                let _ = b;
            }
        }
    }
    None
}

/// Extracts Spanner `"rows": [ [ "val1", "val2" ], ... ]` from an `:executeSql` JSON response.
pub fn extract_spanner_rows(json: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let Some(rows_key_idx) = json.find("\"rows\"") else {
        return rows;
    };
    let after_key = &json[rows_key_idx + 6..];
    let Some(open_outer) = after_key.find('[') else {
        return rows;
    };
    let bytes = after_key.as_bytes();
    let mut i = open_outer + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => {
                i += 1;
                let mut row = Vec::new();
                while i < bytes.len() {
                    while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
                        i += 1;
                    }
                    if i >= bytes.len() || bytes[i] == b']' {
                        i += 1;
                        break;
                    }
                    if bytes[i] == b'"' {
                        if let Some((val, consumed)) = parse_json_quoted_string(&after_key[i..]) {
                            row.push(val);
                            i += consumed;
                        } else {
                            break;
                        }
                    } else {
                        while i < bytes.len() && bytes[i] != b',' && bytes[i] != b']' {
                            i += 1;
                        }
                    }
                }
                rows.push(row);
            }
            b']' => break,
            _ => i += 1,
        }
    }
    rows
}

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(B64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, StoreError> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return Err(StoreError::SnapshotCorrupted(
            "invalid base64 length".into(),
        ));
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        let v0 = b64_val(chunk[0])?;
        let v1 = b64_val(chunk[1])?;
        let v2 = if chunk[2] == b'=' {
            0
        } else {
            b64_val(chunk[2])?
        };
        let v3 = if chunk[3] == b'=' {
            0
        } else {
            b64_val(chunk[3])?
        };
        let triple = ((v0 as u32) << 18) | ((v1 as u32) << 12) | ((v2 as u32) << 6) | (v3 as u32);
        out.push(((triple >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if chunk[3] != b'=' {
            out.push((triple & 0xFF) as u8);
        }
    }
    Ok(out)
}

fn b64_val(b: u8) -> Result<u8, StoreError> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(StoreError::SnapshotCorrupted(format!(
            "invalid base64 byte: {}",
            b
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inarch_types::bonsai::{FileChange, FileType};
    use inarch_types::hash::BlobId;
    use inarch_types::path::MPath;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    #[test]
    fn test_base64_and_json_helpers() {
        let raw = b"Velenza Inarch BonsaiChangeset binary payload \x00\xFF\x7F";
        let encoded = base64_encode(raw);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, raw);

        let spanner_json = r#"{
            "metadata": { "rowType": {} },
            "rows": [
                ["velenza-inarch", "main", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
            ]
        }"#;
        let rows = extract_spanner_rows(spanner_json);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], "velenza-inarch");
        assert_eq!(rows[0][1], "main");
    }

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_gcs_and_spanner_stores_against_mock_cloud_server() {
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var("SPANNER_EMULATOR_HOST");
            std::env::set_var("INARCH_GCP_ACCESS_TOKEN", "test-mock-token-123");
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{}", addr);

        let gcs_objects: Arc<Mutex<HashMap<String, Vec<u8>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let spanner_changesets: Arc<Mutex<HashMap<String, String>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let spanner_refs: Arc<Mutex<HashMap<(String, String), String>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let spanner_derived: Arc<Mutex<HashMap<(String, String), String>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let gcs_clone = gcs_objects.clone();
        let cs_clone = spanner_changesets.clone();
        let refs_clone = spanner_refs.clone();
        let derived_clone = spanner_derived.clone();

        let server_thread = std::thread::spawn(move || {
            for stream_res in listener.incoming() {
                let Ok(mut stream) = stream_res else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                    continue;
                }
                let parts: Vec<&str> = req_line.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }
                let method = parts[0].to_string();
                let path = parts[1].to_string();
                if path == "/__shutdown" {
                    break;
                }

                let mut content_len = 0usize;
                loop {
                    let mut hline = String::new();
                    if reader.read_line(&mut hline).unwrap_or(0) == 0
                        || hline == "\r\n"
                        || hline == "\n"
                    {
                        break;
                    }
                    if let Some((k, v)) = hline.split_once(':')
                        && k.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_len];
                let _ = reader.read_exact(&mut body);
                let body_str = String::from_utf8_lossy(&body).to_string();

                let (status, resp_bytes): (u16, Vec<u8>) = if path
                    .starts_with("/upload/storage/v1/b/test-bucket/o?uploadType=media&name=")
                {
                    let name = path.split("name=").nth(1).unwrap_or("").to_string();
                    gcs_clone.lock().unwrap().insert(name, body);
                    (200, b"{\"status\":\"ok\"}".to_vec())
                } else if path.starts_with("/storage/v1/b/test-bucket/o/") {
                    let rest = path.strip_prefix("/storage/v1/b/test-bucket/o/").unwrap();
                    let name = rest.split('?').next().unwrap_or(rest);
                    if let Some(bytes) = gcs_clone.lock().unwrap().get(name) {
                        (200, bytes.clone())
                    } else {
                        (404, b"not found".to_vec())
                    }
                } else if path.ends_with("/sessions") {
                    (
                        200,
                        b"{\"name\":\"projects/p/instances/i/databases/d/sessions/s1\"}".to_vec(),
                    )
                } else if path.ends_with(":beginTransaction") {
                    (200, b"{\"id\":\"tx-100\"}".to_vec())
                } else if path.ends_with(":rollback") {
                    (200, b"{}".to_vec())
                } else if path.ends_with(":commit") {
                    if body_str.contains("\"ScionChangesets\"") {
                        if let Some(vals_idx) = body_str.find("\"values\":[[") {
                            let sub = &body_str[vals_idx + 11..];
                            let (cs_id, c1) = parse_json_quoted_string(sub).unwrap();
                            let commit_ts_idx =
                                sub.find(",\"spanner.commit_timestamp()\"").unwrap();
                            let before_ts = &sub[..commit_ts_idx];
                            let last_quote_start =
                                before_ts[..before_ts.len() - 1].rfind('"').unwrap();
                            let payload_b64 = &before_ts[last_quote_start + 1..before_ts.len() - 1];
                            let _ = c1;
                            cs_clone
                                .lock()
                                .unwrap()
                                .insert(cs_id, payload_b64.to_string());
                        }
                    } else if body_str.contains("\"ScionRefs\"") {
                        if let Some(vals_idx) = body_str.find("\"values\":[[") {
                            let sub = &body_str[vals_idx + 11..];
                            let (repo, c1) = parse_json_quoted_string(sub).unwrap();
                            let sub2 = sub[c1..].trim_start_matches(',');
                            let (rname, c2) = parse_json_quoted_string(sub2).unwrap();
                            let sub3 = sub2[c2..].trim_start_matches(',');
                            let (cs_id, _) = parse_json_quoted_string(sub3).unwrap();
                            refs_clone.lock().unwrap().insert((repo, rname), cs_id);
                        }
                    } else if body_str.contains("\"ScionDerivedMappings\"")
                        && let Some(vals_idx) = body_str.find("\"values\":[[")
                    {
                        let sub = &body_str[vals_idx + 11..];
                        let (cs_id, c1) = parse_json_quoted_string(sub).unwrap();
                        let sub2 = sub[c1..].trim_start_matches(',');
                        let (kind_s, c2) = parse_json_quoted_string(sub2).unwrap();
                        let sub3 = sub2[c2..].trim_start_matches(',');
                        let (root_h, _) = parse_json_quoted_string(sub3).unwrap();
                        derived_clone
                            .lock()
                            .unwrap()
                            .insert((cs_id, kind_s), root_h);
                    }
                    let _ = method;
                    (
                        200,
                        b"{\"commitTimestamp\":\"2026-10-17T00:00:00Z\"}".to_vec(),
                    )
                } else if path.ends_with(":executeSql") {
                    if body_str.contains("FROM ScionChangesets") {
                        let id = extract_json_string(&body_str, "id").unwrap_or_default();
                        if let Some(b64) = cs_clone.lock().unwrap().get(&id) {
                            (200, format!("{{\"rows\":[[{:?}]]}}", b64).into_bytes())
                        } else {
                            (200, b"{\"rows\":[]}".to_vec())
                        }
                    } else if body_str.contains("SELECT ChangesetId FROM ScionRefs") {
                        let repo = extract_json_string(&body_str, "repo").unwrap_or_default();
                        let rname = extract_json_string(&body_str, "ref").unwrap_or_default();
                        if let Some(cs_id) = refs_clone.lock().unwrap().get(&(repo, rname)) {
                            (200, format!("{{\"rows\":[[{:?}]]}}", cs_id).into_bytes())
                        } else {
                            (200, b"{\"rows\":[]}".to_vec())
                        }
                    } else if body_str
                        .contains("SELECT RepoId, RefName, ChangesetId FROM ScionRefs")
                    {
                        let map = refs_clone.lock().unwrap();
                        let mut row_strs = Vec::new();
                        for ((repo, rname), cs_id) in map.iter() {
                            row_strs.push(format!("[{:?},{:?},{:?}]", repo, rname, cs_id));
                        }
                        (
                            200,
                            format!("{{\"rows\":[{}]}}", row_strs.join(",")).into_bytes(),
                        )
                    } else if body_str.contains("FROM ScionDerivedMappings") {
                        let cs = extract_json_string(&body_str, "cs").unwrap_or_default();
                        let kind = extract_json_string(&body_str, "kind").unwrap_or_default();
                        if let Some(h) = derived_clone.lock().unwrap().get(&(cs, kind)) {
                            (200, format!("{{\"rows\":[[{:?}]]}}", h).into_bytes())
                        } else {
                            (200, b"{\"rows\":[]}".to_vec())
                        }
                    } else {
                        (200, b"{\"rows\":[]}".to_vec())
                    }
                } else {
                    (404, b"unknown route".to_vec())
                };

                let resp_hdr = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status,
                    resp_bytes.len()
                );
                let _ = stream.write_all(resp_hdr.as_bytes());
                let _ = stream.write_all(&resp_bytes);
            }
        });

        // 1. Test GcsBlobStore
        let gcs = GcsBlobStore::with_endpoint("test-bucket", "v1", &endpoint).unwrap();
        let data = b"cloud-native content-addressed chunk";
        let h = ObjectHash::from_domain(ObjectDomain::Chunk, data);
        gcs.put_object(ObjectDomain::Chunk, h, data).unwrap();
        assert!(gcs.has_object(ObjectDomain::Chunk, &h).unwrap());
        let fetched = gcs.get_object(ObjectDomain::Chunk, &h).unwrap().unwrap();
        assert_eq!(fetched, data);

        // 2. Test SpannerMetadataStore (put/get changeset, derived mappings, and serializable CAS)
        let spanner = SpannerMetadataStore::with_endpoint(
            "projects/p/instances/i/databases/d",
            "velenza-inarch-test",
            &endpoint,
        )
        .unwrap();

        let mut fc = BTreeMap::new();
        fc.insert(
            MPath::new("README.md").unwrap(),
            FileChange::Tracked {
                blob_id: BlobId(h),
                file_type: FileType::Regular,
                size: data.len() as u64,
            },
        );
        let cs = BonsaiChangeset::new(
            vec![],
            "tester".into(),
            1_750_000_000,
            0,
            "cloud commit".into(),
            BTreeMap::new(),
            fc,
        )
        .unwrap();
        let cs_id = spanner.put_changeset(&cs).unwrap();

        // Clear local cache to force an actual Spanner SQL SELECT round-trip.
        spanner.changeset_cache.write().unwrap().clear();
        let loaded_cs = spanner.get_changeset(&cs_id).unwrap().unwrap();
        assert_eq!(loaded_cs, cs);

        // Test CAS ref creation and conflict detection.
        assert_eq!(spanner.get_ref("main").unwrap(), None);
        spanner.cas_ref("main", None, cs_id).unwrap();
        assert_eq!(spanner.get_ref("main").unwrap(), Some(cs_id));

        let err = spanner.cas_ref("main", None, cs_id).unwrap_err();
        assert!(matches!(err, StoreError::CasMismatch { .. }));

        // Test derived mapping round-trip.
        spanner
            .put_derived_mapping(cs_id, DerivedDataKind::Fsnode, h)
            .unwrap();
        spanner.derived_cache.write().unwrap().clear();
        assert_eq!(
            spanner
                .get_derived_mapping(cs_id, DerivedDataKind::Fsnode)
                .unwrap(),
            Some(h)
        );

        let _ = curl_request(
            "GET",
            &format!("{}/__shutdown", endpoint),
            "test",
            None,
            None,
        );
        let _ = server_thread.join();
    }

    #[test]
    fn test_principal_and_lease_row_parsers() {
        let p_row = vec![
            "device-alpha@example.iam.gserviceaccount.com".to_string(),
            "workstation".to_string(),
            "*\nrepo-a".to_string(),
            "read\nland\ncheckout_lease".to_string(),
            "active".to_string(),
            "host-alpha".to_string(),
            "1750000000".to_string(),
            "".to_string(),
        ];
        let parsed_p = SpannerMetadataStore::parse_principal_row(&p_row).unwrap();
        assert_eq!(
            parsed_p.principal_email,
            "device-alpha@example.iam.gserviceaccount.com"
        );
        assert_eq!(parsed_p.allowed_repos, vec!["*", "repo-a"]);
        assert_eq!(parsed_p.allowed_ops, vec!["read", "land", "checkout_lease"]);
        assert_eq!(parsed_p.revoked_at_unix, None);

        let l_row = vec![
            "lease-001".to_string(),
            "device-alpha@example.iam.gserviceaccount.com".to_string(),
            "swarm-42".to_string(),
            "task-99".to_string(),
            "repo-a".to_string(),
            "read\nland".to_string(),
            "crates/".to_string(),
            "crates/inarch-store/".to_string(),
            "1750000000".to_string(),
            "1750003600".to_string(),
            "false".to_string(),
            "".to_string(),
        ];
        let parsed_l = SpannerMetadataStore::parse_lease_row(&l_row).unwrap();
        assert_eq!(parsed_l.lease_id, "lease-001");
        assert_eq!(parsed_l.repo_id, "repo-a");
        assert_eq!(
            parsed_l.allowed_write_prefixes,
            vec!["crates/inarch-store/"]
        );
        assert!(!parsed_l.revoked);
    }

    #[test]
    fn test_is_spanner_aborted_detection() {
        assert!(is_spanner_aborted(409, "{}"));
        assert!(is_spanner_aborted(
            400,
            r#"{"error":{"code":409,"status":"ABORTED","message":"Transaction was aborted."}}"#
        ));
        assert!(is_spanner_aborted(
            500,
            "Transaction was aborted due to lock conflict"
        ));
        assert!(!is_spanner_aborted(
            200,
            "{\"commitTimestamp\":\"2026-10-20T00:00:00Z\"}"
        ));
        assert!(!is_spanner_aborted(404, "Session not found"));
    }

    #[test]
    fn test_spanner_session_pool_concurrent_checkout_and_release() {
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var("SPANNER_EMULATOR_HOST");
            std::env::set_var("INARCH_GCP_ACCESS_TOKEN", "test-pool-token");
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{}", addr);
        let next_session_id = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let next_session_clone = next_session_id.clone();

        let server_thread = std::thread::spawn(move || {
            for stream_res in listener.incoming() {
                let Ok(mut stream) = stream_res else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                    continue;
                }
                let parts: Vec<&str> = req_line.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }
                let path = parts[1].to_string();
                if path == "/__shutdown" {
                    break;
                }
                let mut content_len = 0usize;
                loop {
                    let mut hline = String::new();
                    if reader.read_line(&mut hline).unwrap_or(0) == 0
                        || hline == "\r\n"
                        || hline == "\n"
                    {
                        break;
                    }
                    if let Some((k, v)) = hline.split_once(':')
                        && k.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_len];
                let _ = reader.read_exact(&mut body);

                let (status, resp_bytes) = if path.ends_with("/sessions") {
                    let sid = next_session_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let payload = format!(
                        "{{\"name\":\"projects/p/instances/i/databases/d/sessions/s{}\"}}",
                        sid
                    );
                    (200u16, payload.into_bytes())
                } else {
                    (200u16, b"{}".to_vec())
                };
                let resp_hdr = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status,
                    resp_bytes.len()
                );
                let _ = stream.write_all(resp_hdr.as_bytes());
                let _ = stream.write_all(&resp_bytes);
            }
        });

        let spanner = Arc::new(
            SpannerMetadataStore::with_endpoint(
                "projects/p/instances/i/databases/d",
                "pool-repo",
                &endpoint,
            )
            .unwrap(),
        );

        // Check out 4 sessions concurrently and hold them simultaneously so none can be reused until released.
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let sp = spanner.clone();
            let bar = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let s = sp.acquire_session().expect("acquire_session");
                bar.wait();
                sp.release_session(s.clone());
                s
            }));
        }

        let mut sessions = std::collections::HashSet::new();
        for h in handles {
            sessions.insert(h.join().unwrap());
        }
        assert_eq!(
            sessions.len(),
            4,
            "4 concurrent operations must check out 4 distinct Spanner sessions"
        );
        assert_eq!(spanner.idle_session_count(), 4);

        // Subsequent sequential checkouts reuse the pooled sessions without creating new ones.
        let reused = spanner.acquire_session().unwrap();
        assert!(sessions.contains(&reused));
        assert_eq!(spanner.idle_session_count(), 3);
        spanner.release_session(reused);
        assert_eq!(spanner.idle_session_count(), 4);
        assert_eq!(
            next_session_id.load(std::sync::atomic::Ordering::SeqCst),
            5,
            "no extra createSession calls should happen when pooled sessions are available"
        );

        let _ = curl_request("GET", &format!("{}/__shutdown", endpoint), "", None, None);
        let _ = server_thread.join();
    }

    #[test]
    fn test_spanner_cas_ref_and_commit_retry_on_409_aborted() {
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var("SPANNER_EMULATOR_HOST");
            std::env::set_var("INARCH_GCP_ACCESS_TOKEN", "test-abort-token");
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{}", addr);

        let commit_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cas_commit_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let commit_attempts_srv = commit_attempts.clone();
        let cas_commit_attempts_srv = cas_commit_attempts.clone();

        let server_thread = std::thread::spawn(move || {
            for stream_res in listener.incoming() {
                let Ok(mut stream) = stream_res else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                    continue;
                }
                let parts: Vec<&str> = req_line.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }
                let path = parts[1].to_string();
                if path == "/__shutdown" {
                    break;
                }
                let mut content_len = 0usize;
                loop {
                    let mut hline = String::new();
                    if reader.read_line(&mut hline).unwrap_or(0) == 0
                        || hline == "\r\n"
                        || hline == "\n"
                    {
                        break;
                    }
                    if let Some((k, v)) = hline.split_once(':')
                        && k.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_len];
                let _ = reader.read_exact(&mut body);
                let body_str = String::from_utf8_lossy(&body).to_string();

                let (status, resp_bytes): (u16, Vec<u8>) = if path.ends_with("/sessions") {
                    (
                        200,
                        b"{\"name\":\"projects/p/instances/i/databases/d/sessions/s-abort\"}"
                            .to_vec(),
                    )
                } else if path.ends_with(":beginTransaction") {
                    (200, b"{\"id\":\"tx-retry\"}".to_vec())
                } else if path.ends_with(":executeSql") {
                    (200, b"{\"rows\":[]}".to_vec())
                } else if path.ends_with(":commit") {
                    if body_str.contains("\"ScionChangesets\"") {
                        let attempt =
                            commit_attempts_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if attempt < 2 {
                            (
                                409,
                                b"{\"error\":{\"code\":409,\"status\":\"ABORTED\",\"message\":\"Transaction was aborted.\"}}".to_vec(),
                            )
                        } else {
                            (
                                200,
                                b"{\"commitTimestamp\":\"2026-10-20T00:00:00Z\"}".to_vec(),
                            )
                        }
                    } else if body_str.contains("\"ScionRefs\"") {
                        let attempt = cas_commit_attempts_srv
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if attempt < 2 {
                            (
                                409,
                                b"{\"error\":{\"code\":409,\"status\":\"ABORTED\",\"message\":\"Transaction was aborted.\"}}".to_vec(),
                            )
                        } else {
                            (
                                200,
                                b"{\"commitTimestamp\":\"2026-10-20T00:00:00Z\"}".to_vec(),
                            )
                        }
                    } else {
                        (
                            200,
                            b"{\"commitTimestamp\":\"2026-10-20T00:00:00Z\"}".to_vec(),
                        )
                    }
                } else {
                    (200, b"{}".to_vec())
                };

                let resp_hdr = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status,
                    resp_bytes.len()
                );
                let _ = stream.write_all(resp_hdr.as_bytes());
                let _ = stream.write_all(&resp_bytes);
            }
        });

        let spanner = SpannerMetadataStore::with_endpoint(
            "projects/p/instances/i/databases/d",
            "abort-repo",
            &endpoint,
        )
        .unwrap();

        let data = b"retry-on-409-aborted";
        let h = ObjectHash::from_domain(ObjectDomain::Chunk, data);
        let mut fc = BTreeMap::new();
        fc.insert(
            MPath::new("src/retry.rs").unwrap(),
            FileChange::Tracked {
                blob_id: BlobId(h),
                file_type: FileType::Regular,
                size: data.len() as u64,
            },
        );
        let cs = BonsaiChangeset::new(
            vec![],
            "tester".into(),
            1_750_000_000,
            0,
            "commit under contention".into(),
            BTreeMap::new(),
            fc,
        )
        .unwrap();

        // Both put_changeset and cas_ref must transparently retry the two HTTP 409 ABORTED responses and succeed on attempt 3.
        let cs_id = spanner
            .put_changeset(&cs)
            .expect("put_changeset should retry on 409 ABORTED");
        assert_eq!(commit_attempts.load(std::sync::atomic::Ordering::SeqCst), 3);

        spanner
            .cas_ref("main", None, cs_id)
            .expect("cas_ref should retry whole transaction on 409 ABORTED");
        assert_eq!(
            cas_commit_attempts.load(std::sync::atomic::Ordering::SeqCst),
            3
        );

        let _ = curl_request("GET", &format!("{}/__shutdown", endpoint), "", None, None);
        let _ = server_thread.join();
    }

    #[test]
    fn test_spanner_emulator_host_http_and_no_bearer_header() {
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        unsafe {
            std::env::remove_var("INARCH_GCP_ACCESS_TOKEN");
            std::env::set_var("SPANNER_EMULATOR_HOST", addr.to_string());
        }

        let saw_auth_header = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_auth_srv = saw_auth_header.clone();

        let server_thread = std::thread::spawn(move || {
            for stream_res in listener.incoming() {
                let Ok(mut stream) = stream_res else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                    continue;
                }
                let parts: Vec<&str> = req_line.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }
                let path = parts[1].to_string();
                if path == "/__shutdown" {
                    break;
                }
                let mut content_len = 0usize;
                loop {
                    let mut hline = String::new();
                    if reader.read_line(&mut hline).unwrap_or(0) == 0
                        || hline == "\r\n"
                        || hline == "\n"
                    {
                        break;
                    }
                    if let Some((k, v)) = hline.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("authorization") {
                            saw_auth_srv.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let mut body = vec![0u8; content_len];
                let _ = reader.read_exact(&mut body);

                let (status, resp_bytes): (u16, Vec<u8>) = if path.ends_with("/sessions") {
                    (
                        200,
                        b"{\"name\":\"projects/emu/instances/test/databases/db/sessions/s-emu\"}"
                            .to_vec(),
                    )
                } else if path.ends_with(":executeSql") {
                    (200, b"{\"rows\":[]}".to_vec())
                } else {
                    (200, b"{}".to_vec())
                };
                let resp_hdr = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status,
                    resp_bytes.len()
                );
                let _ = stream.write_all(resp_hdr.as_bytes());
                let _ = stream.write_all(&resp_bytes);
            }
        });

        let spanner =
            SpannerMetadataStore::new("projects/emu/instances/test/databases/db", "emu-repo")
                .unwrap();
        assert!(spanner.is_emulator_mode());
        assert_eq!(spanner.api_base_url(), format!("http://{}/v1", addr));

        // Performing a Spanner operation succeeds without any GCP credentials and sends no Authorization header.
        assert_eq!(spanner.get_ref("main").unwrap(), None);
        assert!(
            !saw_auth_header.load(std::sync::atomic::Ordering::SeqCst),
            "emulator mode must not send an Authorization header"
        );

        unsafe {
            std::env::remove_var("SPANNER_EMULATOR_HOST");
        }
        let _ = curl_request(
            "GET",
            &format!("http://{}/__shutdown", addr),
            "",
            None,
            None,
        );
        let _ = server_thread.join();
    }
}
