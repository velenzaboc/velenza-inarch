//! Virtualized On-Demand Workspace Mount (`inr mount` & `inr hydrate`) and Loopback WebDAV VFS.
//!
//! Provides two complementary zero-dependency mechanisms for instant, virtualized workspaces:
//! 1. **Sparse On-Demand Virtual Skeleton (`mount_virtual_workspace` + `hydrate_virtual_paths`)**:
//!    Creates the workspace directory skeleton and `.inarch/virtual_mount.toml` in milliseconds
//!    without downloading or writing any file blobs upfront. Individual files or subtree prefixes
//!    are hydrated on demand via `inr hydrate <mount_dir> <path_or_prefix>`, while Copy-on-Write
//!    edits are tracked seamlessly by `inr status` / `verify_codebase_accuracy` and `inr commit` /
//!    `ingest_directory`.
//! 2. **Loopback OS-Native WebDAV Virtual Filesystem (`spawn_webdav_virtual_mount`)**:
//!    Serves any revision or ref over a zero-dependency loopback HTTP/1.1 WebDAV server
//!    (`OPTIONS`, `PROPFIND`, `GET`, `HEAD`, `PUT`, `DELETE`) mountable natively via macOS Finder /
//!    `mount_webdav`, Linux `davfs2` / GIO, or Windows Explorer without third-party kernel kexts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use inarch_derived::{DerivedError, Fsnode, FsnodeEntry};
use inarch_engine::{
    DirectoryListingEntry, EngineError, PatchFileEdit, PatchSubmission, ScionEngine,
};
use inarch_store::{StoreError, TelemetryEvent};
use inarch_types::bonsai::FileType;
use inarch_types::hash::{BlobId, ChangesetId, FsnodeId, ObjectDomain, ObjectHash, blake3_hash};
use inarch_types::path::MPath;

use crate::CliError;

/// Maximum allowed HTTP/WebDAV request body size (64 MiB).
pub const MAX_WEBDAV_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_WEBDAV_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_WEBDAV_HEADER_LINE_BYTES: usize = 16 * 1024;
const MAX_WEBDAV_HEADERS_BYTES: usize = 32 * 1024;

/// Manifest persisted at `<mount_dir>/.inarch/virtual_mount.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualMountManifest {
    pub changeset_id: ChangesetId,
    pub root_fsnode_id: FsnodeId,
    pub sparse_prefixes: Vec<String>,
    pub hydrated_paths: BTreeSet<String>,
}

impl VirtualMountManifest {
    pub fn manifest_path(mount_dir: &Path) -> std::path::PathBuf {
        mount_dir.join(".inarch").join("virtual_mount.toml")
    }

    pub fn load_if_present(mount_dir: &Path) -> Result<Option<Self>, CliError> {
        let p = Self::manifest_path(mount_dir);
        if !p.is_file() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&p)?;
        Ok(Some(Self::from_toml_str(&raw)?))
    }

    pub fn save(&self, mount_dir: &Path) -> Result<(), CliError> {
        save_virtual_mount_manifest(mount_dir, self).map_err(CliError::Engine)
    }

    pub fn to_toml_string(&self) -> String {
        let mut out = String::new();
        out.push_str("# Velenza Inarch Virtual Mount Manifest (.inarch/virtual_mount.toml)\n");
        out.push_str(&format!(
            "changeset_id = \"{}\"\n",
            self.changeset_id.to_hex()
        ));
        out.push_str(&format!(
            "root_fsnode_id = \"{}\"\n",
            self.root_fsnode_id.to_hex()
        ));
        let sp_list: Vec<String> = self
            .sparse_prefixes
            .iter()
            .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect();
        out.push_str(&format!("sparse_prefixes = [{}]\n", sp_list.join(", ")));
        let hp_list: Vec<String> = self
            .hydrated_paths
            .iter()
            .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect();
        out.push_str(&format!("hydrated_paths = [{}]\n", hp_list.join(", ")));
        out
    }

    pub fn from_toml_str(input: &str) -> Result<Self, CliError> {
        let mut cs_hex = String::new();
        let mut fsnode_hex = String::new();
        let mut sparse_prefixes = Vec::new();
        let mut hydrated_paths = BTreeSet::new();

        for raw_line in input.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let key = k.trim();
            let val = v.trim();
            match key {
                "changeset_id" => {
                    cs_hex = unquote(val);
                }
                "root_fsnode_id" => {
                    fsnode_hex = unquote(val);
                }
                "sparse_prefixes" => {
                    sparse_prefixes = parse_array(val);
                }
                "hydrated_paths" => {
                    hydrated_paths = parse_array(val).into_iter().collect();
                }
                _ => {}
            }
        }

        let changeset_id = ChangesetId::from_hex(&cs_hex).map_err(|e| {
            CliError::InvalidArgument(format!("invalid changeset_id in virtual_mount.toml: {}", e))
        })?;
        let root_fsnode_id = FsnodeId::from_hex(&fsnode_hex).map_err(|e| {
            CliError::InvalidArgument(format!(
                "invalid root_fsnode_id in virtual_mount.toml: {}",
                e
            ))
        })?;

        Ok(Self {
            changeset_id,
            root_fsnode_id,
            sparse_prefixes,
            hydrated_paths,
        })
    }
}

/// Saves `manifest` to `<mount_dir>/.inarch/virtual_mount.toml`.
pub fn save_virtual_mount_manifest(
    mount_dir: &Path,
    manifest: &VirtualMountManifest,
) -> Result<(), EngineError> {
    let p = VirtualMountManifest::manifest_path(mount_dir);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| EngineError::Store(StoreError::Io(e.to_string())))?;
    }
    fs::write(&p, manifest.to_toml_string())
        .map_err(|e| EngineError::Store(StoreError::Io(e.to_string())))?;
    Ok(())
}

fn unquote(val: &str) -> String {
    let t = val.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t[1..t.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        t.to_string()
    }
}

fn parse_array(val: &str) -> Vec<String> {
    let t = val.trim();
    let inner = if t.starts_with('[') && t.ends_with(']') {
        &t[1..t.len() - 1]
    } else {
        t
    };
    inner
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(unquote)
        .filter(|s| !s.is_empty())
        .collect()
}

/// Receipt returned by [`mount_virtual_workspace`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualMountReceipt {
    pub changeset_id: ChangesetId,
    pub root_fsnode_id: FsnodeId,
    pub total_virtual_files: u64,
    pub hydrated_files: usize,
    pub created_directories: usize,
}

/// Receipt returned by [`hydrate_virtual_paths`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydrateReceipt {
    pub changeset_id: ChangesetId,
    pub newly_hydrated_files: usize,
    pub total_hydrated_files: usize,
    pub bytes_written: u64,
}

/// Creates an instant virtual workspace skeleton at `dest_dir` for `cs_id` without materializing
/// any file blobs upfront.
pub fn mount_virtual_workspace(
    engine: &ScionEngine,
    cs_id: ChangesetId,
    sparse_prefixes: &[MPath],
    dest_dir: &Path,
) -> Result<VirtualMountReceipt, CliError> {
    let start = std::time::Instant::now();
    let root_fsnode_id = engine
        .derived()
        .derive_fsnode(cs_id)
        .map_err(EngineError::Derived)?;
    fs::create_dir_all(dest_dir)?;

    let filter_opt = if sparse_prefixes.is_empty() {
        None
    } else {
        Some(sparse_prefixes)
    };

    let mut total_virtual_files = 0u64;
    let mut created_directories = 0usize;
    create_virtual_skeleton(
        engine,
        &root_fsnode_id,
        None,
        filter_opt,
        dest_dir,
        &mut total_virtual_files,
        &mut created_directories,
    )?;

    let manifest = VirtualMountManifest {
        changeset_id: cs_id,
        root_fsnode_id,
        sparse_prefixes: sparse_prefixes
            .iter()
            .map(|p| p.as_str().to_string())
            .collect(),
        hydrated_paths: BTreeSet::new(),
    };
    manifest.save(dest_dir)?;

    let elapsed_us = start.elapsed().as_micros() as u64;
    engine.telemetry().emit(
        &TelemetryEvent::info(
            "mount",
            "mount_virtual_workspace",
            engine.repo_id(),
            format!(
                "mounted virtual workspace at {} ({} virtual files, 0 hydrated)",
                cs_id.to_hex(),
                total_virtual_files
            ),
        )
        .with_duration_us(elapsed_us)
        .with_changeset(cs_id.to_hex()),
    );

    Ok(VirtualMountReceipt {
        changeset_id: cs_id,
        root_fsnode_id,
        total_virtual_files,
        hydrated_files: 0,
        created_directories,
    })
}

fn create_virtual_skeleton(
    engine: &ScionEngine,
    root_fsnode_id: &FsnodeId,
    current_prefix: Option<MPath>,
    sparse_prefixes: Option<&[MPath]>,
    dest_dir: &Path,
    total_virtual_files: &mut u64,
    created_directories: &mut usize,
) -> Result<(), CliError> {
    let mut current_level: Vec<(Option<MPath>, FsnodeId)> = vec![(current_prefix, *root_fsnode_id)];

    while !current_level.is_empty() {
        let level_keys: Vec<(ObjectDomain, ObjectHash)> = current_level
            .iter()
            .map(|(_, id)| (ObjectDomain::Fsnode, id.0))
            .collect();
        let raw_nodes = engine
            .blobs()
            .get_objects_batch(&level_keys)
            .map_err(EngineError::Store)?;

        let mut next_level: Vec<(Option<MPath>, FsnodeId)> = Vec::new();

        for ((prefix_opt, fsnode_id), raw_opt) in current_level.into_iter().zip(raw_nodes) {
            let node = match raw_opt {
                Some(bytes) => Fsnode::from_canonical_bytes(&bytes)
                    .map_err(|e| EngineError::Derived(DerivedError::CorruptPayload(e)))?,
                None => engine
                    .derived()
                    .load_fsnode(&fsnode_id)
                    .map_err(EngineError::Derived)?,
            };

            for (name, entry) in &node.entries {
                let child_path = match &prefix_opt {
                    Some(prefix) => prefix.join_element(name),
                    None => MPath::from_elements(vec![name.clone()]).expect("single element valid"),
                };

                match entry {
                    FsnodeEntry::Directory {
                        fsnode_id: child_id,
                        ..
                    } => {
                        if let Some(prefixes) = sparse_prefixes {
                            if !prefixes
                                .iter()
                                .any(|p| p.is_prefix_of(&child_path) || child_path.is_prefix_of(p))
                            {
                                continue;
                            }
                        }
                        let dir_on_disk = dest_dir.join(child_path.as_str());
                        fs::create_dir_all(&dir_on_disk)?;
                        *created_directories += 1;
                        next_level.push((Some(child_path), *child_id));
                    }
                    FsnodeEntry::File { .. } => {
                        if let Some(prefixes) = sparse_prefixes {
                            if !prefixes.iter().any(|p| p.is_prefix_of(&child_path)) {
                                continue;
                            }
                        }
                        *total_virtual_files += 1;
                    }
                }
            }
        }

        current_level = next_level;
    }

    Ok(())
}

/// Hydrates on demand any files matching `target_prefixes` (exact file paths or directory prefixes)
/// inside an existing virtual workspace mount at `mount_dir`.
pub fn hydrate_virtual_paths(
    engine: &ScionEngine,
    mount_dir: &Path,
    target_prefixes: &[String],
) -> Result<HydrateReceipt, CliError> {
    let start = std::time::Instant::now();
    let mut manifest = VirtualMountManifest::load_if_present(mount_dir)?.ok_or_else(|| {
        CliError::InvalidArgument(format!(
            "directory '{}' does not contain a .inarch/virtual_mount.toml manifest",
            mount_dir.display()
        ))
    })?;

    let mut parsed_targets = Vec::new();
    for raw in target_prefixes {
        let trimmed = raw.trim().trim_matches('/');
        if !trimmed.is_empty() {
            parsed_targets.push(MPath::new(trimmed)?);
        }
    }

    let mut matching_files: Vec<(MPath, BlobId, FileType)> = Vec::new();
    collect_matching_virtual_files(
        engine,
        &manifest.root_fsnode_id,
        None,
        &parsed_targets,
        &mut matching_files,
    )?;

    let mut newly_hydrated_files = 0usize;
    let mut bytes_written = 0u64;

    if !matching_files.is_empty() {
        let blob_ids: Vec<BlobId> = matching_files.iter().map(|(_, id, _)| *id).collect();
        let blob_contents = engine
            .blobs()
            .get_blobs_batch(&blob_ids)
            .map_err(EngineError::Store)?;

        for ((path, _blob_id, file_type), content_opt) in
            matching_files.into_iter().zip(blob_contents)
        {
            let content = content_opt
                .ok_or_else(|| CliError::Engine(EngineError::PathNotFound(path.to_string())))?;

            let disk_path = mount_dir.join(path.as_str());
            if let Some(parent) = disk_path.parent() {
                fs::create_dir_all(parent)?;
            }
            write_materialized_file(&disk_path, &content, file_type)?;
            bytes_written += content.len() as u64;
            if manifest.hydrated_paths.insert(path.as_str().to_string()) {
                newly_hydrated_files += 1;
            }
        }
    }

    manifest.save(mount_dir)?;
    let elapsed_us = start.elapsed().as_micros() as u64;
    engine.telemetry().emit(
        &TelemetryEvent::info(
            "mount",
            "hydrate_virtual_paths",
            engine.repo_id(),
            format!(
                "hydrated {} files ({} bytes) in virtual mount",
                newly_hydrated_files, bytes_written
            ),
        )
        .with_duration_us(elapsed_us)
        .with_changeset(manifest.changeset_id.to_hex()),
    );

    Ok(HydrateReceipt {
        changeset_id: manifest.changeset_id,
        newly_hydrated_files,
        total_hydrated_files: manifest.hydrated_paths.len(),
        bytes_written,
    })
}

fn collect_matching_virtual_files(
    engine: &ScionEngine,
    root_fsnode_id: &FsnodeId,
    current_prefix: Option<MPath>,
    targets: &[MPath],
    out: &mut Vec<(MPath, BlobId, FileType)>,
) -> Result<(), CliError> {
    let mut current_level: Vec<(Option<MPath>, FsnodeId)> = vec![(current_prefix, *root_fsnode_id)];

    while !current_level.is_empty() {
        let level_keys: Vec<(ObjectDomain, ObjectHash)> = current_level
            .iter()
            .map(|(_, id)| (ObjectDomain::Fsnode, id.0))
            .collect();
        let raw_nodes = engine
            .blobs()
            .get_objects_batch(&level_keys)
            .map_err(EngineError::Store)?;

        let mut next_level: Vec<(Option<MPath>, FsnodeId)> = Vec::new();

        for ((prefix_opt, fsnode_id), raw_opt) in current_level.into_iter().zip(raw_nodes) {
            let node = match raw_opt {
                Some(bytes) => Fsnode::from_canonical_bytes(&bytes)
                    .map_err(|e| EngineError::Derived(DerivedError::CorruptPayload(e)))?,
                None => engine
                    .derived()
                    .load_fsnode(&fsnode_id)
                    .map_err(EngineError::Derived)?,
            };

            for (name, entry) in &node.entries {
                let child_path = match &prefix_opt {
                    Some(prefix) => prefix.join_element(name),
                    None => MPath::from_elements(vec![name.clone()]).expect("single element valid"),
                };

                match entry {
                    FsnodeEntry::Directory {
                        fsnode_id: child_id,
                        ..
                    } => {
                        let overlaps = targets.is_empty()
                            || targets
                                .iter()
                                .any(|t| t.is_prefix_of(&child_path) || child_path.is_prefix_of(t));
                        if overlaps {
                            next_level.push((Some(child_path), *child_id));
                        }
                    }
                    FsnodeEntry::File {
                        blob_id, file_type, ..
                    } => {
                        let matches = targets.is_empty()
                            || targets.iter().any(|t| t.is_prefix_of(&child_path));
                        if matches {
                            out.push((child_path, *blob_id, *file_type));
                        }
                    }
                }
            }
        }

        current_level = next_level;
    }

    Ok(())
}

fn write_materialized_file(
    disk_path: &Path,
    content: &[u8],
    file_type: FileType,
) -> Result<(), CliError> {
    if let Ok(meta) = fs::symlink_metadata(disk_path) {
        if meta.file_type().is_dir() {
            fs::remove_dir_all(disk_path)?;
        } else {
            fs::remove_file(disk_path)?;
        }
    }
    match file_type {
        FileType::Symlink => {
            #[cfg(unix)]
            {
                use std::ffi::OsStr;
                use std::os::unix::ffi::OsStrExt;
                let target = Path::new(OsStr::from_bytes(content));
                std::os::unix::fs::symlink(target, disk_path)?;
            }
            #[cfg(not(unix))]
            {
                fs::write(disk_path, content)?;
            }
        }
        FileType::Executable => {
            fs::write(disk_path, content)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(disk_path, fs::Permissions::from_mode(0o755))?;
            }
        }
        FileType::Regular => {
            fs::write(disk_path, content)?;
        }
    }
    Ok(())
}

/// Handle to a running loopback WebDAV virtual filesystem server.
pub struct WebDavMountHandle {
    pub local_addr: SocketAddr,
    pub auth_token: String,
    pub mounted_ref: Option<String>,
    stop: Arc<AtomicBool>,
    join_handle: Option<JoinHandle<()>>,
}

impl WebDavMountHandle {
    /// Signals the loopback WebDAV server to stop and waits for its listener thread to exit.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.local_addr);
        if let Some(jh) = self.join_handle.take() {
            let _ = jh.join();
        }
    }
}

impl Drop for WebDavMountHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.local_addr);
        if let Some(jh) = self.join_handle.take() {
            let _ = jh.join();
        }
    }
}

struct WebDavMountState {
    engine: Arc<ScionEngine>,
    auth_token: String,
    mounted_ref: Option<String>,
    mirror_ref: Option<String>,
    current_changeset: Mutex<ChangesetId>,
    virtual_dirs: Mutex<BTreeSet<String>>,
    locks: Mutex<BTreeMap<String, String>>,
    lock_counter: AtomicU64,
}

impl WebDavMountState {
    fn current_cs(&self) -> ChangesetId {
        if let Some(ref r) = self.mounted_ref
            && let Ok(Some(resolved)) = self.engine.resolve_ref(r)
        {
            if let Ok(mut guard) = self.current_changeset.lock() {
                *guard = resolved;
            }
            return resolved;
        }
        *self
            .current_changeset
            .lock()
            .expect("current_changeset mutex poisoned")
    }

    fn snapshot_virtual_dirs(&self) -> BTreeSet<String> {
        self.virtual_dirs
            .lock()
            .expect("virtual_dirs mutex poisoned")
            .clone()
    }

    fn is_virtual_dir(&self, path_str: &str) -> bool {
        let prefix = format!("{}/", path_str);
        let guard = self
            .virtual_dirs
            .lock()
            .expect("virtual_dirs mutex poisoned");
        guard.contains(path_str) || guard.iter().any(|d| d.starts_with(&prefix))
    }

    fn insert_virtual_dir(&self, path_str: String) {
        self.virtual_dirs
            .lock()
            .expect("virtual_dirs mutex poisoned")
            .insert(path_str);
    }

    fn remove_virtual_dir_subtree(&self, path_str: &str) -> bool {
        let prefix = format!("{}/", path_str);
        let mut guard = self
            .virtual_dirs
            .lock()
            .expect("virtual_dirs mutex poisoned");
        let before = guard.len();
        guard.retain(|d| d != path_str && !d.starts_with(&prefix));
        guard.len() != before
    }

    fn move_virtual_dir_subtree(&self, src_str: &str, dst_str: &str) -> bool {
        let prefix = format!("{}/", src_str);
        let mut guard = self
            .virtual_dirs
            .lock()
            .expect("virtual_dirs mutex poisoned");
        let mut moved = Vec::new();
        guard.retain(|d| {
            if d == src_str {
                moved.push(dst_str.to_string());
                false
            } else if let Some(rest) = d.strip_prefix(&prefix) {
                moved.push(format!("{}/{}", dst_str, rest));
                false
            } else {
                true
            }
        });
        let any_moved = !moved.is_empty();
        for m in moved {
            guard.insert(m);
        }
        any_moved
    }

    fn check_lock_conflict(&self, rel_path: &str, if_header: Option<&str>) -> bool {
        let guard = self.locks.lock().expect("locks mutex poisoned");
        if let Some(existing_token) = guard.get(rel_path)
            && let Some(if_hdr) = if_header
            && !if_hdr.contains(existing_token)
        {
            return true;
        }
        false
    }

    fn land_webdav_patch(
        &self,
        message: String,
        edits: Vec<PatchFileEdit>,
    ) -> Result<ChangesetId, CliError> {
        let Some(ref target_ref) = self.mounted_ref else {
            return Err(CliError::InvalidArgument(
                "detached changeset mount is read-only".to_string(),
            ));
        };
        let base = self.engine.resolve_ref(target_ref)?.or_else(|| {
            Some(
                *self
                    .current_changeset
                    .lock()
                    .expect("current_changeset mutex poisoned"),
            )
        });
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(1_760_000_000);
        let outcome = self.engine.land_patch(PatchSubmission {
            target_ref: target_ref.clone(),
            base_changeset: base,
            author: "webdav-vfs@inarch.local".to_string(),
            timestamp: now,
            tz_offset_secs: 0,
            message,
            extra: BTreeMap::new(),
            edits,
        })?;
        {
            let mut guard = self
                .current_changeset
                .lock()
                .expect("current_changeset mutex poisoned");
            *guard = outcome.changeset_id;
        }
        if let Some(ref mirror) = self.mirror_ref
            && let Ok(cur_mirror) = self.engine.meta().get_ref(mirror)
        {
            let _ = self
                .engine
                .meta()
                .cas_ref(mirror, cur_mirror, outcome.changeset_id);
        }
        Ok(outcome.changeset_id)
    }
}

/// Spawns a zero-dependency loopback HTTP/1.1 + WebDAV virtual filesystem server backed directly by
/// [`ScionEngine`] at `target_ref` (which may be a branch ref like `"refs/heads/main"` / `"main"`
/// or a 64-hex `ChangesetId` for a read-only detached mount).
///
/// Supported WebDAV/HTTP methods:
/// - `OPTIONS`: advertises `DAV: 1, 2` and allowed methods.
/// - `PROPFIND`: returns a `207 Multi-Status` XML directory/file listing derived on demand from `Fsnode`s.
/// - `GET` / `HEAD`: streams file bytes on demand via `engine.read_file` with `ETag`.
/// - `PUT` / `DELETE` / `MKCOL` / `MOVE`: commits Copy-on-Write `BonsaiChangeset`s onto `target_ref`
///   when mounted on a mutable branch ref, or rejects with `405 Method Not Allowed` on detached changeset mounts.
/// - `LOCK` / `UNLOCK`: in-memory exclusive write lock table for RFC 4918 Class 2 OS WebDAV clients.
pub fn spawn_webdav_virtual_mount(
    engine: Arc<ScionEngine>,
    target_ref: String,
    bind_addr: &str,
) -> Result<WebDavMountHandle, CliError> {
    let addrs: Vec<SocketAddr> = bind_addr
        .to_socket_addrs()
        .map_err(|e| {
            CliError::InvalidArgument(format!(
                "invalid WebDAV bind address '{}': {}",
                bind_addr, e
            ))
        })?
        .collect();
    if addrs.is_empty() || addrs.iter().any(|a| !a.ip().is_loopback()) {
        return Err(CliError::InvalidArgument(
            "WebDAV virtual mount must bind to a loopback address (127.0.0.1 or ::1)".to_string(),
        ));
    }

    let (mounted_ref, mirror_ref, initial_cs_id) =
        resolve_initial_webdav_target(&engine, &target_ref)?;

    let listener = TcpListener::bind(bind_addr)?;
    let local_addr = listener.local_addr()?;
    if !local_addr.ip().is_loopback() {
        return Err(CliError::InvalidArgument(
            "WebDAV virtual mount must bind to a loopback address (127.0.0.1 or ::1)".to_string(),
        ));
    }

    let auth_token = generate_webdav_auth_token();
    let state = Arc::new(WebDavMountState {
        engine,
        auth_token: auth_token.clone(),
        mounted_ref: mounted_ref.clone(),
        mirror_ref,
        current_changeset: Mutex::new(initial_cs_id),
        virtual_dirs: Mutex::new(BTreeSet::new()),
        locks: Mutex::new(BTreeMap::new()),
        lock_counter: AtomicU64::new(1),
    });

    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);

    let join_handle = thread::spawn(move || {
        for stream_res in listener.incoming() {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(stream) = stream_res {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                let st = Arc::clone(&state);
                thread::spawn(move || {
                    let _ = handle_webdav_connection(stream, &st);
                });
            }
        }
    });

    Ok(WebDavMountHandle {
        local_addr,
        auth_token,
        mounted_ref,
        stop,
        join_handle: Some(join_handle),
    })
}

fn is_64_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn resolve_initial_webdav_target(
    engine: &ScionEngine,
    target_ref: &str,
) -> Result<(Option<String>, Option<String>, ChangesetId), CliError> {
    if let Some(cs_id) = engine.resolve_ref(target_ref)? {
        let mirror = if let Some(short) = target_ref.strip_prefix("refs/heads/") {
            Some(short.to_string())
        } else if !target_ref.starts_with("refs/") {
            Some(format!("refs/heads/{}", target_ref))
        } else {
            None
        };
        return Ok((Some(target_ref.to_string()), mirror, cs_id));
    }

    if !is_64_hex(target_ref) {
        if let Some(short) = target_ref.strip_prefix("refs/heads/")
            && let Some(cs_id) = engine.resolve_ref(short)?
        {
            engine
                .meta()
                .cas_ref(target_ref, None, cs_id)
                .map_err(EngineError::Store)?;
            return Ok((Some(target_ref.to_string()), Some(short.to_string()), cs_id));
        } else if !target_ref.starts_with("refs/") {
            let full = format!("refs/heads/{}", target_ref);
            if let Some(cs_id) = engine.resolve_ref(&full)? {
                engine
                    .meta()
                    .cas_ref(target_ref, None, cs_id)
                    .map_err(EngineError::Store)?;
                return Ok((Some(target_ref.to_string()), Some(full), cs_id));
            }
        }
        return Err(CliError::Engine(EngineError::UnknownRef(
            target_ref.to_string(),
        )));
    }

    let cs_id = ChangesetId::from_hex(target_ref)?;
    engine
        .derived()
        .derive_fsnode(cs_id)
        .map_err(EngineError::Derived)?;
    Ok((None, None, cs_id))
}

fn generate_webdav_auth_token() -> String {
    if let Ok(env_token) = std::env::var("INARCH_WEBDAV_TOKEN") {
        let trimmed = env_token.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let mut buf = [0u8; 32];
    if let Ok(mut f) = fs::File::open("/dev/urandom")
        && f.read_exact(&mut buf).is_ok()
    {
        return hex_encode(&buf);
    }
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!(
        "inarch-webdav-token:{}:{}:{:p}",
        now_nanos,
        std::process::id(),
        &buf
    );
    blake3_hash(seed.as_bytes()).to_hex()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.is_empty() || clean.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks_exact(4) {
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            let c = val(chunk[2])?;
            out.push((b << 4) | (c >> 2));
            if chunk[3] != b'=' {
                let d = val(chunk[3])?;
                out.push((c << 6) | d);
            }
        }
    }
    Some(out)
}

fn is_allowed_loopback_host(raw_host: &str) -> bool {
    let trimmed = raw_host.trim();
    if trimmed.is_empty() {
        return false;
    }
    let host_only = if trimmed.starts_with('[') {
        let Some(end_idx) = trimmed.find(']') else {
            return false;
        };
        let rest = &trimmed[end_idx + 1..];
        if !rest.is_empty() && !rest.starts_with(':') {
            return false;
        }
        &trimmed[..=end_idx]
    } else if trimmed == "::1" {
        "::1"
    } else {
        trimmed.split(':').next().unwrap_or("")
    };
    host_only == "127.0.0.1"
        || host_only.eq_ignore_ascii_case("localhost")
        || host_only == "[::1]"
        || host_only == "::1"
}

fn verify_request_auth(
    auth_header: Option<&str>,
    token_header: Option<&str>,
    expected_token: &str,
) -> bool {
    let expected = expected_token.as_bytes();
    if let Some(tok) = token_header
        && constant_time_eq(tok.trim().as_bytes(), expected)
    {
        return true;
    }
    let Some(auth) = auth_header else {
        return false;
    };
    let trimmed = auth.trim();
    if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
        let candidate = trimmed[7..].trim();
        return constant_time_eq(candidate.as_bytes(), expected);
    }
    if trimmed.len() > 6 && trimmed[..6].eq_ignore_ascii_case("basic ") {
        let b64 = trimmed[6..].trim();
        if let Some(decoded) = base64_decode(b64)
            && let Ok(creds) = std::str::from_utf8(&decoded)
        {
            let password = creds.split_once(':').map(|(_, p)| p).unwrap_or(creds);
            return constant_time_eq(password.as_bytes(), expected);
        }
    }
    false
}

fn extract_destination_rel_path(dest_header: &str) -> String {
    let trimmed = dest_header.trim();
    let without_scheme = if let Some(rest) = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
    {
        match rest.find('/') {
            Some(idx) => &rest[idx..],
            None => "/",
        }
    } else {
        trimmed
    };
    let without_query = without_scheme.split('?').next().unwrap_or("/");
    let stripped = without_query.trim_matches('/');
    percent_decode_path(stripped)
}

fn check_if_match(if_match_header: Option<&str>, current_cs: ChangesetId) -> bool {
    let Some(raw) = if_match_header else {
        return true;
    };
    let trimmed = raw.trim();
    if trimmed == "*" {
        return true;
    }
    let expected_hex = current_cs.to_hex();
    for candidate in trimmed.split(',') {
        let c = candidate
            .trim()
            .strip_prefix("W/")
            .unwrap_or(candidate.trim())
            .trim_matches('"');
        if c == expected_hex {
            return true;
        }
    }
    false
}

fn handle_webdav_connection(
    mut stream: TcpStream,
    state: &WebDavMountState,
) -> Result<(), CliError> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let Some(request_line) = read_http_line_limited(
        &mut reader,
        MAX_WEBDAV_REQUEST_LINE_BYTES,
        "request line",
    )? else {
        return Ok(());
    };
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0];
    let raw_uri = parts[1];
    let raw_path = raw_uri.split('?').next().unwrap_or("/").trim_matches('/');
    let rel_path = percent_decode_path(raw_path);

    let mut content_length = 0usize;
    let mut malformed_content_length = false;
    let mut depth_header = "1".to_string();
    let mut host_header: Option<String> = None;
    let mut auth_header: Option<String> = None;
    let mut token_header: Option<String> = None;
    let mut destination_header: Option<String> = None;
    let mut overwrite_header = "T".to_string();
    let mut if_match_header: Option<String> = None;
    let mut if_header: Option<String> = None;
    let mut lock_token_header: Option<String> = None;
    let mut file_type_header: Option<String> = None;

    let mut total_header_bytes = 0usize;
    loop {
        let Some(line) = read_http_line_limited(
            &mut reader,
            MAX_WEBDAV_HEADER_LINE_BYTES,
            "header line",
        )? else {
            break;
        };
        total_header_bytes = total_header_bytes
            .checked_add(line.len())
            .ok_or_else(|| CliError::Io("WebDAV header length overflow".to_string()))?;
        if total_header_bytes > MAX_WEBDAV_HEADERS_BYTES {
            return Err(CliError::Io(
                "WebDAV headers exceed the 32 KiB limit".to_string(),
            ));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("content-length") {
                match val.parse::<usize>() {
                    Ok(n) => content_length = n,
                    Err(_) => malformed_content_length = true,
                }
            } else if key.eq_ignore_ascii_case("depth") {
                depth_header = val.to_string();
            } else if key.eq_ignore_ascii_case("host") {
                host_header = Some(val.to_string());
            } else if key.eq_ignore_ascii_case("authorization") {
                auth_header = Some(val.to_string());
            } else if key.eq_ignore_ascii_case("x-inarch-mount-token") {
                token_header = Some(val.to_string());
            } else if key.eq_ignore_ascii_case("destination") {
                destination_header = Some(val.to_string());
            } else if key.eq_ignore_ascii_case("overwrite") {
                overwrite_header = val.to_string();
            } else if key.eq_ignore_ascii_case("if-match") {
                if_match_header = Some(val.to_string());
            } else if key.eq_ignore_ascii_case("if") {
                if_header = Some(val.to_string());
            } else if key.eq_ignore_ascii_case("lock-token") {
                lock_token_header = Some(val.to_string());
            } else if key.eq_ignore_ascii_case("x-inarch-file-type") {
                file_type_header = Some(val.to_string());
            }
        }
    }

    // 1. Validate Host header against DNS rebinding before any further processing.
    if let Some(ref h) = host_header
        && !is_allowed_loopback_host(h)
    {
        return write_http_response(
            &mut stream,
            "403 Forbidden",
            "text/plain",
            b"Forbidden: Host header must be loopback (127.0.0.1, localhost, or ::1)",
        );
    }

    // 2. Reject malformed Content-Length or oversized payloads before allocating body buffer.
    if malformed_content_length {
        return write_http_response(
            &mut stream,
            "400 Bad Request",
            "text/plain",
            b"Bad Request: malformed Content-Length header",
        );
    }
    if content_length > MAX_WEBDAV_BODY_BYTES {
        return write_http_response(
            &mut stream,
            "413 Payload Too Large",
            "text/plain",
            b"Payload Too Large: request body exceeds 64 MiB WebDAV limit",
        );
    }

    // 3. Require valid bearer / mount token authentication on every request.
    if !verify_request_auth(
        auth_header.as_deref(),
        token_header.as_deref(),
        &state.auth_token,
    ) {
        return write_http_response_with_headers(
            &mut stream,
            "401 Unauthorized",
            "text/plain",
            &[("WWW-Authenticate", "Bearer realm=\"inarch-webdav\"")],
            b"Unauthorized: missing or invalid WebDAV bearer token",
        );
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let engine = &state.engine;

    match method {
        "OPTIONS" => {
            let resp = "HTTP/1.1 200 OK\r\nDAV: 1, 2\r\nAllow: OPTIONS, GET, HEAD, PROPFIND, PUT, DELETE, MKCOL, MOVE, LOCK, UNLOCK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(resp.as_bytes())?;
        }
        "PROPFIND" => {
            let cs_id = state.current_cs();
            let mpath_opt = if rel_path.is_empty() {
                None
            } else {
                let Ok(mp) = MPath::new(&rel_path) else {
                    return write_http_response(
                        &mut stream,
                        "400 Bad Request",
                        "text/plain",
                        b"invalid file path",
                    );
                };
                Some(mp)
            };
            let vdirs = state.snapshot_virtual_dirs();
            match build_propfind_xml(engine, cs_id, mpath_opt.as_ref(), &depth_header, &vdirs) {
                Ok(xml) => {
                    let etag = format!("\"{}\"", cs_id.to_hex());
                    write_http_response_with_headers(
                        &mut stream,
                        "207 Multi-Status",
                        "application/xml; charset=utf-8",
                        &[("ETag", &etag)],
                        xml.as_bytes(),
                    )?;
                }
                Err(e) => {
                    write_http_response(
                        &mut stream,
                        "404 Not Found",
                        "text/plain",
                        e.to_string().as_bytes(),
                    )?;
                }
            }
        }
        "GET" | "HEAD" => {
            let cs_id = state.current_cs();
            let Ok(mpath) = MPath::new(&rel_path) else {
                return write_http_response(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    b"invalid file path",
                );
            };
            match engine.read_file(cs_id, &mpath) {
                Ok(bytes) => {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nETag: \"{}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        cs_id.to_hex(),
                        bytes.len()
                    );
                    stream.write_all(header.as_bytes())?;
                    if method == "GET" {
                        stream.write_all(&bytes)?;
                    }
                }
                Err(e) => {
                    write_http_response(
                        &mut stream,
                        "404 Not Found",
                        "text/plain",
                        e.to_string().as_bytes(),
                    )?;
                }
            }
        }
        "PUT" => {
            if state.mounted_ref.is_none() {
                return write_detached_readonly_error(&mut stream);
            }
            let current_cs = state.current_cs();
            if !check_if_match(if_match_header.as_deref(), current_cs) {
                return write_http_response(
                    &mut stream,
                    "412 Precondition Failed",
                    "text/plain",
                    b"Precondition Failed: If-Match does not match current changeset ETag",
                );
            }
            if state.check_lock_conflict(&rel_path, if_header.as_deref()) {
                return write_http_response(
                    &mut stream,
                    "423 Locked",
                    "text/plain",
                    b"Locked: resource is locked by another token",
                );
            }
            let Ok(mpath) = MPath::new(&rel_path) else {
                return write_http_response(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    b"invalid file path",
                );
            };

            // Preserve existing FileType (e.g. Executable) when updating an existing file unless overridden.
            let file_type = if let Some(ref ft_hdr) = file_type_header {
                if ft_hdr.eq_ignore_ascii_case("executable") {
                    FileType::Executable
                } else if ft_hdr.eq_ignore_ascii_case("symlink") {
                    FileType::Symlink
                } else {
                    FileType::Regular
                }
            } else {
                let root_fsnode_id = engine
                    .derived()
                    .derive_fsnode(current_cs)
                    .map_err(EngineError::Derived)?;
                match engine
                    .derived()
                    .lookup_fsnode_path(&root_fsnode_id, &mpath)
                    .map_err(EngineError::Derived)?
                {
                    Some(FsnodeEntry::File { file_type, .. }) => file_type,
                    _ => FileType::Regular,
                }
            };

            let new_cs_id = state.land_webdav_patch(
                format!("webdav PUT {}", mpath),
                vec![PatchFileEdit::Upsert {
                    path: mpath,
                    content: body,
                    file_type,
                }],
            )?;
            let etag = format!("\"{}\"", new_cs_id.to_hex());
            write_http_response_with_headers(
                &mut stream,
                "201 Created",
                "text/plain",
                &[("ETag", &etag)],
                new_cs_id.to_hex().as_bytes(),
            )?;
        }
        "DELETE" => {
            if state.mounted_ref.is_none() {
                return write_detached_readonly_error(&mut stream);
            }
            let current_cs = state.current_cs();
            if !check_if_match(if_match_header.as_deref(), current_cs) {
                return write_http_response(
                    &mut stream,
                    "412 Precondition Failed",
                    "text/plain",
                    b"Precondition Failed: If-Match does not match current changeset ETag",
                );
            }
            if state.check_lock_conflict(&rel_path, if_header.as_deref()) {
                return write_http_response(
                    &mut stream,
                    "423 Locked",
                    "text/plain",
                    b"Locked: resource is locked by another token",
                );
            }
            let Ok(mpath) = MPath::new(&rel_path) else {
                return write_http_response(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    b"invalid file path",
                );
            };

            let root_fsnode_id = engine
                .derived()
                .derive_fsnode(current_cs)
                .map_err(EngineError::Derived)?;
            let entry_opt = engine
                .derived()
                .lookup_fsnode_path(&root_fsnode_id, &mpath)
                .map_err(EngineError::Derived)?;

            let mut edits = Vec::new();
            match entry_opt {
                Some(FsnodeEntry::File { .. }) => {
                    edits.push(PatchFileEdit::Delete {
                        path: mpath.clone(),
                    });
                }
                Some(FsnodeEntry::Directory { fsnode_id, .. }) => {
                    let mut sub_files = Vec::new();
                    collect_matching_virtual_files(
                        engine,
                        &fsnode_id,
                        Some(mpath.clone()),
                        &[],
                        &mut sub_files,
                    )?;
                    for (sub_path, _, _) in sub_files {
                        edits.push(PatchFileEdit::Delete { path: sub_path });
                    }
                    state.remove_virtual_dir_subtree(mpath.as_str());
                }
                None => {
                    if state.remove_virtual_dir_subtree(mpath.as_str()) {
                        let etag = format!("\"{}\"", current_cs.to_hex());
                        return write_http_response_with_headers(
                            &mut stream,
                            "200 OK",
                            "text/plain",
                            &[("ETag", &etag)],
                            current_cs.to_hex().as_bytes(),
                        );
                    }
                    edits.push(PatchFileEdit::Delete {
                        path: mpath.clone(),
                    });
                }
            }

            let new_cs_id = state.land_webdav_patch(format!("webdav DELETE {}", mpath), edits)?;
            let etag = format!("\"{}\"", new_cs_id.to_hex());
            write_http_response_with_headers(
                &mut stream,
                "200 OK",
                "text/plain",
                &[("ETag", &etag)],
                new_cs_id.to_hex().as_bytes(),
            )?;
        }
        "MKCOL" => {
            if state.mounted_ref.is_none() {
                return write_detached_readonly_error(&mut stream);
            }
            if content_length > 0 {
                return write_http_response(
                    &mut stream,
                    "415 Unsupported Media Type",
                    "text/plain",
                    b"Unsupported Media Type: MKCOL with request body is not supported",
                );
            }
            if rel_path.is_empty() {
                return write_http_response(
                    &mut stream,
                    "405 Method Not Allowed",
                    "text/plain",
                    b"Method Not Allowed: root collection already exists",
                );
            }
            let Ok(mpath) = MPath::new(&rel_path) else {
                return write_http_response(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    b"invalid directory path",
                );
            };
            let current_cs = state.current_cs();
            let root_fsnode_id = engine
                .derived()
                .derive_fsnode(current_cs)
                .map_err(EngineError::Derived)?;

            // Check if path already exists in current_cs or virtual_dirs.
            if engine
                .derived()
                .lookup_fsnode_path(&root_fsnode_id, &mpath)
                .map_err(EngineError::Derived)?
                .is_some()
                || state.is_virtual_dir(mpath.as_str())
            {
                return write_http_response(
                    &mut stream,
                    "405 Method Not Allowed",
                    "text/plain",
                    b"Method Not Allowed: collection or resource already exists",
                );
            }

            // Verify parent collection exists if path has a parent.
            if let Some(parent_mpath) = mpath.parent() {
                let parent_in_cs = matches!(
                    engine
                        .derived()
                        .lookup_fsnode_path(&root_fsnode_id, &parent_mpath)
                        .map_err(EngineError::Derived)?,
                    Some(FsnodeEntry::Directory { .. })
                );
                if !parent_in_cs && !state.is_virtual_dir(parent_mpath.as_str()) {
                    return write_http_response(
                        &mut stream,
                        "409 Conflict",
                        "text/plain",
                        b"Conflict: parent collection does not exist",
                    );
                }
            }

            state.insert_virtual_dir(mpath.as_str().to_string());
            let etag = format!("\"{}\"", current_cs.to_hex());
            write_http_response_with_headers(
                &mut stream,
                "201 Created",
                "text/plain",
                &[("ETag", &etag)],
                b"Created",
            )?;
        }
        "MOVE" => {
            if state.mounted_ref.is_none() {
                return write_detached_readonly_error(&mut stream);
            }
            let current_cs = state.current_cs();
            if !check_if_match(if_match_header.as_deref(), current_cs) {
                return write_http_response(
                    &mut stream,
                    "412 Precondition Failed",
                    "text/plain",
                    b"Precondition Failed: If-Match does not match current changeset ETag",
                );
            }
            let Some(ref dest_hdr) = destination_header else {
                return write_http_response(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    b"Bad Request: missing Destination header",
                );
            };
            let dest_rel = extract_destination_rel_path(dest_hdr);
            let Ok(src_mpath) = MPath::new(&rel_path) else {
                return write_http_response(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    b"invalid source path",
                );
            };
            let Ok(dest_mpath) = MPath::new(&dest_rel) else {
                return write_http_response(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    b"invalid destination path",
                );
            };
            if src_mpath == dest_mpath {
                return write_http_response(
                    &mut stream,
                    "403 Forbidden",
                    "text/plain",
                    b"Forbidden: source and destination are identical",
                );
            }
            if state.check_lock_conflict(&rel_path, if_header.as_deref())
                || state.check_lock_conflict(&dest_rel, if_header.as_deref())
            {
                return write_http_response(
                    &mut stream,
                    "423 Locked",
                    "text/plain",
                    b"Locked: source or destination is locked",
                );
            }

            let root_fsnode_id = engine
                .derived()
                .derive_fsnode(current_cs)
                .map_err(EngineError::Derived)?;
            let dest_entry = engine
                .derived()
                .lookup_fsnode_path(&root_fsnode_id, &dest_mpath)
                .map_err(EngineError::Derived)?;
            let dest_exists = dest_entry.is_some() || state.is_virtual_dir(dest_mpath.as_str());
            if overwrite_header.eq_ignore_ascii_case("F") && dest_exists {
                return write_http_response(
                    &mut stream,
                    "412 Precondition Failed",
                    "text/plain",
                    b"Precondition Failed: destination exists and Overwrite is F",
                );
            }

            let src_entry = engine
                .derived()
                .lookup_fsnode_path(&root_fsnode_id, &src_mpath)
                .map_err(EngineError::Derived)?;

            match src_entry {
                Some(FsnodeEntry::File {
                    blob_id, file_type, ..
                }) => {
                    let content = engine
                        .blobs()
                        .get_blob_content(&blob_id)
                        .map_err(EngineError::Store)?
                        .ok_or_else(|| {
                            CliError::Engine(EngineError::PathNotFound(src_mpath.to_string()))
                        })?;
                    let edits = vec![
                        PatchFileEdit::Upsert {
                            path: dest_mpath.clone(),
                            content,
                            file_type,
                        },
                        PatchFileEdit::Delete {
                            path: src_mpath.clone(),
                        },
                    ];
                    let new_cs_id = state.land_webdav_patch(
                        format!("webdav MOVE {} -> {}", src_mpath, dest_mpath),
                        edits,
                    )?;
                    let etag = format!("\"{}\"", new_cs_id.to_hex());
                    let status = if dest_exists {
                        "204 No Content"
                    } else {
                        "201 Created"
                    };
                    write_http_response_with_headers(
                        &mut stream,
                        status,
                        "text/plain",
                        &[("ETag", &etag)],
                        b"",
                    )?;
                }
                Some(FsnodeEntry::Directory { fsnode_id, .. }) => {
                    let mut sub_files = Vec::new();
                    collect_matching_virtual_files(engine, &fsnode_id, None, &[], &mut sub_files)?;
                    let blob_ids: Vec<BlobId> = sub_files.iter().map(|(_, id, _)| *id).collect();
                    let contents = engine
                        .blobs()
                        .get_blobs_batch(&blob_ids)
                        .map_err(EngineError::Store)?;
                    let mut edits = Vec::with_capacity(sub_files.len() * 2);
                    for ((rel_sub, _, file_type), content_opt) in
                        sub_files.into_iter().zip(contents)
                    {
                        let content = content_opt.ok_or_else(|| {
                            CliError::Engine(EngineError::PathNotFound(rel_sub.to_string()))
                        })?;
                        let old_full = src_mpath.join(&rel_sub);
                        let new_full = dest_mpath.join(&rel_sub);
                        edits.push(PatchFileEdit::Upsert {
                            path: new_full,
                            content,
                            file_type,
                        });
                        edits.push(PatchFileEdit::Delete { path: old_full });
                    }
                    state.move_virtual_dir_subtree(src_mpath.as_str(), dest_mpath.as_str());
                    let new_cs_id = state.land_webdav_patch(
                        format!("webdav MOVE {} -> {}", src_mpath, dest_mpath),
                        edits,
                    )?;
                    let etag = format!("\"{}\"", new_cs_id.to_hex());
                    let status = if dest_exists {
                        "204 No Content"
                    } else {
                        "201 Created"
                    };
                    write_http_response_with_headers(
                        &mut stream,
                        status,
                        "text/plain",
                        &[("ETag", &etag)],
                        b"",
                    )?;
                }
                None => {
                    if state.move_virtual_dir_subtree(src_mpath.as_str(), dest_mpath.as_str()) {
                        let etag = format!("\"{}\"", current_cs.to_hex());
                        let status = if dest_exists {
                            "204 No Content"
                        } else {
                            "201 Created"
                        };
                        write_http_response_with_headers(
                            &mut stream,
                            status,
                            "text/plain",
                            &[("ETag", &etag)],
                            b"",
                        )?;
                    } else {
                        write_http_response(
                            &mut stream,
                            "404 Not Found",
                            "text/plain",
                            b"source path not found",
                        )?;
                    }
                }
            }
        }
        "LOCK" => {
            let mut locks_guard = state.locks.lock().expect("locks mutex poisoned");
            if let Some(existing_token) = locks_guard.get(&rel_path) {
                let is_refresh = if_header
                    .as_deref()
                    .is_some_and(|hdr| hdr.contains(existing_token));
                if !is_refresh {
                    return write_http_response(
                        &mut stream,
                        "423 Locked",
                        "text/plain",
                        b"Locked: resource already has an active exclusive write lock",
                    );
                }
            }
            let seq = state.lock_counter.fetch_add(1, Ordering::Relaxed);
            let now_nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let token_urn = format!("opaquelocktoken:{:016x}{:016x}", now_nanos, seq);
            locks_guard.insert(rel_path.clone(), token_urn.clone());
            drop(locks_guard);

            let lock_header_val = format!("<{}>", token_urn);
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:prop xmlns:D=\"DAV:\">\n  <D:lockdiscovery>\n    <D:activelock>\n      <D:locktype><D:write/></D:locktype>\n      <D:lockscope><D:exclusive/></D:lockscope>\n      <D:depth>infinity</D:depth>\n      <D:timeout>Second-3600</D:timeout>\n      <D:locktoken><D:href>{}</D:href></D:locktoken>\n    </D:activelock>\n  </D:lockdiscovery>\n</D:prop>\n",
                xml_escape(&token_urn)
            );
            write_http_response_with_headers(
                &mut stream,
                "200 OK",
                "application/xml; charset=utf-8",
                &[("Lock-Token", &lock_header_val)],
                xml.as_bytes(),
            )?;
        }
        "UNLOCK" => {
            let mut locks_guard = state.locks.lock().expect("locks mutex poisoned");
            if let Some(existing) = locks_guard.get(&rel_path) {
                let expected = format!("<{existing}>");
                if lock_token_header.as_deref().map(str::trim) != Some(expected.as_str()) {
                    return write_http_response(
                        &mut stream,
                        "423 Locked",
                        "text/plain",
                        b"Locked: Lock-Token does not match active lock",
                    );
                }
            }
            locks_guard.remove(&rel_path);
            drop(locks_guard);
            write_http_response(&mut stream, "204 No Content", "text/plain", b"")?;
        }
        _ => {
            write_http_response(
                &mut stream,
                "405 Method Not Allowed",
                "text/plain",
                b"unsupported method",
            )?;
        }
    }
    Ok(())
}

fn read_http_line_limited<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
    label: &str,
) -> Result<Option<String>, CliError> {
    let mut bytes = Vec::with_capacity(max_bytes.min(1024));
    let read = reader
        .take((max_bytes + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() > max_bytes {
        return Err(CliError::Io(format!(
            "WebDAV {label} exceeds the {max_bytes}-byte limit"
        )));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| CliError::Io(format!("WebDAV {label} is not valid UTF-8")))
}

fn write_detached_readonly_error(stream: &mut TcpStream) -> Result<(), CliError> {
    write_http_response(
        stream,
        "405 Method Not Allowed",
        "application/json",
        br#"{"error":"WebDAV mount is attached to a detached immutable changeset ID; mount a branch ref (e.g. refs/heads/main) to enable writes"}"#,
    )
}

fn percent_decode_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn build_propfind_xml(
    engine: &ScionEngine,
    cs_id: ChangesetId,
    path: Option<&MPath>,
    depth: &str,
    virtual_dirs: &BTreeSet<String>,
) -> Result<String, CliError> {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n",
    );

    if let Some(p) = path {
        let root_fsnode_id = engine
            .derived()
            .derive_fsnode(cs_id)
            .map_err(EngineError::Derived)?;
        let entry_opt = engine
            .derived()
            .lookup_fsnode_path(&root_fsnode_id, p)
            .map_err(EngineError::Derived)?;
        match entry_opt {
            Some(FsnodeEntry::File { size, .. }) => {
                let file_href = format!("/{}", xml_escape(p.as_str()));
                xml.push_str(&format!(
                    "  <D:response>\n    <D:href>{}</D:href>\n    <D:propstat>\n      <D:prop>\n        <D:resourcetype/>\n        <D:getcontentlength>{}</D:getcontentlength>\n      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n</D:multistatus>\n",
                    file_href, size
                ));
                return Ok(xml);
            }
            Some(FsnodeEntry::Directory { .. }) => {}
            None => {
                let prefix = format!("{}/", p.as_str());
                let is_vdir = virtual_dirs.contains(p.as_str())
                    || virtual_dirs.iter().any(|d| d.starts_with(&prefix));
                if !is_vdir {
                    return Err(CliError::Engine(EngineError::PathNotFound(p.to_string())));
                }
            }
        }
    }

    let base_href = match path {
        Some(p) => format!("/{}/", xml_escape(p.as_str())),
        None => "/".to_string(),
    };
    xml.push_str(&format!(
        "  <D:response>\n    <D:href>{}</D:href>\n    <D:propstat>\n      <D:prop>\n        <D:resourcetype><D:collection/></D:resourcetype>\n      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n",
        base_href
    ));

    if depth != "0" {
        let mut seen_names = BTreeSet::new();
        if let Ok(entries) = engine.list_directory(cs_id, path) {
            for entry in entries {
                match entry {
                    DirectoryListingEntry::File { name, size, .. } => {
                        seen_names.insert(name.as_str().to_string());
                        let href = format!("{}{}", base_href, xml_escape(name.as_str()));
                        xml.push_str(&format!(
                            "  <D:response>\n    <D:href>{}</D:href>\n    <D:propstat>\n      <D:prop>\n        <D:resourcetype/>\n        <D:getcontentlength>{}</D:getcontentlength>\n      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n",
                            href, size
                        ));
                    }
                    DirectoryListingEntry::Directory { name, .. } => {
                        seen_names.insert(name.as_str().to_string());
                        let href = format!("{}{}/", base_href, xml_escape(name.as_str()));
                        xml.push_str(&format!(
                            "  <D:response>\n    <D:href>{}</D:href>\n    <D:propstat>\n      <D:prop>\n        <D:resourcetype><D:collection/></D:resourcetype>\n      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n",
                            href
                        ));
                    }
                }
            }
        }

        // Also include direct child virtual directories created via MKCOL.
        let prefix = match path {
            Some(p) => format!("{}/", p.as_str()),
            None => String::new(),
        };
        for vdir in virtual_dirs {
            let rel = if prefix.is_empty() {
                Some(vdir.as_str())
            } else {
                vdir.strip_prefix(&prefix)
            };
            if let Some(r) = rel
                && !r.is_empty()
            {
                let child_name = r.split('/').next().unwrap_or(r);
                if seen_names.insert(child_name.to_string()) {
                    let href = format!("{}{}/", base_href, xml_escape(child_name));
                    xml.push_str(&format!(
                        "  <D:response>\n    <D:href>{}</D:href>\n    <D:propstat>\n      <D:prop>\n        <D:resourcetype><D:collection/></D:resourcetype>\n      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n",
                        href
                    ));
                }
            }
        }
    }

    xml.push_str("</D:multistatus>\n");
    Ok(xml)
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), CliError> {
    write_http_response_with_headers(stream, status, content_type, &[], body)
}

fn write_http_response_with_headers(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(), CliError> {
    let mut header = format!("HTTP/1.1 {}\r\nContent-Type: {}\r\n", status, content_type);
    for (k, v) in extra_headers {
        header.push_str(&format!("{}: {}\r\n", k, v));
    }
    header.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    stream.write_all(header.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use inarch_store::{MemBlobStore, MemMetadataStore};

    fn make_test_engine() -> Arc<ScionEngine> {
        let blobs = Arc::new(MemBlobStore::new());
        let meta = Arc::new(MemMetadataStore::new());
        Arc::new(ScionEngine::new(blobs, meta))
    }

    fn seed_test_repo(engine: &ScionEngine) -> ChangesetId {
        let outcome = engine
            .land_patch(PatchSubmission {
                target_ref: "refs/heads/main".to_string(),
                base_changeset: None,
                author: "tester@inarch.local".to_string(),
                timestamp: 1_760_000_000,
                tz_offset_secs: 0,
                message: "initial commit".to_string(),
                extra: BTreeMap::new(),
                edits: vec![
                    PatchFileEdit::Upsert {
                        path: MPath::new("README.md").expect("valid mpath"),
                        content: b"# Hello Inarch\n".to_vec(),
                        file_type: FileType::Regular,
                    },
                    PatchFileEdit::Upsert {
                        path: MPath::new("scripts/run.sh").expect("valid mpath"),
                        content: b"#!/bin/sh\necho v1\n".to_vec(),
                        file_type: FileType::Executable,
                    },
                    PatchFileEdit::Upsert {
                        path: MPath::new("src/lib/mod.rs").expect("valid mpath"),
                        content: b"pub fn answer() -> u32 { 42 }\n".to_vec(),
                        file_type: FileType::Regular,
                    },
                ],
            })
            .expect("seed commit should succeed");
        outcome.changeset_id
    }

    fn send_raw_http(addr: SocketAddr, req: &str, body: &[u8]) -> String {
        let mut stream = TcpStream::connect(addr).expect("connect to loopback webdav");
        stream.write_all(req.as_bytes()).expect("write headers");
        if !body.is_empty() {
            stream.write_all(body).expect("write body");
        }
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).expect("read response");
        String::from_utf8_lossy(&resp).into_owned()
    }

    #[test]
    fn b4_webdav_unauthenticated_writer_and_security_guards() {
        let engine = make_test_engine();
        let _cs = seed_test_repo(&engine);

        // 1. Non-loopback bind (0.0.0.0:0) must be rejected before binding.
        let non_loopback = spawn_webdav_virtual_mount(
            Arc::clone(&engine),
            "refs/heads/main".to_string(),
            "0.0.0.0:0",
        );
        assert!(
            non_loopback.is_err(),
            "non-loopback bind address 0.0.0.0:0 must be rejected"
        );

        let handle = spawn_webdav_virtual_mount(
            Arc::clone(&engine),
            "refs/heads/main".to_string(),
            "127.0.0.1:0",
        )
        .expect("loopback bind should succeed");
        let addr = handle.local_addr;
        let token = handle.auth_token.clone();
        assert!(!token.is_empty(), "auth_token must be non-empty");

        // 2. Unauthenticated GET and PUT must return 401 Unauthorized.
        let unauth_get = send_raw_http(
            addr,
            "GET /README.md HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            b"",
        );
        assert!(
            unauth_get.starts_with("HTTP/1.1 401 Unauthorized"),
            "unexpected unauth GET response: {}",
            unauth_get
        );
        assert!(unauth_get.contains("WWW-Authenticate: Bearer"));

        let unauth_put = send_raw_http(
            addr,
            "PUT /pwned.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\n",
            b"evil",
        );
        assert!(
            unauth_put.starts_with("HTTP/1.1 401 Unauthorized"),
            "unexpected unauth PUT response: {}",
            unauth_put
        );

        // 3. DNS-rebinding Host header must return 403 Forbidden even with valid token.
        let rebind_req = format!(
            "GET /README.md HTTP/1.1\r\nHost: evil.example.com\r\nAuthorization: Bearer {}\r\n\r\n",
            token
        );
        let rebind_resp = send_raw_http(addr, &rebind_req, b"");
        assert!(
            rebind_resp.starts_with("HTTP/1.1 403 Forbidden"),
            "unexpected DNS rebinding response: {}",
            rebind_resp
        );

        // 4. Malformed Content-Length: abc must return 400 Bad Request.
        let bad_cl_req = format!(
            "PUT /README.md HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Length: abc\r\n\r\n",
            token
        );
        let bad_cl_resp = send_raw_http(addr, &bad_cl_req, b"");
        assert!(
            bad_cl_resp.starts_with("HTTP/1.1 400 Bad Request"),
            "unexpected malformed Content-Length response: {}",
            bad_cl_resp
        );

        // 5. Oversized Content-Length: 999999999 must return 413 Payload Too Large without OOM.
        let huge_cl_req = format!(
            "PUT /README.md HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Length: 999999999\r\n\r\n",
            token
        );
        let huge_cl_resp = send_raw_http(addr, &huge_cl_req, b"");
        assert!(
            huge_cl_resp.starts_with("HTTP/1.1 413 Payload Too Large"),
            "unexpected oversized Content-Length response: {}",
            huge_cl_resp
        );

        handle.shutdown();
    }

    #[test]
    fn s1_webdav_hex_target_versus_branch_ref_mount() {
        let engine = make_test_engine();
        let initial_cs = seed_test_repo(&engine);

        // 1. Mount by branch ref ("refs/heads/main"), PUT a file, verify ref advances and GET sees new content.
        let handle_ref = spawn_webdav_virtual_mount(
            Arc::clone(&engine),
            "refs/heads/main".to_string(),
            "127.0.0.1:0",
        )
        .expect("mount branch ref");
        let addr_ref = handle_ref.local_addr;
        let token_ref = handle_ref.auth_token.clone();

        let body = b"# Updated via WebDAV\n";
        let put_req = format!(
            "PUT /README.md HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n",
            token_ref,
            body.len()
        );
        let put_resp = send_raw_http(addr_ref, &put_req, body);
        assert!(
            put_resp.starts_with("HTTP/1.1 201 Created"),
            "PUT on branch ref failed: {}",
            put_resp
        );

        let advanced_cs = engine
            .resolve_ref("refs/heads/main")
            .expect("resolve_ref")
            .expect("ref exists");
        assert_ne!(
            advanced_cs, initial_cs,
            "refs/heads/main should advance after WebDAV PUT"
        );

        let get_req = format!(
            "GET /README.md HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            token_ref
        );
        let get_resp = send_raw_http(addr_ref, &get_req, b"");
        assert!(get_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(
            get_resp.ends_with("# Updated via WebDAV\n"),
            "subsequent GET must return updated content, got: {}",
            get_resp
        );
        handle_ref.shutdown();

        // 2. Mount by raw 64-hex ChangesetId: GET works at that immutable revision, PUT returns 405 Method Not Allowed.
        let handle_hex =
            spawn_webdav_virtual_mount(Arc::clone(&engine), initial_cs.to_hex(), "127.0.0.1:0")
                .expect("mount detached hex changeset");
        let addr_hex = handle_hex.local_addr;
        let token_hex = handle_hex.auth_token.clone();

        let get_old_req = format!(
            "GET /README.md HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\n\r\n",
            token_hex
        );
        let get_old_resp = send_raw_http(addr_hex, &get_old_req, b"");
        assert!(get_old_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(get_old_resp.ends_with("# Hello Inarch\n"));

        let put_hex_req = format!(
            "PUT /README.md HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Length: 4\r\n\r\n",
            token_hex
        );
        let put_hex_resp = send_raw_http(addr_hex, &put_hex_req, b"nope");
        assert!(
            put_hex_resp.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "PUT on detached changeset mount must return 405, got: {}",
            put_hex_resp
        );
        assert!(
            engine
                .resolve_ref(&initial_cs.to_hex())
                .expect("resolve_ref")
                .is_none(),
            "detached 64-hex changeset ID must never be created as a bogus ref"
        );
        handle_hex.shutdown();
    }

    #[test]
    fn s2_and_s3_webdav_protocol_subset_and_write_semantics() {
        let engine = make_test_engine();
        let _initial_cs = seed_test_repo(&engine);

        let handle = spawn_webdav_virtual_mount(
            Arc::clone(&engine),
            "refs/heads/main".to_string(),
            "127.0.0.1:0",
        )
        .expect("mount webdav");
        let addr = handle.local_addr;
        let token = handle.auth_token.clone();

        // 1. MKCOL creates a virtual directory (201 Created).
        let mkcol_req = format!(
            "MKCOL /docs HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\n\r\n",
            token
        );
        let mkcol_resp = send_raw_http(addr, &mkcol_req, b"");
        assert!(
            mkcol_resp.starts_with("HTTP/1.1 201 Created"),
            "MKCOL failed: {}",
            mkcol_resp
        );

        // PROPFIND on root shows /docs/.
        let propfind_req = format!(
            "PROPFIND / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nDepth: 1\r\n\r\n",
            token
        );
        let propfind_resp = send_raw_http(addr, &propfind_req, b"");
        assert!(propfind_resp.starts_with("HTTP/1.1 207 Multi-Status"));
        assert!(propfind_resp.contains("<D:href>/docs/</D:href>"));

        // 2. PUT a file inside /docs.
        let note_body = b"architecture notes";
        let put_note_req = format!(
            "PUT /docs/note.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n",
            token,
            note_body.len()
        );
        let put_note_resp = send_raw_http(addr, &put_note_req, note_body);
        assert!(put_note_resp.starts_with("HTTP/1.1 201 Created"));

        // 3. MOVE /docs/note.txt -> /docs/renamed.txt and verify old path is deleted & new path has content.
        let move_req = format!(
            "MOVE /docs/note.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nDestination: http://127.0.0.1/docs/renamed.txt\r\n\r\n",
            token
        );
        let move_resp = send_raw_http(addr, &move_req, b"");
        assert!(
            move_resp.starts_with("HTTP/1.1 201 Created")
                || move_resp.starts_with("HTTP/1.1 204 No Content"),
            "MOVE failed: {}",
            move_resp
        );

        let get_old = send_raw_http(
            addr,
            &format!(
                "GET /docs/note.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\n\r\n",
                token
            ),
            b"",
        );
        assert!(get_old.starts_with("HTTP/1.1 404 Not Found"));

        let get_new = send_raw_http(
            addr,
            &format!(
                "GET /docs/renamed.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\n\r\n",
                token
            ),
            b"",
        );
        assert!(get_new.starts_with("HTTP/1.1 200 OK"));
        assert!(get_new.ends_with("architecture notes"));

        // 4. LOCK / UNLOCK roundtrip.
        let lock_req = format!(
            "LOCK /docs/renamed.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\n\r\n",
            token
        );
        let lock_resp = send_raw_http(addr, &lock_req, b"");
        assert!(
            lock_resp.starts_with("HTTP/1.1 200 OK"),
            "LOCK failed: {}",
            lock_resp
        );
        assert!(lock_resp.contains("opaquelocktoken:"));

        // Conflicting second LOCK without If header returns 423 Locked.
        let lock_conflict = send_raw_http(addr, &lock_req, b"");
        assert!(
            lock_conflict.starts_with("HTTP/1.1 423 Locked"),
            "conflicting LOCK should return 423: {}",
            lock_conflict
        );

        let lock_token = lock_resp
            .lines()
            .find_map(|line| line.strip_prefix("Lock-Token: "))
            .expect("LOCK response must carry its token");
        let unlock_req = format!(
            "UNLOCK /docs/renamed.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nLock-Token: {}\r\n\r\n",
            token, lock_token
        );
        let unlock_resp = send_raw_http(addr, &unlock_req, b"");
        assert!(
            unlock_resp.starts_with("HTTP/1.1 204 No Content"),
            "UNLOCK failed: {}",
            unlock_resp
        );

        // 5. PUT update to an existing FileType::Executable file preserves FileType::Executable.
        let new_script = b"#!/bin/sh\necho v2\n";
        let put_exec_req = format!(
            "PUT /scripts/run.sh HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n",
            token,
            new_script.len()
        );
        let put_exec_resp = send_raw_http(addr, &put_exec_req, new_script);
        assert!(put_exec_resp.starts_with("HTTP/1.1 201 Created"));

        let head_cs = engine
            .resolve_ref("refs/heads/main")
            .expect("resolve")
            .expect("head exists");
        let root_fsnode = engine
            .derived()
            .derive_fsnode(head_cs)
            .expect("derive_fsnode");
        let script_entry = engine
            .derived()
            .lookup_fsnode_path(&root_fsnode, &MPath::new("scripts/run.sh").unwrap())
            .expect("lookup")
            .expect("scripts/run.sh exists");
        match script_entry {
            FsnodeEntry::File { file_type, .. } => {
                assert_eq!(
                    file_type,
                    FileType::Executable,
                    "PUT to existing executable file must preserve FileType::Executable"
                );
            }
            other => panic!("expected File entry, got {:?}", other),
        }

        handle.shutdown();
    }

    #[test]
    fn s4_mount_virtual_workspace_batched_level_order_skeleton() {
        let engine = make_test_engine();
        let cs_id = seed_test_repo(&engine);
        let tmp_dir = std::env::temp_dir().join(format!(
            "inarch-mount-unit-test-{}-{}",
            std::process::id(),
            cs_id.to_hex()
        ));
        let _ = fs::remove_dir_all(&tmp_dir);

        let receipt = mount_virtual_workspace(&engine, cs_id, &[], &tmp_dir)
            .expect("mount_virtual_workspace");
        assert_eq!(receipt.total_virtual_files, 3);
        assert_eq!(receipt.hydrated_files, 0);
        assert!(tmp_dir.join("scripts").is_dir());
        assert!(tmp_dir.join("src/lib").is_dir());

        let hydrate = hydrate_virtual_paths(&engine, &tmp_dir, &["scripts".to_string()])
            .expect("hydrate_virtual_paths");
        assert_eq!(hydrate.newly_hydrated_files, 1);
        assert!(tmp_dir.join("scripts/run.sh").is_file());

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
