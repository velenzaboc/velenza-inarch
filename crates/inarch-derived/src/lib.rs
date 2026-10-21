//! Recursive Derived Data Engine (`inarch-derived`) for Velenza Inarch.
//!
//! Inductively derives and caches four derived data families from `BonsaiChangeset`s:
//! - [`Fsnode`]: Content-addressed Merkle directory trees with recursive [`FsnodeSummary`] counts.
//! - [`UnodeFile`] & [`UnodeManifest`]: Per-file and per-directory history graphs for $O(k)$ `log <path>`.
//! - [`BlameV2`]: Inductive line-by-line attribution derived along `UnodeFile` edges.
//! - [`CommitGraphNode`]: Topological generation numbers and binary-lifting skip pointers for $O(\log N)$ ancestry.

pub mod blame;
pub mod commit_graph;
pub mod copy_detection;
pub mod fsnode;
pub mod path_search;
pub mod unode;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, RwLock};

use inarch_store::{BlobStore, DerivedDataKind, MetadataStore, StoreError};
use inarch_types::bonsai::{BonsaiChangeset, FileChange, FileType};
use inarch_types::hash::{
    BlobId, ChangesetId, CopyInfoId, FsnodeId, ObjectDomain, ObjectHash, PathSearchIndexId,
    UnodeFileId, UnodeManifestId,
};
use inarch_types::path::{MPath, MPathElement};

pub use blame::{BlameLine, BlameV2};
pub use commit_graph::{CommitGraphNode, collect_commits_between};
pub use copy_detection::{CopyDetectionReport, CopyKind, CopyRecord, compute_line_similarity_bps};
pub use fsnode::{Fsnode, FsnodeEntry, FsnodeSummary};
pub use path_search::{PathSearchEntry, PathSearchIndex, glob_match};
pub use unode::{UnodeEntry, UnodeFile, UnodeManifest};

/// Alias for [`DerivedDataEngine`] used by commit-graph and CLI callers.
pub type DerivedDataManager = DerivedDataEngine;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedError {
    Store(StoreError),
    UnknownChangeset(ChangesetId),
    MissingObject {
        domain: ObjectDomain,
        id_hex: String,
    },
    PathNotFound(String),
    NotAFile(String),
    NotADirectory(String),
    CorruptDerivedObject(String),
    CorruptPayload(String),
}

impl fmt::Display for DerivedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store error: {}", e),
            Self::UnknownChangeset(id) => write!(f, "unknown changeset {}", id),
            Self::MissingObject { domain, id_hex } => {
                write!(f, "missing {:?} object {}", domain, id_hex)
            }
            Self::PathNotFound(p) => write!(f, "path not found: {}", p),
            Self::NotAFile(p) => write!(f, "path is not a file: {}", p),
            Self::NotADirectory(p) => write!(f, "path is not a directory: {}", p),
            Self::CorruptDerivedObject(msg) | Self::CorruptPayload(msg) => {
                write!(f, "corrupt derived object: {}", msg)
            }
        }
    }
}

impl std::error::Error for DerivedError {}

impl From<StoreError> for DerivedError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Engine coordinating inductive derivation across `BlobStore` and `MetadataStore`.
pub struct DerivedDataEngine {
    blobs: Arc<dyn BlobStore>,
    meta: Arc<dyn MetadataStore>,
    commit_graph_cache: RwLock<BTreeMap<ChangesetId, CommitGraphNode>>,
    blame_cache: RwLock<BTreeMap<UnodeFileId, BlameV2>>,
}

impl DerivedDataEngine {
    pub fn new<B, M>(blobs: Arc<B>, meta: Arc<M>) -> Self
    where
        B: BlobStore + 'static,
        M: MetadataStore + 'static,
    {
        Self::from_dyn(blobs, meta)
    }

    pub fn from_dyn(blobs: Arc<dyn BlobStore>, meta: Arc<dyn MetadataStore>) -> Self {
        Self {
            blobs,
            meta,
            commit_graph_cache: RwLock::new(BTreeMap::new()),
            blame_cache: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn blobs(&self) -> &Arc<dyn BlobStore> {
        &self.blobs
    }

    pub fn meta(&self) -> &Arc<dyn MetadataStore> {
        &self.meta
    }

    // =========================================================================
    // 1. Fsnode Inductive Merkle Tree Derivation
    // =========================================================================

    /// Inductively derives and stores the root [`FsnodeId`] for `cs_id` in $O(\Delta \cdot \text{depth})$.
    pub fn derive_fsnode(&self, cs_id: ChangesetId) -> Result<FsnodeId, DerivedError> {
        if let Some(hash) = self
            .meta
            .get_derived_mapping(cs_id, DerivedDataKind::Fsnode)?
        {
            return Ok(FsnodeId::from_hash(hash));
        }

        let cs = self
            .meta
            .get_changeset(&cs_id)?
            .ok_or(DerivedError::UnknownChangeset(cs_id))?;

        let mut parent_root_ids = Vec::with_capacity(cs.parents.len());
        for &p in &cs.parents {
            parent_root_ids.push(self.derive_fsnode(p)?);
        }

        let mut split_changes = BTreeMap::new();
        for (path, change) in &cs.file_changes {
            split_changes.insert(path.elements().to_vec(), change.clone());
        }

        let mut pending_fsnodes = Vec::new();
        let (root_id, _) = self
            .apply_fsnode_changes(&parent_root_ids, &split_changes, true, &mut pending_fsnodes)?
            .expect("root Fsnode is never pruned");

        if !pending_fsnodes.is_empty() {
            self.blobs.put_objects_batch(&pending_fsnodes)?;
        }

        self.meta
            .put_derived_mapping(cs_id, DerivedDataKind::Fsnode, root_id.0)?;
        Ok(root_id)
    }

    fn apply_fsnode_changes(
        &self,
        parent_dir_ids: &[FsnodeId],
        changes: &BTreeMap<Vec<MPathElement>, FileChange>,
        is_root: bool,
        pending_fsnodes: &mut Vec<(ObjectDomain, ObjectHash, Vec<u8>)>,
    ) -> Result<Option<(FsnodeId, FsnodeSummary)>, DerivedError> {
        let mut loaded_parents = Vec::with_capacity(parent_dir_ids.len());
        for dir_id in parent_dir_ids {
            loaded_parents.push(self.load_fsnode(dir_id)?);
        }

        let mut entries = if let Some(first_parent) = loaded_parents.first() {
            first_parent.entries.clone()
        } else {
            BTreeMap::new()
        };

        let mut subdir_changes: BTreeMap<MPathElement, BTreeMap<Vec<MPathElement>, FileChange>> =
            BTreeMap::new();
        for parent_fsnode in loaded_parents.iter().skip(1) {
            for (name, entry) in &parent_fsnode.entries {
                match (entries.get(name), entry) {
                    (None, _) => {
                        entries.insert(name.clone(), entry.clone());
                    }
                    (
                        Some(FsnodeEntry::Directory { fsnode_id: id0, .. }),
                        FsnodeEntry::Directory { fsnode_id: id1, .. },
                    ) if id0 != id1 => {
                        subdir_changes.entry(name.clone()).or_default();
                    }
                    _ => {}
                }
            }
        }

        let mut direct_tracked: Vec<(MPathElement, BlobId, u64, FileType)> = Vec::new();

        // Step 1: Apply direct file deletions at this directory level and partition remaining changes.
        for (parts, change) in changes {
            if parts.len() == 1 {
                let name = parts[0].clone();
                match change {
                    FileChange::Tracked {
                        blob_id,
                        size,
                        file_type,
                    } => {
                        direct_tracked.push((name, *blob_id, *size, *file_type));
                    }
                    FileChange::Deleted => {
                        entries.remove(&name);
                    }
                }
            } else if parts.len() > 1 {
                let head = parts[0].clone();
                let tail = parts[1..].to_vec();
                subdir_changes
                    .entry(head)
                    .or_default()
                    .insert(tail, change.clone());
            }
        }

        // Step 2: Apply recursive subdirectory changes (handles File -> Directory and prunes empty dirs before Directory -> File).
        for (dir_name, sub_map) in subdir_changes {
            let mut child_parent_ids = Vec::new();
            for p_fsnode in &loaded_parents {
                if let Some(FsnodeEntry::Directory { fsnode_id, .. }) =
                    p_fsnode.entries.get(&dir_name)
                {
                    if !child_parent_ids.contains(fsnode_id) {
                        child_parent_ids.push(*fsnode_id);
                    }
                }
            }
            match self.apply_fsnode_changes(&child_parent_ids, &sub_map, false, pending_fsnodes)? {
                Some((new_child_id, new_child_summary)) => {
                    entries.insert(
                        dir_name,
                        FsnodeEntry::Directory {
                            fsnode_id: new_child_id,
                            summary: new_child_summary,
                        },
                    );
                }
                None => {
                    entries.remove(&dir_name);
                }
            }
        }

        // Step 3: Apply direct tracked files at this directory level (handles Directory -> File cleanly).
        for (name, blob_id, size, file_type) in direct_tracked {
            entries.insert(
                name,
                FsnodeEntry::File {
                    blob_id,
                    size,
                    file_type,
                },
            );
        }

        if entries.is_empty() && !is_root {
            return Ok(None);
        }

        let fsnode = Fsnode::new(entries);
        let summary = fsnode.summary();
        let bytes = fsnode.to_canonical_bytes();
        let id = FsnodeId::from_canonical_bytes(&bytes);
        pending_fsnodes.push((ObjectDomain::Fsnode, id.0, bytes));
        Ok(Some((id, summary)))
    }

    /// Loads an [`Fsnode`] by its [`FsnodeId`].
    pub fn load_fsnode(&self, fsnode_id: &FsnodeId) -> Result<Fsnode, DerivedError> {
        let bytes = self
            .blobs
            .get_object(ObjectDomain::Fsnode, &fsnode_id.0)?
            .ok_or_else(|| DerivedError::MissingObject {
                domain: ObjectDomain::Fsnode,
                id_hex: fsnode_id.to_hex(),
            })?;
        Fsnode::from_canonical_bytes(&bytes).map_err(DerivedError::CorruptDerivedObject)
    }

    /// Resolves `path` starting from `root_fsnode_id` in $O(\text{depth})$ hash lookups.
    pub fn lookup_fsnode_path(
        &self,
        root_fsnode_id: &FsnodeId,
        path: &MPath,
    ) -> Result<Option<FsnodeEntry>, DerivedError> {
        let mut current_dir = self.load_fsnode(root_fsnode_id)?;
        let elems = path.elements();
        for (idx, elem) in elems.iter().enumerate() {
            let Some(entry) = current_dir.entries.get(elem).cloned() else {
                return Ok(None);
            };
            if idx + 1 == elems.len() {
                return Ok(Some(entry));
            }
            match entry {
                FsnodeEntry::Directory { fsnode_id, .. } => {
                    current_dir = self.load_fsnode(&fsnode_id)?;
                }
                FsnodeEntry::File { .. } => return Ok(None),
            }
        }
        Ok(None)
    }

    // =========================================================================
    // 2. Unode Inductive Per-File & Per-Directory History Graph Derivation
    // =========================================================================

    /// Inductively derives and stores the root [`UnodeManifestId`] for `cs_id`.
    pub fn derive_unode(&self, cs_id: ChangesetId) -> Result<UnodeManifestId, DerivedError> {
        if let Some(hash) = self
            .meta
            .get_derived_mapping(cs_id, DerivedDataKind::Unode)?
        {
            return Ok(UnodeManifestId::from_hash(hash));
        }

        let cs = self
            .meta
            .get_changeset(&cs_id)?
            .ok_or(DerivedError::UnknownChangeset(cs_id))?;

        let mut parent_manifests = Vec::with_capacity(cs.parents.len());
        for &p in &cs.parents {
            parent_manifests.push(self.derive_unode(p)?);
        }

        let mut split_changes = BTreeMap::new();
        for (path, change) in &cs.file_changes {
            split_changes.insert(path.elements().to_vec(), change.clone());
        }

        let root_manifest_id = self
            .apply_unode_changes(parent_manifests, &split_changes, cs_id, true)?
            .expect("root UnodeManifest is never pruned");

        self.meta
            .put_derived_mapping(cs_id, DerivedDataKind::Unode, root_manifest_id.0)?;
        Ok(root_manifest_id)
    }

    fn apply_unode_changes(
        &self,
        parent_manifest_ids: Vec<UnodeManifestId>,
        changes: &BTreeMap<Vec<MPathElement>, FileChange>,
        linknode: ChangesetId,
        is_root: bool,
    ) -> Result<Option<UnodeManifestId>, DerivedError> {
        if changes.is_empty() && parent_manifest_ids.len() == 1 {
            return Ok(Some(parent_manifest_ids[0]));
        }

        let mut loaded_parents = Vec::with_capacity(parent_manifest_ids.len());
        for pid in &parent_manifest_ids {
            loaded_parents.push(self.load_unode_manifest(pid)?);
        }

        let mut entries = if let Some(first_parent) = loaded_parents.first() {
            first_parent.entries.clone()
        } else {
            BTreeMap::new()
        };

        let mut subdir_changes: BTreeMap<MPathElement, BTreeMap<Vec<MPathElement>, FileChange>> =
            BTreeMap::new();
        for p_manifest in loaded_parents.iter().skip(1) {
            for (name, entry) in &p_manifest.entries {
                match (entries.get(name), entry) {
                    (None, _) => {
                        entries.insert(name.clone(), *entry);
                    }
                    (Some(UnodeEntry::Directory(id0)), UnodeEntry::Directory(id1))
                        if id0 != id1 =>
                    {
                        subdir_changes.entry(name.clone()).or_default();
                    }
                    _ => {}
                }
            }
        }

        let mut direct_tracked: Vec<(MPathElement, BlobId, FileType)> = Vec::new();

        // Step 1: Apply direct file deletions at this directory level and partition remaining changes.
        for (parts, change) in changes {
            if parts.len() == 1 {
                let name = parts[0].clone();
                match change {
                    FileChange::Tracked {
                        blob_id, file_type, ..
                    } => {
                        direct_tracked.push((name, *blob_id, *file_type));
                    }
                    FileChange::Deleted => {
                        entries.remove(&name);
                    }
                }
            } else if parts.len() > 1 {
                let head = parts[0].clone();
                let tail = parts[1..].to_vec();
                subdir_changes
                    .entry(head)
                    .or_default()
                    .insert(tail, change.clone());
            }
        }

        // Step 2: Apply recursive subdirectory changes.
        for (dir_name, sub_map) in subdir_changes {
            let mut child_parent_ids = Vec::new();
            for p_manifest in &loaded_parents {
                if let Some(UnodeEntry::Directory(pmid)) = p_manifest.entries.get(&dir_name) {
                    if !child_parent_ids.contains(pmid) {
                        child_parent_ids.push(*pmid);
                    }
                }
            }
            match self.apply_unode_changes(child_parent_ids, &sub_map, linknode, false)? {
                Some(new_child_mid) => {
                    entries.insert(dir_name, UnodeEntry::Directory(new_child_mid));
                }
                None => {
                    entries.remove(&dir_name);
                }
            }
        }

        // Step 3: Apply direct tracked files at this directory level.
        for (name, blob_id, file_type) in direct_tracked {
            let mut file_parents = Vec::new();
            for p_manifest in &loaded_parents {
                if let Some(UnodeEntry::File(pfid)) = p_manifest.entries.get(&name) {
                    if !file_parents.contains(pfid) {
                        file_parents.push(*pfid);
                    }
                }
            }
            let unode_file = UnodeFile {
                parents: file_parents,
                blob_id,
                file_type,
                linknode,
            };
            let bytes = unode_file.to_canonical_bytes();
            let fid = UnodeFileId::from_canonical_bytes(&bytes);
            self.blobs
                .put_object(ObjectDomain::UnodeFile, fid.0, &bytes)?;
            entries.insert(name, UnodeEntry::File(fid));
        }

        if entries.is_empty() && !is_root {
            return Ok(None);
        }

        let manifest = UnodeManifest {
            parents: parent_manifest_ids,
            entries,
            linknode,
        };
        let bytes = manifest.to_canonical_bytes();
        let mid = UnodeManifestId::from_canonical_bytes(&bytes);
        self.blobs
            .put_object(ObjectDomain::UnodeManifest, mid.0, &bytes)?;
        Ok(Some(mid))
    }

    pub fn load_unode_manifest(
        &self,
        manifest_id: &UnodeManifestId,
    ) -> Result<UnodeManifest, DerivedError> {
        let bytes = self
            .blobs
            .get_object(ObjectDomain::UnodeManifest, &manifest_id.0)?
            .ok_or_else(|| DerivedError::MissingObject {
                domain: ObjectDomain::UnodeManifest,
                id_hex: manifest_id.to_hex(),
            })?;
        UnodeManifest::from_canonical_bytes(&bytes).map_err(DerivedError::CorruptDerivedObject)
    }

    pub fn load_unode_file(&self, file_id: &UnodeFileId) -> Result<UnodeFile, DerivedError> {
        let bytes = self
            .blobs
            .get_object(ObjectDomain::UnodeFile, &file_id.0)?
            .ok_or_else(|| DerivedError::MissingObject {
                domain: ObjectDomain::UnodeFile,
                id_hex: file_id.to_hex(),
            })?;
        UnodeFile::from_canonical_bytes(&bytes).map_err(DerivedError::CorruptDerivedObject)
    }

    pub fn lookup_unode_path(
        &self,
        root_manifest_id: &UnodeManifestId,
        path: &MPath,
    ) -> Result<Option<UnodeEntry>, DerivedError> {
        let mut current = self.load_unode_manifest(root_manifest_id)?;
        let elems = path.elements();
        for (idx, elem) in elems.iter().enumerate() {
            let Some(&entry) = current.entries.get(elem) else {
                return Ok(None);
            };
            if idx + 1 == elems.len() {
                return Ok(Some(entry));
            }
            match entry {
                UnodeEntry::Directory(mid) => {
                    current = self.load_unode_manifest(&mid)?;
                }
                UnodeEntry::File(_) => return Ok(None),
            }
        }
        Ok(None)
    }

    /// Walks the [`UnodeFile`] history graph for `path` starting at `cs_id` in $O(k)$ time,
    /// where $k$ is strictly the number of commits that modified `path`.
    pub fn file_history(
        &self,
        cs_id: ChangesetId,
        path: &MPath,
    ) -> Result<Vec<ChangesetId>, DerivedError> {
        let root_mid = self.derive_unode(cs_id)?;
        let entry = self
            .lookup_unode_path(&root_mid, path)?
            .ok_or_else(|| DerivedError::PathNotFound(path.as_str().to_string()))?;
        let UnodeEntry::File(start_fid) = entry else {
            return Err(DerivedError::NotAFile(path.as_str().to_string()));
        };

        let mut history = Vec::new();
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start_fid);
        visited.insert(start_fid);

        while let Some(fid) = queue.pop_front() {
            let unode = self.load_unode_file(&fid)?;
            history.push(unode.linknode);
            for p in unode.parents {
                if visited.insert(p) {
                    queue.push_back(p);
                }
            }
        }
        Ok(history)
    }

    /// Walks the [`UnodeManifest`] history graph for directory `path` starting at `cs_id` in $O(k)$ time.
    pub fn directory_history(
        &self,
        cs_id: ChangesetId,
        path: &MPath,
    ) -> Result<Vec<ChangesetId>, DerivedError> {
        let root_mid = self.derive_unode(cs_id)?;
        let entry = self
            .lookup_unode_path(&root_mid, path)?
            .ok_or_else(|| DerivedError::PathNotFound(path.as_str().to_string()))?;
        let UnodeEntry::Directory(start_mid) = entry else {
            return Err(DerivedError::NotADirectory(path.as_str().to_string()));
        };

        let mut history = Vec::new();
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start_mid);
        visited.insert(start_mid);

        while let Some(mid) = queue.pop_front() {
            let manifest = self.load_unode_manifest(&mid)?;
            history.push(manifest.linknode);
            for p in manifest.parents {
                if visited.insert(p) {
                    queue.push_back(p);
                }
            }
        }
        Ok(history)
    }

    // =========================================================================
    // 3. BlameV2 Inductive Line-by-Line Attribution
    // =========================================================================

    /// Derives [`BlameV2`] for `path` at `cs_id` by walking only its [`UnodeFile`] ancestry.
    pub fn blame_file(&self, cs_id: ChangesetId, path: &MPath) -> Result<BlameV2, DerivedError> {
        let root_mid = self.derive_unode(cs_id)?;
        let entry = self
            .lookup_unode_path(&root_mid, path)?
            .ok_or_else(|| DerivedError::PathNotFound(path.as_str().to_string()))?;
        let UnodeEntry::File(fid) = entry else {
            return Err(DerivedError::NotAFile(path.as_str().to_string()));
        };
        self.derive_blame_for_unode(fid)
    }

    fn derive_blame_for_unode(&self, fid: UnodeFileId) -> Result<BlameV2, DerivedError> {
        if let Some(cached) = self
            .blame_cache
            .read()
            .expect("blame_cache poisoned")
            .get(&fid)
            .cloned()
        {
            return Ok(cached);
        }

        let unode = self.load_unode_file(&fid)?;
        let cs = self
            .meta
            .get_changeset(&unode.linknode)?
            .ok_or(DerivedError::UnknownChangeset(unode.linknode))?;
        let blob_bytes = self
            .blobs
            .get_blob_content(&unode.blob_id)?
            .ok_or_else(|| DerivedError::MissingObject {
                domain: ObjectDomain::Blob,
                id_hex: unode.blob_id.to_hex(),
            })?;
        let content_str = String::from_utf8_lossy(&blob_bytes);

        let blame = if let Some(&first_parent_fid) = unode.parents.first() {
            let parent_blame = self.derive_blame_for_unode(first_parent_fid)?;
            BlameV2::derive_from_parent(&parent_blame, &content_str, unode.linknode, &cs.author)
        } else {
            BlameV2::from_initial(&content_str, unode.linknode, &cs.author)
        };

        self.blame_cache
            .write()
            .expect("blame_cache poisoned")
            .insert(fid, blame.clone());
        Ok(blame)
    }

    // =========================================================================
    // 4. CommitGraph Generation Numbers & Binary-Lifting Skip Pointers
    // =========================================================================

    /// Derives [`CommitGraphNode`] with generation numbers and $2^k$ skip pointers.
    pub fn derive_commit_graph_node(
        &self,
        cs_id: ChangesetId,
    ) -> Result<CommitGraphNode, DerivedError> {
        if let Some(node) = self
            .commit_graph_cache
            .read()
            .expect("commit_graph_cache poisoned")
            .get(&cs_id)
            .cloned()
        {
            return Ok(node);
        }

        // Iterative post-order traversal using parent headers (`get_changeset_parents`) so deep
        // commit chains never overflow the call stack or decode large ancestor changeset bodies.
        let mut work_stack: Vec<(ChangesetId, Option<Vec<ChangesetId>>)> = vec![(cs_id, None)];
        while let Some((curr_id, parents_opt)) = work_stack.pop() {
            if self
                .commit_graph_cache
                .read()
                .expect("commit_graph_cache poisoned")
                .contains_key(&curr_id)
            {
                continue;
            }
            match parents_opt {
                None => {
                    let parents = self
                        .meta
                        .get_changeset_parents(&curr_id)?
                        .ok_or(DerivedError::UnknownChangeset(curr_id))?;
                    let mut missing_parents = Vec::new();
                    {
                        let cache = self
                            .commit_graph_cache
                            .read()
                            .expect("commit_graph_cache poisoned");
                        for &p in &parents {
                            if !cache.contains_key(&p) {
                                missing_parents.push(p);
                            }
                        }
                    }
                    work_stack.push((curr_id, Some(parents)));
                    for p in missing_parents {
                        work_stack.push((p, None));
                    }
                }
                Some(parents) => {
                    let mut cache = self
                        .commit_graph_cache
                        .write()
                        .expect("commit_graph_cache poisoned");
                    if cache.contains_key(&curr_id) {
                        continue;
                    }
                    let mut max_parent_gen = 0u64;
                    for &p in &parents {
                        let p_node = cache
                            .get(&p)
                            .expect("parent CommitGraphNode derived before child");
                        if p_node.generation > max_parent_gen {
                            max_parent_gen = p_node.generation;
                        }
                    }
                    let generation = max_parent_gen + 1;

                    // Build binary-lifting skip pointers along first-parent ancestry:
                    // skip_ancestors[k] = 2^k-th first-parent ancestor
                    let mut skip_ancestors = Vec::new();
                    if let Some(&first_parent) = parents.first() {
                        skip_ancestors.push(first_parent);
                        let mut k = 0usize;
                        loop {
                            let prev_jump = skip_ancestors[k];
                            let prev_node = cache
                                .get(&prev_jump)
                                .expect("skip ancestor derived before child");
                            if let Some(&next_jump) = prev_node.skip_ancestors.get(k) {
                                skip_ancestors.push(next_jump);
                                k += 1;
                            } else {
                                break;
                            }
                        }
                    }

                    let node = CommitGraphNode {
                        changeset_id: curr_id,
                        parents,
                        generation,
                        skip_ancestors,
                    };
                    cache.insert(curr_id, node);
                }
            }
        }

        Ok(self
            .commit_graph_cache
            .read()
            .expect("commit_graph_cache poisoned")
            .get(&cs_id)
            .cloned()
            .expect("target CommitGraphNode derived"))
    }

    /// Collects all changesets in the half-open topological interval `(ancestor..descendant]`.
    ///
    /// Returns:
    /// - `Ok(None)` if `ancestor` is not an ancestor of `descendant` (non-fast-forward).
    /// - `Ok(Some(vec![]))` if `ancestor == descendant`.
    /// - `Ok(Some(delta_changesets))` ordered topologically from oldest (closest to `ancestor`)
    ///   to newest (`descendant`), visiting only the $O(|\Delta|)$ commits in `(ancestor..descendant]`
    ///   via `CommitGraphNode` generation pruning (`gen(p) > gen(ancestor)`).
    pub fn collect_commits_between(
        &self,
        ancestor: ChangesetId,
        descendant: ChangesetId,
    ) -> Result<Option<Vec<BonsaiChangeset>>, DerivedError> {
        if ancestor == descendant {
            return Ok(Some(Vec::new()));
        }
        if !self.is_ancestor(ancestor, descendant)? {
            return Ok(None);
        }

        let anc_node = self.derive_commit_graph_node(ancestor)?;
        let ancestor_gen = anc_node.generation;

        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        visited.insert(descendant);
        queue.push_back(descendant);

        let mut delta_with_gen: Vec<(u64, ChangesetId, BonsaiChangeset)> = Vec::new();

        while let Some(curr) = queue.pop_front() {
            if curr == ancestor {
                continue;
            }
            let curr_node = self.derive_commit_graph_node(curr)?;
            let cs = self
                .meta
                .get_changeset(&curr)?
                .ok_or(DerivedError::UnknownChangeset(curr))?;

            for &p in &cs.parents {
                if p == ancestor || visited.contains(&p) {
                    continue;
                }
                let p_node = self.derive_commit_graph_node(p)?;
                if p_node.generation > ancestor_gen && self.is_ancestor(ancestor, p)? {
                    visited.insert(p);
                    queue.push_back(p);
                }
            }

            delta_with_gen.push((curr_node.generation, curr, cs));
        }

        delta_with_gen.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let delta_changesets = delta_with_gen.into_iter().map(|(_, _, cs)| cs).collect();
        Ok(Some(delta_changesets))
    }

    /// Convenience wrapper accepting explicit store references for callers holding `&dyn BlobStore`
    /// and `&dyn MetadataStore`.
    pub fn collect_commits_between_with_stores(
        &self,
        _blobs: &dyn BlobStore,
        _meta: &dyn MetadataStore,
        ancestor: ChangesetId,
        descendant: ChangesetId,
    ) -> Result<Option<Vec<BonsaiChangeset>>, DerivedError> {
        self.collect_commits_between(ancestor, descendant)
    }

    /// Determines whether `ancestor` is an ancestor of (or equal to) `descendant`
    /// using generation pruning and binary-lifting skip pointers.
    pub fn is_ancestor(
        &self,
        ancestor: ChangesetId,
        descendant: ChangesetId,
    ) -> Result<bool, DerivedError> {
        if ancestor == descendant {
            return Ok(true);
        }
        let anc_node = self.derive_commit_graph_node(ancestor)?;
        let desc_node = self.derive_commit_graph_node(descendant)?;
        if anc_node.generation >= desc_node.generation {
            return Ok(false);
        }

        let mut visited = BTreeSet::new();
        let mut stack = vec![desc_node];

        while let Some(curr) = stack.pop() {
            if curr.changeset_id == ancestor {
                return Ok(true);
            }
            if curr.generation <= anc_node.generation {
                continue;
            }

            // Fast binary-lifting jump when `curr` has a single parent chain down to `anc_node.generation`
            if curr.parents.len() == 1 {
                let mut jumped = None;
                for &skip_id in curr.skip_ancestors.iter().rev() {
                    let skip_node = self.derive_commit_graph_node(skip_id)?;
                    if skip_node.generation >= anc_node.generation && skip_node.parents.len() <= 1 {
                        jumped = Some(skip_node);
                        break;
                    }
                }
                if let Some(next_node) = jumped {
                    if visited.insert(next_node.changeset_id) {
                        stack.push(next_node);
                    }
                    continue;
                }
            }

            for &p in &curr.parents {
                let p_node = self.derive_commit_graph_node(p)?;
                if p_node.generation >= anc_node.generation && visited.insert(p) {
                    stack.push(p_node);
                }
            }
        }

        Ok(false)
    }

    /// Computes the Lowest Common Ancestor (merge-base) of `a` and `b`.
    pub fn lowest_common_ancestor(
        &self,
        a: ChangesetId,
        b: ChangesetId,
    ) -> Result<Option<ChangesetId>, DerivedError> {
        if a == b {
            return Ok(Some(a));
        }
        if self.is_ancestor(a, b)? {
            return Ok(Some(a));
        }
        if self.is_ancestor(b, a)? {
            return Ok(Some(b));
        }

        // Collect ancestors of `a` keyed by generation
        let mut ancestors_a = BTreeSet::new();
        let mut queue_a = VecDeque::new();
        queue_a.push_back(a);
        ancestors_a.insert(a);
        while let Some(curr_id) = queue_a.pop_front() {
            let node = self.derive_commit_graph_node(curr_id)?;
            for p in node.parents {
                if ancestors_a.insert(p) {
                    queue_a.push_back(p);
                }
            }
        }

        // Walk `b` ancestors in descending generation order to find the highest-generation common ancestor
        let mut candidates: BTreeMap<(u64, ChangesetId), ()> = BTreeMap::new();
        let node_b = self.derive_commit_graph_node(b)?;
        candidates.insert((node_b.generation, b), ());
        let mut visited_b = BTreeSet::new();
        visited_b.insert(b);

        while let Some(((_gen, curr_id), ())) = candidates.pop_last() {
            if ancestors_a.contains(&curr_id) {
                return Ok(Some(curr_id));
            }
            let node = self.derive_commit_graph_node(curr_id)?;
            for p in node.parents {
                if visited_b.insert(p) {
                    let p_node = self.derive_commit_graph_node(p)?;
                    candidates.insert((p_node.generation, p), ());
                }
            }
        }

        Ok(None)
    }

    /// Inductively derives and stores the [`PathSearchIndex`] for `cs_id` in $O(\Delta \log N)$
    /// from its parent changeset's `PathSearchIndex` and `BonsaiChangeset::file_changes`.
    pub fn derive_path_search_index(
        &self,
        cs_id: ChangesetId,
    ) -> Result<PathSearchIndexId, DerivedError> {
        if let Some(existing) = self
            .meta
            .get_derived_mapping(cs_id, DerivedDataKind::PathSearchIndex)?
        {
            return Ok(PathSearchIndexId::from_hash(existing));
        }

        let cs = self
            .meta
            .get_changeset(&cs_id)?
            .ok_or(DerivedError::UnknownChangeset(cs_id))?;

        let mut entries = if let Some(&first_parent) = cs.parents.first() {
            let parent_idx_id = self.derive_path_search_index(first_parent)?;
            let mut merged = self.load_path_search_index(&parent_idx_id)?.entries;
            for &extra_parent in cs.parents.iter().skip(1) {
                let extra_id = self.derive_path_search_index(extra_parent)?;
                let extra_idx = self.load_path_search_index(&extra_id)?;
                for (path, entry) in extra_idx.entries {
                    merged.entry(path).or_insert(entry);
                }
            }
            merged
        } else {
            BTreeMap::new()
        };

        for (path, change) in &cs.file_changes {
            match change {
                FileChange::Tracked {
                    blob_id,
                    file_type,
                    size,
                } => {
                    entries.insert(
                        path.clone(),
                        PathSearchEntry {
                            path: path.clone(),
                            blob_id: *blob_id,
                            size: *size,
                            file_type: *file_type,
                        },
                    );
                }
                FileChange::Deleted => {
                    entries.remove(path);
                }
            }
        }

        let index = PathSearchIndex { entries };
        let bytes = index.to_canonical_bytes();
        let index_id = PathSearchIndexId::from_canonical_bytes(&bytes);
        self.blobs
            .put_object(ObjectDomain::PathSearchIndex, index_id.0, &bytes)?;
        self.meta
            .put_derived_mapping(cs_id, DerivedDataKind::PathSearchIndex, index_id.0)?;
        Ok(index_id)
    }

    /// Loads a [`PathSearchIndex`] by its [`PathSearchIndexId`].
    pub fn load_path_search_index(
        &self,
        index_id: &PathSearchIndexId,
    ) -> Result<PathSearchIndex, DerivedError> {
        let bytes = self
            .blobs
            .get_object(ObjectDomain::PathSearchIndex, &index_id.0)?
            .ok_or_else(|| DerivedError::MissingObject {
                domain: ObjectDomain::PathSearchIndex,
                id_hex: index_id.to_hex(),
            })?;
        PathSearchIndex::from_canonical_bytes(&bytes)
    }

    /// Searches repository paths at `cs_id` using the inductive [`PathSearchIndex`].
    pub fn search_paths(
        &self,
        cs_id: ChangesetId,
        query: &str,
        limit: usize,
    ) -> Result<Vec<PathSearchEntry>, DerivedError> {
        let index_id = self.derive_path_search_index(cs_id)?;
        let index = self.load_path_search_index(&index_id)?;
        Ok(index.search(query, limit))
    }

    /// Inductively derives and caches the [`CopyDetectionReport`] for `cs_id`.
    ///
    /// Identifies `ExactRename`, `ExactCopy`, `SimilarRename`, and `SimilarCopy` edges
    /// for files newly added in `cs_id` relative to its first parent changeset.
    pub fn derive_copy_detection(
        &self,
        cs_id: ChangesetId,
    ) -> Result<CopyDetectionReport, DerivedError> {
        if let Some(existing) = self
            .meta
            .get_derived_mapping(cs_id, DerivedDataKind::CopyDetection)?
        {
            let bytes = self
                .blobs
                .get_object(ObjectDomain::CopyInfo, &existing)?
                .ok_or_else(|| DerivedError::MissingObject {
                    domain: ObjectDomain::CopyInfo,
                    id_hex: existing.to_hex(),
                })?;
            return CopyDetectionReport::from_canonical_bytes(&bytes);
        }

        let cs = self
            .meta
            .get_changeset(&cs_id)?
            .ok_or(DerivedError::UnknownChangeset(cs_id))?;

        let mut records = Vec::new();
        if let Some(&parent_id) = cs.parents.first() {
            let parent_idx_id = self.derive_path_search_index(parent_id)?;
            let parent_idx = self.load_path_search_index(&parent_idx_id)?;

            let mut deleted_paths = BTreeSet::new();
            for (path, change) in &cs.file_changes {
                if matches!(change, FileChange::Deleted) {
                    deleted_paths.insert(path.clone());
                }
            }

            let mut by_blob: BTreeMap<BlobId, Vec<MPath>> = BTreeMap::new();
            for (path, entry) in &parent_idx.entries {
                by_blob.entry(entry.blob_id).or_default().push(path.clone());
            }

            for (dest_path, change) in &cs.file_changes {
                let FileChange::Tracked {
                    blob_id: dest_blob_id,
                    ..
                } = change
                else {
                    continue;
                };
                // Only detect copy/rename origins for newly introduced destination paths
                if parent_idx.entries.contains_key(dest_path) {
                    continue;
                }

                // 1. Check O(1) exact BlobId match against parent files
                if let Some(candidates) = by_blob.get(dest_blob_id) {
                    if let Some(deleted_src) =
                        candidates.iter().find(|p| deleted_paths.contains(*p))
                    {
                        records.push(CopyRecord {
                            dest_path: dest_path.clone(),
                            source_path: deleted_src.clone(),
                            kind: CopyKind::ExactRename,
                            similarity_bps: 10_000,
                            dest_blob_id: *dest_blob_id,
                            source_blob_id: *dest_blob_id,
                        });
                        continue;
                    } else if let Some(first_src) = candidates.first() {
                        records.push(CopyRecord {
                            dest_path: dest_path.clone(),
                            source_path: first_src.clone(),
                            kind: CopyKind::ExactCopy,
                            similarity_bps: 10_000,
                            dest_blob_id: *dest_blob_id,
                            source_blob_id: *dest_blob_id,
                        });
                        continue;
                    }
                }

                // 2. Check content similarity (>= 5000 bps / 50%) against deleted parent files first,
                // then same-directory or same-extension parent files.
                let Some(dest_bytes) = self.blobs.get_blob_content(dest_blob_id)? else {
                    continue;
                };

                let mut best_match: Option<(MPath, BlobId, u16, bool)> = None;

                // Prioritize deleted paths in this commit (renames with modifications)
                for del_path in &deleted_paths {
                    if let Some(parent_entry) = parent_idx.entries.get(del_path) {
                        if let Some(src_bytes) =
                            self.blobs.get_blob_content(&parent_entry.blob_id)?
                        {
                            let sim = compute_line_similarity_bps(&dest_bytes, &src_bytes);
                            if sim >= 5_000
                                && best_match
                                    .as_ref()
                                    .is_none_or(|(_, _, b_sim, _)| sim > *b_sim)
                            {
                                best_match =
                                    Some((del_path.clone(), parent_entry.blob_id, sim, true));
                            }
                        }
                    }
                }

                // If no deleted file matched >= 50%, check existing parent files sharing extension or directory
                if best_match.is_none() {
                    let dest_ext = dest_path.as_str().rsplit('.').next().unwrap_or("");
                    for (src_path, parent_entry) in &parent_idx.entries {
                        let src_ext = src_path.as_str().rsplit('.').next().unwrap_or("");
                        if !dest_ext.is_empty() && dest_ext == src_ext {
                            if let Some(src_bytes) =
                                self.blobs.get_blob_content(&parent_entry.blob_id)?
                            {
                                let sim = compute_line_similarity_bps(&dest_bytes, &src_bytes);
                                if sim >= 5_000
                                    && best_match
                                        .as_ref()
                                        .is_none_or(|(_, _, b_sim, _)| sim > *b_sim)
                                {
                                    best_match =
                                        Some((src_path.clone(), parent_entry.blob_id, sim, false));
                                }
                            }
                        }
                    }
                }

                if let Some((source_path, source_blob_id, similarity_bps, is_rename)) = best_match {
                    records.push(CopyRecord {
                        dest_path: dest_path.clone(),
                        source_path,
                        kind: if is_rename {
                            CopyKind::SimilarRename
                        } else {
                            CopyKind::SimilarCopy
                        },
                        similarity_bps,
                        dest_blob_id: *dest_blob_id,
                        source_blob_id,
                    });
                }
            }
        }

        let report = CopyDetectionReport {
            changeset_id: cs_id,
            records,
        };
        let bytes = report.to_canonical_bytes();
        let info_id = CopyInfoId::from_canonical_bytes(&bytes);
        self.blobs
            .put_object(ObjectDomain::CopyInfo, info_id.0, &bytes)?;
        self.meta
            .put_derived_mapping(cs_id, DerivedDataKind::CopyDetection, info_id.0)?;
        Ok(report)
    }
}
