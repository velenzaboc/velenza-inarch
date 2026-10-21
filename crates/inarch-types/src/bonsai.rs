//! Tree-Free Bonsai Changeset data model (`BonsaiChangeset`), canonical binary serialization,
//! and $O(\Delta)$ path-conflict detection.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::hash::{BlobId, ChangesetId, ObjectHash};
use crate::path::{MPath, PathError};

/// POSIX / repository file mode stored in a [`FileChange`] or derived tree entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileType {
    Regular,
    Executable,
    Symlink,
}

impl FileType {
    pub const fn to_byte(self) -> u8 {
        match self {
            FileType::Regular => 1,
            FileType::Executable => 2,
            FileType::Symlink => 3,
        }
    }

    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(FileType::Regular),
            2 => Some(FileType::Executable),
            3 => Some(FileType::Symlink),
            _ => None,
        }
    }
}

/// An explicit file mutation recorded inside a [`BonsaiChangeset`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileChange {
    Tracked {
        blob_id: BlobId,
        size: u64,
        file_type: FileType,
    },
    Deleted,
}

impl FileChange {
    pub const fn is_tracked(&self) -> bool {
        matches!(self, FileChange::Tracked { .. })
    }
}

/// Errors produced when validating or decoding a [`BonsaiChangeset`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BonsaiError {
    DuplicateParent(ChangesetId),
    PathPrefixConflict { prefix: MPath, descendant: MPath },
    InvalidMagic,
    UnexpectedEof,
    InvalidUtf8,
    InvalidFileType(u8),
    InvalidFileChangeTag(u8),
    InvalidPath(PathError),
    TrailingBytes(usize),
}

impl fmt::Display for BonsaiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BonsaiError::DuplicateParent(id) => {
                write!(f, "duplicate parent changeset id in BonsaiChangeset: {id}")
            }
            BonsaiError::PathPrefixConflict { prefix, descendant } => write!(
                f,
                "path '{prefix}' conflicts with descendant path '{descendant}' in the same changeset"
            ),
            BonsaiError::InvalidMagic => write!(f, "invalid BonsaiChangeset binary header magic"),
            BonsaiError::UnexpectedEof => {
                write!(f, "unexpected EOF decoding BonsaiChangeset bytes")
            }
            BonsaiError::InvalidUtf8 => write!(f, "invalid UTF-8 string in BonsaiChangeset"),
            BonsaiError::InvalidFileType(tag) => write!(f, "invalid FileType tag {tag}"),
            BonsaiError::InvalidFileChangeTag(tag) => write!(f, "invalid FileChange tag {tag}"),
            BonsaiError::InvalidPath(err) => write!(f, "invalid MPath in BonsaiChangeset: {err}"),
            BonsaiError::TrailingBytes(n) => {
                write!(f, "unexpected {n} trailing bytes after BonsaiChangeset")
            }
        }
    }
}

impl std::error::Error for BonsaiError {}

const BONSAI_MAGIC: &[u8; 8] = b"INRCBCS1";

/// A tree-free commit node (Mononoke/Scion Bonsai model).
///
/// Crucially, `BonsaiChangeset` stores **only** parent `ChangesetId`s, metadata, and the
/// explicit `BTreeMap<MPath, FileChange>` delta. It never embeds a root Merkle tree hash,
/// making commit creation pure $O(\Delta)$ with zero tree reads and allowing path-disjoint
/// speculative rebases on `main` by updating `parents` without recomputing trees in the lock loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BonsaiChangeset {
    pub parents: Vec<ChangesetId>,
    pub author: String,
    pub author_date_secs: i64,
    pub author_tz_offset_secs: i32,
    pub message: String,
    pub extra: BTreeMap<String, Vec<u8>>,
    pub file_changes: BTreeMap<MPath, FileChange>,
}

impl BonsaiChangeset {
    /// Validates and constructs a [`BonsaiChangeset`].
    pub fn new(
        parents: Vec<ChangesetId>,
        author: String,
        author_date_secs: i64,
        author_tz_offset_secs: i32,
        message: String,
        extra: BTreeMap<String, Vec<u8>>,
        file_changes: BTreeMap<MPath, FileChange>,
    ) -> Result<Self, BonsaiError> {
        let cs = Self {
            parents,
            author,
            author_date_secs,
            author_tz_offset_secs,
            message,
            extra,
            file_changes,
        };
        cs.validate()?;
        Ok(cs)
    }

    /// Verifies structural invariants:
    /// 1. No duplicate parent `ChangesetId`s.
    /// 2. No two `Tracked` paths in `file_changes` where one path is a directory prefix of another.
    pub fn validate(&self) -> Result<(), BonsaiError> {
        let mut seen_parents = BTreeSet::new();
        for &p in &self.parents {
            if !seen_parents.insert(p) {
                return Err(BonsaiError::DuplicateParent(p));
            }
        }

        // A tracked path conflicts exactly when one of its directory ancestors is itself a
        // tracked path, so each path is checked against its own ancestors in the map instead
        // of against every other path: $O(n \cdot depth)$ map probes rather than $O(n^2)$ pairs.
        //
        // `BTreeMap<MPath, FileChange>` iterates in component-wise sorted order, and a prefix
        // sorts directly before its descendants, so the first tracked path found to have a
        // tracked ancestor is the first conflicting pair in sorted order: `prefix` is that
        // ancestor and `descendant` is the path. Deleted entries are neither prefixes nor
        // descendants.
        for (path, change) in &self.file_changes {
            if !change.is_tracked() {
                continue;
            }
            let mut ancestor = path.parent();
            while let Some(prefix) = ancestor {
                if self
                    .file_changes
                    .get(&prefix)
                    .is_some_and(FileChange::is_tracked)
                {
                    return Err(BonsaiError::PathPrefixConflict {
                        prefix,
                        descendant: path.clone(),
                    });
                }
                ancestor = prefix.parent();
            }
        }

        Ok(())
    }

    /// Computes the deterministic content-addressed [`ChangesetId`] for this changeset.
    pub fn changeset_id(&self) -> ChangesetId {
        ChangesetId::from_canonical_bytes(&self.to_canonical_bytes())
    }

    /// Produces a rebased copy of this changeset with `new_parents` in $O(1)$ without touching trees.
    pub fn with_parents(&self, new_parents: Vec<ChangesetId>) -> Result<Self, BonsaiError> {
        let mut cloned = self.clone();
        cloned.parents = new_parents;
        cloned.validate()?;
        Ok(cloned)
    }

    /// Checks whether `self` and `other` have any conflicting file changes in $O(\Delta)$.
    ///
    /// Two changesets conflict if:
    /// - They modify the exact same [`MPath`], OR
    /// - One changeset modifies a path `P` that is a strict directory prefix of a path `Q`
    ///   modified by the other changeset (file-vs-directory collision).
    ///
    /// Returns the sorted list of paths from `self` that conflict with `other`.
    pub fn conflicting_paths(&self, other: &BonsaiChangeset) -> Vec<MPath> {
        let mut conflicts = Vec::new();
        for self_path in self.file_changes.keys() {
            if other.file_changes.contains_key(self_path) {
                conflicts.push(self_path.clone());
                continue;
            }
            let has_prefix_collision = other.file_changes.keys().any(|other_path| {
                self_path.is_strict_prefix_of(other_path)
                    || other_path.is_strict_prefix_of(self_path)
            });
            if has_prefix_collision {
                conflicts.push(self_path.clone());
            }
        }
        conflicts
    }

    /// Serializes this `BonsaiChangeset` into its deterministic canonical binary representation.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(BONSAI_MAGIC);

        // Parents
        write_u32(&mut buf, self.parents.len() as u32);
        for parent in &self.parents {
            buf.extend_from_slice(parent.as_bytes());
        }

        // Author & timestamps & message
        write_str(&mut buf, &self.author);
        buf.extend_from_slice(&self.author_date_secs.to_le_bytes());
        buf.extend_from_slice(&self.author_tz_offset_secs.to_le_bytes());
        write_str(&mut buf, &self.message);

        // Extra metadata (BTreeMap ensures sorted key order)
        write_u32(&mut buf, self.extra.len() as u32);
        for (k, v) in &self.extra {
            write_str(&mut buf, k);
            write_bytes(&mut buf, v);
        }

        // File changes (BTreeMap ensures sorted MPath order)
        write_u32(&mut buf, self.file_changes.len() as u32);
        for (path, change) in &self.file_changes {
            write_str(&mut buf, path.as_str());
            match change {
                FileChange::Deleted => {
                    buf.push(0);
                }
                FileChange::Tracked {
                    blob_id,
                    size,
                    file_type,
                } => {
                    buf.push(1);
                    buf.extend_from_slice(blob_id.as_bytes());
                    buf.extend_from_slice(&size.to_le_bytes());
                    buf.push(file_type.to_byte());
                }
            }
        }

        buf
    }

    /// Decodes only the parent list from canonical binary bytes.
    ///
    /// Reads the fixed header (magic, parent count, parent ids) and nothing after it: the
    /// author, message, extras and file changes are neither parsed nor validated, so the cost
    /// is proportional to the number of parents, never to the size of the changeset body.
    /// Ancestry walks use it where only the graph shape matters; it performs no integrity
    /// check against the [`ChangesetId`], which only a full decode plus re-hash provides.
    pub fn parents_from_canonical_bytes(bytes: &[u8]) -> Result<Vec<ChangesetId>, BonsaiError> {
        let mut cursor = Cursor::new(bytes);
        let magic = cursor.read_exact(8)?;
        if magic != BONSAI_MAGIC {
            return Err(BonsaiError::InvalidMagic);
        }
        let parent_count = cursor.read_u32()? as usize;
        if parent_count > cursor.remaining() / 32 {
            return Err(BonsaiError::UnexpectedEof);
        }
        let mut parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            parents.push(ChangesetId::from_hash(cursor.read_hash()?));
        }
        Ok(parents)
    }

    /// Returns the length in bytes of the canonical header that holds `parent_count` parents:
    /// the magic, the parent count and the parent ids.
    pub const fn canonical_header_len(parent_count: usize) -> usize {
        BONSAI_MAGIC.len() + 4 + 32 * parent_count
    }

    /// Deserializes and validates a `BonsaiChangeset` from canonical binary bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BonsaiError> {
        let mut cursor = Cursor::new(bytes);
        let magic = cursor.read_exact(8)?;
        if magic != BONSAI_MAGIC {
            return Err(BonsaiError::InvalidMagic);
        }

        let parent_count = cursor.read_u32()? as usize;
        let mut parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            let raw = cursor.read_hash()?;
            parents.push(ChangesetId::from_hash(raw));
        }

        let author = cursor.read_str()?;
        let author_date_secs = cursor.read_i64()?;
        let author_tz_offset_secs = cursor.read_i32()?;
        let message = cursor.read_str()?;

        let extra_count = cursor.read_u32()? as usize;
        let mut extra = BTreeMap::new();
        for _ in 0..extra_count {
            let k = cursor.read_str()?;
            let v = cursor.read_vec()?;
            extra.insert(k, v);
        }

        let changes_count = cursor.read_u32()? as usize;
        let mut file_changes = BTreeMap::new();
        for _ in 0..changes_count {
            let path_str = cursor.read_str()?;
            let path = MPath::new(&path_str).map_err(BonsaiError::InvalidPath)?;
            let tag = cursor.read_u8()?;
            let change = match tag {
                0 => FileChange::Deleted,
                1 => {
                    let blob_hash = cursor.read_hash()?;
                    let size = cursor.read_u64()?;
                    let ft_byte = cursor.read_u8()?;
                    let file_type = FileType::from_byte(ft_byte)
                        .ok_or(BonsaiError::InvalidFileType(ft_byte))?;
                    FileChange::Tracked {
                        blob_id: BlobId::from_hash(blob_hash),
                        size,
                        file_type,
                    }
                }
                other => return Err(BonsaiError::InvalidFileChangeTag(other)),
            };
            file_changes.insert(path, change);
        }

        if cursor.remaining() != 0 {
            return Err(BonsaiError::TrailingBytes(cursor.remaining()));
        }

        Self::new(
            parents,
            author,
            author_date_secs,
            author_tz_offset_secs,
            message,
            extra,
            file_changes,
        )
    }
}

fn write_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    write_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

fn write_str(buf: &mut Vec<u8>, s: &str) {
    write_bytes(buf, s.as_bytes());
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], BonsaiError> {
        if self.pos + len > self.data.len() {
            return Err(BonsaiError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, BonsaiError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, BonsaiError> {
        let b = self.read_exact(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_i32(&mut self) -> Result<i32, BonsaiError> {
        let b = self.read_exact(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, BonsaiError> {
        let b = self.read_exact(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_i64(&mut self) -> Result<i64, BonsaiError> {
        let b = self.read_exact(8)?;
        Ok(i64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_hash(&mut self) -> Result<ObjectHash, BonsaiError> {
        let b = self.read_exact(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(b);
        Ok(ObjectHash(arr))
    }

    fn read_vec(&mut self) -> Result<Vec<u8>, BonsaiError> {
        let len = self.read_u32()? as usize;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_str(&mut self) -> Result<String, BonsaiError> {
        let vec = self.read_vec()?;
        String::from_utf8(vec).map_err(|_| BonsaiError::InvalidUtf8)
    }
}
