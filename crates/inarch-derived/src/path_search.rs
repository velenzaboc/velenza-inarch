//! Inductive Path Search Index (`PathSearchIndex`) derived data family.
//!
//! Maintains a sorted, content-addressed path index per `ChangesetId` that updates
//! inductively in $O(\Delta \log N)$ from the parent commit's `PathSearchIndex` using
//! only `BonsaiChangeset::file_changes`. Supports fast substring, prefix, extension,
//! and glob (`*`, `?`, `**`) queries without walking the `Fsnode` tree.

use std::collections::BTreeMap;

use inarch_types::bonsai::FileType;
use inarch_types::hash::{BlobId, ObjectHash, PathSearchIndexId};
use inarch_types::path::MPath;

use crate::DerivedError;

const PATH_SEARCH_MAGIC: &[u8; 8] = b"INRCPSI1";
const PATH_SEARCH_VERSION: u8 = 1;

/// A single indexed file entry inside a [`PathSearchIndex`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSearchEntry {
    pub path: MPath,
    pub blob_id: BlobId,
    pub size: u64,
    pub file_type: FileType,
}

/// Content-addressed sorted path index for a changeset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathSearchIndex {
    pub entries: BTreeMap<MPath, PathSearchEntry>,
}

impl PathSearchIndex {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn index_id(&self) -> PathSearchIndexId {
        PathSearchIndexId::from_canonical_bytes(&self.to_canonical_bytes())
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.entries.len() * 64);
        buf.extend_from_slice(PATH_SEARCH_MAGIC);
        buf.push(PATH_SEARCH_VERSION);
        buf.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for entry in self.entries.values() {
            let path_bytes = entry.path.as_str().as_bytes();
            buf.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(path_bytes);
            buf.extend_from_slice(entry.blob_id.as_bytes());
            buf.extend_from_slice(&entry.size.to_le_bytes());
            buf.push(file_type_to_u8(entry.file_type));
        }
        buf
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DerivedError> {
        if bytes.len() < 13 || &bytes[0..8] != PATH_SEARCH_MAGIC {
            return Err(DerivedError::CorruptDerivedObject(
                "invalid PathSearchIndex magic".into(),
            ));
        }
        if bytes[8] != PATH_SEARCH_VERSION {
            return Err(DerivedError::CorruptDerivedObject(format!(
                "unsupported PathSearchIndex version {}",
                bytes[8]
            )));
        }
        let mut pos = 9usize;
        let count = read_u32(bytes, &mut pos)? as usize;
        let mut entries = BTreeMap::new();
        for _ in 0..count {
            let path_len = read_u32(bytes, &mut pos)? as usize;
            if pos + path_len > bytes.len() {
                return Err(DerivedError::CorruptDerivedObject(
                    "truncated path in PathSearchIndex".into(),
                ));
            }
            let path_str = std::str::from_utf8(&bytes[pos..pos + path_len])
                .map_err(|e| DerivedError::CorruptDerivedObject(e.to_string()))?;
            pos += path_len;
            let path = MPath::new(path_str)
                .map_err(|e| DerivedError::CorruptDerivedObject(e.to_string()))?;
            if pos + 32 + 8 + 1 > bytes.len() {
                return Err(DerivedError::CorruptDerivedObject(
                    "truncated entry in PathSearchIndex".into(),
                ));
            }
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            let blob_id = BlobId::from_hash(ObjectHash(hash_arr));
            let mut size_arr = [0u8; 8];
            size_arr.copy_from_slice(&bytes[pos..pos + 8]);
            pos += 8;
            let size = u64::from_le_bytes(size_arr);
            let file_type = u8_to_file_type(bytes[pos])?;
            pos += 1;
            entries.insert(
                path.clone(),
                PathSearchEntry {
                    path,
                    blob_id,
                    size,
                    file_type,
                },
            );
        }
        if pos != bytes.len() {
            return Err(DerivedError::CorruptDerivedObject(
                "trailing bytes in PathSearchIndex".into(),
            ));
        }
        Ok(Self { entries })
    }

    /// Searches indexed paths by glob pattern (`*`, `?`, `**`) or case-insensitive substring.
    pub fn search(&self, query: &str, limit: usize) -> Vec<PathSearchEntry> {
        let max_results = if limit == 0 { usize::MAX } else { limit };
        let trimmed = query.trim();
        let is_glob = trimmed.contains('*') || trimmed.contains('?');
        let query_lower = trimmed.to_ascii_lowercase();
        let has_slash = trimmed.contains('/');

        let mut results = Vec::new();
        for entry in self.entries.values() {
            let path_str = entry.path.as_str();
            let matched = if trimmed.is_empty() {
                true
            } else if is_glob {
                let path_lower = path_str.to_ascii_lowercase();
                if has_slash {
                    glob_match(&query_lower, &path_lower)
                } else {
                    let basename = path_lower.rsplit('/').next().unwrap_or(&path_lower);
                    glob_match(&query_lower, basename) || glob_match(&query_lower, &path_lower)
                }
            } else {
                path_str.to_ascii_lowercase().contains(&query_lower)
            };
            if matched {
                results.push(entry.clone());
                if results.len() >= max_results {
                    break;
                }
            }
        }
        results
    }
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, DerivedError> {
    if *pos + 4 > bytes.len() {
        return Err(DerivedError::CorruptDerivedObject(
            "unexpected EOF reading u32".into(),
        ));
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes[*pos..*pos + 4]);
    *pos += 4;
    Ok(u32::from_le_bytes(arr))
}

fn file_type_to_u8(ft: FileType) -> u8 {
    match ft {
        FileType::Regular => 1,
        FileType::Executable => 2,
        FileType::Symlink => 3,
    }
}

fn u8_to_file_type(b: u8) -> Result<FileType, DerivedError> {
    match b {
        1 => Ok(FileType::Regular),
        2 => Ok(FileType::Executable),
        3 => Ok(FileType::Symlink),
        other => Err(DerivedError::CorruptDerivedObject(format!(
            "unknown FileType tag {other}"
        ))),
    }
}

/// Fast zero-dependency glob matcher supporting `*` (single segment), `**` (cross-directory), and `?`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_bytes(p: &[u8], t: &[u8]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    if p[0] == b'*' {
        let mut stars = 0usize;
        while stars < p.len() && p[stars] == b'*' {
            stars += 1;
        }
        let rest = &p[stars..];
        if stars >= 2 {
            if rest.is_empty() {
                return true;
            }
            if rest[0] == b'/' && glob_match_bytes(&rest[1..], t) {
                return true;
            }
            return glob_match_bytes(rest, t) || (!t.is_empty() && glob_match_bytes(p, &t[1..]));
        } else {
            return glob_match_bytes(rest, t)
                || (!t.is_empty() && t[0] != b'/' && glob_match_bytes(p, &t[1..]));
        }
    }
    if t.is_empty() {
        return false;
    }
    if p[0] == b'?' {
        return t[0] != b'/' && glob_match_bytes(&p[1..], &t[1..]);
    }
    p[0] == t[0] && glob_match_bytes(&p[1..], &t[1..])
}
