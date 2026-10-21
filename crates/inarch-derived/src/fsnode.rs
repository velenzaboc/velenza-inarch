//! Content-addressed Merkle directory trees (`Fsnode`) with recursive subtree summaries.
//!
//! Derived inductively in $O(\Delta \cdot \text{depth})$ from parent `Fsnode`s and a `BonsaiChangeset`:
//! untouched subdirectories are never traversed or re-hashed.

use std::collections::BTreeMap;

use inarch_types::bonsai::FileType;
use inarch_types::hash::{BlobId, FsnodeId, ObjectDomain, ObjectHash};
use inarch_types::path::MPathElement;

const FSNODE_MAGIC: &[u8; 8] = b"INRCFSN1";

/// Recursive file and byte-size summary stored inline on every directory reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsnodeSummary {
    pub child_files_count: u64,
    pub child_files_total_size: u64,
    pub child_dirs_count: u64,
    pub descendant_files_count: u64,
    pub descendant_files_total_size: u64,
}

/// An entry inside an [`Fsnode`] directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsnodeEntry {
    File {
        blob_id: BlobId,
        size: u64,
        file_type: FileType,
    },
    Directory {
        fsnode_id: FsnodeId,
        summary: FsnodeSummary,
    },
}

/// A content-addressed Merkle directory node.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fsnode {
    pub entries: BTreeMap<MPathElement, FsnodeEntry>,
}

impl Fsnode {
    pub fn new(entries: BTreeMap<MPathElement, FsnodeEntry>) -> Self {
        Self { entries }
    }

    /// Computes the aggregate [`FsnodeSummary`] for this directory node in $O(\text{children})$.
    pub fn summary(&self) -> FsnodeSummary {
        let mut s = FsnodeSummary::default();
        for entry in self.entries.values() {
            match entry {
                FsnodeEntry::File { size, .. } => {
                    s.child_files_count += 1;
                    s.child_files_total_size += *size;
                    s.descendant_files_count += 1;
                    s.descendant_files_total_size += *size;
                }
                FsnodeEntry::Directory { summary, .. } => {
                    s.child_dirs_count += 1;
                    s.descendant_files_count += summary.descendant_files_count;
                    s.descendant_files_total_size += summary.descendant_files_total_size;
                }
            }
        }
        s
    }

    /// Deterministically encodes this `Fsnode` into canonical bytes.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(FSNODE_MAGIC);
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for (name, entry) in &self.entries {
            let name_bytes = name.as_str().as_bytes();
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(name_bytes);
            match entry {
                FsnodeEntry::File {
                    blob_id,
                    size,
                    file_type,
                } => {
                    out.push(1);
                    out.extend_from_slice(blob_id.as_bytes());
                    out.extend_from_slice(&size.to_le_bytes());
                    out.push(file_type_to_u8(*file_type));
                }
                FsnodeEntry::Directory { fsnode_id, summary } => {
                    out.push(2);
                    out.extend_from_slice(fsnode_id.as_bytes());
                    out.extend_from_slice(&summary.child_files_count.to_le_bytes());
                    out.extend_from_slice(&summary.child_files_total_size.to_le_bytes());
                    out.extend_from_slice(&summary.child_dirs_count.to_le_bytes());
                    out.extend_from_slice(&summary.descendant_files_count.to_le_bytes());
                    out.extend_from_slice(&summary.descendant_files_total_size.to_le_bytes());
                }
            }
        }
        out
    }

    /// Computes the canonical domain-separated [`FsnodeId`] for this directory node.
    pub fn fsnode_id(&self) -> FsnodeId {
        FsnodeId::from_canonical_bytes(&self.to_canonical_bytes())
    }

    /// Decodes an `Fsnode` from its canonical binary representation.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 12 || &bytes[0..8] != FSNODE_MAGIC {
            return Err("invalid Fsnode magic header".to_string());
        }
        let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let mut pos = 12;
        let mut entries = BTreeMap::new();
        for _ in 0..count {
            if pos + 2 > bytes.len() {
                return Err("unexpected EOF reading Fsnode entry name length".to_string());
            }
            let name_len = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + name_len + 1 > bytes.len() {
                return Err("unexpected EOF reading Fsnode entry name".to_string());
            }
            let name_str = std::str::from_utf8(&bytes[pos..pos + name_len])
                .map_err(|e| format!("invalid UTF-8 in Fsnode entry: {}", e))?;
            let elem = MPathElement::new(name_str).map_err(|e| e.to_string())?;
            pos += name_len;
            let tag = bytes[pos];
            pos += 1;
            match tag {
                1 => {
                    if pos + 32 + 8 + 1 > bytes.len() {
                        return Err("unexpected EOF reading Fsnode file entry".to_string());
                    }
                    let mut hash_bytes = [0u8; 32];
                    hash_bytes.copy_from_slice(&bytes[pos..pos + 32]);
                    pos += 32;
                    let size = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    let file_type = file_type_from_u8(bytes[pos])?;
                    pos += 1;
                    entries.insert(
                        elem,
                        FsnodeEntry::File {
                            blob_id: BlobId::from_hash(ObjectHash(hash_bytes)),
                            size,
                            file_type,
                        },
                    );
                }
                2 => {
                    if pos + 32 + 40 > bytes.len() {
                        return Err("unexpected EOF reading Fsnode directory entry".to_string());
                    }
                    let mut hash_bytes = [0u8; 32];
                    hash_bytes.copy_from_slice(&bytes[pos..pos + 32]);
                    pos += 32;
                    let child_files_count =
                        u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    let child_files_total_size =
                        u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    let child_dirs_count =
                        u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    let descendant_files_count =
                        u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    let descendant_files_total_size =
                        u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    entries.insert(
                        elem,
                        FsnodeEntry::Directory {
                            fsnode_id: FsnodeId::from_hash(ObjectHash(hash_bytes)),
                            summary: FsnodeSummary {
                                child_files_count,
                                child_files_total_size,
                                child_dirs_count,
                                descendant_files_count,
                                descendant_files_total_size,
                            },
                        },
                    );
                }
                other => return Err(format!("unknown FsnodeEntry tag {}", other)),
            }
        }
        if pos != bytes.len() {
            return Err("trailing bytes in Fsnode encoding".to_string());
        }
        Ok(Self { entries })
    }
}

pub(crate) fn file_type_to_u8(ft: FileType) -> u8 {
    match ft {
        FileType::Regular => 1,
        FileType::Executable => 2,
        FileType::Symlink => 3,
    }
}

pub(crate) fn file_type_from_u8(tag: u8) -> Result<FileType, String> {
    match tag {
        1 => Ok(FileType::Regular),
        2 => Ok(FileType::Executable),
        3 => Ok(FileType::Symlink),
        other => Err(format!("unknown FileType tag {}", other)),
    }
}

pub const fn fsnode_domain() -> ObjectDomain {
    ObjectDomain::Fsnode
}
