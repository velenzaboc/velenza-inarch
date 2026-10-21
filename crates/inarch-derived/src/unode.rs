//! Per-file (`UnodeFile`) and per-directory (`UnodeManifest`) history graph nodes.
//!
//! Unlike `Fsnode`s (which are pure content-addressed Merkle trees where two commits
//! with the same file content share the same node), a `Unode` embeds its `parents`
//! and `linknode: ChangesetId` (the exact commit that modified that file or directory).
//!
//! Crucially, if a commit does NOT touch a file or directory, the parent commit's
//! `UnodeFileId` / `UnodeManifestId` is reused directly without creating a new Unode.
//! Walking `unode.parents` therefore visits ONLY the $k$ commits that modified the path
//! in $O(k)$ time!

use std::collections::BTreeMap;

use inarch_types::bonsai::FileType;
use inarch_types::hash::{BlobId, ChangesetId, ObjectHash, UnodeFileId, UnodeManifestId};
use inarch_types::path::MPathElement;

use crate::fsnode::{file_type_from_u8, file_type_to_u8};

const UNODE_FILE_MAGIC: &[u8; 8] = b"INRCUNF1";
const UNODE_MANIFEST_MAGIC: &[u8; 8] = b"INRCUNM1";

/// A history graph node for a single file revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnodeFile {
    pub parents: Vec<UnodeFileId>,
    pub blob_id: BlobId,
    pub file_type: FileType,
    pub linknode: ChangesetId,
}

impl UnodeFile {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(UNODE_FILE_MAGIC);
        out.extend_from_slice(&(self.parents.len() as u32).to_le_bytes());
        for p in &self.parents {
            out.extend_from_slice(p.as_bytes());
        }
        out.extend_from_slice(self.blob_id.as_bytes());
        out.push(file_type_to_u8(self.file_type));
        out.extend_from_slice(self.linknode.as_bytes());
        out
    }

    pub fn unode_file_id(&self) -> UnodeFileId {
        UnodeFileId::from_canonical_bytes(&self.to_canonical_bytes())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 12 || &bytes[0..8] != UNODE_FILE_MAGIC {
            return Err("invalid UnodeFile magic header".to_string());
        }
        let parent_count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let expected_len = 12 + parent_count * 32 + 32 + 1 + 32;
        if bytes.len() != expected_len {
            return Err("invalid UnodeFile payload length".to_string());
        }
        let mut pos = 12;
        let mut parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes[pos..pos + 32]);
            parents.push(UnodeFileId::from_hash(ObjectHash(h)));
            pos += 32;
        }
        let mut blob_h = [0u8; 32];
        blob_h.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        let file_type = file_type_from_u8(bytes[pos])?;
        pos += 1;
        let mut link_h = [0u8; 32];
        link_h.copy_from_slice(&bytes[pos..pos + 32]);

        Ok(Self {
            parents,
            blob_id: BlobId::from_hash(ObjectHash(blob_h)),
            file_type,
            linknode: ChangesetId::from_hash(ObjectHash(link_h)),
        })
    }
}

/// Child entry inside a [`UnodeManifest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnodeEntry {
    File(UnodeFileId),
    Directory(UnodeManifestId),
}

/// A history graph node for a directory revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnodeManifest {
    pub parents: Vec<UnodeManifestId>,
    pub entries: BTreeMap<MPathElement, UnodeEntry>,
    pub linknode: ChangesetId,
}

impl UnodeManifest {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(UNODE_MANIFEST_MAGIC);
        out.extend_from_slice(&(self.parents.len() as u32).to_le_bytes());
        for p in &self.parents {
            out.extend_from_slice(p.as_bytes());
        }
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for (name, entry) in &self.entries {
            let name_bytes = name.as_str().as_bytes();
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(name_bytes);
            match entry {
                UnodeEntry::File(fid) => {
                    out.push(1);
                    out.extend_from_slice(fid.as_bytes());
                }
                UnodeEntry::Directory(mid) => {
                    out.push(2);
                    out.extend_from_slice(mid.as_bytes());
                }
            }
        }
        out.extend_from_slice(self.linknode.as_bytes());
        out
    }

    pub fn unode_manifest_id(&self) -> UnodeManifestId {
        UnodeManifestId::from_canonical_bytes(&self.to_canonical_bytes())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 12 || &bytes[0..8] != UNODE_MANIFEST_MAGIC {
            return Err("invalid UnodeManifest magic header".to_string());
        }
        let parent_count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let mut pos = 12;
        if pos + parent_count * 32 + 4 > bytes.len() {
            return Err("unexpected EOF reading UnodeManifest parents".to_string());
        }
        let mut parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes[pos..pos + 32]);
            parents.push(UnodeManifestId::from_hash(ObjectHash(h)));
            pos += 32;
        }
        let entry_count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let mut entries = BTreeMap::new();
        for _ in 0..entry_count {
            if pos + 2 > bytes.len() {
                return Err("unexpected EOF reading UnodeManifest entry name len".to_string());
            }
            let name_len = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + name_len + 1 + 32 > bytes.len() {
                return Err("unexpected EOF reading UnodeManifest entry".to_string());
            }
            let name_str = std::str::from_utf8(&bytes[pos..pos + name_len])
                .map_err(|e| format!("invalid UTF-8 in UnodeManifest entry: {}", e))?;
            let elem = MPathElement::new(name_str).map_err(|e| e.to_string())?;
            pos += name_len;
            let tag = bytes[pos];
            pos += 1;
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            let entry = match tag {
                1 => UnodeEntry::File(UnodeFileId::from_hash(ObjectHash(h))),
                2 => UnodeEntry::Directory(UnodeManifestId::from_hash(ObjectHash(h))),
                other => return Err(format!("unknown UnodeEntry tag {}", other)),
            };
            entries.insert(elem, entry);
        }
        if pos + 32 != bytes.len() {
            return Err("unexpected trailing bytes in UnodeManifest".to_string());
        }
        let mut link_h = [0u8; 32];
        link_h.copy_from_slice(&bytes[pos..pos + 32]);
        Ok(Self {
            parents,
            entries,
            linknode: ChangesetId::from_hash(ObjectHash(link_h)),
        })
    }
}
