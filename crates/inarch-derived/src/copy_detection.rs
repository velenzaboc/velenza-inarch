//! Inductive Copy and Rename Detection (`CopyDetectionReport`) derived data family.
//!
//! Inductively derives file copy and rename provenance for a `ChangesetId` by comparing
//! newly added paths in `BonsaiChangeset::file_changes` against the parent commit's
//! [`PathSearchIndex`]:
//! - **ExactRename / ExactCopy**: $O(1)$ `BlobId` content-hash identity check against parent files.
//! - **SimilarRename / SimilarCopy**: Line-multiset Dice similarity ($\ge 50\%$, i.e. $\ge 5000$ bps)
//!   against deleted or candidate files in the parent commit.

use std::collections::BTreeMap;

use inarch_types::hash::{BlobId, ChangesetId, CopyInfoId, ObjectHash};
use inarch_types::path::MPath;

use crate::DerivedError;

const COPY_INFO_MAGIC: &[u8; 8] = b"INRCCPY1";
const COPY_INFO_VERSION: u8 = 1;

/// Classification of a detected copy or rename edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CopyKind {
    /// 100% identical `BlobId` where the source path was deleted in the same changeset.
    ExactRename,
    /// 100% identical `BlobId` where the source path still exists in the parent changeset.
    ExactCopy,
    /// Modified file ($\ge 50\%$ similarity) where the source path was deleted in the same changeset.
    SimilarRename,
    /// Modified file ($\ge 50\%$ similarity) where the source path still exists in the parent changeset.
    SimilarCopy,
}

impl CopyKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            CopyKind::ExactRename => "ExactRename",
            CopyKind::ExactCopy => "ExactCopy",
            CopyKind::SimilarRename => "SimilarRename",
            CopyKind::SimilarCopy => "SimilarCopy",
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            CopyKind::ExactRename => 1,
            CopyKind::ExactCopy => 2,
            CopyKind::SimilarRename => 3,
            CopyKind::SimilarCopy => 4,
        }
    }

    fn from_u8(b: u8) -> Result<Self, DerivedError> {
        match b {
            1 => Ok(CopyKind::ExactRename),
            2 => Ok(CopyKind::ExactCopy),
            3 => Ok(CopyKind::SimilarRename),
            4 => Ok(CopyKind::SimilarCopy),
            other => Err(DerivedError::CorruptDerivedObject(format!(
                "unknown CopyKind tag {other}"
            ))),
        }
    }
}

/// A single detected file copy or rename edge within a changeset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyRecord {
    pub dest_path: MPath,
    pub source_path: MPath,
    pub kind: CopyKind,
    /// Content similarity in basis points (`0..=10_000`, where `10_000 == 100.00%`).
    pub similarity_bps: u16,
    pub dest_blob_id: BlobId,
    pub source_blob_id: BlobId,
}

/// Content-addressed copy/rename detection report for a `ChangesetId`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyDetectionReport {
    pub changeset_id: ChangesetId,
    pub records: Vec<CopyRecord>,
}

impl CopyDetectionReport {
    pub fn copy_info_id(&self) -> CopyInfoId {
        CopyInfoId::from_canonical_bytes(&self.to_canonical_bytes())
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.records.len() * 96);
        buf.extend_from_slice(COPY_INFO_MAGIC);
        buf.push(COPY_INFO_VERSION);
        buf.extend_from_slice(self.changeset_id.as_bytes());
        buf.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        for rec in &self.records {
            let dest_bytes = rec.dest_path.as_str().as_bytes();
            buf.extend_from_slice(&(dest_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(dest_bytes);
            let src_bytes = rec.source_path.as_str().as_bytes();
            buf.extend_from_slice(&(src_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(src_bytes);
            buf.push(rec.kind.to_u8());
            buf.extend_from_slice(&rec.similarity_bps.to_le_bytes());
            buf.extend_from_slice(rec.dest_blob_id.as_bytes());
            buf.extend_from_slice(rec.source_blob_id.as_bytes());
        }
        buf
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DerivedError> {
        if bytes.len() < 45 || &bytes[0..8] != COPY_INFO_MAGIC {
            return Err(DerivedError::CorruptDerivedObject(
                "invalid CopyDetectionReport magic".into(),
            ));
        }
        if bytes[8] != COPY_INFO_VERSION {
            return Err(DerivedError::CorruptDerivedObject(format!(
                "unsupported CopyDetectionReport version {}",
                bytes[8]
            )));
        }
        let mut cs_arr = [0u8; 32];
        cs_arr.copy_from_slice(&bytes[9..41]);
        let changeset_id = ChangesetId::from_hash(ObjectHash(cs_arr));
        let mut pos = 41usize;
        let count = read_u32(bytes, &mut pos)? as usize;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let dest_len = read_u32(bytes, &mut pos)? as usize;
            if pos + dest_len > bytes.len() {
                return Err(DerivedError::CorruptDerivedObject(
                    "truncated dest_path in CopyDetectionReport".into(),
                ));
            }
            let dest_str = std::str::from_utf8(&bytes[pos..pos + dest_len])
                .map_err(|e| DerivedError::CorruptDerivedObject(e.to_string()))?;
            pos += dest_len;
            let dest_path = MPath::new(dest_str)
                .map_err(|e| DerivedError::CorruptDerivedObject(e.to_string()))?;

            let src_len = read_u32(bytes, &mut pos)? as usize;
            if pos + src_len > bytes.len() {
                return Err(DerivedError::CorruptDerivedObject(
                    "truncated source_path in CopyDetectionReport".into(),
                ));
            }
            let src_str = std::str::from_utf8(&bytes[pos..pos + src_len])
                .map_err(|e| DerivedError::CorruptDerivedObject(e.to_string()))?;
            pos += src_len;
            let source_path = MPath::new(src_str)
                .map_err(|e| DerivedError::CorruptDerivedObject(e.to_string()))?;

            if pos + 1 + 2 + 32 + 32 > bytes.len() {
                return Err(DerivedError::CorruptDerivedObject(
                    "truncated record fields in CopyDetectionReport".into(),
                ));
            }
            let kind = CopyKind::from_u8(bytes[pos])?;
            pos += 1;
            let similarity_bps = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
            pos += 2;
            let mut d_arr = [0u8; 32];
            d_arr.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            let mut s_arr = [0u8; 32];
            s_arr.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;

            records.push(CopyRecord {
                dest_path,
                source_path,
                kind,
                similarity_bps,
                dest_blob_id: BlobId::from_hash(ObjectHash(d_arr)),
                source_blob_id: BlobId::from_hash(ObjectHash(s_arr)),
            });
        }
        if pos != bytes.len() {
            return Err(DerivedError::CorruptDerivedObject(
                "trailing bytes in CopyDetectionReport".into(),
            ));
        }
        Ok(Self {
            changeset_id,
            records,
        })
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

/// Computes content similarity in basis points (`0..=10_000`) between `a` and `b`
/// using line-multiset Dice similarity ($2 \cdot |A \cap B| / (|A| + |B|)$).
pub fn compute_line_similarity_bps(a: &[u8], b: &[u8]) -> u16 {
    if a == b {
        return 10_000;
    }
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    let lines_a: Vec<&[u8]> = a
        .split(|&c| c == b'\n')
        .map(trim_cr)
        .filter(|l| !l.is_empty())
        .collect();
    let lines_b: Vec<&[u8]> = b
        .split(|&c| c == b'\n')
        .map(trim_cr)
        .filter(|l| !l.is_empty())
        .collect();

    if lines_a.is_empty() || lines_b.is_empty() {
        return 0;
    }

    let mut counts_a: BTreeMap<&[u8], usize> = BTreeMap::new();
    for line in &lines_a {
        *counts_a.entry(*line).or_insert(0) += 1;
    }

    let mut intersection = 0usize;
    for line in &lines_b {
        if let Some(cnt) = counts_a.get_mut(*line) {
            if *cnt > 0 {
                *cnt -= 1;
                intersection += 1;
            }
        }
    }

    let total = lines_a.len() + lines_b.len();
    let bps = ((intersection as u64) * 20_000) / (total as u64);
    bps.min(10_000) as u16
}

fn trim_cr(line: &[u8]) -> &[u8] {
    if let Some(stripped) = line.strip_suffix(b"\r") {
        stripped
    } else {
        line
    }
}
