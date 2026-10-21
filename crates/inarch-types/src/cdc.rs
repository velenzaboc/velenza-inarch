//! Content-Defined Chunking (FastCDC) using a 64-bit Gear rolling hash.

use std::fmt;

use crate::hash::{BlobId, ChunkId};

/// Errors produced by FastCDC configuration or blob reassembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdcError {
    InvalidBounds {
        min_size: usize,
        avg_size: usize,
        max_size: usize,
    },
    MissingChunk(ChunkId),
    BlobHashMismatch {
        expected: BlobId,
        actual: BlobId,
    },
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
}

impl fmt::Display for CdcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CdcError::InvalidBounds {
                min_size,
                avg_size,
                max_size,
            } => write!(
                f,
                "invalid CDC bounds: require 64 <= min_size ({min_size}) < avg_size ({avg_size}) < max_size ({max_size}) and avg_size power of two"
            ),
            CdcError::MissingChunk(id) => write!(f, "missing chunk during blob reassembly: {id}"),
            CdcError::BlobHashMismatch { expected, actual } => write!(
                f,
                "reassembled blob hash mismatch: expected {expected}, got {actual}"
            ),
            CdcError::SizeMismatch { expected, actual } => write!(
                f,
                "reassembled blob size mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for CdcError {}

/// Parameters controlling Content-Defined Chunking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdcConfig {
    pub min_size: usize,
    pub avg_size: usize,
    pub max_size: usize,
}

impl Default for CdcConfig {
    fn default() -> Self {
        Self {
            min_size: 16 * 1024,
            avg_size: 64 * 1024,
            max_size: 256 * 1024,
        }
    }
}

/// A single content-addressed chunk produced by [`FastCdcChunker`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub id: ChunkId,
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Metadata entry for a chunk within a [`BlobManifest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRef {
    pub id: ChunkId,
    pub offset: u64,
    pub len: u32,
}

/// Manifest mapping a logical [`BlobId`] to its ordered sequence of [`ChunkRef`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobManifest {
    pub blob_id: BlobId,
    pub total_size: u64,
    pub chunks: Vec<ChunkRef>,
}

/// Deterministic 256-entry 64-bit Gear table generated via SplitMix64 with fixed seed.
const fn build_gear_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut i = 0;
    while i < 256 {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        table[i] = z ^ (z >> 31);
        i += 1;
    }
    table
}

const GEAR_TABLE: [u64; 256] = build_gear_table();

/// FastCDC rolling-hash content-defined chunker with normalized chunk-size distribution.
#[derive(Debug, Clone)]
pub struct FastCdcChunker {
    config: CdcConfig,
    mask_s: u64,
    mask_l: u64,
}

impl FastCdcChunker {
    /// Creates a new [`FastCdcChunker`] from `config`.
    pub fn new(config: CdcConfig) -> Result<Self, CdcError> {
        if config.min_size < 64
            || config.min_size >= config.avg_size
            || config.avg_size >= config.max_size
            || !config.avg_size.is_power_of_two()
        {
            return Err(CdcError::InvalidBounds {
                min_size: config.min_size,
                avg_size: config.avg_size,
                max_size: config.max_size,
            });
        }
        let bits = config.avg_size.trailing_zeros();
        // Normalized FastCDC masks: stricter mask before avg_size, looser mask after avg_size
        let mask_s = ((1u64 << (bits + 1)) - 1) << 16;
        let mask_l = ((1u64 << (bits.saturating_sub(1))) - 1) << 16;
        Ok(Self {
            config,
            mask_s,
            mask_l,
        })
    }

    /// Splits `data` into content-defined chunks.
    pub fn chunk(&self, data: &[u8]) -> Vec<Chunk> {
        if data.is_empty() {
            return Vec::new();
        }
        let mut chunks = Vec::new();
        let mut offset = 0usize;
        while offset < data.len() {
            let cut = self.next_cut(&data[offset..]);
            let slice = &data[offset..offset + cut];
            chunks.push(Chunk {
                id: ChunkId::from_content(slice),
                offset: offset as u64,
                data: slice.to_vec(),
            });
            offset += cut;
        }
        chunks
    }

    fn next_cut(&self, buf: &[u8]) -> usize {
        let len = buf.len();
        if len <= self.config.min_size {
            return len;
        }
        let max_len = len.min(self.config.max_size);
        let center = self.config.avg_size.min(max_len);

        let mut fp: u64 = 0;
        let mut idx = self.config.min_size;

        while idx < center {
            fp = (fp << 1).wrapping_add(GEAR_TABLE[buf[idx] as usize]);
            if (fp & self.mask_s) == 0 {
                return idx + 1;
            }
            idx += 1;
        }

        while idx < max_len {
            fp = (fp << 1).wrapping_add(GEAR_TABLE[buf[idx] as usize]);
            if (fp & self.mask_l) == 0 {
                return idx + 1;
            }
            idx += 1;
        }

        max_len
    }

    /// Builds a [`BlobManifest`] from the original blob bytes and its chunk slice.
    pub fn build_manifest(&self, full_data: &[u8], chunks: &[Chunk]) -> BlobManifest {
        BlobManifest {
            blob_id: BlobId::from_content(full_data),
            total_size: full_data.len() as u64,
            chunks: chunks
                .iter()
                .map(|c| ChunkRef {
                    id: c.id,
                    offset: c.offset,
                    len: c.data.len() as u32,
                })
                .collect(),
        }
    }

    /// Reassembles and cryptographically verifies a blob from its [`BlobManifest`].
    pub fn reassemble<F>(manifest: &BlobManifest, mut fetch_chunk: F) -> Result<Vec<u8>, CdcError>
    where
        F: FnMut(&ChunkId) -> Option<Vec<u8>>,
    {
        let mut out = Vec::with_capacity(manifest.total_size as usize);
        for cref in &manifest.chunks {
            let bytes = fetch_chunk(&cref.id).ok_or(CdcError::MissingChunk(cref.id))?;
            if bytes.len() != cref.len as usize {
                return Err(CdcError::SizeMismatch {
                    expected: cref.len as u64,
                    actual: bytes.len() as u64,
                });
            }
            out.extend_from_slice(&bytes);
        }
        if out.len() as u64 != manifest.total_size {
            return Err(CdcError::SizeMismatch {
                expected: manifest.total_size,
                actual: out.len() as u64,
            });
        }
        let actual_id = BlobId::from_content(&out);
        if actual_id != manifest.blob_id {
            return Err(CdcError::BlobHashMismatch {
                expected: manifest.blob_id,
                actual: actual_id,
            });
        }
        Ok(out)
    }
}
