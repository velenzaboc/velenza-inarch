//! `inarch-types`: Foundational content-addressed types for Velenza Inarch.
//!
//! Includes:
//! - [`hash`]: Official BLAKE3 256-bit cryptographic hashing and domain-separated object IDs.
//! - [`path`]: Validated canonical repository paths (`MPath`, `MPathElement`).
//! - [`cdc`]: Content-Defined Chunking (`FastCdcChunker`) and [`cdc::BlobManifest`].
//! - [`bonsai`]: Tree-free `BonsaiChangeset` commits with canonical binary encoding and $O(\Delta)$ conflict checks.

pub mod bonsai;
pub mod cdc;
pub mod hash;
pub mod path;

pub use bonsai::{BonsaiChangeset, FileChange, FileType};
pub use hash::{
    BlobId, ChangesetId, ChunkId, CopyInfoId, FsnodeId, ObjectDomain, ObjectHash,
    PathSearchIndexId, UnodeFileId, UnodeManifestId,
};
pub use path::{MPath, MPathElement};
