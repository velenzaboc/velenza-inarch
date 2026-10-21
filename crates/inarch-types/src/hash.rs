//! Official BLAKE3 256-bit cryptographic hashing and domain-separated object identifiers.

use std::fmt;

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

#[inline]
fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Mix columns
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    // Mix diagonals
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

#[inline]
fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for i in 0..16 {
        permuted[i] = m[MSG_PERMUTATION[i]];
    }
    *m = permuted;
}

fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut block = *block_words;

    round(&mut state, &block); // round 1
    permute(&mut block);
    round(&mut state, &block); // round 2
    permute(&mut block);
    round(&mut state, &block); // round 3
    permute(&mut block);
    round(&mut state, &block); // round 4
    permute(&mut block);
    round(&mut state, &block); // round 5
    permute(&mut block);
    round(&mut state, &block); // round 6
    permute(&mut block);
    round(&mut state, &block); // round 7

    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

fn first_8_words(compression_output: [u32; 16]) -> [u32; 8] {
    [
        compression_output[0],
        compression_output[1],
        compression_output[2],
        compression_output[3],
        compression_output[4],
        compression_output[5],
        compression_output[6],
        compression_output[7],
    ]
}

fn words_from_little_endian_bytes(bytes: &[u8], words: &mut [u32]) {
    for (bytes_block, word) in bytes.as_chunks::<4>().0.iter().zip(words.iter_mut()) {
        *word = u32::from_le_bytes([
            bytes_block[0],
            bytes_block[1],
            bytes_block[2],
            bytes_block[3],
        ]);
    }
}

#[derive(Clone, Copy)]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_output_bytes(&self) -> [u8; OUT_LEN] {
        let words = compress(
            &self.input_chaining_value,
            &self.block_words,
            0,
            self.block_len,
            self.flags | ROOT,
        );
        let mut out = [0u8; OUT_LEN];
        for (i, word) in words[..8].iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

#[derive(Clone)]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            chaining_value: key_words,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * (self.blocks_compressed as usize) + (self.block_len as usize)
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let mut block_words = [0u32; 16];
                words_from_little_endian_bytes(&self.block, &mut block_words);
                self.chaining_value = first_8_words(compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }

            let want = BLOCK_LEN - (self.block_len as usize);
            let take = want.min(input.len());
            self.block[self.block_len as usize..self.block_len as usize + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let mut block_words = [0u32; 16];
        words_from_little_endian_bytes(&self.block, &mut block_words);
        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(
    left_child_cv: [u32; 8],
    right_child_cv: [u32; 8],
    key_words: [u32; 8],
    flags: u32,
) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left_child_cv);
    block_words[8..].copy_from_slice(&right_child_cv);
    Output {
        input_chaining_value: key_words,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT | flags,
    }
}

fn parent_cv(
    left_child_cv: [u32; 8],
    right_child_cv: [u32; 8],
    key_words: [u32; 8],
    flags: u32,
) -> [u32; 8] {
    parent_output(left_child_cv, right_child_cv, key_words, flags).chaining_value()
}

/// Streaming BLAKE3 hasher conforming to the official BLAKE3 specification.
#[derive(Clone)]
pub struct Blake3Hasher {
    chunk_state: ChunkState,
    key_words: [u32; 8],
    cv_stack: [[u32; 8]; 54],
    cv_stack_len: u8,
    flags: u32,
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3Hasher {
    /// Creates a new standard BLAKE3 hasher.
    pub fn new() -> Self {
        Self::new_internal(IV, 0)
    }

    /// Creates a 256-bit keyed BLAKE3 MAC hasher (`KEYED_HASH`).
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        let mut key_words = [0u32; 8];
        words_from_little_endian_bytes(key, &mut key_words);
        Self::new_internal(key_words, KEYED_HASH)
    }

    /// Creates a domain-separated BLAKE3 key-derivation hasher for a context string.
    pub fn new_derive_key(context: &str) -> Self {
        let mut context_hasher = Self::new_internal(IV, DERIVE_KEY_CONTEXT);
        context_hasher.update(context.as_bytes());
        let context_key = context_hasher.finalize_bytes();
        let mut context_key_words = [0u32; 8];
        words_from_little_endian_bytes(&context_key, &mut context_key_words);
        Self::new_internal(context_key_words, DERIVE_KEY_MATERIAL)
    }

    fn new_internal(key_words: [u32; 8], flags: u32) -> Self {
        Self {
            chunk_state: ChunkState::new(key_words, 0, flags),
            key_words,
            cv_stack: [[0; 8]; 54],
            cv_stack_len: 0,
            flags,
        }
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len as usize] = cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len as usize]
    }

    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            new_cv = parent_cv(self.pop_stack(), new_cv, self.key_words, self.flags);
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    /// Appends bytes to the BLAKE3 hash state.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(self.key_words, total_chunks, self.flags);
            }

            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// Finalizes the hasher and returns the 32-byte digest.
    pub fn finalize_bytes(&self) -> [u8; OUT_LEN] {
        let mut output = self.chunk_state.output();
        let mut parent_nodes_remaining = self.cv_stack_len as usize;
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            output = parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
                self.key_words,
                self.flags,
            );
        }
        output.root_output_bytes()
    }

    /// Finalizes the hasher into an [`ObjectHash`].
    pub fn finalize(&self) -> ObjectHash {
        ObjectHash(self.finalize_bytes())
    }
}

/// Computes the unkeyed 256-bit BLAKE3 digest of `data`.
pub fn blake3_hash(data: &[u8]) -> ObjectHash {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Computes the 256-bit keyed BLAKE3 MAC of `data` under `key`.
pub fn blake3_keyed_hash(key: &[u8; 32], data: &[u8]) -> ObjectHash {
    let mut hasher = Blake3Hasher::new_keyed(key);
    hasher.update(data);
    hasher.finalize()
}

/// Cryptographic domain tags for Velenza Inarch content-addressed objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectDomain {
    Blob,
    Chunk,
    Changeset,
    Fsnode,
    UnodeFile,
    UnodeManifest,
    PathSearchIndex,
    CopyInfo,
}

impl ObjectDomain {
    /// Returns the canonical BLAKE3 key-derivation context string for this domain.
    pub const fn context_str(self) -> &'static str {
        match self {
            ObjectDomain::Blob => "velenza-inarch 2026-10 v1 blob",
            ObjectDomain::Chunk => "velenza-inarch 2026-10 v1 chunk",
            ObjectDomain::Changeset => "velenza-inarch 2026-10 v1 bonsai-changeset",
            ObjectDomain::Fsnode => "velenza-inarch 2026-10 v1 fsnode",
            ObjectDomain::UnodeFile => "velenza-inarch 2026-10 v1 unode-file",
            ObjectDomain::UnodeManifest => "velenza-inarch 2026-10 v1 unode-manifest",
            ObjectDomain::PathSearchIndex => "velenza-inarch 2026-10 v1 path-search-index",
            ObjectDomain::CopyInfo => "velenza-inarch 2026-10 v1 copy-info",
        }
    }
}

/// Errors encountered when parsing or validating an [`ObjectHash`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashError {
    InvalidHexLength(usize),
    InvalidHexCharacter { index: usize, ch: char },
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashError::InvalidHexLength(len) => {
                write!(f, "expected 64 hex characters for 32-byte hash, got {len}")
            }
            HashError::InvalidHexCharacter { index, ch } => {
                write!(f, "invalid hex character '{ch}' at index {index}")
            }
        }
    }
}

impl std::error::Error for HashError {}

/// A 256-bit (32-byte) BLAKE3 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectHash(pub [u8; 32]);

impl ObjectHash {
    /// Computes a domain-separated BLAKE3 hash over `payload`.
    pub fn from_domain(domain: ObjectDomain, payload: &[u8]) -> Self {
        let mut hasher = Blake3Hasher::new_derive_key(domain.context_str());
        hasher.update(payload);
        hasher.finalize()
    }

    /// Returns the raw 32-byte array.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encodes this 32-byte hash as a 64-character lowercase hexadecimal string.
    pub fn to_hex(&self) -> String {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for &b in &self.0 {
            out.push(HEX_CHARS[(b >> 4) as usize] as char);
            out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        out
    }

    /// Parses a 64-character hexadecimal string into an [`ObjectHash`].
    pub fn from_hex(hex: &str) -> Result<Self, HashError> {
        if hex.len() != 64 {
            return Err(HashError::InvalidHexLength(hex.len()));
        }
        let mut bytes = [0u8; 32];
        let raw = hex.as_bytes();
        for i in 0..32 {
            let hi = decode_nibble(raw[i * 2], i * 2)?;
            let lo = decode_nibble(raw[i * 2 + 1], i * 2 + 1)?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(ObjectHash(bytes))
    }
}

fn decode_nibble(b: u8, index: usize) -> Result<u8, HashError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(HashError::InvalidHexCharacter {
            index,
            ch: b as char,
        }),
    }
}

impl fmt::Debug for ObjectHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectHash({})", self.to_hex())
    }
}

impl fmt::Display for ObjectHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

macro_rules! define_typed_id {
    ($name:ident, $domain:expr, $constructor:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub ObjectHash);

        impl $name {
            pub fn $constructor(bytes: &[u8]) -> Self {
                Self(ObjectHash::from_domain($domain, bytes))
            }

            pub const fn from_hash(hash: ObjectHash) -> Self {
                Self(hash)
            }

            pub const fn as_hash(&self) -> &ObjectHash {
                &self.0
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }

            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }

            pub fn from_hex(hex: &str) -> Result<Self, HashError> {
                ObjectHash::from_hex(hex).map(Self)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0.to_hex())
            }
        }
    };
}

define_typed_id!(
    BlobId,
    ObjectDomain::Blob,
    from_content,
    "Domain-separated BLAKE3 identifier for a logical file blob."
);
define_typed_id!(
    ChunkId,
    ObjectDomain::Chunk,
    from_content,
    "Domain-separated BLAKE3 identifier for a Content-Defined Chunk."
);
define_typed_id!(
    ChangesetId,
    ObjectDomain::Changeset,
    from_canonical_bytes,
    "Domain-separated BLAKE3 identifier for a BonsaiChangeset."
);
define_typed_id!(
    FsnodeId,
    ObjectDomain::Fsnode,
    from_canonical_bytes,
    "Domain-separated BLAKE3 identifier for a derived Fsnode directory tree."
);
define_typed_id!(
    UnodeFileId,
    ObjectDomain::UnodeFile,
    from_canonical_bytes,
    "Domain-separated BLAKE3 identifier for a derived file history Unode."
);
define_typed_id!(
    UnodeManifestId,
    ObjectDomain::UnodeManifest,
    from_canonical_bytes,
    "Domain-separated BLAKE3 identifier for a derived directory history Unode."
);
define_typed_id!(
    PathSearchIndexId,
    ObjectDomain::PathSearchIndex,
    from_canonical_bytes,
    "Domain-separated BLAKE3 identifier for a derived PathSearchIndex."
);
define_typed_id!(
    CopyInfoId,
    ObjectDomain::CopyInfo,
    from_canonical_bytes,
    "Domain-separated BLAKE3 identifier for a derived CopyDetection report."
);
