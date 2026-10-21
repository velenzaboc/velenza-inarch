# Velenza Inarch Architecture Specification

Velenza Inarch (`inr`) is a server-centric, API-first version control system designed for organizations where autonomous AI coding agents and ephemeral CI runners generate tens of thousands of merges and millions of repository reads per day.

---

## 1. System Topology

```text
  [ AI Agents / MCP Tool Calls ]           [ Human Devs / CI Sandboxes ]
                │                                        │
   (Checkout-Free RPC / MCP)              (Stateless Sparse Tree-Walk)
                ▼                                        ▼
                │                              ┌───────────────────┐
                │                              │    inarch-daemon    │ (Tier 1: Host NVMe/RAM CAS)
                │                              └─────────┬─────────┘
                │                                        │ (Cache Miss)
                └───────────────────┬────────────────────┘
                                    ▼
                          ┌───────────────────┐
                          │    inarch-cache     │ (Tier 2: Regional Distributed CAS)
                          └─────────┬─────────┘
                                    │ (Strict Tiering Anti-Stampede Boundary)
                                    ▼
                          ┌───────────────────┐
                          │    inarch-server    │ (Tier 3: Stateless Merge & Derived Engine)
                          └─────────┬─────────┘
                                    │
                   ┌────────────────┴────────────────┐
                   ▼                                 ▼
     ┌───────────────────────────┐     ┌───────────────────────────┐
     │      MetadataStore        │     │         BlobStore         │
     │ - BonsaiChangesets        │     │ - FastCDC Chunks          │
     │ - Atomic CAS Global Refs  │     │ - BlobManifests           │
     │ - Derived Data Index      │     │ - Fsnodes, Unodes, Blame  │
     └───────────────────────────┘     └───────────────────────────┘
```

---

## 2. Cryptographic & Content-Addressing Model (`inarch-types`)

### 2.1 Keyed BLAKE3 Domain Separation
Unlike Git's SHA-1 header prefix (`blob <len>\0`), Velenza Inarch uses **BLAKE3's native keyed/derive-key mode** to guarantee cryptographic domain separation across every object class:

| Object Class | Domain Context String | Typed Identifier |
| :--- | :--- | :--- |
| Logical File Blob | `velenza-inarch.blob.v1` | `BlobId` |
| FastCDC Chunk | `velenza-inarch.chunk.v1` | `ChunkId` |
| Canonical Commit | `velenza-inarch.changeset.v1` | `ChangesetId` |
| Derived Merkle Tree | `velenza-inarch.fsnode.v1` | `FsnodeId` |
| Derived File History Node | `velenza-inarch.unode.file.v1` | `UnodeFileId` |
| Derived Directory History Node | `velenza-inarch.unode.manifest.v1` | `UnodeManifestId` |
| Derived Path Search Index | `velenza-inarch.pathsearch.v1` | `PathSearchIndexId` |
| Derived Copy Detection Report | `velenza-inarch.copyinfo.v1` | `CopyInfoId` |

Identical payload bytes hashed under two different `ObjectDomain` variants produce completely unrelated 256-bit digests, eliminating cross-type hash collision vectors.

### 2.2 Shift-Resilient 64-Bit Gear FastCDC
When storing files in `BlobStore::put_blob_content`:
1. The raw file is hashed under `ObjectDomain::Blob` to obtain its logical `BlobId`.
2. A 64-bit Gear rolling hash (`FastCdcChunker`) partitions the byte stream into variable-length chunks (configurable via `[chunking]`; library default min `4 KiB` / avg `16 KiB` / max `64 KiB`, CLI config default min `16 KiB` / avg `64 KiB` / max `256 KiB`) using normalized two-stage Gear masks (`mask_s` before average size, `mask_l` after average size).
3. Each unique chunk is stored once under `ObjectDomain::Chunk` (`ChunkId`), and a compact `BlobManifest` (`INARCHBM01`) is stored under `ObjectDomain::Blob` (`BlobId`).
4. Inserting or deleting bytes near the beginning of a large file shifts at most one boundary before the rolling Gear hash re-synchronizes with all subsequent chunk boundaries.

### 2.3 Tree-Free `BonsaiChangeset`
A canonical commit (`BonsaiChangeset`, magic header `INARCHBC01`) contains:
- `parents: Vec<ChangesetId>`
- `author: String`, `timestamp: i64`, `tz_offset_secs: i32`, `message: String`
- `extra: BTreeMap<String, Vec<u8>>`
- `file_changes: BTreeMap<MPath, FileChange>`

Crucially, `BonsaiChangeset` omits the root Merkle tree hash. Additionally, internal path consistency is enforced at construction time: a single changeset cannot simultaneously record a file at `a/b` and a file under `a/b/c`.

---

## 3. Lock-Free Speculative Rebase (`inarch-engine`)

When $N$ concurrent AI agents read `main` at commit $B$ (`base_changeset`) and submit patches simultaneously:

1. **Pre-Loop Content Upload**: Each agent chunks and stores its modified file blobs into `BlobStore` *before* entering the ref update loop.
2. **Fast Path**: If `MetadataStore::get_ref("main")` still equals $B$, `ScionEngine::land_patch` writes the `BonsaiChangeset` and executes `cas_ref("main", Some(B), new_cs_id)`.
3. **Speculative Rebase Path**: If `main` has advanced to $H \neq B$:
   - `ScionEngine` walks the first-parent chain in $(B..H]$ and verifies that $B$ is an ancestor of $H$.
   - For every intermediate commit $C_i \in (B..H]$, `ScionEngine` calls `template_cs.conflicting_paths(&C_i)` in $O(\Delta)$.
   - Two paths $p_1, p_2$ conflict if and only if $p_1 == p_2$ or one is a directory prefix of the other (`p_1.conflicts_with(&p_2)`).
   - If any $C_i$ conflicts, `land_patch` immediately aborts with `EngineError::MergeConflict { base, head, conflicting_changeset, conflicting_paths }`.
   - If all $C_i \in (B..H]$ are path-disjoint, `template_cs.with_parents(vec![H])` produces the rebased `BonsaiChangeset` in **$O(1)$ without reading a single Merkle tree**, stores it, and retries `cas_ref("main", Some(H), rebased_cs_id)`.

---

## 4. Inductive Derived Data (`inarch-derived`)

All read indexes are derived deterministically on the server and cached in `MetadataStore`:

| Derived Structure | Binary Magic | Complexity | Purpose |
| :--- | :--- | :--- | :--- |
| **`Fsnode`** | `INRCFS01` | $O(\Delta \cdot \text{depth})$ | Content-addressed directory trees with untouched subtree reuse, empty-directory auto-pruning, and recursive `FsnodeSummary` file/byte counts |
| **`UnodeFile` / `UnodeManifest`** | `INRCUF01` / `INRCUM01` | $O(k)$ history walk | Per-file and per-directory commit history graphs that link directly to parent revisions where that specific path changed |
| **`BlameV2`** | `INRCBL01` | $O(L \cdot k)$ | Inductive line-by-line attribution computed along `UnodeFile` edges via Longest Common Subsequence (LCS) |
| **`CommitGraphNode`** | `INRCCG01` | $O(\log N)$ | Topological generation numbers + $2^k$ binary-lifting skip pointers (`step_parents`) for fast `is_ancestor` and `lowest_common_ancestor` |
| **`PathSearchIndex`** | `INRCPS01` | $O(\Delta)$ inductive update | Sorted path-and-basename search index derived inductively from parent `PathSearchIndex` + `BonsaiChangeset` delta; supports glob (`*.rs`), prefix, and case-insensitive substring queries |
| **`CopyDetectionReport`** | `INRCCP01` | $O(\Delta \cdot P)$ | Inductive detection of `ExactRename`, `ExactCopy`, `SimilarRename`, and `SimilarCopy` across changeset boundaries using `BlobId` equality and line-gram Jaccard similarity (in basis points) |

---

## 5. Antique Governance & Post-Merge Recovery (`inarch-antique`)

- **Longest-Prefix Directory ACLs (`PathAclPolicy`)**: Rules match by longest directory prefix (`MPath::is_prefix_of`), allowing fine-grained ownership (e.g., open agent access to `crates/` while restricting `crates/kernel/security` to security reviewers).
- **Rebase-Surviving `SemanticApproval`**:
  - `ApprovalScope::ExactDelta`: hashes the sorted `(MPath, FileChange)` map (`compute_delta_hash`). Because parent `ChangesetId`s are excluded from the delta hash, approvals remain valid across lock-free speculative rebases onto new parents.
  - `ApprovalScope::ScopedPaths`: authorizes an agent to amend any files underneath the approved path prefixes without invalidating the review, while immediately invalidating if an amendment touches a path outside the approved prefixes.
- **$O(\log N)$ Regression Bisect (`bisect_regression`)**: Walks the first-parent chain in $(G..B]$ and binary-searches with a caller-supplied health predicate in $\lceil \log_2 N \rceil$ steps.
- **Instant Checkout-Free Revert (`revert_changeset`)**: Inspects the culprit `BonsaiChangeset` and its parent `Fsnode`, synthesizes the exact inverse `PatchFileEdit`s (restoring modified/deleted files to their pre-culprit blobs and deleting newly added files), and lands the revert via `ScionEngine::land_patch` using the culprit as `base_changeset` (which automatically guarantees via speculative rebase that no subsequent commit modified the reverted paths).

---

## 6. Remote Binary RPC (`INRCSR01`), Cloud Backends & Swarm Access Control (`inarch-store`)

### 6.1 Binary RPC Framing (`INRCSR01` / `INRCSR02`)
`inr serve` exposes a persistent HTTP/1.1 keep-alive endpoint (`POST /v1/rpc`) that exchanges length-prefixed binary frames (`INRCSR01` requests, `INRCSR02` responses). Every request carries a logical `repo_id` partition key alongside the operation payload (`GetObject`, `PutObject`, `HasObject`, `GetChangeset`, `PutChangeset`, `GetRef`, `CasRef`, `ListRefs`, `GetDerived`, `PutDerived`, `EnrollPrincipal`, `CheckoutLease`, `CheckinLease`, `WhoAmI`, etc.).

### 6.2 Cloud Spanner & Google Cloud Storage Backends
- **`GcsBlobStore`**: Stores immutable, content-addressed objects under `gs://<bucket>/<prefix>/<domain>/<first_byte_hex>/<hash_hex>`, verifying the full 256-bit keyed BLAKE3 digest on every read and write.
- **`SpannerMetadataStore`**: Persists `ScionChangesets`, `ScionRefs`, `ScionDerivedMappings`, `ScionPrincipals`, and `ScionLeases` in Google Cloud Spanner with strict read-write transactional `cas_ref` Compare-And-Swap semantics partitioned by `(RepoId, RefName)`.

### 6.3 Workstation OIDC Principals & Quantum-Safe JIT Swarm Leases
- **Workstation OIDC Principals (`ScionPrincipals`)**: Workstations authenticate using short-lived Google OIDC ID tokens minted from their service account keys (`gcp_credentials_file`). The server validates the OIDC token, caches verification for up to 5 minutes, and enforces the principal's `AllowedRepos` and `AllowedOps` (`read`, `land`, `admin`).
- **Quantum-Safe JIT Swarm Leases (`ScionLeases`)**: When an orchestrator spawns an ephemeral agent swarm, it requests a Just-In-Time lease (`inr lease checkout`). The server inserts a row into `ScionLeases` and returns a bearer token (`inarch_jit_v1_<payload_hex>.<mac_hex>`) authenticated with a 256-bit **BLAKE3 keyed MAC** (`blake3_keyed_hash`). Every request carrying a JIT token is verified both cryptographically and against the live `ScionLeases` row for:
  1. Non-revocation (`Revoked == false`) and TTL expiration (`now < ExpiresAt`),
  2. Single-repository isolation (`lease.repo_id == request.repo_id`),
  3. Operation scope (`read` vs. `land`), and
  4. Fine-grained path-prefix enforcement (`WritePrefixes` checked against every `MPath` in `PutChangeset`).

---

## 7. Virtualized On-Demand Workspace Mounts & Pluggable Telemetry

### 7.1 Virtualized On-Demand Workspace Mounts (`inarch-cli::mount`)
For large monorepos where even sparse checkouts may span thousands of files, Velenza Inarch provides two zero-dependency on-demand virtualization modes:
1. **Lazy Skeleton Mount (`inr mount <rev> <dest>` + `inr hydrate <dest> <prefix>`)**:
   - Creates the directory skeleton and writes `.inarch/virtual_mount.toml` recording `changeset_id`, `root_fsnode_id`, and `hydrated_paths` with **zero file blobs written upfront**.
   - Files or subtrees are materialized on demand via `inr hydrate`.
   - Copy-on-Write integration: `verify_codebase_accuracy` (`inr status`) and `ingest_directory` (`inr commit`) automatically treat unhydrated virtual paths as unmodified at their base `Fsnode` state while detecting edits to hydrated files, deletions of hydrated files, and newly created files anywhere in the mount.
2. **OS-Native Loopback WebDAV Virtual Filesystem (`inr mount <rev> --serve-webdav 127.0.0.1:<port>`)**:
   - Serves an RFC 4918 WebDAV virtual filesystem (`OPTIONS`, `PROPFIND` Depth 0/1, `GET`, `HEAD`, `PUT`, `DELETE`, `MKCOL`) directly from `ScionEngine` + `TieredBlobStore` with an in-memory Copy-on-Write overlay.
   - Mountable natively without kernel extensions on macOS (`mount_webdav`), Linux (`davfs2` / GVFS), and Windows (`net use`).

### 7.2 Pluggable Structured Logging & Telemetry (`inarch-store::telemetry`)
`TelemetrySink` decouples observability from the storage and merge engines, supporting:
- **`NoopTelemetrySink` (`log_backend = "none"`)**: Zero-overhead default when telemetry is disabled.
- **`JsonlFileTelemetrySink` (`log_backend = "local"`)**: Thread-safe append-only `.inarch/logs/inarch.jsonl` structured log sink.
- **`StderrTelemetrySink` (`log_backend = "stderr"`)**: Structured JSON Lines output to `stderr`.
- **`GcpCloudLoggingSink` (`log_backend = "gcp"`)**: Formats events into Google Cloud Logging `StructuredLogEntry` JSON (`severity`, `logging.googleapis.com/labels`, `logging.googleapis.com/operation`, `duration_us`, `logName`) with optional direct REST API shipping (`https://logging.googleapis.com/v2/entries:write`).


