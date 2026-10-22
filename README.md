# Velenza Inarch (`velenza-inarch` / `inr`)

**Layer 0 of the Velenza Arbor Stack** (`velenza-inarch` → `velenza-cambium` → `velenza-canon` → `velenza-trellis`).

**Velenza Inarch** (`inr`) is an open-source, server-centric version control system written in pure Rust (zero external crate dependencies) for concurrent AI coding agents, ephemeral CI runners, and large repositories.

> **Why the name "Inarch"?**  
> In horticulture, *inarching* (approach grafting) joins a growing shoot (*scion*) onto a rootstock while both remain attached to their own roots until the union heals. In Velenza Inarch, concurrent AI agents work in lightweight sparse worktrees—or completely checkout-free over RPC/MCP—and land their patches onto `main` via client-side rebase on CAS retry without cloning full repository histories or waiting on a global merge lock.

---

## The Velenza Arbor Stack (Unified 4-Layer Agent Architecture)

`velenza-inarch` (`inr`) is **Layer 0** and the umbrella CLI of the open-source **Velenza Arbor Stack**, a 4-layer neuro-symbolic software engineering stack for concurrent AI coding agents:

| Layer | Repository | Canonical Binary | Compatibility Alias | Umbrella CLI | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Layer 0** | [`velenzaboc/velenza-inarch`](https://github.com/velenzaboc/velenza-inarch) | `velenza-inarch` | `inr` | `inr` | **The Graft Union & Rootstock** — Checkout-free content-addressed VCS (`BonsaiChangeset`, 64-char BLAKE3 changeset IDs, client-side rebase, JIT leases) |
| **Layer 1** | [`velenzaboc/velenza-cambium`](https://github.com/velenzaboc/velenza-cambium) | `velenza-cambium` | `code-graph` | `inr cambium` / `inr code` | **The Living Vascular Code Tissue** — CPG/SSA/VTA semantic code graph and deterministic production hazard analyzer (`code_graph_hazards`) |
| **Layer 2** | [`velenzaboc/velenza-canon`](https://github.com/velenzaboc/velenza-canon) | `velenza-canon` | `spec-graph` | `inr canon` / `inr spec` | **The Normative Root Canon** — Versioned architectural specification graph and requirement-to-symbol governance (`trace-code`) |
| **Layer 3** | [`velenzaboc/velenza-trellis`](https://github.com/velenzaboc/velenza-trellis) | `velenza-trellis` | `task-graph` | `inr trellis` / `inr task` | **The Structural Growth Trellis** — Multi-agent execution DAG, TDD receipts, and cryptographic worklink provenance (`fg-validator-runner`) |

### How the 4 Layers Integrate End-to-End

1. **Unified CLI & Shared Environment (`inr stack` & `ARBOR_*`):**
   `velenza-inarch` (`inr`) serves as the single entry point for the stack (`inr stack`, `inr cambium ...`, `inr canon ...`, `inr trellis ...`), propagating unified `ARBOR_GCP_PROJECT` and `ARBOR_SPANNER_INSTANCE` coordinates and streaming stdio across all 4 binaries.
2. **Cryptographic Revision Spine (`velenza-inarch` → `velenza-cambium` & `velenza-trellis`):**
   Every commit landed in `velenza-inarch` produces a 64-character hex BLAKE3 `ChangesetId`. Both `velenza-cambium` (which resolves `.inarch/refs/` natively and stores 64-char changeset IDs in `Snapshots.commit_sha`) and `velenza-trellis` (which validates 64-char BLAKE3 changeset IDs alongside 40-char Git SHAs in `TaskLinks` and `fg-validator-runner`) key their graph snapshots and task worklinks directly to `velenza-inarch` revisions.
3. **Normative Spec-to-Code Traceability (`velenza-canon` ↔ `velenza-cambium`):**
   Architectural specifications admitted in `velenza-canon` are linked to code symbols via `//spec:<REQ-ID>` and `//volt:<SENTINEL>` annotations. `velenza-cambium` extracts these annotations into the SSA/VTA symbol graph during ingestion (`code_graph_annotations`), while `velenza-canon trace-code` (`spec_graph_trace_code`) audits bidirectional requirement-to-symbol coverage and fails closed on dangling or uncovered specification anchors.
4. **Multi-Agent Execution & Hazard-Gated Delivery (`velenza-trellis` ↔ All Layers):**
   Agents claim dependency-ready tasks in `velenza-trellis` (`task_graph_claim`), mint path-scoped JIT workspace leases in `velenza-inarch` (`inr lease checkout`), run static SSA/VTA concurrency/lifecycle hazard checks via `velenza-cambium` (`inr cambium hazards --analyze`), verify normative spec coverage via `velenza-canon` (`inr canon trace-code`), and bind the resulting BLAKE3 `ChangesetId` and TDD receipts into `velenza-trellis` (`task_graph_add_worklink`).
5. **Co-Registered Model Context Protocol (MCP) Surface:**
   All 4 layers run side-by-side as MCP servers (`inr mcp-stdio`, `velenza-cambium mcp`, `velenza-canon mcp`, `velenza-trellis mcp`), giving AI agents checkout-free VCS operations, call-graph and hazard queries, normative specification retrieval, and multi-agent task coordination in one unified tool surface.

```bash
# Inspect resolved binaries and environment configuration across all 4 layers
inr stack
inr stack --json

# Delegate to any Arbor layer directly through `inr` with inherited streaming stdio
inr cambium arbor-info --json
inr canon arbor-info --json
inr trellis arbor-info --json

# End-to-end 4-layer workflow from a single CLI:
inr cambium hazards --analyze /path/to/go-repo
inr canon trace-code --spec-dir /path/to/specs --code-dir /path/to/go-repo
inr trellis fg-validator-runner /path/to/snapshot.json

# Run the 60-second local 4-layer Velenza Arbor Stack quickstart (zero cloud credentials required)
./quickstart/arbor-quickstart.sh
```

---

## Background: The Problem & Why We Are Sharing This

Git was designed twenty years ago for human developers working offline on full local clones, merging changes at human cadence. When engineering teams transition to running dozens of parallel AI coding agents and ephemeral CI sandboxes against a shared repository, Git's offline peer-to-peer design creates three recurring bottlenecks:

1. **Cloning & Checkout Amplification:** Ephemeral agent sandboxes repeatedly clone or check out entire repositories just to inspect and edit a handful of files, wasting disk I/O, CPU, and cloud network egress.
2. **$O(C^2)$ Push-Rebase Storms on `main`:** When $C$ concurrent agents finish tasks at the same time and push to `main`, $C - 1$ pushes fail the Compare-And-Swap check (`non-fast-forward`). Each rejected agent must pull, recompute Merkle directory trees locally, rebase, and retry.
3. **Lack of Path-Scoped Agent Containment:** Standard Git credentials grant access at the repository level. Autonomous agents given repository push tokens cannot easily be restricted at the VCS protocol layer to modifying only their assigned subdirectory for a 30-minute task window.

Recently, **Anthropic** published [*"Redesigning source control at Anthropic"*](https://www.anthropic.com/engineering/redesigning-source-control), an engineering breakdown of **Scion** and **Antique**—the internal version control infrastructure they built to handle 25 million daily checkouts and over 30,000 daily merges across their autonomous coding fleets (building on architectural concepts pioneered by Meta's *Mononoke/Bonsai* and Google's *Piper*).

We are grateful to Anthropic's source control team for [openly sharing the problem statement and architectural design behind Scion](https://www.anthropic.com/engineering/redesigning-source-control). Because Scion itself is bespoke to Anthropic's internal environment—and every organization adopting AI agent workflows is running into the exact same Git bottlenecks—we built **Velenza Inarch** for our own engineering workflows and are releasing the core VCS engine under the **Apache 2.0 License** so the community has an open, self-hostable foundation to build on.

---

## Core Capabilities

| Capability | How Git Works | How Velenza Inarch (`inr`) Works |
| :--- | :--- | :--- |
| **Commit Representation** | Tree-bound commit: hashes every directory along the modified path ($O(\text{Tree Depth} \cdot \text{Width})$). | **Tree-Free `BonsaiChangeset` ($O(\Delta)$):** Stores only the sorted map of modified `MPath -> FileChange` entries (`INARCHBC01`). Zero Merkle trees are read or written on the commit write path. |
| **Concurrent Swarm Landing** | Tree-bound optimistic push-rebase loop ($O(C^2 \cdot \text{Tree})$ retries under contention). | **Lock-Free Speculative Rebase ($O(1)$ parent rewrite):** On client-side CAS retry, `ScionEngine` checks sorted `MPath` intersections in $O(\Delta_1 + \Delta_2)$ and rewrites parent pointers in $O(1)$ without reading directory trees. |
| **Workspace Provisioning** | Full clone, shallow clone, or stateful `have`/`want` packfile negotiation. | **Checkout-Free MCP (`inr mcp-stdio`), Stateless Sparse Checkout (`inr checkout --prefix`), & Virtual On-Demand Mounts (`inr mount` / `inr hydrate`):** Agents either operate with zero local disk checkout over MCP/RPC, mount an instant 0-blob virtual workspace skeleton (or a loopback-only, token-authenticated WebDAV virtual FS that requires a branch ref for writes and treats changeset-ID mounts as read-only) that hydrates files on demand, or walk only their target directory prefix through a 3-tier CAS cache. |
| **Large-File Updates & Wire Egress** | Whole-file blob storage & dynamic packfile compression. | **64-Bit Gear FastCDC + `HasObjectsBatch` + `OSRP` LZ4:** Files above threshold are split into shift-resilient ~16–64 KiB chunks (`INRCBLK1`). Clients preflight-check existing hashes before upload and compress RPC frames with built-in LZ4 framing. |
| **History, Blame, Search, Copy Detection & Bisect** | History walks commit chains; `git bisect` checks out working trees at each step. | **Inductive Derived Graphs (`Fsnode`, `Unode`, `BlameV2`, `CommitGraph`, `PathSearchIndex`, `CopyDetection`):** $O(k)$ path history, checkout-free LCS blame, $O(\log N)$ binary-lifting ancestry, instant glob/substring path search, inductive exact/similar copy & rename detection, checkout-free regression bisect, and checkout-free single-parent inverse-changeset revert (`inr revert`). |
| **Agent Blast-Radius Security & Telemetry** | Repository-wide SSH keys or personal access tokens; ad-hoc stderr logs. | **Workstation OIDC + BLAKE3 JIT Swarm Leases (`inarch_jit_v1_`) + Pluggable Telemetry:** Quantum-safe BLAKE3-keyed MAC tokens bind each agent swarm to a single `repo_id`, allowed operations (`read`, `land`), allowed write directory prefixes, allowed target refs, and a strict TTL, while emitting structured JSONL or Google Cloud Logging (`StructuredLogEntry`) telemetry. |

---

## Architecture & Workspace Layout

Velenza Inarch is structured as a 6-crate Rust workspace with **zero third-party crate dependencies** (`cargo tree --workspace` contains only these 6 crates, compiling a clean release build in ~9 seconds into a single ~2.7 MB binary):

| Crate | Purpose |
| :--- | :--- |
| [`crates/inarch-types`](crates/inarch-types) | Pure-Rust BLAKE3 (verified against official test vectors), domain-separated object IDs (`BlobId`, `ChunkId`, `ChangesetId`, `FsnodeId`, `UnodeFileId`, `UnodeManifestId`, `PathSearchIndexId`, `CopyInfoId`), validated `MPath`, 64-bit Gear FastCDC, and `BonsaiChangeset`. |
| [`crates/inarch-store`](crates/inarch-store) | `BlobStore` and `MetadataStore` traits, 3-tier CAS cache (`TieredBlobStore`), `OSRP` LZ4 wire protocol, `HasObjectsBatch` preflight deduplication, OIDC principals, BLAKE3 JIT leases, pluggable structured telemetry (`telemetry`: local JSONL, `stderr`, and GCP Cloud Logging), and built-in local/cloud storage drivers. |
| [`crates/inarch-derived`](crates/inarch-derived) | Lazy, memoized derivation of `Fsnode` Merkle directory trees, `UnodeFile` / `UnodeManifest` history graphs, `BlameV2` line attribution, `CommitGraph` ($2^k$ binary lifting), `PathSearchIndex` (`INRCPS01`), and `CopyDetection` (`INRCCP01`). |
| [`crates/inarch-engine`](crates/inarch-engine) | `ScionEngine` lock-free speculative rebase (`land_patch`), longest-prefix path ACL enforcement, structured telemetry instrumentation, and checkout-free query execution (`read_file`, `list_directory`, `diff_changesets`, `log_path`, `blame`, `search_paths`, `detect_copies`). |
| [`crates/inarch-antique`](crates/inarch-antique) | `AntiqueService` governance: longest-prefix directory ACLs (`PathAclPolicy`), rebase-surviving semantic approvals (`SemanticApproval`), $O(\log N)$ checkout-free regression bisect, and checkout-free single-parent inverse-changeset revert (`revert_changeset`). |
| [`crates/inarch-cli`](crates/inarch-cli) | `inr` CLI binary, `inr serve` HTTP/1.1 keep-alive RPC server, `inr mount` / `inr hydrate` virtual on-demand workspace & WebDAV server, `inr mcp-stdio` Checkout-Free Model Context Protocol server, `inr git-import` / `inr git-export` migration bridge, and `inr bench` benchmark suite. |

---

## Extending Velenza Inarch with Custom Storage Backends

A core design goal of Velenza Inarch is that **the version control engine is never coupled to a specific database or cloud provider**. Everything in `inarch-derived`, `inarch-engine`, `inarch-antique`, and `inarch-cli` communicates exclusively through two traits defined in [`crates/inarch-store/src/lib.rs`](crates/inarch-store/src/lib.rs):

1. **`BlobStore` (Content-Addressed Immutable Objects):**
   Stores immutable `Blob`, `Chunk`, `Fsnode`, `UnodeFile`, `UnodeManifest`, `PathSearchIndex`, and `CopyInfo` payloads keyed by `(ObjectDomain, ObjectHash)`. Because every object is immutable and content-addressed, blobs can be cached indefinitely at any tier without invalidation traffic.
2. **`MetadataStore` (Changesets, Atomic Ref CAS, Derived Pointers & Leases):**
   Stores `BonsaiChangeset` records, derived-data mapping pointers (`ChangesetId -> FsnodeId`), principals, JIT leases, and provides a single atomic Compare-And-Swap primitive (`cas_ref`) used by lock-free speculative rebase.

### Built-In Backends Included Out of the Box

| Deployment Target | `BlobStore` Implementation | `MetadataStore` Implementation |
| :--- | :--- | :--- |
| **In-Memory / Testing (Rust API)** | `MemBlobStore` | `MemMetadataStore` |
| **Local Workstation / Single-VM NVMe** | `FsBlobStore` (`blob_backend = "fs"`) | `FsMetadataStore` (`meta_backend = "fs"`) |
| **Remote HTTP/RPC Client (with Tier-1 NVMe Cache)** | `RemoteBlobStore` + `TieredBlobStore` (`blob_backend = "remote"`) | `RemoteMetadataStore` (`meta_backend = "remote"`) |
| **Google Cloud Platform (GCP)** | `GcsBlobStore` (`blob_backend = "gcs"`) | `SpannerMetadataStore` (`meta_backend = "spanner"`) |

### Writing a New Backend (PostgreSQL, SQLite, RocksDB, Azure Blob, Cloudflare R2)

To add a new storage backend (for example, PostgreSQL or SQLite for metadata, or Azure Blob Storage / RocksDB for blobs), implement `BlobStore` and/or `MetadataStore` in [`crates/inarch-store`](crates/inarch-store):

```rust
use inarch_store::{BlobStore, MetadataStore, ObjectDomain, StoreError};
use inarch_types::bonsai::BonsaiChangeset;
use inarch_types::hash::{ChangesetId, ObjectHash};

pub struct CustomBlobStore { /* connection pool or handle */ }

impl BlobStore for CustomBlobStore {
    fn get_object(&self, domain: ObjectDomain, hash: &ObjectHash) -> Result<Option<Vec<u8>>, StoreError> {
        // Fetch immutable bytes by (domain. prefix, hash.to_hex()) and call verify_object_integrity(...)
        todo!()
    }

    fn put_object(&self, domain: ObjectDomain, hash: ObjectHash, bytes: Vec<u8>) -> Result<(), StoreError> {
        // Verify BLAKE3 integrity and write idempotently by (domain, hash)
        todo!()
    }
    // Optional overrides: has_objects_batch, get_objects_batch, put_objects_batch
}

pub struct CustomMetadataStore { /* SQL/KV handle */ }

impl MetadataStore for CustomMetadataStore {
    fn get_changeset(&self, id: &ChangesetId) -> Result<Option<BonsaiChangeset>, StoreError> { todo!() }
    fn put_changeset(&self, cs: BonsaiChangeset) -> Result<ChangesetId, StoreError> { todo!() }
    fn get_ref(&self, ref_name: &str) -> Result<Option<ChangesetId>, StoreError> { todo!() }
    fn list_refs(&self) -> Result<std::collections::BTreeMap<String, ChangesetId>, StoreError> { todo!() }
    fn cas_ref(&self, ref_name: &str, expected: Option<ChangesetId>, new_target: ChangesetId) -> Result<(), StoreError> {
        // Single-row conditional UPDATE / INSERT WHERE current_target = expected
        todo!()
    }
    fn get_derived_mapping(&self, cs_id: &ChangesetId, kind: &str) -> Result<Option<ObjectHash>, StoreError> { todo!() }
    fn put_derived_mapping(&self, cs_id: ChangesetId, kind: &str, root: ObjectHash) -> Result<(), StoreError> { todo!() }
}
```

Once implemented, register the backend identifier in [`InarchConfig::open_engine`](crates/inarch-cli/src/config.rs)—every CLI command, MCP tool, speculative rebase, and benchmark workload works automatically against the new backend.

---

## Getting Started

### 1. Build & Test

Requires **Rust 1.89+** (Rust 2024 Edition) on macOS, Linux, or Windows:

```bash
# Build release binaries (`inr` and `velenza-inarch`)
cargo build --release

# Run the test suite
cargo test --workspace
```

### 2. Local or Centralized Usage

```bash
# Initialize a repository and commit a working tree
inr init ./my-project
inr commit -m "Initial commit" --author "dev@example.com" ./my-project

# Checkout-free inspection, path search, and copy/rename detection
inr refs
inr log --path src/main.rs
inr ls main
inr cat main src/main.rs
inr blame main src/main.rs
inr search main "*.rs"
inr copies main
inr diff <base_changeset_id> main

# Materialize a sparse working tree containing only selected directory prefixes
inr checkout main /tmp/agent-worktree --prefix crates/inarch-store,crates/inarch-types

# Or mount an instant virtual workspace (0 blobs written upfront) and hydrate files on demand
inr mount main /tmp/virtual-worktree
inr hydrate /tmp/virtual-worktree crates/inarch-engine/src/lib.rs
# Or serve a loopback-only, token-authenticated WebDAV virtual filesystem that fetches blobs on open()
# (requires a branch ref such as `main` for writes; mounting a 64-hex changeset ID is read-only)
inr mount main --serve-webdav 127.0.0.1:8088

# Start the stateless plaintext HTTP/1.1 RPC server on loopback (backed by local NVMe or GCP Spanner+GCS).
# Non-loopback binds are refused by default unless `--allow-plaintext-non-loopback` is passed;
# place behind a TLS-terminating reverse proxy (Caddy, Envoy, Nginx, or Cloud Run) for network exposure.
inr --config /etc/inarch/server.toml serve --listen 127.0.0.1:7331
```

### 3. Structured Logging & Cloud Telemetry (`[telemetry]`)

Velenza Inarch includes a zero-dependency structured logging and telemetry subsystem (`inarch_store::telemetry`) configurable via `inarch.toml` or `INARCH_LOG_BACKEND`:

- **`log_backend = "local"` (or `"jsonl"`)**: Appends structured JSON Lines events (with microsecond latency `duration_us`, `repo_id`, `changeset_id`, `component`, and `operation`) to `.inarch/logs/inarch.jsonl` (or `INARCH_LOG_FILE`).
- **`log_backend = "stderr"`**: Emits structured JSON Lines to standard error for container log collectors.
- **`log_backend = "gcp"`**: Formats events into Google Cloud Logging `StructuredLogEntry` payloads (`severity`, `logging.googleapis.com/labels`, `logging.googleapis.com/operation`, `logName`) and optionally ships entries directly to `https://logging.googleapis.com/v2/entries:write` when `INARCH_GCP_ACCESS_TOKEN` is set.

### 4. Minting Path-Scoped JIT Leases for AI Agent Swarms

```bash
# Issue a 30-minute, path-restricted JIT lease for an autonomous agent task
inr lease checkout \
  --repo my-repo \
  --swarm swarm-01 \
  --task TASK-101 \
  --ttl 1800 \
  --ops "read,land" \
  --write-prefix "crates/my-crate" \
  --dest /tmp/swarm-01-worktree

# Revoke the lease immediately when the agent finishes
inr lease checkin --dir /tmp/swarm-01-worktree
```

### 5. Migrating from Git (`inr git-import` / `inr git-export`) & GitHub Actions

You can adopt Velenza Inarch incrementally alongside existing Git workflows and CI pipelines:

```bash
# Import an existing Git branch into tree-free BonsaiChangesets (idempotent & incremental)
inr git-import /path/to/git-repo --branch main --ref main

# Export any Velenza Inarch revision back to a Git branch (with an Inarch-Changeset-Id trailer)
inr git-export main /path/to/git-mirror --branch main

# Run the built-in 5-workload scientific benchmark comparing Git vs. Velenza Inarch on your repo
# (measures full & `--filter=blob:none` sparse Git clones, checkout-free & working-copy commits,
# concurrent swarm landing with CAS retry counts, and FastCDC delta storage/wire transfer)
inr bench --source /path/to/git-repo --agents 16 --iterations 5 --output-dir ./bench-results
```

For **GitHub Actions** pipelines, use the included composite action ([`action.yml`](action.yml)) to replace full `actions/checkout` clones with sparse checkouts:

```yaml
steps:
  - name: Sparse checkout via Velenza Inarch
    uses: velenzaboc/velenza-inarch@main
    with:
      remote-url: ${{ secrets.INARCH_REMOTE_URL }}
      auth-token: ${{ secrets.INARCH_JIT_TOKEN }}
      repo-id: "monorepo"
      rev: "main"
      sparse-prefix: "services/billing,crates/common"
      dest: "."
```

---

## CLI Command Summary

| Command | Description |
| :--- | :--- |
| `inr init [dir]` | Initialize `.inarch/` store and `.inarch/config.toml` |
| `inr serve [--listen <addr>]` | Start the stateless plaintext HTTP/1.1 keep-alive RPC server (binds to loopback by default; place behind a TLS-terminating proxy for network exposure, or pass `--allow-plaintext-non-loopback`) |
| `inr commit -m <msg> [dir]` | Ingest full, sparse, or virtual-mount CoW edits and land onto `<ref>` via lock-free speculative rebase |
| `inr checkout <rev> <dest> [--prefix p1,p2]` | Materialize a full or sparse working tree via stateless tree-walk |
| `inr mount <rev> [dest] [--serve-webdav <addr>]` | Create an instant 0-blob virtual workspace skeleton or serve a loopback-only, token-authenticated WebDAV virtual FS (writable on branch refs, read-only on changeset IDs) |
| `inr hydrate <mount_dir> <path_or_prefix...>` | Materialize specific files or directory subtrees on demand inside a virtual workspace mount |
| `inr status [dir]` | Show modified/added/deleted files in a full, sparse, or virtual-mount working tree |
| `inr log [--ref <r>] [--path <p>]` | Show branch history or $O(k)$ path-specific history via `Unode` graphs |
| `inr diff <base> <head>` | Compute $O(\Delta)$ structural Merkle diff between two revisions |
| `inr cat <rev> <path>` / `inr ls <rev> [path]` | Read file contents or list directory summaries checkout-free |
| `inr blame <rev> <path>` | Compute checkout-free line authorship (`BlameV2`) |
| `inr search <rev> <query> [--limit <n>]` | Search repository file paths checkout-free by glob (`*.rs`), prefix, or substring (`PathSearchIndex`) |
| `inr copies [rev]` | Detect exact and similar file copies and renames (`CopyDetection`) |
| `inr bisect --good <id> --bad <id> --run <cmd>` | Run $O(\log N)$ regression bisect across first-parent history |
| `inr revert <changeset_id> [--ref <r>]` | Synthesize and land an inverse `BonsaiChangeset` for a single-parent commit checkout-free |
| `inr principal <enroll\|list\|get\|revoke>` | Manage workstation and service-account OIDC principals |
| `inr lease <checkout\|checkin\|renew\|revoke\|list>` | Mint, renew, inspect, or revoke path-scoped JIT swarm leases |
| `inr git-import` / `inr git-export` | Bidirectional, incremental Git history import and export |
| `inr bench` | Run the 5-workload Git vs. Velenza Inarch benchmark suite (full & sparse Git clones, working-copy & checkout-free commits, CAS retry counts, and pre-run host baseline) |
| `inr mcp-stdio` / `inr mcp-tools` | Run the Checkout-Free Model Context Protocol (MCP) JSON-RPC server over stdio |
| `inr stack [--json]` | Inspect all 4 **Velenza Arbor Stack** layers, environment bindings, and resolved binaries |
| `inr cambium\|code <args...>` | Stream-delegate to Layer 1: `velenza-cambium` (`code-graph` CPG/SSA/VTA Semantic Code & Hazard Graph) |
| `inr canon\|spec <args...>` | Stream-delegate to Layer 2: `velenza-canon` (`spec-graph` Versioned Architectural & Normative Spec Graph) |
| `inr trellis\|task <args...>` | Stream-delegate to Layer 3: `velenza-trellis` (`task-graph` Multi-Agent Execution & Worklink DAG) |

---

## Documentation

- **[`benchmarks/REPORT.md`](benchmarks/REPORT.md)**: Multi-host `N=50,000`-file empirical benchmark report, methodology, fairness controls, raw datasets ([`benchmarks/results/`](benchmarks/results/)), and independent verification guide.
- **[`benchmarks/ARBOR_4REPO_STUDY.md`](benchmarks/ARBOR_4REPO_STUDY.md)**: 4-codebase Velenza Arbor Stack (`velenza-inarch`, `velenza-cambium`, `velenza-canon`, `velenza-trellis`) dogfood study and reproducible runner ([`benchmarks/bench-arbor-4repos.py`](benchmarks/bench-arbor-4repos.py)).
- **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**: Data structures, wire formats (`INARCHBC01`, `INRCBLK1`, `OSRP`), complexity bounds, and security model.
- **[`docs/CENTRALIZED_DEPLOYMENT.md`](docs/CENTRALIZED_DEPLOYMENT.md)**: Deployment guide for standalone local mode, single-VM NVMe server mode, and cloud-native mode (GCP Cloud Spanner + GCS).
- **[`deploy/spanner-schema.sql`](deploy/spanner-schema.sql)**: Cloud Spanner DDL schema (`ScionChangesets`, `ScionRefs`, `ScionDerivedMappings`, `ScionPrincipals`, `ScionLeases`).
- **[`CONTRIBUTING.md`](CONTRIBUTING.md)**: Contribution guidelines and pre-commit hygiene checks.

## License

Licensed under the [Apache License, Version 2.0](LICENSE) — Copyright 2026 Velenza. See [`NOTICE`](NOTICE) for attribution details.
