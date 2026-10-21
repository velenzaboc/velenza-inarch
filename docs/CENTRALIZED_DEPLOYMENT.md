# Velenza Inarch Standalone & Centralized Deployment Guide

Velenza Inarch (`inr`) is a self-contained single binary with **zero external Rust crate dependencies**. Depending on your environment, it runs in three modes from the same binary:

1. **Mode 1: Standalone Local Mode** — Zero server or cloud dependencies; stores objects and metadata in `.inarch/store/` on local disk.
2. **Mode 2: Centralized Single-Host Server Mode** — Runs `inr serve` on a central Linux/macOS host backed by local NVMe storage (`/var/lib/inarch/store`), accessible to multiple workstations and agent swarms over a private network or mesh VPN.
3. **Mode 3: Centralized Cloud-Native Mode (Cloud Spanner + GCS)** — Runs stateless `inr serve` instances backed by Google Cloud Storage (`GcsBlobStore`) for immutable content-addressed blobs and Cloud Spanner (`SpannerMetadataStore`) for linearizable `cas_ref`, `BonsaiChangeset`, OIDC `ScionPrincipals`, and Just-In-Time (JIT) `ScionLeases`.

---

## Mode 1: Standalone Local Usage (Works Out of the Box)

No server, network, or cloud account is required:

```bash
# Build the release binary
cargo build --release --bin inr

# Initialize a local repository
inr init ./my-repo

# Ingest and commit a directory onto `main`
inr commit -m "Initial import" ./my-repo

# Verify 100% byte-for-byte BLAKE3 accuracy against stored changeset
inr status ./my-repo

# Checkout-free queries (no working tree required)
inr ls main
inr cat main src/lib.rs
inr log --path src/lib.rs
inr blame main src/lib.rs
```

---

## Mode 2: Centralized Single-Host Server (Filesystem Backend)

To share repositories across multiple workstations and agent workers without cloud infrastructure:

1. **Copy `inr` and [`deploy/server.example.toml`](../deploy/server.example.toml) to your server**:
   ```toml
   [repository]
   repo_id = "default"

   [network]
   listen_addr = "127.0.0.1:7331"
   oidc_tokeninfo_url = "https://oauth2.googleapis.com/tokeninfo"
   jit_signing_key = "<output-of-openssl-rand-hex-32>"

   [storage]
   blob_backend = "fs"
   meta_backend = "fs"
   store_dir = "/var/lib/inarch/store"
   tier1_cache_dir = "/var/lib/inarch/cache/t1"
   tier2_cache_dir = "/var/lib/inarch/cache/t2"
   ```
   > **Transport Security (`inr serve` is plaintext HTTP/1.1):** Because `velenza-inarch` has zero external crate dependencies, `inr serve` speaks plaintext HTTP/1.1 and **refuses non-loopback bind addresses (wildcard or external network interfaces) by default** unless `--allow-plaintext-non-loopback` is explicitly passed so `Authorization: Bearer` tokens are not inadvertently transmitted in cleartext. For multi-workstation deployments, bind `inr serve` to `127.0.0.1:7331` behind a TLS-terminating reverse proxy (such as Caddy, Envoy, or Nginx), or pass `--allow-plaintext-non-loopback` only when binding directly to an encrypted WireGuard/Tailscale mesh interface.
2. **Install and start the `systemd` service ([`deploy/inarch-server.service`](../deploy/inarch-server.service))**:
   ```bash
   sudo cp deploy/inarch-server.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now inarch-server
   ```

---

## Mode 3: Centralized Cloud-Native Deployment (Cloud Spanner + GCS)

For multi-workstation fleets and high-concurrency autonomous agent swarms:

### Step 1: Provision the Cloud Spanner Database & GCS Bucket

Apply [`deploy/spanner-schema.sql`](../deploy/spanner-schema.sql) to create the five tables (`ScionChangesets`, `ScionRefs`, `ScionDerivedMappings`, `ScionPrincipals`, and `ScionLeases`):

```bash
gcloud spanner databases create velenza-inarch-vcs \
  --instance=<YOUR_SPANNER_INSTANCE> \
  --project=<YOUR_GCP_PROJECT> \
  --ddl-file=deploy/spanner-schema.sql

gcloud storage buckets create gs://<YOUR_BLOB_BUCKET> \
  --project=<YOUR_GCP_PROJECT> \
  --location=us-central1 \
  --uniform-bucket-level-access \
  --public-access-prevention
```

### Step 2: Grant Least-Privilege IAM to the Server Service Account

Grant the `inarch-server` VM service account access **only** to the `velenza-inarch-vcs` database and blob bucket:

```bash
gcloud spanner databases add-iam-policy-binding velenza-inarch-vcs \
  --instance=<YOUR_SPANNER_INSTANCE> \
  --project=<YOUR_GCP_PROJECT> \
  --member="serviceAccount:inarch-server@<YOUR_GCP_PROJECT>.iam.gserviceaccount.com" \
  --role="roles/spanner.databaseUser"

gcloud storage buckets add-iam-policy-binding gs://<YOUR_BLOB_BUCKET> \
  --project=<YOUR_GCP_PROJECT> \
  --member="serviceAccount:inarch-server@<YOUR_GCP_PROJECT>.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"
```

### Step 3: Configure `/etc/inarch/inarch.toml` on the Server

Use [`deploy/server.example.toml`](../deploy/server.example.toml) with `blob_backend = "gcs"`, `meta_backend = "spanner"`, and `listen_addr = "127.0.0.1:7331"`. Terminate TLS in front of `inr serve` via Cloud Run, an internal HTTPS load balancer, or a local TLS-terminating reverse proxy (Caddy, Envoy, or Nginx), and restrict inbound access to your private mesh VPN / subnet router via `nftables` (only pass `--allow-plaintext-non-loopback` if binding directly to an already-encrypted mesh interface).

---

## Adding & Enrolling Workstations (OIDC Principal Enrollment)

Workstations never connect directly to Cloud Spanner or GCS and never share a static bearer token. Instead, each workstation authenticates with its own Google Cloud service-account key (`gcp_credentials_file`), which `inr` exchanges locally for a short-lived Google-signed OIDC `id_token` verified by `inarch-server` against `ScionPrincipals`.

### Automated Onboarding Script ([`scripts/enroll-workstation.sh`](../scripts/enroll-workstation.sh))

From an already-enrolled `admin` workstation:

```bash
./scripts/enroll-workstation.sh \
  --server http://velenza-inarch.internal:7331 \
  --host workstation-02 \
  --email workstation-02@example-project.iam.gserviceaccount.com \
  --ssh dev@workstation-02 \
  --sa-key-path /path/on/workstation-02/to/service_account.json \
  --kind workstation \
  --repos "*" \
  --ops "read,land"
```

### Direct CLI Principal Management

```bash
# Enroll a workstation or admin principal
inr principal enroll workstation-02@example-project.iam.gserviceaccount.com \
  --kind workstation \
  --host workstation-02 \
  --repos "*" \
  --ops "read,land" \
  --write-prefixes "*"

# List all enrolled principals
inr principal list

# Inspect a specific principal
inr principal get workstation-02@example-project.iam.gserviceaccount.com

# Immediately revoke a compromised or retired workstation
inr principal revoke workstation-02@example-project.iam.gserviceaccount.com

# Verify the caller's active identity against the server
inr whoami
```

---

## Restricting Agent Swarms with Just-In-Time (JIT) Access Leases

Autonomous agent swarms should never receive workstation or cloud credentials. Instead, an orchestrator checks out a **Just-In-Time (JIT) Lease** (`ScionLeases`) bound to:
- A single `repo_id`
- Allowed operations (`read` vs `read,land`)
- Allowed write directory prefixes (`--write-prefix`) and target refs (`--refs`)
- A strict Time-To-Live (`--ttl <seconds>`)

The server mints a quantum-safe 256-bit BLAKE3 keyed MAC token (`inarch_jit_v1.<lease_id>.<blake3_mac_hex>`) written to `.inarch/jit_lease.json` inside the swarm's workspace.

### 1. Check Out a Scoped JIT Lease for a Swarm

```bash
inr lease checkout \
  --repo my-repo \
  --swarm swarm-alpha \
  --task TASK-42 \
  --ttl 1800 \
  --ops read,land \
  --write-prefix crates/feature-a \
  --dest /tmp/swarm-alpha-workspace
```

Or combine sparse checkout + JIT lease creation in one command:

```bash
inr checkout main /tmp/swarm-alpha-workspace \
  --prefix crates/feature-a \
  --jit-ttl 1800 \
  --swarm-id swarm-alpha \
  --task-id TASK-42
```

### 2. Swarm Execution (Zero Cloud Credentials Required)

Inside `/tmp/swarm-alpha-workspace`, the swarm authenticates solely via `.inarch/jit_lease.json`:
- Commits touching files under `crates/feature-a/**` succeed via lock-free speculative rebase.
- Any attempt to read another `repo_id` or modify files outside `crates/feature-a/**` is immediately refused by `inarch-server`.

### 3. Check In or Revoke the Lease Immediately on Task Completion

```bash
# Check in from the swarm workspace (revokes the lease on the server and deletes .inarch/jit_lease.json)
inr lease checkin --dir /tmp/swarm-alpha-workspace

# Or revoke any lease by ID from an admin/orchestrator workstation
inr lease revoke <lease_id>

# List active leases
inr lease list --repo my-repo
```
