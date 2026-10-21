-- =============================================================================
-- Velenza Inarch — Cloud Spanner Production Schema
-- =============================================================================
-- Provides linearizable metadata storage (`SpannerMetadataStore`) for:
--   1. `ScionChangesets`       (canonical Bonsai changesets)
--   2. `ScionRefs`             (atomic compare-and-swap branch/bookmark pointers)
--   3. `ScionDerivedMappings`  (lazy, content-addressed derived data mappings)
--   4. `ScionPrincipals`       (enrolled OIDC workstations, admins, and CI runners)
--   5. `ScionLeases`           (Just-In-Time (JIT) scoped swarm access leases)
-- =============================================================================

CREATE TABLE ScionChangesets (
    ChangesetId STRING(64) NOT NULL,
    Author STRING(320) NOT NULL,
    Message STRING(MAX) NOT NULL,
    TimestampUnix INT64 NOT NULL,
    Parents ARRAY<STRING(64)> NOT NULL,
    Payload BYTES(MAX) NOT NULL,
    CreatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (ChangesetId);

CREATE TABLE ScionRefs (
    RepoId STRING(128) NOT NULL,
    RefName STRING(512) NOT NULL,
    ChangesetId STRING(64) NOT NULL,
    UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (RepoId, RefName);

CREATE TABLE ScionDerivedMappings (
    ChangesetId STRING(64) NOT NULL,
    DerivedKind INT64 NOT NULL,
    RootHash STRING(64) NOT NULL,
    CreatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (ChangesetId, DerivedKind);

CREATE TABLE ScionPrincipals (
    PrincipalId STRING(320) NOT NULL,
    Role STRING(64) NOT NULL,
    AllowedRepos ARRAY<STRING(128)> NOT NULL,
    AllowedOps ARRAY<STRING(64)> NOT NULL,
    AllowedWritePrefixes ARRAY<STRING(1024)> NOT NULL,
    Status STRING(32) NOT NULL,
    HostLabel STRING(256) NOT NULL,
    EnrolledBy STRING(320) NOT NULL,
    CreatedAtUnix INT64 NOT NULL,
    RevokedAtUnix INT64,
    UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (PrincipalId);

CREATE TABLE ScionLeases (
    LeaseId STRING(128) NOT NULL,
    PrincipalId STRING(320) NOT NULL,
    SwarmId STRING(256) NOT NULL,
    TaskId STRING(256) NOT NULL,
    RepoId STRING(128) NOT NULL,
    AllowedOps ARRAY<STRING(64)> NOT NULL,
    AllowedReadPrefixes ARRAY<STRING(1024)> NOT NULL,
    AllowedWritePrefixes ARRAY<STRING(1024)> NOT NULL,
    AllowedRefs ARRAY<STRING(512)> NOT NULL,
    IssuedAtUnix INT64 NOT NULL,
    ExpiresAtUnix INT64 NOT NULL,
    Revoked BOOL NOT NULL,
    RevokedAtUnix INT64,
    UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (LeaseId);
