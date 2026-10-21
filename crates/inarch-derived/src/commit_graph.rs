//! Commit Graph nodes (`CommitGraphNode`) with topological generation numbers
//! and binary-lifting $2^k$ skip pointers for $O(\log N)$ ancestry and merge-base queries.

use inarch_types::bonsai::BonsaiChangeset;
use inarch_types::hash::ChangesetId;

use crate::{DerivedDataEngine, DerivedError};

/// Derived commit-graph metadata for a single `ChangesetId`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitGraphNode {
    pub changeset_id: ChangesetId,
    pub parents: Vec<ChangesetId>,
    /// Monotonic topological generation number: `1` for root commits,
    /// `1 + max(parent.generation)` for commits with parents.
    pub generation: u64,
    /// Binary-lifting first-parent skip pointers:
    /// `skip_ancestors[k]` is the $2^k$-th first-parent ancestor of `changeset_id`.
    pub skip_ancestors: Vec<ChangesetId>,
}

/// Collects all changesets in the half-open interval `(ancestor..descendant]` in topological order
/// using generation-pruned commit-graph traversal ($O(|\Delta|)$ time and memory).
///
/// Returns `Ok(None)` when `ancestor` is not an ancestor of `descendant`.
pub fn collect_commits_between(
    engine: &DerivedDataEngine,
    ancestor: ChangesetId,
    descendant: ChangesetId,
) -> Result<Option<Vec<BonsaiChangeset>>, DerivedError> {
    engine.collect_commits_between(ancestor, descendant)
}
