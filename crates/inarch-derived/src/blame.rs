//! Inductive line-by-line attribution (`BlameV2`) derived along a file's `UnodeFile` DAG.
//!
//! Instead of scanning the entire commit graph on every `blame` request, `BlameV2`
//! walks only the file's `UnodeFile` history and applies longest-common-subsequence (LCS)
//! line diffing between parent and child file blobs.

use std::collections::BTreeSet;

use inarch_types::hash::ChangesetId;

/// Attribution for a single 1-indexed line in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlameLine {
    pub line_number: usize,
    pub changeset_id: ChangesetId,
    pub author: String,
    pub origin_line: usize,
    pub content: String,
}

/// Complete line-by-line blame attribution for a file revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlameV2 {
    pub lines: Vec<BlameLine>,
}

impl BlameV2 {
    /// Creates an initial `BlameV2` for a newly added file (no parent Unode).
    pub fn from_initial(content: &str, changeset_id: ChangesetId, author: &str) -> Self {
        let raw_lines = split_lines(content);
        let lines = raw_lines
            .into_iter()
            .enumerate()
            .map(|(idx, line)| BlameLine {
                line_number: idx + 1,
                changeset_id,
                author: author.to_string(),
                origin_line: idx + 1,
                content: line.to_string(),
            })
            .collect();
        Self { lines }
    }

    /// Inductively derives `BlameV2` for `new_content` from `parent_blame` using LCS line matching.
    pub fn derive_from_parent(
        parent_blame: &BlameV2,
        new_content: &str,
        changeset_id: ChangesetId,
        author: &str,
    ) -> Self {
        let new_lines = split_lines(new_content);
        let n = parent_blame.lines.len();
        let m = new_lines.len();

        // Reconstruct exact LCS matches with Hirschberg's divide-and-conquer
        // algorithm. It preserves LCS behavior while using linear memory.
        let mut matched_parent_for_new = vec![None; m];
        if n > 0 && m > 0 {
            let parent_values: BTreeSet<&str> = parent_blame
                .lines
                .iter()
                .map(|line| line.content.as_str())
                .collect();
            if new_lines
                .iter()
                .any(|line| parent_values.contains(*line))
            {
                collect_lcs_matches(
                    &parent_blame.lines,
                    &new_lines,
                    0,
                    0,
                    &mut matched_parent_for_new,
                );
            }
        }

        let mut lines = Vec::with_capacity(m);
        for (new_idx, &line_str) in new_lines.iter().enumerate() {
            let line_number = new_idx + 1;
            if let Some(p_idx) = matched_parent_for_new[new_idx] {
                let p_line = &parent_blame.lines[p_idx];
                lines.push(BlameLine {
                    line_number,
                    changeset_id: p_line.changeset_id,
                    author: p_line.author.clone(),
                    origin_line: p_line.origin_line,
                    content: line_str.to_string(),
                });
            } else {
                lines.push(BlameLine {
                    line_number,
                    changeset_id,
                    author: author.to_string(),
                    origin_line: line_number,
                    content: line_str.to_string(),
                });
            }
        }

        Self { lines }
    }
}

fn collect_lcs_matches(
    parent: &[BlameLine],
    child: &[&str],
    parent_offset: usize,
    child_offset: usize,
    matched_parent_for_new: &mut [Option<usize>],
) {
    if parent.is_empty() || child.is_empty() {
        return;
    }
    if parent.len() == 1 {
        if let Some(child_index) = child
            .iter()
            .position(|line| *line == parent[0].content.as_str())
        {
            matched_parent_for_new[child_offset + child_index] = Some(parent_offset);
        }
        return;
    }

    let midpoint = parent.len() / 2;
    let forward = lcs_prefix_lengths(&parent[..midpoint], child);
    let suffix = lcs_suffix_lengths(&parent[midpoint..], child);
    let mut split = 0usize;
    let mut best_score = 0usize;
    for index in 0..=child.len() {
        let score = forward[index] + suffix[index];
        if score > best_score {
            best_score = score;
            split = index;
        }
    }
    drop(forward);
    drop(suffix);

    collect_lcs_matches(
        &parent[..midpoint],
        &child[..split],
        parent_offset,
        child_offset,
        matched_parent_for_new,
    );
    collect_lcs_matches(
        &parent[midpoint..],
        &child[split..],
        parent_offset + midpoint,
        child_offset + split,
        matched_parent_for_new,
    );
}

fn lcs_prefix_lengths(parent: &[BlameLine], child: &[&str]) -> Vec<usize> {
    let mut previous = vec![0usize; child.len() + 1];
    let mut current = vec![0usize; child.len() + 1];
    for parent_line in parent {
        current[0] = 0;
        for (index, child_line) in child.iter().enumerate() {
            current[index + 1] = if parent_line.content == *child_line {
                previous[index] + 1
            } else {
                previous[index + 1].max(current[index])
            };
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous
}

fn lcs_suffix_lengths(parent: &[BlameLine], child: &[&str]) -> Vec<usize> {
    let mut previous = vec![0usize; child.len() + 1];
    let mut current = vec![0usize; child.len() + 1];
    for parent_line in parent.iter().rev() {
        current[child.len()] = 0;
        for index in (0..child.len()).rev() {
            current[index] = if parent_line.content == child[index] {
                previous[index + 1] + 1
            } else {
                previous[index].max(current[index + 1])
            };
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous
}

fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.lines().collect()
    }
}
