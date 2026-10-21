//! Inductive line-by-line attribution (`BlameV2`) derived along a file's `UnodeFile` DAG.
//!
//! Instead of scanning the entire commit graph on every `blame` request, `BlameV2`
//! walks only the file's `UnodeFile` history and applies longest-common-subsequence (LCS)
//! line diffing between parent and child file blobs.

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

        // Standard dynamic-programming LCS table over (parent_lines, new_lines)
        let mut dp = vec![vec![0usize; m + 1]; n + 1];
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                if parent_blame.lines[i].content == new_lines[j] {
                    dp[i][j] = 1 + dp[i + 1][j + 1];
                } else {
                    dp[i][j] = dp[i + 1][j].max(dp[i][j + 1]);
                }
            }
        }

        // Reconstruct matched indices (parent_idx -> new_idx)
        let mut matched_parent_for_new = vec![None; m];
        let mut i = 0;
        let mut j = 0;
        while i < n && j < m {
            if parent_blame.lines[i].content == new_lines[j] {
                matched_parent_for_new[j] = Some(i);
                i += 1;
                j += 1;
            } else if dp[i + 1][j] >= dp[i][j + 1] {
                i += 1;
            } else {
                j += 1;
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

fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.lines().collect()
    }
}
