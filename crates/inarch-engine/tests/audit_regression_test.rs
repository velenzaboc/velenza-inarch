//! Regression contracts for engine merge, CAS ambiguity, and resource bounds.

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use inarch_engine::{
    EngineError, PatchFileEdit, PatchSubmission, ScionEngine, three_way_merge_lines,
};
use inarch_store::{
    DerivedDataKind, MemBlobStore, MemMetadataStore, MetadataStore, StoreError,
};
use inarch_types::bonsai::{BonsaiChangeset, FileType};
use inarch_types::hash::{ChangesetId, ObjectHash};
use inarch_types::path::MPath;

const ENGINE_LCS_CHILD: &str = "INARCH_AUDIT_ENGINE_LCS_CHILD";

struct CommitThenConflictStore {
    inner: MemMetadataStore,
    inject_after_commit: AtomicBool,
    committed_targets: Mutex<Vec<ChangesetId>>,
}

impl CommitThenConflictStore {
    fn new() -> Self {
        Self {
            inner: MemMetadataStore::new(),
            inject_after_commit: AtomicBool::new(false),
            committed_targets: Mutex::new(Vec::new()),
        }
    }

    fn arm_response_loss(&self) {
        self.committed_targets
            .lock()
            .expect("commit log lock")
            .clear();
        self.inject_after_commit.store(true, Ordering::SeqCst);
    }

    fn committed_targets(&self) -> Vec<ChangesetId> {
        self.committed_targets
            .lock()
            .expect("commit log lock")
            .clone()
    }
}

impl MetadataStore for CommitThenConflictStore {
    fn put_changeset(&self, changeset: &BonsaiChangeset) -> Result<ChangesetId, StoreError> {
        self.inner.put_changeset(changeset)
    }

    fn get_changeset(
        &self,
        changeset_id: &ChangesetId,
    ) -> Result<Option<BonsaiChangeset>, StoreError> {
        self.inner.get_changeset(changeset_id)
    }

    fn get_ref(&self, ref_name: &str) -> Result<Option<ChangesetId>, StoreError> {
        self.inner.get_ref(ref_name)
    }

    fn list_refs(&self) -> Result<BTreeMap<String, ChangesetId>, StoreError> {
        self.inner.list_refs()
    }

    fn cas_ref(
        &self,
        ref_name: &str,
        expected: Option<ChangesetId>,
        new_target: ChangesetId,
    ) -> Result<(), StoreError> {
        self.inner.cas_ref(ref_name, expected, new_target)?;
        self.committed_targets
            .lock()
            .expect("commit log lock")
            .push(new_target);
        if self.inject_after_commit.swap(false, Ordering::SeqCst) {
            return Err(StoreError::CasMismatch {
                ref_name: ref_name.to_string(),
                expected,
                actual: Some(new_target),
            });
        }
        Ok(())
    }

    fn put_derived_mapping(
        &self,
        changeset_id: ChangesetId,
        kind: DerivedDataKind,
        derived_hash: ObjectHash,
    ) -> Result<(), StoreError> {
        self.inner
            .put_derived_mapping(changeset_id, kind, derived_hash)
    }

    fn get_derived_mapping(
        &self,
        changeset_id: ChangesetId,
        kind: DerivedDataKind,
    ) -> Result<Option<ObjectHash>, StoreError> {
        self.inner.get_derived_mapping(changeset_id, kind)
    }
}

fn patch(
    target_ref: &str,
    base: Option<ChangesetId>,
    timestamp: i64,
    message: &str,
    edit: PatchFileEdit,
) -> PatchSubmission {
    PatchSubmission {
        target_ref: target_ref.to_string(),
        base_changeset: base,
        author: "audit@inarch.dev".to_string(),
        timestamp,
        tz_offset_secs: 0,
        message: message.to_string(),
        extra: BTreeMap::new(),
        edits: vec![edit],
    }
}

fn assert_ambiguous_result_did_not_create_another_commit(
    result: Result<inarch_engine::LandOutcome, EngineError>,
    committed: &[ChangesetId],
) {
    assert_eq!(
        committed.len(),
        1,
        "a lost success response must not cause a second history commit: {committed:?}"
    );
    match result {
        Ok(outcome) => assert_eq!(
            outcome.changeset_id, committed[0],
            "successful recovery must return the already committed changeset"
        ),
        Err(EngineError::Store(StoreError::Io(message))) => assert!(
            message.to_ascii_lowercase().contains("ambiguous"),
            "an unrecoverable lost response must be surfaced explicitly as ambiguous: {message}"
        ),
        Err(other) => panic!("unexpected result after a committed CAS response loss: {other:?}"),
    }
}

#[test]
fn committed_cas_with_lost_response_does_not_duplicate_upsert_history() {
    let meta = Arc::new(CommitThenConflictStore::new());
    let engine = ScionEngine::new(Arc::new(MemBlobStore::new()), meta.clone());
    let path = MPath::new("src/lib.rs").expect("valid path");

    let seed = engine
        .land_patch(patch(
            "main",
            None,
            1_760_100_000,
            "seed",
            PatchFileEdit::Upsert {
                path: path.clone(),
                content: b"old\n".to_vec(),
                file_type: FileType::Regular,
            },
        ))
        .expect("seed main");

    meta.arm_response_loss();
    let result = engine.land_patch(patch(
        "main",
        Some(seed.changeset_id),
        1_760_100_001,
        "update once",
        PatchFileEdit::Upsert {
            path,
            content: b"new\n".to_vec(),
            file_type: FileType::Regular,
        },
    ));
    let committed = meta.committed_targets();
    assert_ambiguous_result_did_not_create_another_commit(result, &committed);
    assert_eq!(meta.get_ref("main").expect("read main"), Some(committed[0]));
}

#[test]
fn committed_cas_with_lost_response_does_not_report_delete_as_merge_conflict() {
    let meta = Arc::new(CommitThenConflictStore::new());
    let engine = ScionEngine::new(Arc::new(MemBlobStore::new()), meta.clone());
    let path = MPath::new("obsolete.txt").expect("valid path");

    let seed = engine
        .land_patch(patch(
            "main",
            None,
            1_760_200_000,
            "seed delete target",
            PatchFileEdit::Upsert {
                path: path.clone(),
                content: b"remove me\n".to_vec(),
                file_type: FileType::Regular,
            },
        ))
        .expect("seed main");

    meta.arm_response_loss();
    let result = engine.land_patch(patch(
        "main",
        Some(seed.changeset_id),
        1_760_200_001,
        "delete once",
        PatchFileEdit::Delete { path },
    ));
    let committed = meta.committed_targets();
    assert_ambiguous_result_did_not_create_another_commit(result, &committed);
    assert_eq!(meta.get_ref("main").expect("read main"), Some(committed[0]));
}

#[test]
fn three_way_merge_preserves_an_independent_final_newline_removal() {
    let base = "a\nb\n";
    let ours = "A\nb";
    let theirs = "a\nB\n";

    let merged = three_way_merge_lines(base, theirs, ours)
        .expect("disjoint line and EOF edits must merge cleanly");
    assert_eq!(merged.as_bytes(), b"A\nB");
}

#[test]
fn engine_lcs_memory_child() {
    if std::env::var_os(ENGINE_LCS_CHILD).is_none() {
        return;
    }

    let base: String = (0..15_000).map(|i| format!("base-{i:05}\n")).collect();
    let theirs: String = (0..15_000)
        .map(|i| format!("theirs-{i:05}\n"))
        .collect();
    let ours: String = (0..15_000)
        .map(|i| format!("ours-{i:05}\n"))
        .collect();
    // Both sides differ from the base: an unchanged-side shortcut must not
    // bypass the quadratic diff that this regression is intended to exercise.
    let merged = three_way_merge_lines(&base, &theirs, &ours);
    assert_eq!(merged, None, "overlapping replacements must remain a conflict");
}

#[test]
#[cfg(target_os = "linux")]
fn line_dense_merge_completes_within_a_bounded_address_space() {
    let executable = std::env::current_exe().expect("current test executable");
    let output = Command::new("sh")
        .arg("-c")
        .arg("ulimit -v 524288; exec \"$1\" --exact engine_lcs_memory_child --nocapture")
        .arg("sh")
        .arg(executable)
        .env(ENGINE_LCS_CHILD, "1")
        .output()
        .expect("run bounded-memory merge child");
    assert!(
        output.status.success(),
        "line-dense merge exceeded 512 MiB or failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
