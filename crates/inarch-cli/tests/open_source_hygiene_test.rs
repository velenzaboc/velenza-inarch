//! Open-Source Clean-Room & Externalized Configuration Contract Tests (`inarch-cli`).
//!
//! Enforces three permanent repository invariants:
//! 1. All operational settings, paths, refs, authors, ignore rules, chunk sizes, and ACL policies
//!    are configurable via `InarchConfig` (`inarch.toml` / `.inarch/config.toml` / `INARCH_*`).
//! 2. Zero hardcoded workstation paths (`/Users/<name>`, `/Volumes/<name>`, `/home/<name>`,
//!    `C:\Users\<name>`) or private/Tailscale network addresses appear anywhere in the repository.
//! 3. Zero proprietary organization identifiers or internal environment codenames appear anywhere
//!    in the repository (enforced via cryptographic `BlobId` token digests and optional local
//!    `.git/info/forbidden-patterns.txt`).

mod audit_regression;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use inarch_cli::{
    AclRuleConfig, InarchConfig, checkout_stateless, ingest_directory, verify_codebase_accuracy,
};
use inarch_types::bonsai::{BonsaiChangeset, FileChange, FileType};
use inarch_types::hash::BlobId;
use inarch_types::path::MPath;

/// Cryptographic `BlobId` digests of forbidden proprietary/environment tokens.
/// Storing only 256-bit BLAKE3 digests in the public test suite prevents the test file itself
/// from disclosing internal identifiers while strictly blocking their introduction in any file.
const FORBIDDEN_TOKEN_BLOB_IDS: &[&str] = &[
    "046bb13fc68a5598ff6c11297f3871b279012dd3f61aab8f30daa423964fe348",
    "06e6e7db6b75ea571b313eb83a723f3a59e473c51f15c12bb2ad633b48ec523b",
    "07185509873ec5c41ebf65940c8d3ec9c56626e840b7223e102530378208e2c8",
    "08b0fbfaacd89b843e2e39a373c51c13e99d90ce005833c78a2229fff3746ad6",
    "09e267ff2d0b00165dd97b27a2ca26a2398a50cd2568512435ce518a2749323d",
    "169635f3446d24bd05aa72a52bca2c7d90e05c98bf00c9d850457a93625115f3",
    "1feafe4573bace6c09c0639988f7abd2b809346f844f8e89f54fc5ce6fdddb32",
    "27bc668db6e0e0a9c5600d8159c0395973a607ca09a719170fa2af1dd88e7980",
    "2a10271944250e000ade63bb19f1816f821dc6e4288440e0aae526980f4809cc",
    "3114a21bffaebcc168c9e89fcad246a9c0d70799a599863ae2e4158807985ab3",
    "3267e47e7adf6442144987bfd872cf0b4cbd28b4e88c69c88740ec6b4178441f",
    "43396084a7c8e08a74401abdbe213da4f948cd4cab58072cfbf2e412ae5c8e2e",
    "462ff617d540a8acbc8b41447166c284eb26be82db2868dba96156a031620b60",
    "6e91c487bd335e189c600b02793259ffbe366fa85bf4810eb14b3421c1d1331a",
    "7632cf3f4d8784979b83d14319b0b20d17b249f0aa91fc37b4b71a83e88a6845",
    "7d876c5744fbba213e861842d2de6b4b72469826c6a993f5cec189ae61119c0f",
    "8383482894a8d2c6a6d015b79f68dc0b122324455d17fa26d7bd139398bc5bc7",
    "89224438c9b98abba6fa0e6087fd9fbca29732e953d4f10babec460651e14ee7",
    "93232e5f1cef9eabca392d40f1b05586e80967b3b182cd599145b5190910edc0",
    "9349eee1ed3bf4468c60443f678726495e8b70f0bf024b96121a81112de54aa8",
    "96b20d5f155c3bcae0fd952a47ed5dfe8de37211c62ba91df6649f0e4ce3f961",
    "9e748bf086bf4bb13c57a39e8d3d4a237645c837c52229b9b33e09143949c1eb",
    "a454a19eefa2e5a953ff96aaed9b615a0e76ad2c89f373c4b045303f721db43d",
    "ad68403fc5b75dce26ffc294d006b45e51b7358afce2fca94d38fc55c5036f07",
    "b11a3e2fcfcabffba020e60231a38503b38074ee670b4404ac3fce6762b78b9c",
    "b3eb8953cd90d2ca2cd708069bc0545df6b5c063796be1ba5bf536e382e6aae5",
    "be6adece37f315ef55b3347f8049cdd800b62fbcc2526fcef544857695380ae4",
    "ca7f1240e3d0e4a4d5a901ba695fec3a789e415fad04b6e814a6df6e2cae8e70",
    "caa29d465fd269cbe79eb5c7dfc5b778cbe4309cec4fa67799bbf9b0aabee829",
    "cd6dd13f95950d1776f9ab82ad40f0ae4704f52f46f4c3fd1e2557767875c755",
    "cd785985b9ef0d467b4ca7edb777e47c6435b0b3625643920aaba8a08d56b3e9",
    "d4f48792e687b409e909427c3e7e0b80ef4c669bbede7440788a09592ab45d92",
    "db629a355c20934d91026e9532ed4ce1353b12bb59f6e081bc39bb2c862c998d",
    "e07df5c710bbb320e218f00572191044b49dcffadecca6c3df54fbd0af6784df",
    "e2a24304ca4ecd15bba637aa0369285b834eee024b41944d68ca7b006e893a04",
    "e9e116e6308ec71d69c83c7c9f4d42a41b919988a38ee4a7ff9334825b0bde49",
    "f2b51191e5482480be6ca09999c6c18e9065eba8c0cff55b8506ba858e3fc84d",
    "f704e0875b9ee0612a3c7c673d2248997b2610fdd99b8b403aed4ba4a51dbe37",
    "fd41adb28176777e3006fb23c03d94c6e6445bffeafb20895282126fc55510f7",
];

fn unique_temp_dir(label: &str) -> PathBuf {
    // Short on purpose: a GnuPG home created here names its agent socket, and a socket path has
    // about a hundred bytes to spend (macOS TMPDIR under /var/folders/... is already ~50 bytes).
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let base = if cfg!(unix) && Path::new("/tmp").is_dir() {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    let short_label: String = label.chars().take(4).collect();
    let dir = base.join(format!(
        "ih-{}-{}-{}",
        short_label,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn readme_advertises_the_workspace_minimum_supported_rust_version() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root above inarch-cli crate");
    let workspace_manifest = fs::read_to_string(repo_root.join("Cargo.toml"))
        .expect("read workspace Cargo.toml");
    let declared = workspace_manifest
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("rust-version = \"")
                .and_then(|value| value.strip_suffix('\"'))
        })
        .expect("workspace rust-version declaration");
    let readme = fs::read_to_string(repo_root.join("README.md")).expect("read workspace README");
    let advertised = format!("Requires **Rust {declared}+**");
    assert!(
        readme.contains(&advertised),
        "README build prerequisites must advertise the Cargo.toml MSRV exactly; expected {advertised:?}"
    );
}

#[test]
fn config_toml_roundtrip_and_acl_policy_construction() {
    let custom_cfg = InarchConfig {
        repo_id: "acme-monorepo".to_string(),
        default_ref: "trunk".to_string(),
        default_author: "ci-bot@example.com".to_string(),
        tz_offset_secs: -14400,
        ignore_names: vec![
            ".git".to_string(),
            "target".to_string(),
            ".inarch".to_string(),
            "dist".to_string(),
        ],
        listen_addr: "0.0.0.0:7331".to_string(),
        remote_url: "https://scion.example.com".to_string(),
        auth_token: "token-example-123".to_string(),
        gcp_credentials_file: "etc/inarch/device-sa.json".to_string(),
        jit_lease_file: ".inarch/jit_lease.json".to_string(),
        jit_signing_key: "example-jit-signing-seed-v1".to_string(),
        oidc_tokeninfo_url: "https://oauth2.googleapis.com/tokeninfo".to_string(),
        oidc_token_uri: "https://oauth2.googleapis.com/token".to_string(),
        oidc_audience: "https://scion.example.com".to_string(),
        store_dir: "var/inarch/store".to_string(),
        blobs_subdir: "cas-blobs".to_string(),
        meta_subdir: "cas-meta".to_string(),
        tier1_cache_dir: "var/inarch/cache-t1".to_string(),
        tier2_cache_dir: "var/inarch/cache-t2".to_string(),
        blob_backend: "gcs".to_string(),
        gcs_bucket: "example-inarch-blobs".to_string(),
        gcs_prefix: "objects/v1".to_string(),
        meta_backend: "spanner".to_string(),
        spanner_database: "projects/example-proj/instances/example-inst/databases/example-db"
            .to_string(),
        chunk_min_size: 8192,
        chunk_avg_size: 32768,
        chunk_max_size: 131072,
        log_backend: "local".to_string(),
        log_level: "info".to_string(),
        log_file: ".inarch/logs/inarch.jsonl".to_string(),
        gcp_log_name: "projects/example-proj/logs/velenza-inarch".to_string(),
        acl_rules: vec![
            AclRuleConfig {
                prefix: "security/keys".to_string(),
                allowed_actors: vec![
                    "secops@example.com".to_string(),
                    "release-bot@example.com".to_string(),
                ],
                required_reviewers: Vec::new(),
            },
            AclRuleConfig {
                prefix: "billing/ledger".to_string(),
                allowed_actors: vec!["finance-lead@example.com".to_string()],
                required_reviewers: Vec::new(),
            },
        ],
    };

    let serialized = custom_cfg.to_toml_string();
    let parsed =
        InarchConfig::from_toml_str(&serialized).expect("parse serialized InarchConfig TOML");
    assert_eq!(parsed, custom_cfg);

    // Also verify `inarch.example.toml` at the repository root parses cleanly
    let manifest_dir_str = std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
    let repo_root = Path::new(&manifest_dir_str)
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let example_toml = fs::read_to_string(repo_root.join("inarch.example.toml"))
        .expect("read inarch.example.toml");
    let example_cfg =
        InarchConfig::from_toml_str(&example_toml).expect("parse inarch.example.toml cleanly");
    assert_eq!(example_cfg.default_ref, "main");
    assert_eq!(example_cfg.chunk_avg_size, 65536);

    // Verify the supported actor-only ACL policy construction from config.
    let acl_policy = parsed.build_acl_policy().expect("build ACL policy");
    let restricted_path = MPath::new("security/keys/root.pem").unwrap();
    let unrestricted_path = MPath::new("crates/core/lib.rs").unwrap();

    let unauthorized_cs = BonsaiChangeset {
        parents: Vec::new(),
        author: "untrusted-agent@example.com".to_string(),
        author_date_secs: 1_761_000_000,
        author_tz_offset_secs: 0,
        message: "attempt to touch restricted path".to_string(),
        extra: BTreeMap::new(),
        file_changes: BTreeMap::from([(
            restricted_path.clone(),
            FileChange::Tracked {
                blob_id: BlobId::from_content(b"key"),
                file_type: FileType::Regular,
                size: 3,
            },
        )]),
    };
    assert!(acl_policy.evaluate_changeset(&unauthorized_cs).is_err());

    let authorized_cs = BonsaiChangeset {
        author: "secops@example.com".to_string(),
        ..unauthorized_cs.clone()
    };
    assert!(acl_policy.evaluate_changeset(&authorized_cs).is_ok());

    let unrestricted_cs = BonsaiChangeset {
        file_changes: BTreeMap::from([(
            unrestricted_path,
            FileChange::Tracked {
                blob_id: BlobId::from_content(b"code"),
                file_type: FileType::Regular,
                size: 4,
            },
        )]),
        ..unauthorized_cs
    };
    assert!(acl_policy.evaluate_changeset(&unrestricted_cs).is_ok());
}

#[test]
fn config_driven_persistent_engine_commit_and_checkout() {
    let root = unique_temp_dir("config-engine");
    let workspace = root.join("workspace");
    let src_dir = root.join("sample-project");
    let checkout_dir = root.join("checkout");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(src_dir.join("src")).unwrap();

    fs::write(
        src_dir.join("src/lib.rs"),
        b"pub fn configured_greeting() -> &'static str { \"hello from InarchConfig\" }\n",
    )
    .unwrap();
    fs::write(
        src_dir.join("Cargo.toml"),
        b"[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    let cfg = InarchConfig {
        default_ref: "release".to_string(),
        default_author: "builder@example.com".to_string(),
        tier1_cache_dir: ".inarch/cache/t1".to_string(),
        tier2_cache_dir: ".inarch/cache/t2".to_string(),
        ..Default::default()
    };

    let config_path = workspace.join("inarch.toml");
    cfg.write_to_file(&config_path).expect("write inarch.toml");

    // Discover configuration from workspace directory without explicit path
    let discovered =
        InarchConfig::discover(&workspace, None).expect("discover workspace inarch.toml");
    assert_eq!(discovered, cfg);

    // Open persistent engine purely via discovered config and ingest project
    let ignore_refs = discovered.ignore_slices();
    let receipt = {
        let engine = discovered
            .open_engine(&workspace)
            .expect("open configured engine");
        ingest_directory(
            &engine,
            &discovered.default_ref,
            &discovered.default_author,
            1_761_000_000,
            "initial config-driven commit",
            &src_dir,
            &ignore_refs,
        )
        .expect("ingest directory via configured engine")
    };
    assert_eq!(receipt.files_scanned, 2);

    // Cold reopen via discovered config and verify 100% accuracy + stateless checkout
    let reopened = discovered
        .open_engine(&workspace)
        .expect("reopen configured engine from disk");
    let head = reopened
        .resolve_ref("release")
        .unwrap()
        .expect("release ref persisted");
    assert_eq!(head, receipt.changeset_id);

    let report = verify_codebase_accuracy(&reopened, head, &src_dir, &ignore_refs)
        .expect("verify accuracy from reopened configured engine");
    assert_eq!(report.files_verified, 2);

    let co = checkout_stateless(&reopened, head, None, &checkout_dir)
        .expect("stateless checkout from configured engine");
    assert_eq!(co.files_materialized, 2);
    let co_verify = verify_codebase_accuracy(&reopened, head, &checkout_dir, &ignore_refs)
        .expect("verify materialized checkout");
    assert_eq!(co_verify.bytes_verified, report.bytes_verified);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn repository_contains_zero_proprietary_tokens_or_hardcoded_environment_paths() {
    let manifest_dir_str = std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
    let repo_root = Path::new(&manifest_dir_str)
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    // If `.git/info/forbidden-patterns.txt` is present, include its patterns in the scan
    let patterns_file = repo_root.join(".git/info/forbidden-patterns.txt");
    let mut local_forbidden_patterns: Vec<String> = Vec::new();
    if patterns_file.exists() {
        let raw = fs::read_to_string(&patterns_file).unwrap();
        for line in raw.lines() {
            let trimmed = line.trim().to_ascii_lowercase();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                local_forbidden_patterns.push(trimmed);
            }
        }
    }

    let forbidden_digests: BTreeSet<&str> = FORBIDDEN_TOKEN_BLOB_IDS.iter().copied().collect();

    // Ensure local runtime files are not present or tracked in the repository root
    assert!(
        !repo_root.join("inarch.toml").exists(),
        "local inarch.toml must not exist in repository root"
    );
    if repo_root.join(".git").exists() {
        let tracked = std::process::Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args(["ls-files", "inarch.toml", ".inarch"])
            .output()
            .expect("git ls-files inarch.toml .inarch");
        assert!(
            tracked.stdout.is_empty(),
            "local inarch.toml or .inarch directory must never be tracked by git"
        );
    } else {
        assert!(
            !repo_root.join(".inarch").exists(),
            "local .inarch directory must not exist in exported repository root"
        );
    }

    let mut files = Vec::new();
    collect_repo_files(repo_root, repo_root, &mut files);
    assert!(
        files.len() >= 25,
        "expected to scan all repository files, found {}",
        files.len()
    );
    for required_prefix in [
        ".github/workflows/",
        "benchmarks/",
        "crates/",
        "deploy/",
        "docs/",
        "quickstart/",
        "scripts/",
    ] {
        assert!(
            files
                .iter()
                .any(|(rel, _)| rel.starts_with(required_prefix)),
            "hygiene scan must include files under `{required_prefix}`"
        );
    }

    for (rel_path, abs_path) in files {
        check_text_hygiene(
            &rel_path,
            &rel_path,
            &forbidden_digests,
            &local_forbidden_patterns,
        );

        let bytes = fs::read(&abs_path).expect("read repository file");
        let text = String::from_utf8_lossy(&bytes);
        check_text_hygiene(
            &rel_path,
            &text,
            &forbidden_digests,
            &local_forbidden_patterns,
        );
    }

    // Also verify git commit history metadata (author, committer, messages) if .git is present
    if repo_root.join(".git").exists() {
        let keyring = PlatformKeyring::import(PLATFORM_SIGNING_KEYS);
        if let Some(scan) = commit_metadata_to_scan(
            repo_root,
            keyring.as_ref(),
            PLATFORM_SIGNING_KEY_FINGERPRINTS,
        ) {
            assert!(
                scan.unverifiable_platform_commits.is_empty(),
                "Open-source hygiene: commits {:?} carry GitHub's committer identity but no gpg program is available to check GitHub's signature on them; install gpg (the platform's public signing keys are embedded in this test)",
                scan.unverifiable_platform_commits
            );
            check_text_hygiene(
                ".git/log-history",
                &scan.text,
                &forbidden_digests,
                &local_forbidden_patterns,
            );
            assert!(
                !scan.text.to_ascii_lowercase().contains("co-authored-by:"),
                "Open-source hygiene violation in `.git/log-history`: commit message contains Co-Authored-By trailer"
            );
        }
    }
}

/// Committer identity GitHub stamps on every commit object it creates itself: the merge commits
/// of its merge button and queue, squash merges and web edits.
const PLATFORM_COMMITTER_EMAIL: &str = "noreply@github.com";

/// The public keys GitHub signs the commits it creates with, as served by
/// `https://github.com/web-flow.gpg` (fetched 2026-10-20). The 2017 key expired on 2024-01-16 and
/// still verifies the commits made while it was current; the 2024 key signs current commits.
/// When GitHub rotates its key, the new block is appended here and its fingerprint below.
const PLATFORM_SIGNING_KEYS: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=uMz0
-----END PGP PUBLIC KEY BLOCK-----
"#;

/// Primary-key fingerprints of `PLATFORM_SIGNING_KEYS`. A signature by any other key, or no
/// signature, does not make a commit a platform commit.
const PLATFORM_SIGNING_KEY_FINGERPRINTS: &[&str] = &[
    "5DE3E0509C47EA3CF04A42D34AEE18F83AFDEB23",
    "968479A1AFF927E37D1A566BB5690EEEBB952194",
];

/// The commit history text the hygiene scan covers, plus the commits it could not classify.
struct CommitScan {
    /// The author and committer identity of every commit the project authored, and the message
    /// of every commit.
    text: String,
    /// Abbreviated hashes of commits that carry the platform committer identity while no gpg
    /// program was available to verify the platform's signature on them.
    unverifiable_platform_commits: Vec<String>,
}

/// A throwaway GnuPG home holding only the platform's public signing keys, so that `git log`
/// can report which commits the platform signed.
struct PlatformKeyring {
    home: PathBuf,
    program: PathBuf,
}

impl PlatformKeyring {
    /// Imports `armored_keys` into a fresh keyring, or returns `None` when this machine has no
    /// gpg program.
    fn import(armored_keys: &str) -> Option<Self> {
        use std::io::Write as _;
        let program = gpg_program()?;
        let home = gnupg_home("keyring");
        let keyring = Self { home, program };
        // The keys go in on stdin, so no file path has to be spelled for gpg.
        let mut child = keyring
            .gpg()
            .arg("--import")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        child
            .stdin
            .take()?
            .write_all(armored_keys.as_bytes())
            .ok()?;
        if !child.wait().ok()?.success() {
            return None;
        }
        Some(keyring)
    }

    /// The home directory as this gpg program spells it (`gpg_path_text`).
    fn home_text(&self) -> String {
        gpg_path_text(&self.program, &self.home)
    }

    fn gpg(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.program);
        cmd.arg("--homedir")
            .arg(self.home_text())
            .args(["--batch", "--no-tty", "--quiet"]);
        cmd
    }

    /// Points a git command at this keyring and gpg program for signature verification.
    fn configure(&self, cmd: &mut std::process::Command) {
        cmd.env("GNUPGHOME", self.home_text())
            .arg("-c")
            .arg(format!("gpg.program={}", self.program.display()));
    }
}

impl Drop for PlatformKeyring {
    fn drop(&mut self) {
        remove_gnupg_home(&self.program, &self.home);
    }
}

/// Creates an empty GnuPG home. The empty `common.conf` keeps gpg from writing one that enables
/// the keyboxd daemon, so nothing but gpg-agent can outlive the home.
fn gnupg_home(label: &str) -> PathBuf {
    let home = unique_temp_dir(label);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&home, fs::Permissions::from_mode(0o700));
    }
    fs::write(home.join("common.conf"), "").expect("write common.conf");
    home
}

/// Stops the daemons gpg may have started for `home` and deletes it.
fn remove_gnupg_home(program: &Path, home: &Path) {
    let gpgconf = program.with_file_name(
        program
            .file_name()
            .map(|name| name.to_string_lossy().replacen("gpg", "gpgconf", 1))
            .unwrap_or_else(|| "gpgconf".to_string()),
    );
    let _ = std::process::Command::new(gpgconf)
        .arg("--homedir")
        .arg(gpg_path_text(program, home))
        .args(["--kill", "all"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = fs::remove_dir_all(home);
}

/// The gpg program git can run on this machine: `gpg` on the path, or the copy Git for Windows
/// installs beside its own executables. The path is resolved so that `gpg_is_msys` can look
/// beside it.
fn gpg_program() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    candidates.extend(program_on_path("gpg"));
    if let Ok(out) = std::process::Command::new("git")
        .arg("--exec-path")
        .output()
    {
        if out.status.success() {
            let exec_path = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
            // <install>/mingw64/libexec/git-core -> <install>/usr/bin/gpg.exe
            if let Some(install) = exec_path.ancestors().nth(3) {
                candidates.push(install.join("usr").join("bin").join("gpg.exe"));
            }
        }
    }
    candidates.into_iter().find(|program| {
        std::process::Command::new(program)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    })
}

/// The first `name` found in a directory of `PATH` (`name.exe` on Windows).
fn program_on_path(name: &str) -> Option<PathBuf> {
    let file_name = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(&file_name))
        .find(|candidate| candidate.is_file())
}

/// Whether `program` is the MSYS2 build of gpg that Git for Windows ships. That build takes a
/// path which does not start with `/` for a relative one, a drive-letter path included, and
/// resolves it below its working directory; it understands the same path spelled `/c/<rest>`.
fn gpg_is_msys(program: &Path) -> bool {
    program
        .parent()
        .map(|dir| dir.join("msys-2.0.dll").is_file())
        .unwrap_or(false)
}

/// `path` as `program` spells an absolute path: unchanged, except for an MSYS gpg, which gets a
/// drive-letter path in its `/c/...` form.
fn gpg_path_text(program: &Path, path: &Path) -> String {
    let text = path.to_string_lossy().into_owned();
    if !gpg_is_msys(program) {
        return text;
    }
    let text = text.replace('\\', "/");
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(drive), Some(':')) if drive.is_ascii_alphabetic() => {
            format!("/{}{}", drive.to_ascii_lowercase(), &text[2..])
        }
        _ => text,
    }
}

/// Scans the commit history of `repo_root`: the identity of every commit except the ones GitHub
/// created, and the message of every commit.
///
/// Commits created by GitHub carry the merging account's public profile name and `noreply`
/// address as their author. That identity is written by the platform from the account profile
/// and is visible on the pull request page regardless of what this repository contains, so it is
/// not a byte the project can keep out of its history. A commit counts as created by GitHub only
/// when its committer is GitHub's address *and* it carries a good signature by one of
/// `trusted_fingerprints`, verified against `keyring`; the committer field alone is whatever the
/// committer chose to write. Without a keyring such a commit is reported as unverifiable and its
/// identity is scanned like any other. The messages of every commit stay in scope: branch names
/// and pull request titles land there.
fn commit_metadata_to_scan(
    repo_root: &Path,
    keyring: Option<&PlatformKeyring>,
    trusted_fingerprints: &[&str],
) -> Option<CommitScan> {
    let mut cmd = std::process::Command::new("git");
    cmd.arg("-C").arg(repo_root);
    if let Some(keyring) = keyring {
        keyring.configure(&mut cmd);
    }
    let output = cmd
        .args([
            "log",
            "--exclude=refs/heads/preserve/*",
            "--exclude=refs/remotes/*/preserve/*",
            "--all",
            "--format=%x1e%h%x1f%G?%x1f%GP%x1f%ce%x1f%an%n%ae%n%cn%n%ce%x1f%B",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let mut scan = CommitScan {
        text: String::new(),
        unverifiable_platform_commits: Vec::new(),
    };
    for record in raw.split('\u{1e}').filter(|record| !record.is_empty()) {
        let mut fields = record.splitn(6, '\u{1f}');
        let hash = fields.next().unwrap_or("").trim();
        let signature = fields.next().unwrap_or("").trim();
        let fingerprint = fields.next().unwrap_or("").trim();
        let committer_email = fields.next().unwrap_or("").trim();
        let identity = fields.next().unwrap_or("");
        let message = fields.next().unwrap_or("");
        let claims_platform = committer_email == PLATFORM_COMMITTER_EMAIL;
        // G: good; U: good, key of unknown validity; X: good but expired; Y: good, key expired.
        let platform_signed = matches!(signature, "G" | "U" | "X" | "Y")
            && trusted_fingerprints
                .iter()
                .any(|trusted| trusted.eq_ignore_ascii_case(fingerprint));
        if claims_platform && keyring.is_none() {
            scan.unverifiable_platform_commits.push(hash.to_string());
        }
        if !(claims_platform && keyring.is_some() && platform_signed) {
            scan.text.push_str(identity);
            scan.text.push('\n');
        }
        scan.text.push_str(message);
        scan.text.push('\n');
    }
    Some(scan)
}

/// Author and committer fields of a commit that claims to be GitHub-created.
const PLATFORM_CLAIM_ENV: [(&str, &str); 4] = [
    ("GIT_AUTHOR_NAME", "Profile Display Name"),
    ("GIT_AUTHOR_EMAIL", "1+profile@users.noreply.github.com"),
    ("GIT_COMMITTER_NAME", "GitHub"),
    ("GIT_COMMITTER_EMAIL", PLATFORM_COMMITTER_EMAIL),
];

fn git(dir: &Path, args: &[&str], env: &[(&str, &str)]) {
    let mut cmd = std::process::Command::new("git");
    cmd.arg("-C").arg(dir).args(args);
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("run git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repository with one project-authored commit and a staged second file.
fn fixture_repo(label: &str) -> PathBuf {
    let dir = unique_temp_dir(label);
    git(&dir, &["init", "-q"], &[]);
    git(&dir, &["config", "user.name", "Project Author"], &[]);
    git(&dir, &["config", "user.email", "author@example.com"], &[]);
    git(&dir, &["config", "commit.gpgsign", "false"], &[]);
    fs::write(dir.join("a.txt"), "a\n").unwrap();
    git(&dir, &["add", "a.txt"], &[]);
    git(&dir, &["commit", "-q", "-m", "project: first change"], &[]);
    fs::write(dir.join("b.txt"), "b\n").unwrap();
    git(&dir, &["add", "b.txt"], &[]);
    dir
}

#[test]
fn commit_metadata_scan_keeps_the_identity_of_an_unsigned_commit_that_claims_the_platform_committer()
 {
    let dir = fixture_repo("platform-claim-unsigned");
    // Anyone can write GitHub's address into the committer field of a commit they make
    // themselves; without GitHub's signature the claim is not honored.
    git(
        &dir,
        &[
            "commit",
            "-q",
            "-m",
            "Merge pull request #1 from example/topic-branch",
        ],
        &PLATFORM_CLAIM_ENV,
    );

    let keyring = PlatformKeyring::import(PLATFORM_SIGNING_KEYS);
    let scan = commit_metadata_to_scan(&dir, keyring.as_ref(), PLATFORM_SIGNING_KEY_FINGERPRINTS)
        .expect("git log of the fixture repository");

    // Project-authored identity and every message stay in scope.
    assert!(scan.text.contains("Project Author"), "{}", scan.text);
    assert!(scan.text.contains("author@example.com"), "{}", scan.text);
    assert!(scan.text.contains("project: first change"), "{}", scan.text);
    assert!(
        scan.text
            .contains("Merge pull request #1 from example/topic-branch"),
        "{}",
        scan.text
    );
    // The unsigned claim's identity is scanned like any project identity.
    assert!(scan.text.contains("Profile Display Name"), "{}", scan.text);
    assert!(
        scan.text.contains("1+profile@users.noreply.github.com"),
        "{}",
        scan.text
    );
    match keyring {
        // With a keyring the signature was checked and found absent: nothing is unverifiable.
        Some(_) => assert!(
            scan.unverifiable_platform_commits.is_empty(),
            "{:?}",
            scan.unverifiable_platform_commits
        ),
        // Without gpg the claim cannot be checked and the commit is reported.
        None => assert_eq!(scan.unverifiable_platform_commits.len(), 1),
    }

    let _ = fs::remove_dir_all(&dir);
}

// [pqc-reference-only] This fixture verifies a third-party platform's OpenPGP commit signature
// (GitHub signs the commits it creates with its own key; this test only verifies, never signs
// anything Velenza-controlled). The stand-in key below uses gpg's default algorithm and exists
// only for the duration of the test.
#[test]
fn commit_metadata_scan_leaves_out_the_identity_of_a_commit_signed_by_a_trusted_platform_key() {
    let Some(program) = gpg_program() else {
        eprintln!(
            "no gpg program on this machine: the signed platform commit is not exercised here"
        );
        return;
    };
    // A stand-in for the platform: a fresh signing key in its own GnuPG home.
    let signer_home = gnupg_home("signer");
    let gpg = |args: &[&str]| -> String {
        let out = std::process::Command::new(&program)
            .arg("--homedir")
            .arg(gpg_path_text(&program, &signer_home))
            .args([
                "--batch",
                "--no-tty",
                "--quiet",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
            ])
            .args(args)
            .output()
            .expect("run gpg");
        assert!(
            out.status.success(),
            "gpg {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    gpg(&[
        "--quick-generate-key",
        "Platform Signer <signer@example.com>",
        "default",
        "sign",
        "never",
    ]);
    let fingerprint = gpg(&["--with-colons", "--list-secret-keys"])
        .lines()
        .find_map(|line| {
            line.strip_prefix("fpr:")
                .map(|rest| rest.trim_matches(':').to_string())
        })
        .expect("fingerprint of the generated key");
    let armored = gpg(&["--armor", "--export", &fingerprint]);

    let dir = fixture_repo("platform-claim-signed");
    let signing_key = format!("user.signingkey={fingerprint}");
    let gpg_program_config = format!("gpg.program={}", program.display());
    let signer_home_text = gpg_path_text(&program, &signer_home);
    let mut env = PLATFORM_CLAIM_ENV.to_vec();
    env.push(("GNUPGHOME", signer_home_text.as_str()));
    git(
        &dir,
        &[
            "-c",
            &signing_key,
            "-c",
            &gpg_program_config,
            "commit",
            "-q",
            "-S",
            "-m",
            "Merge pull request #1 from example/topic-branch",
        ],
        &env,
    );

    let keyring = PlatformKeyring::import(&armored).expect("import the generated public key");
    let trusted = [fingerprint.as_str()];
    let scan = commit_metadata_to_scan(&dir, Some(&keyring), &trusted)
        .expect("git log of the fixture repository");
    assert!(
        scan.unverifiable_platform_commits.is_empty(),
        "{:?}",
        scan.unverifiable_platform_commits
    );
    // Project-authored identity and every message stay in scope.
    assert!(scan.text.contains("Project Author"), "{}", scan.text);
    assert!(scan.text.contains("author@example.com"), "{}", scan.text);
    assert!(scan.text.contains("project: first change"), "{}", scan.text);
    assert!(
        scan.text
            .contains("Merge pull request #1 from example/topic-branch"),
        "{}",
        scan.text
    );
    // The platform-signed commit's author and committer identity do not.
    assert!(!scan.text.contains("Profile Display Name"), "{}", scan.text);
    assert!(
        !scan.text.contains("1+profile@users.noreply.github.com"),
        "{}",
        scan.text
    );
    assert!(
        !scan.text.contains(PLATFORM_COMMITTER_EMAIL),
        "{}",
        scan.text
    );

    // The same good signature by a key that is not the platform's leaves the identity in scope.
    let scan = commit_metadata_to_scan(&dir, Some(&keyring), PLATFORM_SIGNING_KEY_FINGERPRINTS)
        .expect("git log of the fixture repository");
    assert!(scan.text.contains("Profile Display Name"), "{}", scan.text);

    drop(keyring);
    remove_gnupg_home(&program, &signer_home);
    let _ = fs::remove_dir_all(&dir);
}

fn collect_repo_files(root: &Path, current: &Path, out: &mut Vec<(String, PathBuf)>) {
    let entries = fs::read_dir(current).expect("read repo directory");
    for entry in entries {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if current == root
            && (name == ".git" || name == "target" || name == ".inarch" || name == ".DS_Store")
        {
            continue;
        }
        if name == ".DS_Store" {
            continue;
        }
        let path = entry.path();
        let ft = fs::symlink_metadata(&path).unwrap().file_type();
        if ft.is_dir() {
            collect_repo_files(root, &path, out);
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
}

fn check_text_hygiene(
    rel_path: &str,
    text: &str,
    forbidden_digests: &BTreeSet<&str>,
    local_patterns: &[String],
) {
    // 1. Check hardcoded workstation paths (`/Users/<alnum>`, `/Volumes/<alnum>`, `/home/<alnum>`, `C:\Users\<alnum>`)
    for prefix in ["/Users/", "/Volumes/", "/home/", "C:\\Users\\", "C:/Users/"] {
        let mut search_from = 0;
        while let Some(idx) = text[search_from..].find(prefix) {
            let abs_idx = search_from + idx + prefix.len();
            if let Some(next_ch) = text[abs_idx..].chars().next() {
                if next_ch.is_ascii_alphanumeric() {
                    panic!(
                        "Open-source hygiene violation in `{}`: hardcoded workstation path prefix `{}{}`",
                        rel_path, prefix, next_ch
                    );
                }
            }
            search_from = abs_idx;
        }
    }

    // 2. Check Tailscale / private network IPv4 literals (`100.<d>.<d>.<d>`, `192.168.<d>.<d>`)
    for (line_idx, line) in text.lines().enumerate() {
        if contains_ipv4_with_first_octet(line, "100.")
            || contains_ipv4_with_first_octet(line, "192.168.")
        {
            panic!(
                "Open-source hygiene violation in `{}:{}`: hardcoded private/Tailscale IPv4 address",
                rel_path,
                line_idx + 1
            );
        }
    }

    // 3. Check every alphanumeric word & hyphenated compound token against FORBIDDEN_TOKEN_BLOB_IDS
    let lower = text.to_ascii_lowercase();
    for token in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
        if token.is_empty() {
            continue;
        }
        let digest = BlobId::from_content(token.as_bytes()).to_hex();
        if forbidden_digests.contains(digest.as_str()) {
            panic!(
                "Open-source hygiene violation in `{}`: file contains a forbidden proprietary/environment token (digest={})",
                rel_path, digest
            );
        }
    }
    for compound in lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '-') {
        let token = compound.trim_matches('-');
        if token.is_empty() || !token.contains('-') {
            continue;
        }
        let digest = BlobId::from_content(token.as_bytes()).to_hex();
        if forbidden_digests.contains(digest.as_str()) {
            panic!(
                "Open-source hygiene violation in `{}`: file contains a forbidden compound proprietary/environment token (digest={})",
                rel_path, digest
            );
        }
    }
    for slash_compound in lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '/')
    {
        let token = slash_compound.trim_matches(|c| c == '-' || c == '/');
        if token.is_empty() || !token.contains('/') {
            continue;
        }
        let digest = BlobId::from_content(token.as_bytes()).to_hex();
        if forbidden_digests.contains(digest.as_str()) {
            panic!(
                "Open-source hygiene violation in `{}`: file contains a forbidden repository coordinate token (digest={})",
                rel_path, digest
            );
        }
    }

    // 4. Check local `.git/info/forbidden-patterns.txt` substrings if present
    for pat in local_patterns {
        if lower.contains(pat) {
            panic!(
                "Open-source hygiene violation in `{}`: file contains forbidden pattern from .git/info/forbidden-patterns.txt",
                rel_path
            );
        }
    }
}

fn contains_ipv4_with_first_octet(line: &str, prefix: &str) -> bool {
    let mut start = 0;
    while let Some(idx) = line[start..].find(prefix) {
        let abs = start + idx;
        let prev_ok = if abs == 0 {
            true
        } else {
            let prev = line.as_bytes()[abs - 1] as char;
            !prev.is_ascii_alphanumeric() && prev != '.'
        };
        if prev_ok {
            let rest = &line[abs + prefix.len()..];
            let parts: Vec<&str> = rest
                .split(|c: char| !c.is_ascii_digit() && c != '.')
                .next()
                .unwrap_or("")
                .split('.')
                .collect();
            let expected_octets = if prefix == "100." { 3 } else { 2 };
            if parts.len() >= expected_octets
                && parts
                    .iter()
                    .take(expected_octets)
                    .all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()))
            {
                return true;
            }
        }
        start = abs + prefix.len();
    }
    false
}
