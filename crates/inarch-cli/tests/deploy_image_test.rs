//! Deploy image contract: the runtime image must ship `curl` (the server shells
//! out to it for HTTPS OIDC and cloud REST calls) on a base whose OpenSSL
//! offers a post-quantum hybrid key exchange by default (Debian trixie), and the
//! builder must use the same Debian release so the binary's glibc matches.

const DOCKERFILE: &str = include_str!("../../../Dockerfile");

#[derive(Debug)]
struct Stage {
    /// Image reference after `FROM` (flags such as `--platform=` removed).
    image: String,
    /// Stage alias after `AS`, if any.
    alias: Option<String>,
    /// Logical instructions (continuation lines joined), excluding the FROM line.
    instructions: Vec<String>,
}

/// Join backslash-continued lines into logical instructions, dropping blank
/// lines and comment-only lines.
fn logical_lines(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for raw in src.lines() {
        let line = raw.trim_end_matches('\r').trim();
        if current.is_empty() && (line.is_empty() || line.starts_with('#')) {
            continue;
        }
        if line.starts_with('#') {
            // Comment inside a continued instruction.
            continue;
        }
        if let Some(stripped) = line.strip_suffix('\\') {
            current.push_str(stripped.trim_end());
            current.push(' ');
        } else {
            current.push_str(line);
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

fn parse_stages(src: &str) -> Vec<Stage> {
    let mut stages: Vec<Stage> = Vec::new();
    for line in logical_lines(src) {
        let mut words = line.split_whitespace();
        let Some(first) = words.next() else { continue };
        if first.eq_ignore_ascii_case("FROM") {
            let rest: Vec<&str> = words.filter(|w| !w.starts_with("--")).collect();
            let image = rest.first().copied().unwrap_or("").to_string();
            let alias = if rest.len() >= 3 && rest[1].eq_ignore_ascii_case("AS") {
                Some(rest[2].to_string())
            } else {
                None
            };
            stages.push(Stage {
                image,
                alias,
                instructions: Vec::new(),
            });
        } else if let Some(stage) = stages.last_mut() {
            stage.instructions.push(line);
        }
    }
    stages
}

fn final_stage(stages: &[Stage]) -> &Stage {
    stages
        .last()
        .expect("Dockerfile must contain at least one stage")
}

/// Tokens of every `RUN` instruction in the stage that performs an
/// `apt-get install`, split on whitespace.
fn apt_install_tokens(stage: &Stage) -> Vec<String> {
    let mut tokens = Vec::new();
    for instr in &stage.instructions {
        let mut parts = instr.split_whitespace();
        let Some(kw) = parts.next() else { continue };
        if !kw.eq_ignore_ascii_case("RUN") {
            continue;
        }
        let body: Vec<&str> = parts.collect();
        let has_install = body
            .windows(2)
            .any(|w| w[0] == "apt-get" && w[1] == "install")
            || body
                .windows(3)
                .any(|w| w[0] == "apt-get" && w[1].starts_with('-') && w[2] == "install");
        if has_install || body.contains(&"install") && body.contains(&"apt-get") {
            tokens.extend(body.iter().map(|t| t.to_string()));
        }
    }
    tokens
}

#[test]
fn dockerfile_parses_into_builder_and_runtime_stages() {
    let stages = parse_stages(DOCKERFILE);
    assert!(
        stages.len() >= 2,
        "expected a multi-stage Dockerfile, parsed {} stage(s): {:?}",
        stages.len(),
        stages
    );
    assert!(
        stages.iter().all(|s| !s.image.is_empty()),
        "every FROM must name an image: {:?}",
        stages
    );
    assert!(
        stages.iter().any(|s| s
            .alias
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case("builder"))),
        "expected a stage aliased `builder`: {:?}",
        stages
    );
}

#[test]
fn final_stage_base_image_is_debian_trixie() {
    let stages = parse_stages(DOCKERFILE);
    let last = final_stage(&stages);
    assert!(
        last.image.to_ascii_lowercase().contains("trixie"),
        "final stage base image must be Debian trixie (OpenSSL 3.5 default X25519MLKEM768), got `{}`",
        last.image
    );
}

#[test]
fn builder_stage_base_image_matches_runtime_release() {
    let stages = parse_stages(DOCKERFILE);
    let builder = stages
        .iter()
        .find(|s| {
            s.alias
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case("builder"))
        })
        .expect("a `builder` stage must exist");
    assert!(
        builder.image.to_ascii_lowercase().contains("trixie"),
        "builder base image must be trixie so the binary's glibc matches the runtime, got `{}`",
        builder.image
    );
}

#[test]
fn final_stage_installs_curl_ca_certificates_and_git() {
    let stages = parse_stages(DOCKERFILE);
    let last = final_stage(&stages);
    let tokens = apt_install_tokens(last);
    assert!(
        !tokens.is_empty(),
        "final stage must run `apt-get install`; instructions: {:?}",
        last.instructions
    );
    for pkg in ["curl", "ca-certificates", "git"] {
        assert!(
            tokens.iter().any(|t| t == pkg),
            "final stage must apt-get install `{pkg}`; RUN tokens: {:?}",
            tokens
        );
    }
}

#[test]
fn no_line_references_bookworm() {
    let offending: Vec<(usize, &str)> = DOCKERFILE
        .lines()
        .enumerate()
        .filter(|(_, l)| l.to_ascii_lowercase().contains("bookworm"))
        .map(|(i, l)| (i + 1, l))
        .collect();
    assert!(
        offending.is_empty(),
        "Dockerfile must not reference bookworm anywhere: {:?}",
        offending
    );
}
