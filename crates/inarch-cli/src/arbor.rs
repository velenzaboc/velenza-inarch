use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArborLayerId {
    Inarch,
    Cambium,
    Canon,
    Trellis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArborLayerDescriptor {
    pub layer: u8,
    pub id: ArborLayerId,
    pub canonical_name: &'static str,
    pub compat_alias: &'static str,
    pub umbrella_subcommands: &'static [&'static str],
    pub binary_env_vars: &'static [&'static str],
    pub config_env_vars: &'static [&'static str],
    pub role: &'static str,
    pub resolved_binary: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArborStackReport {
    pub stack_name: &'static str,
    pub umbrella_cli: &'static str,
    pub layers: Vec<ArborLayerDescriptor>,
}

impl ArborStackReport {
    pub fn to_json_string(&self) -> String {
        let mut out = String::from("{\n");
        out.push_str(&format!("  \"stack_name\": \"{}\",\n", self.stack_name));
        out.push_str(&format!("  \"umbrella_cli\": \"{}\",\n", self.umbrella_cli));
        out.push_str("  \"layers\": [\n");
        for (idx, layer) in self.layers.iter().enumerate() {
            out.push_str("    {\n");
            out.push_str(&format!("      \"layer\": {},\n", layer.layer));
            out.push_str(&format!(
                "      \"canonical_name\": \"{}\",\n",
                layer.canonical_name
            ));
            out.push_str(&format!(
                "      \"compat_alias\": \"{}\",\n",
                layer.compat_alias
            ));
            let subcmds: Vec<String> = layer
                .umbrella_subcommands
                .iter()
                .map(|s| format!("\"{}\"", s))
                .collect();
            out.push_str(&format!(
                "      \"umbrella_subcommands\": [{}],\n",
                subcmds.join(", ")
            ));
            let bin_envs: Vec<String> = layer
                .binary_env_vars
                .iter()
                .map(|s| format!("\"{}\"", s))
                .collect();
            out.push_str(&format!(
                "      \"binary_env_vars\": [{}],\n",
                bin_envs.join(", ")
            ));
            let cfg_envs: Vec<String> = layer
                .config_env_vars
                .iter()
                .map(|s| format!("\"{}\"", s))
                .collect();
            out.push_str(&format!(
                "      \"config_env_vars\": [{}],\n",
                cfg_envs.join(", ")
            ));
            out.push_str(&format!("      \"role\": \"{}\",\n", layer.role));
            match &layer.resolved_binary {
                Some(path) => {
                    let escaped = path
                        .to_string_lossy()
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"");
                    out.push_str(&format!("      \"resolved_binary\": \"{}\"\n", escaped));
                }
                None => {
                    out.push_str("      \"resolved_binary\": null\n");
                }
            }
            if idx + 1 < self.layers.len() {
                out.push_str("    },\n");
            } else {
                out.push_str("    }\n");
            }
        }
        out.push_str("  ]\n}\n");
        out
    }

    pub fn to_text_table(&self) -> String {
        let mut out = format!(
            "Velenza Arbor Stack ({} / umbrella CLI: {})\n",
            self.stack_name, self.umbrella_cli
        );
        out.push_str(&format!(
            "  {:<6} {:<18} {:<14} {:<24} {}\n",
            "LAYER", "CANONICAL", "COMPAT ALIAS", "UMBRELLA", "RESOLVED BINARY"
        ));
        for l in &self.layers {
            let umbrella = l.umbrella_subcommands.join(" | ");
            let resolved = l
                .resolved_binary
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "<not found>".to_string());
            out.push_str(&format!(
                "  L{:<5} {:<18} {:<14} {:<24} {}\n",
                l.layer, l.canonical_name, l.compat_alias, umbrella, resolved
            ));
        }
        out
    }
}

pub fn resolve_umbrella_subcommand(subcmd: &str) -> Option<ArborLayerId> {
    match subcmd {
        "cambium" | "code" | "code-graph" => Some(ArborLayerId::Cambium),
        "canon" | "spec" | "spec-graph" => Some(ArborLayerId::Canon),
        "trellis" | "task" | "task-graph" => Some(ArborLayerId::Trellis),
        _ => None,
    }
}

fn resolve_layer_binary(
    canonical_name: &str,
    compat_alias: &str,
    binary_env_vars: &[&str],
    search_dirs: &[PathBuf],
    env_override: &dyn Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    for env_key in binary_env_vars {
        if let Some(raw) = env_override(env_key) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                let candidate = PathBuf::from(trimmed);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    for dir in search_dirs {
        let candidate = dir.join(canonical_name);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe_candidate = dir.join(format!("{canonical_name}.exe"));
            if exe_candidate.is_file() {
                return Some(exe_candidate);
            }
        }
    }
    for dir in search_dirs {
        let candidate = dir.join(compat_alias);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe_candidate = dir.join(format!("{compat_alias}.exe"));
            if exe_candidate.is_file() {
                return Some(exe_candidate);
            }
        }
    }
    None
}

pub fn default_arbor_search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    if let Some(path_os) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path_os) {
            if !entry.as_os_str().is_empty() && !dirs.contains(&entry) {
                dirs.push(entry);
            }
        }
    }
    dirs
}

pub fn discover_arbor_stack(
    search_dirs: &[PathBuf],
    env_override: &dyn Fn(&str) -> Option<String>,
) -> ArborStackReport {
    let l0 = ArborLayerDescriptor {
        layer: 0,
        id: ArborLayerId::Inarch,
        canonical_name: "velenza-inarch",
        compat_alias: "inr",
        umbrella_subcommands: &["inr"],
        binary_env_vars: &["VELENZA_INARCH_BIN", "INARCH_BIN"],
        config_env_vars: &["INARCH_CONFIG"],
        role: "The Graft Union & Rootstock (Checkout-Free Content-Addressed VCS)",
        resolved_binary: resolve_layer_binary(
            "velenza-inarch",
            "inr",
            &["VELENZA_INARCH_BIN", "INARCH_BIN"],
            search_dirs,
            env_override,
        ),
    };
    let l1 = ArborLayerDescriptor {
        layer: 1,
        id: ArborLayerId::Cambium,
        canonical_name: "velenza-cambium",
        compat_alias: "code-graph",
        umbrella_subcommands: &["inr cambium", "inr code"],
        binary_env_vars: &["VELENZA_CAMBIUM_BIN", "CODE_GRAPH_BIN"],
        config_env_vars: &[
            "CODE_GRAPH_GCP_PROJECT",
            "CODE_GRAPH_SPANNER_INSTANCE",
            "CODE_GRAPH_SPANNER_DATABASE",
            "ARBOR_GCP_PROJECT",
            "ARBOR_SPANNER_INSTANCE",
        ],
        role: "The Living Vascular Code Tissue (CPG/SSA/VTA Semantic Code & Hazard Graph)",
        resolved_binary: resolve_layer_binary(
            "velenza-cambium",
            "code-graph",
            &["VELENZA_CAMBIUM_BIN", "CODE_GRAPH_BIN"],
            search_dirs,
            env_override,
        ),
    };
    let l2 = ArborLayerDescriptor {
        layer: 2,
        id: ArborLayerId::Canon,
        canonical_name: "velenza-canon",
        compat_alias: "spec-graph",
        umbrella_subcommands: &["inr canon", "inr spec"],
        binary_env_vars: &["VELENZA_CANON_BIN", "SPEC_GRAPH_BIN"],
        config_env_vars: &[
            "VELENZA_CANON_CONFIG",
            "SPEC_GRAPH_CONFIG",
            "ARBOR_GCP_PROJECT",
            "ARBOR_SPANNER_INSTANCE",
        ],
        role: "The Normative Root Canon (Versioned Architectural & Normative Spec Graph)",
        resolved_binary: resolve_layer_binary(
            "velenza-canon",
            "spec-graph",
            &["VELENZA_CANON_BIN", "SPEC_GRAPH_BIN"],
            search_dirs,
            env_override,
        ),
    };
    let l3 = ArborLayerDescriptor {
        layer: 3,
        id: ArborLayerId::Trellis,
        canonical_name: "velenza-trellis",
        compat_alias: "task-graph",
        umbrella_subcommands: &["inr trellis", "inr task"],
        binary_env_vars: &["VELENZA_TRELLIS_BIN", "TASK_GRAPH_BIN"],
        config_env_vars: &[
            "VELENZA_TRELLIS_CONFIG",
            "TASK_GRAPH_CONFIG",
            "ARBOR_GCP_PROJECT",
            "ARBOR_SPANNER_INSTANCE",
        ],
        role: "The Structural Growth Trellis (Multi-Agent Execution & Worklink DAG)",
        resolved_binary: resolve_layer_binary(
            "velenza-trellis",
            "task-graph",
            &["VELENZA_TRELLIS_BIN", "TASK_GRAPH_BIN"],
            search_dirs,
            env_override,
        ),
    };

    ArborStackReport {
        stack_name: "velenza-arbor",
        umbrella_cli: "inr",
        layers: vec![l0, l1, l2, l3],
    }
}

pub fn spawn_arbor_subcommand_inherited(
    layer: ArborLayerId,
    args: &[String],
    search_dirs: &[PathBuf],
    env_override: &dyn Fn(&str) -> Option<String>,
) -> Result<i32, String> {
    let report = discover_arbor_stack(search_dirs, env_override);
    let descriptor = report
        .layers
        .into_iter()
        .find(|d| d.id == layer)
        .ok_or_else(|| format!("unknown Velenza Arbor layer: {:?}", layer))?;

    let bin_path = descriptor.resolved_binary.ok_or_else(|| {
        format!(
            "Velenza Arbor Layer {} binary not found: looked for '{}' or '{}' (set {} to override)",
            descriptor.layer,
            descriptor.canonical_name,
            descriptor.compat_alias,
            descriptor.binary_env_vars.join(" or ")
        )
    })?;

    let status = match Command::new(&bin_path).args(args).status() {
        Ok(st) => st,
        Err(e) if cfg!(windows) && e.raw_os_error() == Some(193) => Command::new("sh")
            .arg(&bin_path)
            .args(args)
            .status()
            .map_err(|sh_err| {
                format!(
                    "failed to execute '{}' ({}) via sh fallback: {}",
                    descriptor.canonical_name,
                    bin_path.display(),
                    sh_err
                )
            })?,
        Err(e) => {
            return Err(format!(
                "failed to execute '{}' ({}): {}",
                descriptor.canonical_name,
                bin_path.display(),
                e
            ));
        }
    };

    Ok(status.code().unwrap_or(1))
}

pub fn delegate_arbor_subcommand(
    layer: ArborLayerId,
    args: &[String],
    search_dirs: &[PathBuf],
    env_override: &dyn Fn(&str) -> Option<String>,
) -> Result<(i32, String, String), String> {
    let report = discover_arbor_stack(search_dirs, env_override);
    let descriptor = report
        .layers
        .into_iter()
        .find(|d| d.id == layer)
        .ok_or_else(|| format!("unknown Velenza Arbor layer: {:?}", layer))?;

    let bin_path = descriptor.resolved_binary.ok_or_else(|| {
        format!(
            "Velenza Arbor Layer {} binary not found: looked for '{}' or '{}' (set {} to override)",
            descriptor.layer,
            descriptor.canonical_name,
            descriptor.compat_alias,
            descriptor.binary_env_vars.join(" or ")
        )
    })?;

    let output = match Command::new(&bin_path).args(args).output() {
        Ok(out) => out,
        Err(e) if cfg!(windows) && e.raw_os_error() == Some(193) => Command::new("sh")
            .arg(&bin_path)
            .args(args)
            .output()
            .map_err(|sh_err| {
                format!(
                    "failed to execute '{}' ({}) via sh fallback: {}",
                    descriptor.canonical_name,
                    bin_path.display(),
                    sh_err
                )
            })?,
        Err(e) => {
            return Err(format!(
                "failed to execute '{}' ({}): {}",
                descriptor.canonical_name,
                bin_path.display(),
                e
            ));
        }
    };

    let code = output.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    Ok((code, stdout, stderr))
}
