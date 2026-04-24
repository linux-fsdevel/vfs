// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::formatter::OutputFormatter;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::{
    display_api_spec, ApiExtractor, ApiSpec, CapabilitySpec, ConstraintSpec, ErrorSpec, LockSpec,
    ParamSpec, ReturnSpec,
};

// Schema matching what kapi_export_json() in the kernel emits.  The kernel
// serialises several enum-like fields as hex strings ("0x%x") or token
// strings ("exact", "process"); we keep them as Option<String> here and
// interpret them during conversion.
#[derive(Deserialize)]
struct KernelApiJson {
    name: String,
    #[serde(default)]
    api_type: Option<String>,
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    long_description: Option<String>,
    #[serde(default)]
    context_flags: Option<String>,
    #[serde(default)]
    examples: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    capabilities: Option<Vec<KernelCapabilityJson>>,
    #[serde(default)]
    parameters: Option<Vec<KernelParamJson>>,
    #[serde(default)]
    errors: Option<Vec<KernelErrorJson>>,
    #[serde(default, rename = "return")]
    return_spec: Option<KernelReturnJson>,
    #[serde(default)]
    locks: Option<Vec<KernelLockJson>>,
    #[serde(default)]
    constraints: Option<Vec<KernelConstraintJson>>,
    #[serde(default)]
    signals: Option<Vec<KernelSignalJson>>,
    #[serde(default)]
    side_effects: Option<Vec<KernelSideEffectJson>>,
}

#[derive(Deserialize)]
struct KernelConstraintJson {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    expression: Option<String>,
}

#[derive(Deserialize)]
struct KernelSignalJson {
    #[serde(default)]
    signal_num: i32,
    #[serde(default)]
    signal_name: Option<String>,
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    action: u32,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    condition: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    restartable: bool,
    #[serde(default)]
    sa_flags_required: Option<String>,
    #[serde(default)]
    sa_flags_forbidden: Option<String>,
    #[serde(default)]
    error_on_signal: i32,
    #[serde(default)]
    transform_to: i32,
    #[serde(default)]
    timing: Option<String>,
    #[serde(default)]
    priority: u32,
    #[serde(default)]
    interruptible: bool,
    #[serde(default)]
    queue_behavior: Option<String>,
    #[serde(default)]
    state_required: Option<String>,
    #[serde(default)]
    state_forbidden: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct KernelSideEffectJson {
    #[serde(rename = "type", default)]
    type_hex: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    condition: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    reversible: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct KernelParamJson {
    name: String,
    #[serde(rename = "type", default)]
    type_name: Option<String>,
    #[serde(default)]
    type_class: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    flags: Option<String>,
}

#[derive(Deserialize)]
struct KernelErrorJson {
    #[serde(rename = "code")]
    error_code: i32,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    condition: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct KernelReturnJson {
    #[serde(rename = "type", default)]
    type_name: Option<String>,
    #[serde(default)]
    type_class: Option<String>,
    #[serde(default)]
    check_type: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    success_value: Option<i64>,
    #[serde(default)]
    success_min: Option<i64>,
    #[serde(default)]
    success_max: Option<i64>,
}

#[derive(Deserialize)]
struct KernelLockJson {
    name: String,
    #[serde(rename = "type", default)]
    lock_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
struct KernelCapabilityJson {
    capability: i32,
    name: String,
    action: String,
    allows: String,
    without_cap: String,
    check_condition: Option<String>,
    priority: Option<u8>,
    alternatives: Option<Vec<i32>>,
}

/// Extractor for kernel API specifications from debugfs
pub struct DebugfsExtractor {
    debugfs_path: PathBuf,
}

impl DebugfsExtractor {
    /// Create a new debugfs extractor with the specified debugfs path
    pub fn new(debugfs_path: Option<String>) -> Result<Self> {
        let path = match debugfs_path {
            Some(p) => PathBuf::from(p),
            None => PathBuf::from("/sys/kernel/debug"),
        };

        // Check if the debugfs path exists
        if !path.exists() {
            bail!("Debugfs path does not exist: {}", path.display());
        }

        // Check if kapi directory exists
        let kapi_path = path.join("kapi");
        if !kapi_path.exists() {
            bail!(
                "Kernel API debugfs interface not found at: {}",
                kapi_path.display()
            );
        }

        Ok(Self { debugfs_path: path })
    }

    /// Parse the list file to get all available API names
    fn parse_list_file(&self) -> Result<Vec<String>> {
        let list_path = self.debugfs_path.join("kapi/list");
        let content = fs::read_to_string(&list_path)
            .with_context(|| format!("Failed to read {}", list_path.display()))?;

        let mut apis = Vec::new();
        let mut in_list = false;

        for line in content.lines() {
            if line.contains("===") {
                in_list = true;
                continue;
            }

            if in_list && line.starts_with("Total:") {
                break;
            }

            if in_list && !line.trim().is_empty() {
                // Extract API name from lines like "sys_read - Read from a file descriptor"
                if let Some(name) = line.split(" - ").next() {
                    apis.push(name.trim().to_string());
                }
            }
        }

        Ok(apis)
    }

    /// Convert context flags (emitted by the kernel as a hex string like
    /// "0x21") into the token list consumed by the formatter.
    fn parse_context_flags(flags: &str) -> Vec<String> {
        let mut result = Vec::new();
        let bits = flags
            .strip_prefix("0x")
            .or_else(|| flags.strip_prefix("0X"))
            .unwrap_or(flags);
        let Ok(flags) = u32::from_str_radix(bits, 16) else {
            return result;
        };

        // These values should match KAPI_CTX_* flags from kernel
        if flags & (1 << 0) != 0 {
            result.push("PROCESS".to_string());
        }
        if flags & (1 << 1) != 0 {
            result.push("SOFTIRQ".to_string());
        }
        if flags & (1 << 2) != 0 {
            result.push("HARDIRQ".to_string());
        }
        if flags & (1 << 3) != 0 {
            result.push("NMI".to_string());
        }
        if flags & (1 << 4) != 0 {
            result.push("ATOMIC".to_string());
        }
        if flags & (1 << 5) != 0 {
            result.push("SLEEPABLE".to_string());
        }
        if flags & (1 << 6) != 0 {
            result.push("PREEMPT_DISABLED".to_string());
        }
        if flags & (1 << 7) != 0 {
            result.push("IRQ_DISABLED".to_string());
        }

        result
    }

    /// Parse a hex-string like "0x123" into u32, returning 0 on failure.
    fn parse_hex_u32(value: &str) -> u32 {
        let bits = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value);
        u32::from_str_radix(bits, 16).unwrap_or(0)
    }

    /// Map the check-type token emitted by the kernel
    /// (return_check_type_to_string) back to the u32 enum the formatter wants.
    fn parse_check_type(token: &str) -> u32 {
        match token {
            "exact" => 0,
            "range" => 1,
            "error_check" => 2,
            "file_descriptor" => 3,
            "custom" => 4,
            "no_return" => 5,
            _ => 0,
        }
    }

    /// Map the lock-type token emitted by the kernel (lock_type_to_string).
    fn parse_lock_type(token: &str) -> u32 {
        match token {
            "none" => 0,
            "mutex" => 1,
            "spinlock" => 2,
            "rwlock" => 3,
            "seqlock" => 4,
            "rcu" => 5,
            "semaphore" => 6,
            "custom" => 7,
            _ => 0,
        }
    }

    /// Map the lock-scope token emitted by the kernel (lock_scope_to_string).
    fn parse_lock_scope(token: &str) -> u32 {
        match token {
            "internal" => 0,
            "acquires" => 1,
            "releases" => 2,
            "caller_held" => 3,
            _ => 0,
        }
    }

    /// Map the signal-timing token (e.g. "during") back to the u32 enum that
    /// the source-side parser produces. Mirrors
    /// KerneldocParser::parse_signal_timing in kerneldoc_parser.rs so the
    /// debugfs path and the source path agree.
    fn parse_signal_timing(token: &str) -> u32 {
        match token.trim().to_ascii_lowercase().as_str() {
            "before" => 0,
            "during" => 1,
            "after" => 2,
            _ => 0,
        }
    }

    /// Convert capability action from kernel representation
    fn parse_capability_action(action: &str) -> String {
        match action {
            "bypass_check" => "Bypasses check".to_string(),
            "increase_limit" => "Increases limit".to_string(),
            "override_restriction" => "Overrides restriction".to_string(),
            "grant_permission" => "Grants permission".to_string(),
            "modify_behavior" => "Modifies behavior".to_string(),
            "access_resource" => "Allows resource access".to_string(),
            "perform_operation" => "Allows operation".to_string(),
            _ => action.to_string(),
        }
    }

    /// Try to parse as JSON first
    fn try_parse_json(&self, content: &str) -> Option<ApiSpec> {
        let json_data: KernelApiJson = serde_json::from_str(content).ok()?;

        let mut spec = ApiSpec {
            name: json_data.name,
            api_type: json_data.api_type.unwrap_or_else(|| "syscall".to_string()),
            description: json_data.description,
            long_description: json_data.long_description,
            version: json_data.version.map(|v| v.to_string()),
            context_flags: json_data
                .context_flags
                .as_deref()
                .map_or_else(Vec::new, Self::parse_context_flags),
            param_count: None,
            error_count: None,
            examples: json_data.examples,
            notes: json_data.notes,
            subsystem: None,   // Not in current JSON format
            sysfs_path: None,  // Not in current JSON format
            permissions: None, // Not in current JSON format
            capabilities: vec![],
            parameters: vec![],
            return_spec: None,
            errors: vec![],
            signals: vec![],
            signal_masks: vec![],
            side_effects: vec![],
            state_transitions: vec![],
            constraints: vec![],
            locks: vec![],
            struct_specs: vec![],
        };

        // Convert capabilities
        if let Some(caps) = json_data.capabilities {
            for cap in caps {
                spec.capabilities.push(CapabilitySpec {
                    capability: cap.capability,
                    name: cap.name,
                    action: Self::parse_capability_action(&cap.action),
                    allows: cap.allows,
                    without_cap: cap.without_cap,
                    check_condition: cap.check_condition,
                    priority: cap.priority,
                    alternatives: cap.alternatives.unwrap_or_default(),
                });
            }
        }

        // Convert parameters.  kapi_json_str() passes through trailing
        // whitespace that the macro generator may leave on description
        // strings; trim here to match --source / --vmlinux.
        if let Some(params) = json_data.parameters {
            for (i, p) in params.into_iter().enumerate() {
                let flags = p.flags.as_deref().map_or(0, Self::parse_hex_u32);
                spec.parameters.push(ParamSpec {
                    index: i as u32,
                    name: p.name,
                    type_name: p.type_name.unwrap_or_default(),
                    description: p
                        .description
                        .map(|s| s.trim_end().to_string())
                        .unwrap_or_default(),
                    flags,
                    param_type: 0,
                    constraint_type: 0,
                    constraint: None,
                    min_value: None,
                    max_value: None,
                    valid_mask: None,
                    enum_values: vec![],
                    size: None,
                    alignment: None,
                    size_param_idx: None,
                });
            }
            spec.param_count = Some(spec.parameters.len() as u32);
        }

        // Convert errors
        if let Some(errors) = json_data.errors {
            for e in errors {
                spec.errors.push(ErrorSpec {
                    error_code: e.error_code,
                    name: e.name.unwrap_or_default(),
                    condition: e.condition.unwrap_or_default(),
                    description: e.description.unwrap_or_default(),
                });
            }
            spec.error_count = Some(spec.errors.len() as u32);
        }

        // Convert return spec
        if let Some(ret) = json_data.return_spec {
            let check_type = ret.check_type.as_deref().map_or(0, Self::parse_check_type);
            spec.return_spec = Some(ReturnSpec {
                type_name: ret.type_name.unwrap_or_default(),
                description: ret.description.unwrap_or_default(),
                return_type: 0,
                check_type,
                success_value: ret.success_value,
                success_min: ret.success_min,
                success_max: ret.success_max,
                error_values: vec![],
            });
        }

        // Convert locks
        if let Some(locks) = json_data.locks {
            for l in locks {
                let lock_type = l.lock_type.as_deref().map_or(0, Self::parse_lock_type);
                let scope = l.scope.as_deref().map_or(0, Self::parse_lock_scope);
                spec.locks.push(LockSpec {
                    lock_name: l.name,
                    lock_type,
                    scope,
                    description: l.description.unwrap_or_default(),
                });
            }
        }

        // Convert constraints.  Empty strings emitted from kapi_json_str()
        // for NULL char * fields normalise back to None to match --source.
        if let Some(constraints) = json_data.constraints {
            for c in constraints {
                spec.constraints.push(ConstraintSpec {
                    name: c.name,
                    description: c.description.unwrap_or_default(),
                    expression: c.expression.filter(|v| !v.is_empty()),
                });
            }
        }

        // Convert signals.  The kernel-side kapi_json_str() emits NULL
        // char * as the empty string "", so normalise empty -> None here
        // to match the ApiSpec convention used by --source / --vmlinux.
        fn opt_str(s: Option<String>) -> Option<String> {
            s.filter(|v| !v.is_empty())
        }
        if let Some(signals) = json_data.signals {
            for s in signals {
                let direction = s.direction.as_deref().map_or(0, Self::parse_hex_u32);
                let sa_flags_required = s
                    .sa_flags_required
                    .as_deref()
                    .map_or(0, Self::parse_hex_u32);
                let sa_flags_forbidden = s
                    .sa_flags_forbidden
                    .as_deref()
                    .map_or(0, Self::parse_hex_u32);
                let state_required = s.state_required.as_deref().map_or(0, Self::parse_hex_u32);
                let state_forbidden = s.state_forbidden.as_deref().map_or(0, Self::parse_hex_u32);
                let timing = s.timing.as_deref().map_or(0, Self::parse_signal_timing);
                spec.signals.push(super::SignalSpec {
                    signal_num: s.signal_num,
                    signal_name: s.signal_name.unwrap_or_default(),
                    direction,
                    action: s.action,
                    target: opt_str(s.target),
                    condition: opt_str(s.condition),
                    description: opt_str(s.description),
                    timing,
                    priority: s.priority,
                    restartable: s.restartable,
                    interruptible: s.interruptible,
                    queue: opt_str(s.queue_behavior),
                    sa_flags: 0,
                    sa_flags_required,
                    sa_flags_forbidden,
                    state_required,
                    state_forbidden,
                    error_on_signal: if s.error_on_signal != 0 {
                        Some(s.error_on_signal)
                    } else {
                        None
                    },
                    transform_to: if s.transform_to != 0 {
                        // Kernel JSON already carries the numeric value.
                        Some(s.transform_to)
                    } else {
                        None
                    },
                });
            }
        }

        // Convert side effects.
        if let Some(effects) = json_data.side_effects {
            for e in effects {
                let effect_type = e.type_hex.as_deref().map_or(0, Self::parse_hex_u32);
                spec.side_effects.push(super::SideEffectSpec {
                    effect_type,
                    target: e.target.unwrap_or_default(),
                    condition: e.condition.filter(|v| !v.is_empty()),
                    description: e.description.unwrap_or_default(),
                    reversible: e.reversible,
                });
            }
        }

        Some(spec)
    }

    /// Parse a single API specification file
    fn parse_spec_file(&self, api_name: &str) -> Result<ApiSpec> {
        // Prefer the JSON endpoint if the kernel exposes it (added together
        // with the framework). Fall back to parsing the plain-text dump for
        // older kernels that only provide /sys/kernel/debug/kapi/specs/.
        let json_path = self
            .debugfs_path
            .join(format!("kapi/specs-json/{}", api_name));
        if let Ok(content) = fs::read_to_string(&json_path) {
            if let Some(spec) = self.try_parse_json(&content) {
                return Ok(spec);
            }
        }

        let spec_path = self.debugfs_path.join(format!("kapi/specs/{}", api_name));
        let content = fs::read_to_string(&spec_path)
            .with_context(|| format!("Failed to read {}", spec_path.display()))?;

        // Older kernels may still emit JSON via specs/ if someone backported it.
        if let Some(spec) = self.try_parse_json(&content) {
            return Ok(spec);
        }

        // Fall back to plain text parsing
        let mut spec = ApiSpec {
            name: api_name.to_string(),
            api_type: "unknown".to_string(),
            description: None,
            long_description: None,
            version: None,
            context_flags: Vec::new(),
            param_count: None,
            error_count: None,
            examples: None,
            notes: None,
            subsystem: None,
            sysfs_path: None,
            permissions: None,
            capabilities: vec![],
            parameters: vec![],
            return_spec: None,
            errors: vec![],
            signals: vec![],
            signal_masks: vec![],
            side_effects: vec![],
            state_transitions: vec![],
            constraints: vec![],
            locks: vec![],
            struct_specs: vec![],
        };

        // Parse the content
        let mut collecting_multiline = false;
        let mut multiline_buffer = String::new();
        let mut multiline_field = "";
        let mut parsing_capability = false;
        let mut in_capabilities_section = false;
        let mut current_capability: Option<CapabilitySpec> = None;

        for line in content.lines() {
            // Handle capability sections
            if line.starts_with("Capabilities (") {
                in_capabilities_section = true;
                continue;
            }
            // Any other top-level section header ends the capabilities section
            // so that "  pending_signals (0):" inside "Signal handling (1):"
            // isn't mis-parsed as a capability entry.
            if !line.starts_with(' ') && !line.is_empty() && line.ends_with(':') {
                in_capabilities_section = false;
            }
            if in_capabilities_section
                && line.starts_with("  ")
                && line.contains(" (")
                && line.ends_with("):")
            {
                // Start of a capability entry like "  CAP_IPC_LOCK (14):"
                if let Some(cap) = current_capability.take() {
                    spec.capabilities.push(cap);
                }

                let parts: Vec<&str> = line.trim().split(" (").collect();
                if parts.len() == 2 {
                    let cap_name = parts[0].to_string();
                    let cap_id = parts[1].trim_end_matches("):").parse().unwrap_or(0);
                    current_capability = Some(CapabilitySpec {
                        capability: cap_id,
                        name: cap_name,
                        action: String::new(),
                        allows: String::new(),
                        without_cap: String::new(),
                        check_condition: None,
                        priority: None,
                        alternatives: Vec::new(),
                    });
                    parsing_capability = true;
                }
                continue;
            }
            if parsing_capability && line.starts_with("    ") {
                // Parse capability fields
                if let Some(ref mut cap) = current_capability {
                    if let Some(action) = line.strip_prefix("    Action: ") {
                        cap.action = action.to_string();
                    } else if let Some(allows) = line.strip_prefix("    Allows: ") {
                        cap.allows = allows.to_string();
                    } else if let Some(without) = line.strip_prefix("    Without: ") {
                        cap.without_cap = without.to_string();
                    } else if let Some(cond) = line.strip_prefix("    Condition: ") {
                        cap.check_condition = Some(cond.to_string());
                    } else if let Some(prio) = line.strip_prefix("    Priority: ") {
                        cap.priority = prio.parse().ok();
                    } else if let Some(alts) = line.strip_prefix("    Alternatives: ") {
                        cap.alternatives =
                            alts.split(", ").filter_map(|s| s.parse().ok()).collect();
                    }
                }
                continue;
            }
            if parsing_capability && !line.starts_with("  ") {
                // End of capabilities section
                if let Some(cap) = current_capability.take() {
                    spec.capabilities.push(cap);
                }
                parsing_capability = false;
            }

            // Handle section headers
            if line.starts_with("Parameters (") {
                if let Some(count_str) = line
                    .strip_prefix("Parameters (")
                    .and_then(|s| s.strip_suffix("):"))
                {
                    spec.param_count = count_str.parse().ok();
                }
                continue;
            } else if line.starts_with("Errors (") {
                if let Some(count_str) = line
                    .strip_prefix("Errors (")
                    .and_then(|s| s.strip_suffix("):"))
                {
                    spec.error_count = count_str.parse().ok();
                }
                continue;
            } else if line.starts_with("Examples:") {
                collecting_multiline = true;
                multiline_field = "examples";
                multiline_buffer.clear();
                continue;
            } else if line.starts_with("Notes:") {
                collecting_multiline = true;
                multiline_field = "notes";
                multiline_buffer.clear();
                continue;
            }

            // Handle multiline sections
            if collecting_multiline {
                // Terminate multiline on known field patterns or double blank line
                let is_field = line.starts_with("Description: ")
                    || line.starts_with("Long description: ")
                    || line.starts_with("Version: ")
                    || line.starts_with("Context flags: ")
                    || line.starts_with("Subsystem: ")
                    || line.starts_with("Sysfs Path: ")
                    || line.starts_with("Permissions: ")
                    || line.starts_with("Parameters (")
                    || line.starts_with("Errors (")
                    || line.starts_with("Capabilities (");
                if is_field || (line.trim().is_empty() && multiline_buffer.ends_with("\n\n")) {
                    collecting_multiline = false;
                    match multiline_field {
                        "examples" => spec.examples = Some(multiline_buffer.trim().to_string()),
                        "notes" => spec.notes = Some(multiline_buffer.trim().to_string()),
                        _ => {}
                    }
                    multiline_buffer.clear();
                    if !is_field {
                        continue;
                    }
                    // Fall through to parse this line as a field
                } else {
                    if !multiline_buffer.is_empty() {
                        multiline_buffer.push('\n');
                    }
                    multiline_buffer.push_str(line);
                    continue;
                }
            }

            // Parse regular fields
            if let Some(desc) = line.strip_prefix("Description: ") {
                spec.description = Some(desc.to_string());
            } else if let Some(long_desc) = line.strip_prefix("Long description: ") {
                spec.long_description = Some(long_desc.to_string());
            } else if let Some(version) = line.strip_prefix("Version: ") {
                spec.version = Some(version.to_string());
            } else if let Some(flags) = line.strip_prefix("Context flags: ") {
                spec.context_flags = flags.split_whitespace().map(str::to_string).collect();
            } else if let Some(subsys) = line.strip_prefix("Subsystem: ") {
                spec.subsystem = Some(subsys.to_string());
            } else if let Some(path) = line.strip_prefix("Sysfs Path: ") {
                spec.sysfs_path = Some(path.to_string());
            } else if let Some(perms) = line.strip_prefix("Permissions: ") {
                spec.permissions = Some(perms.to_string());
            }
        }

        // Flush any remaining multiline buffer
        if collecting_multiline {
            match multiline_field {
                "examples" => spec.examples = Some(multiline_buffer.trim().to_string()),
                "notes" => spec.notes = Some(multiline_buffer.trim().to_string()),
                _ => {}
            }
        }

        // Handle any remaining capability
        if let Some(cap) = current_capability.take() {
            spec.capabilities.push(cap);
        }

        // Determine API type based on name
        if api_name.starts_with("sys_") {
            spec.api_type = "syscall".to_string();
        } else if api_name.contains("_ioctl") || api_name.starts_with("ioctl_") {
            spec.api_type = "ioctl".to_string();
        } else if api_name.contains("sysfs")
            || api_name.ends_with("_show")
            || api_name.ends_with("_store")
        {
            spec.api_type = "sysfs".to_string();
        } else {
            spec.api_type = "function".to_string();
        }

        Ok(spec)
    }
}

impl ApiExtractor for DebugfsExtractor {
    fn extract_all(&self) -> Result<Vec<ApiSpec>> {
        let api_names = self.parse_list_file()?;
        let mut specs = Vec::new();

        for name in api_names {
            match self.parse_spec_file(&name) {
                Ok(spec) => specs.push(spec),
                Err(e) => {
                    eprintln!("Warning: failed to parse API spec '{}': {}", name, e);
                }
            }
        }

        Ok(specs)
    }

    fn extract_by_name(&self, name: &str) -> Result<Option<ApiSpec>> {
        let api_names = self.parse_list_file()?;

        if api_names.contains(&name.to_string()) {
            Ok(Some(self.parse_spec_file(name)?))
        } else {
            Ok(None)
        }
    }

    fn display_api_details(
        &self,
        api_name: &str,
        formatter: &mut dyn OutputFormatter,
        writer: &mut dyn Write,
    ) -> Result<()> {
        if let Some(spec) = self.extract_by_name(api_name)? {
            display_api_spec(&spec, formatter, writer)?;
        } else {
            writeln!(writer, "API '{api_name}' not found in debugfs")?;
        }

        Ok(())
    }
}
