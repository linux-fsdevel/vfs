// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use super::{
    ApiSpec, CapabilitySpec, ConstraintSpec, ErrorSpec, LockSpec, ParamSpec, ReturnSpec,
    SideEffectSpec, SignalSpec, StateTransitionSpec, StructFieldSpec, StructSpec,
};
use anyhow::Result;
use std::collections::HashMap;

/// Real kerneldoc parser that extracts KAPI annotations
pub struct KerneldocParserImpl;

/// What block are we currently inside?
#[derive(Debug, Clone, PartialEq)]
enum BlockContext {
    None,
    Param(String),   // param: <name>
    Error(String),   // error: <name>
    Signal,          // signal: <name>
    Capability,      // capability: <name>
    SideEffect,      // side-effect: <type>
    StateTransition, // state-trans: ...
    Constraint,      // constraint: <name>
    Lock,            // lock: <name>
    Return,          // return:
}

/// Parse a numeric literal, supporting plain decimal and 0x-prefixed hex.
/// Returns `None` for anything that requires cpp-level constant resolution
/// (e.g. symbolic masks like `O_RDONLY | O_WRONLY`). Callers must treat
/// that case as "mask unknown" and leave the downstream slot unset, not
/// store it as 0 — which would wrongly assert that zero bits are valid.
fn parse_u64_literal(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse().ok()
    }
}

/// `true` if `s` contains more '(' than ')' when scanned left-to-right.
/// Used to decide whether the caller needs to pull more continuation
/// lines before trying to parse a constraint expression.
fn has_unbalanced_paren(s: &str) -> bool {
    let mut depth: i32 = 0;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    depth > 0
}

/// Canonicalise a kerneldoc `type:` value to its KAPI_TYPE_* spelling.
/// Used in the `return:` block so `type_name` carries the long form
/// regardless of which spelling the source used.
fn canon_kapi_type_name(s: &str) -> String {
    let t = s.trim();
    if t.starts_with("KAPI_TYPE_") {
        return t.to_string();
    }
    match t.to_ascii_lowercase().as_str() {
        "void" => "KAPI_TYPE_VOID".to_string(),
        "int" => "KAPI_TYPE_INT".to_string(),
        "uint" => "KAPI_TYPE_UINT".to_string(),
        "ptr" => "KAPI_TYPE_PTR".to_string(),
        "struct" => "KAPI_TYPE_STRUCT".to_string(),
        "union" => "KAPI_TYPE_UNION".to_string(),
        "enum" => "KAPI_TYPE_ENUM".to_string(),
        "func_ptr" => "KAPI_TYPE_FUNC_PTR".to_string(),
        "array" => "KAPI_TYPE_ARRAY".to_string(),
        "fd" => "KAPI_TYPE_FD".to_string(),
        "user_ptr" | "uptr" => "KAPI_TYPE_USER_PTR".to_string(),
        "path" => "KAPI_TYPE_PATH".to_string(),
        "custom" => "KAPI_TYPE_CUSTOM".to_string(),
        _ => t.to_string(),
    }
}

/// Canonicalise a capability `type:` value to its KAPI_CAP_* spelling.
fn canon_kapi_cap_action(s: &str) -> String {
    let t = s.trim();
    if t.starts_with("KAPI_CAP_") {
        return t.to_string();
    }
    match t.to_ascii_lowercase().as_str() {
        "bypass_check" => "KAPI_CAP_BYPASS_CHECK".to_string(),
        "increase_limit" => "KAPI_CAP_INCREASE_LIMIT".to_string(),
        "override_restriction" => "KAPI_CAP_OVERRIDE_RESTRICTION".to_string(),
        "grant_permission" => "KAPI_CAP_GRANT_PERMISSION".to_string(),
        "modify_behavior" => "KAPI_CAP_MODIFY_BEHAVIOR".to_string(),
        "access_resource" => "KAPI_CAP_ACCESS_RESOURCE".to_string(),
        "perform_operation" => "KAPI_CAP_PERFORM_OPERATION".to_string(),
        _ => t.to_string(),
    }
}

/// Types whose semantics imply `KAPI_PARAM_USER` on the param, so
/// `type: user_ptr, input` doesn't need a separate `user` flag.
fn type_implies_user_flag(tok: &str) -> bool {
    matches!(tok.trim(), "KAPI_TYPE_USER_PTR" | "KAPI_TYPE_PATH")
        || matches!(
            tok.trim().to_ascii_lowercase().as_str(),
            "user_ptr" | "uptr" | "path"
        )
}

/// Return true if the line's first whitespace-delimited token is a
/// bare identifier ending in ':' (e.g. `type:`, `constraint-type:`,
/// `error:`). Used by the continuation folder to stop at the next
/// block attribute.
fn is_block_key(s: &str) -> bool {
    let head = s.split_whitespace().next().unwrap_or("");
    if !head.ends_with(':') || head.len() < 2 {
        return false;
    }
    let ident = &head[..head.len() - 1];
    !ident.is_empty()
        && ident
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

impl KerneldocParserImpl {
    pub fn new() -> Self {
        KerneldocParserImpl
    }

    pub fn parse_kerneldoc(
        &self,
        doc: &str,
        name: &str,
        api_type: &str,
        signature: Option<&str>,
    ) -> Result<ApiSpec> {
        let mut spec = ApiSpec {
            name: name.to_string(),
            api_type: api_type.to_string(),
            ..Default::default()
        };

        let lines: Vec<&str> = doc.lines().collect();

        // Extract main description from function name line
        if let Some(first_line) = lines.first() {
            if let Some((_, desc)) = first_line.split_once(" - ") {
                spec.description = Some(desc.trim().to_string());
            }
        }

        // Extract type names from SYSCALL_DEFINE signature
        let type_map = if let Some(sig) = signature {
            self.extract_types_from_signature(sig)
        } else {
            HashMap::new()
        };

        // Keep track of parameters we've seen (from @param lines)
        let mut param_map: HashMap<String, ParamSpec> = HashMap::new();
        let mut struct_fields: Vec<StructFieldSpec> = Vec::new();

        // Current block being parsed
        let mut block = BlockContext::None;

        // Temporary storage for current block items
        let mut current_lock: Option<LockSpec> = None;
        let mut current_signal: Option<SignalSpec> = None;
        // Pending symbolic `transform-to:` token. Captured when the parser
        // sees a non-numeric value, but only reported if the final
        // `transform_to` after all lines in the signal block is still
        // unresolved. A later numeric `transform-to:` clears this so we
        // don't warn about a value that was subsequently overridden.
        let mut pending_transform_warning: Option<String> = None;
        let mut current_capability: Option<CapabilitySpec> = None;
        let mut current_side_effect: Option<SideEffectSpec> = None;
        let mut current_constraint: Option<ConstraintSpec> = None;
        let mut current_error: Option<ErrorSpec> = None;
        let mut current_return: Option<ReturnSpec> = None;

        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();

            // Skip empty lines
            if trimmed.is_empty() {
                i += 1;
                continue;
            }

            // Check if this is an indented continuation line (part of current block)
            let is_indented = line.starts_with("  ") || line.starts_with('\t');

            // If indented and we're in a block, parse as block attribute.
            // Before dispatching, fold continuation lines into `trimmed`
            // when the value has an unbalanced '(' so that expressions
            // like `constraint-type: mask(FOO | BAR |` ... `| BAZ)`
            // arrive as a single logical line.
            if is_indented && block != BlockContext::None {
                let mut folded: Option<String> = None;
                if has_unbalanced_paren(trimmed) {
                    let mut buf = trimmed.to_string();
                    let mut j = i + 1;
                    while j < lines.len() {
                        let next = lines[j];
                        let next_trim = next.trim();
                        if next_trim.is_empty() {
                            break;
                        }
                        if !(next.starts_with("  ") || next.starts_with('\t')) {
                            break;
                        }
                        // Stop if we've hit another known key
                        if is_block_key(next_trim) {
                            break;
                        }
                        buf.push(' ');
                        buf.push_str(next_trim);
                        j += 1;
                        if !has_unbalanced_paren(&buf) {
                            break;
                        }
                    }
                    if j > i + 1 {
                        i = j - 1; // outer loop will += 1
                        folded = Some(buf);
                    }
                }
                let line_to_parse: &str = folded.as_deref().unwrap_or(trimmed);
                self.parse_block_attribute(
                    line_to_parse,
                    &block,
                    &mut param_map,
                    &mut current_error,
                    &mut current_signal,
                    &mut pending_transform_warning,
                    &mut current_capability,
                    &mut current_side_effect,
                    &mut current_constraint,
                    &mut current_lock,
                    &mut current_return,
                );
                i += 1;
                continue;
            }

            // Not indented or not in block — flush current block if any.
            // If a symbolic `transform-to:` was captured and no later
            // numeric line cleared it, surface the warning now; by
            // construction `transform_to` is None in that case.
            if matches!(block, BlockContext::Signal) {
                if let Some(raw) = pending_transform_warning.take() {
                    eprintln!(
                        "kapi: warning: transform-to: {raw:?} is symbolic; \
                         source-mode cannot resolve signal numbers portably. \
                         Use --vmlinux or --debugfs to get the resolved value.",
                    );
                }
            }
            self.flush_block(
                &mut block,
                &mut spec,
                &mut current_error,
                &mut current_signal,
                &mut current_capability,
                &mut current_side_effect,
                &mut current_constraint,
                &mut current_lock,
                &mut current_return,
            );

            // Parse top-level annotations
            if let Some(rest) = trimmed.strip_prefix("@") {
                // @param: description — standard kerneldoc parameter
                if let Some((param_name, desc)) = rest.split_once(':') {
                    let param_name = param_name.trim();
                    let desc = desc.trim();
                    if !param_name.contains('-') {
                        let idx = param_map.len() as u32;
                        let type_name = type_map.get(param_name).cloned().unwrap_or_default();
                        param_map.insert(
                            param_name.to_string(),
                            ParamSpec {
                                index: idx,
                                name: param_name.to_string(),
                                type_name,
                                description: desc.to_string(),
                                flags: 0,
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
                            },
                        );
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("long-desc:") {
                let (val, next_i) = self.collect_multiline_value(&lines, i, rest);
                spec.long_description = Some(val);
                i = next_i;
                continue;
            } else if let Some(rest) = trimmed.strip_prefix("context-flags:") {
                spec.context_flags = self.parse_context_flags(rest.trim());
            } else if let Some(rest) = trimmed.strip_prefix("contexts:") {
                // Short form: "contexts: process, sleepable"
                spec.context_flags = self.parse_context_list(rest.trim());
            } else if let Some(rest) = trimmed.strip_prefix("param-count:") {
                spec.param_count = rest.trim().parse().ok();
            }
            // Flat param-* annotations (alternative format)
            else if let Some(rest) = trimmed.strip_prefix("param-type:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    if let Some(param) = param_map.get_mut(parts[0]) {
                        param.param_type = self.parse_param_type(parts[1]);
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("param-flags:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    if let Some(param) = param_map.get_mut(parts[0]) {
                        param.flags = self.parse_param_flags(parts[1]);
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("param-range:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    if let Some(param) = param_map.get_mut(parts[0]) {
                        param.min_value = parts[1].parse().ok();
                        param.max_value = parts[2].parse().ok();
                        param.constraint_type = 1; // KAPI_CONSTRAINT_RANGE
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("param-constraint:") {
                let parts: Vec<&str> = rest.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    if let Some(param) = param_map.get_mut(parts[0]) {
                        param.constraint = Some(parts[1].to_string());
                    }
                }
            }
            // Block-start annotations
            else if let Some(rest) = trimmed.strip_prefix("param:") {
                let param_name = rest.trim().to_string();
                block = BlockContext::Param(param_name.clone());
                // Ensure param exists in map
                if !param_map.contains_key(&param_name) {
                    let idx = param_map.len() as u32;
                    let type_name = type_map
                        .get(param_name.as_str())
                        .cloned()
                        .unwrap_or_default();
                    param_map.insert(
                        param_name.clone(),
                        ParamSpec {
                            index: idx,
                            name: param_name,
                            type_name,
                            description: String::new(),
                            flags: 0,
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
                        },
                    );
                }
            } else if let Some(rest) = trimmed.strip_prefix("error:") {
                // error: NAME, condition
                let parts: Vec<&str> = rest.splitn(2, ',').map(|s| s.trim()).collect();
                if !parts.is_empty() {
                    let error_name = parts[0].to_string();
                    let condition = if parts.len() >= 2 {
                        parts[1].to_string()
                    } else {
                        String::new()
                    };
                    let error_code = self.error_name_to_code(&error_name);
                    current_error = Some(ErrorSpec {
                        error_code,
                        name: error_name.clone(),
                        condition,
                        description: String::new(),
                    });
                    block = BlockContext::Error(error_name);
                }
            } else if let Some(rest) = trimmed.strip_prefix("signal:") {
                let signal_name = rest.trim().to_string();
                current_signal = Some(SignalSpec {
                    signal_num: 0,
                    signal_name,
                    direction: 1,
                    action: 0,
                    target: None,
                    condition: None,
                    description: None,
                    restartable: false,
                    timing: 0,
                    priority: 0,
                    interruptible: false,
                    queue: None,
                    sa_flags: 0,
                    sa_flags_required: 0,
                    sa_flags_forbidden: 0,
                    state_required: 0,
                    state_forbidden: 0,
                    error_on_signal: None,
                    transform_to: None,
                });
                block = BlockContext::Signal;
            } else if let Some(rest) = trimmed.strip_prefix("capability:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if !parts.is_empty() {
                    let cap_name = parts[0].to_string();
                    let cap_value = self.parse_capability_value(&cap_name);
                    // If we have 3 parts, it's flat format: capability: CAP, action, name
                    let (action, name) = if parts.len() >= 3 {
                        (parts[1].to_string(), parts[2].to_string())
                    } else {
                        (String::new(), cap_name.clone())
                    };
                    current_capability = Some(CapabilitySpec {
                        capability: cap_value,
                        name,
                        action,
                        allows: String::new(),
                        without_cap: String::new(),
                        check_condition: None,
                        priority: Some(0),
                        alternatives: vec![],
                    });
                    block = BlockContext::Capability;
                }
            } else if let Some(rest) = trimmed.strip_prefix("side-effect:") {
                // Could be flat format (comma-separated) or block start
                let rest = rest.trim();
                // Check if it's the flat format with commas
                let comma_parts: Vec<&str> = rest.splitn(3, ',').map(|s| s.trim()).collect();
                if comma_parts.len() >= 3 {
                    // Flat format: side-effect: TYPE, target, desc
                    let mut effect = SideEffectSpec {
                        effect_type: self.parse_effect_type(comma_parts[0]),
                        target: comma_parts[1].to_string(),
                        condition: None,
                        description: comma_parts[2].to_string(),
                        reversible: false,
                    };
                    if comma_parts[2].contains("reversible=yes") {
                        effect.reversible = true;
                    }
                    spec.side_effects.push(effect);
                } else {
                    // Block format: side-effect: TYPE
                    current_side_effect = Some(SideEffectSpec {
                        effect_type: self.parse_effect_type(rest),
                        target: String::new(),
                        condition: None,
                        description: String::new(),
                        reversible: false,
                    });
                    block = BlockContext::SideEffect;
                }
            } else if let Some(rest) = trimmed.strip_prefix("state-trans:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 4 {
                    spec.state_transitions.push(StateTransitionSpec {
                        object: parts[0].to_string(),
                        from_state: parts[1].to_string(),
                        to_state: parts[2].to_string(),
                        condition: None,
                        description: parts[3].to_string(),
                    });
                }
                block = BlockContext::StateTransition;
            } else if let Some(rest) = trimmed.strip_prefix("constraint:") {
                let rest = rest.trim();
                // Could be flat format: constraint: name, desc
                // Or block format: constraint: name
                let parts: Vec<&str> = rest.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    // Flat format
                    current_constraint = Some(ConstraintSpec {
                        name: parts[0].to_string(),
                        description: parts[1].to_string(),
                        expression: None,
                    });
                } else {
                    // Block format
                    current_constraint = Some(ConstraintSpec {
                        name: rest.to_string(),
                        description: String::new(),
                        expression: None,
                    });
                }
                block = BlockContext::Constraint;
            } else if let Some(rest) = trimmed.strip_prefix("constraint-expr:") {
                // Flat format: constraint-expr: name, expr
                let parts: Vec<&str> = rest.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    if let Some(constraint) =
                        spec.constraints.iter_mut().find(|c| c.name == parts[0])
                    {
                        constraint.expression = Some(parts[1].to_string());
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("lock:") {
                let rest = rest.trim();
                // Could be flat: lock: name, type
                // Or block: lock: name
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    current_lock = Some(LockSpec {
                        lock_name: parts[0].to_string(),
                        lock_type: self.parse_lock_type(parts[1]),
                        scope: super::KAPI_LOCK_INTERNAL,
                        description: String::new(),
                    });
                } else {
                    current_lock = Some(LockSpec {
                        lock_name: rest.to_string(),
                        lock_type: 0,
                        scope: super::KAPI_LOCK_INTERNAL,
                        description: String::new(),
                    });
                }
                block = BlockContext::Lock;
            }
            // Flat signal-* attributes (alternative format)
            else if let Some(rest) = trimmed.strip_prefix("signal-direction:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.direction = self.parse_signal_direction(rest.trim());
                }
            } else if let Some(rest) = trimmed.strip_prefix("signal-action:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.action = self.parse_signal_action(rest.trim());
                }
            } else if let Some(rest) = trimmed.strip_prefix("signal-condition:") {
                if let Some(signal) = current_signal.as_mut() {
                    let (val, next_i) = self.collect_multiline_value(&lines, i, rest);
                    signal.condition = Some(val);
                    i = next_i;
                    continue;
                }
            } else if let Some(rest) = trimmed.strip_prefix("signal-desc:") {
                if let Some(signal) = current_signal.as_mut() {
                    let (val, next_i) = self.collect_multiline_value(&lines, i, rest);
                    signal.description = Some(val);
                    i = next_i;
                    continue;
                }
            } else if let Some(rest) = trimmed.strip_prefix("signal-timing:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.timing = self.parse_signal_timing(rest.trim());
                }
            } else if let Some(rest) = trimmed.strip_prefix("signal-priority:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.priority = rest.trim().parse().unwrap_or(0);
                }
            } else if let Some(rest) = trimmed.strip_prefix("signal-interruptible:") {
                if let Some(signal) = current_signal.as_mut() {
                    let val = rest.trim().to_lowercase();
                    signal.interruptible = !matches!(val.as_str(), "no" | "false" | "0");
                }
            } else if let Some(rest) = trimmed.strip_prefix("signal-state-req:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.state_required = self.parse_signal_state(rest.trim());
                }
            }
            // Flat capability-* attributes
            else if let Some(rest) = trimmed.strip_prefix("capability-allows:") {
                if let Some(cap) = current_capability.as_mut() {
                    let (val, next_i) = self.collect_multiline_value(&lines, i, rest);
                    cap.allows = val;
                    i = next_i;
                    continue;
                }
            } else if let Some(rest) = trimmed.strip_prefix("capability-without:") {
                if let Some(cap) = current_capability.as_mut() {
                    let (val, next_i) = self.collect_multiline_value(&lines, i, rest);
                    cap.without_cap = val;
                    i = next_i;
                    continue;
                }
            } else if let Some(rest) = trimmed.strip_prefix("capability-condition:") {
                if let Some(cap) = current_capability.as_mut() {
                    let (val, next_i) = self.collect_multiline_value(&lines, i, rest);
                    cap.check_condition = Some(val);
                    i = next_i;
                    continue;
                }
            } else if let Some(rest) = trimmed.strip_prefix("capability-priority:") {
                if let Some(cap) = current_capability.as_mut() {
                    cap.priority = rest.trim().parse().ok();
                }
            }
            // Lock flat attributes
            else if let Some(rest) = trimmed.strip_prefix("lock-scope:") {
                if let Some(lock) = current_lock.as_mut() {
                    lock.scope = match rest.trim() {
                        "internal" => super::KAPI_LOCK_INTERNAL,
                        "acquires" => super::KAPI_LOCK_ACQUIRES,
                        "releases" => super::KAPI_LOCK_RELEASES,
                        "caller_held" => super::KAPI_LOCK_CALLER_HELD,
                        _ => super::KAPI_LOCK_INTERNAL,
                    };
                }
            } else if let Some(rest) = trimmed.strip_prefix("lock-desc:") {
                if let Some(lock) = current_lock.as_mut() {
                    let (val, next_i) = self.collect_multiline_value(&lines, i, rest);
                    lock.description = val;
                    i = next_i;
                    continue;
                }
            }
            // Struct field annotations
            else if let Some(rest) = trimmed.strip_prefix("struct-field:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    struct_fields.push(StructFieldSpec {
                        name: parts[0].to_string(),
                        field_type: self.parse_field_type(parts[1]),
                        type_name: parts[1].to_string(),
                        offset: 0,
                        size: 0,
                        flags: 0,
                        constraint_type: 0,
                        min_value: 0,
                        max_value: 0,
                        valid_mask: 0,
                        description: parts[2].to_string(),
                    });
                }
            } else if let Some(rest) = trimmed.strip_prefix("struct-field-range:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    if let Some(field) = struct_fields.iter_mut().find(|f| f.name == parts[0]) {
                        field.min_value = parts[1].parse().unwrap_or(0);
                        field.max_value = parts[2].parse().unwrap_or(0);
                        field.constraint_type = 1;
                    }
                }
            }
            // Other top-level annotations
            else if let Some(rest) = trimmed.strip_prefix("return:") {
                let rest = rest.trim();
                if rest.is_empty() {
                    // Block format
                    current_return = Some(ReturnSpec {
                        type_name: String::new(),
                        description: String::new(),
                        return_type: 0,
                        check_type: 0,
                        success_value: None,
                        success_min: None,
                        success_max: None,
                        error_values: vec![],
                    });
                    block = BlockContext::Return;
                }
            } else if let Some(rest) = trimmed.strip_prefix("return-type:") {
                if spec.return_spec.is_none() {
                    spec.return_spec = Some(ReturnSpec {
                        type_name: rest.trim().to_string(),
                        description: String::new(),
                        return_type: self.parse_param_type(rest.trim()),
                        check_type: 0,
                        success_value: None,
                        success_min: None,
                        success_max: None,
                        error_values: vec![],
                    });
                }
            } else if let Some(rest) = trimmed.strip_prefix("return-check-type:") {
                if let Some(ret) = spec.return_spec.as_mut() {
                    ret.check_type = self.parse_return_check_type(rest.trim());
                }
            } else if let Some(rest) = trimmed.strip_prefix("return-success:") {
                if let Some(ret) = spec.return_spec.as_mut() {
                    ret.success_value = rest.trim().parse().ok();
                }
            } else if let Some(rest) = trimmed.strip_prefix("examples:") {
                let (val, next_i) = self.collect_multiline_value(&lines, i, rest);
                spec.examples = Some(val);
                i = next_i;
                continue;
            } else if let Some(rest) = trimmed.strip_prefix("notes:") {
                let (val, next_i) = self.collect_multiline_value(&lines, i, rest);
                spec.notes = Some(val);
                i = next_i;
                continue;
            }

            i += 1;
        }

        // Flush any remaining block. Emit a pending symbolic
        // `transform-to:` warning if the final state still has no
        // resolved numeric value (see per-line loop for rationale).
        if matches!(block, BlockContext::Signal) {
            if let Some(raw) = pending_transform_warning.take() {
                eprintln!(
                    "kapi: warning: transform-to: {raw:?} is symbolic; \
                     source-mode cannot resolve signal numbers portably. \
                     Use --vmlinux or --debugfs to get the resolved value.",
                );
            }
        }
        self.flush_block(
            &mut block,
            &mut spec,
            &mut current_error,
            &mut current_signal,
            &mut current_capability,
            &mut current_side_effect,
            &mut current_constraint,
            &mut current_lock,
            &mut current_return,
        );

        // Convert param_map to vec preserving order
        let mut params: Vec<ParamSpec> = param_map.into_values().collect();
        params.sort_by_key(|p| p.index);

        // If the spec carries an explicit param-count, warn when it
        // disagrees with the number of param: blocks we actually saw.
        // param-count: is otherwise redundant with the block count, and
        // new short-form specs should just drop it.
        if let Some(claimed) = spec.param_count {
            if claimed as usize != params.len() {
                eprintln!(
                    "kapi: {}: param-count: {} disagrees with {} param: block(s)",
                    name,
                    claimed,
                    params.len(),
                );
            }
        }

        spec.parameters = params;

        // Create struct spec if we have fields
        if !struct_fields.is_empty() {
            spec.struct_specs.push(StructSpec {
                name: format!("struct {name}"),
                size: 0,
                alignment: 0,
                field_count: struct_fields.len() as u32,
                fields: struct_fields,
                description: "Structure specification".to_string(),
            });
        }

        Ok(spec)
    }

    /// Parse an indented attribute line within a block
    #[allow(clippy::too_many_arguments)]
    fn parse_block_attribute(
        &self,
        trimmed: &str,
        block: &BlockContext,
        param_map: &mut HashMap<String, ParamSpec>,
        current_error: &mut Option<ErrorSpec>,
        current_signal: &mut Option<SignalSpec>,
        pending_transform_warning: &mut Option<String>,
        current_capability: &mut Option<CapabilitySpec>,
        current_side_effect: &mut Option<SideEffectSpec>,
        current_constraint: &mut Option<ConstraintSpec>,
        current_lock: &mut Option<LockSpec>,
        current_return: &mut Option<ReturnSpec>,
    ) {
        match block {
            BlockContext::Param(param_name) => {
                if let Some(param) = param_map.get_mut(param_name) {
                    if let Some(rest) = trimmed.strip_prefix("type:") {
                        // Accept either:
                        //   type: KAPI_TYPE_UINT              (long, single token)
                        //   type: uint                        (short, single token)
                        //   type: uint, input                 (short, type + flags)
                        //   type: path, input                 (short, type + flags)
                        // Single-token inputs leave flags alone so existing
                        // long-form specs that use a separate `flags:` line
                        // keep working unchanged.
                        //
                        // User-space pointer types (user_ptr, path) imply
                        // KAPI_PARAM_USER, so specs don't need to repeat
                        // `user` after the type.
                        let mut parts = rest.split(',').map(str::trim);
                        let type_token = parts.next();
                        if let Some(ty) = type_token {
                            param.param_type = self.parse_param_type(ty);
                        }
                        for flag in parts {
                            param.flags |= self.parse_param_flag_token(flag);
                        }
                        if type_token.map(type_implies_user_flag).unwrap_or(false) {
                            param.flags |= 1 << 6; // KAPI_PARAM_USER
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("flags:") {
                        param.flags = self.parse_param_flags(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("constraint-type:") {
                        // Accepts `KAPI_CONSTRAINT_*` enum tokens or
                        // function-call expressions like `range(0, 4096)`
                        // / `mask(0xff)` / `buffer(2)` that also populate
                        // the matching numeric fields on `param`.
                        let text = rest.trim();
                        if !self.apply_constraint_expr(param, text) {
                            param.constraint_type = self.parse_constraint_type(text);
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("valid-mask:") {
                        // Symbolic mask values need cpp-level resolution;
                        // leave that to the binary reader.
                        let _ = rest;
                    } else if let Some(rest) = trimmed.strip_prefix("constraint:") {
                        // Free-text constraint description; multiline append.
                        let text = rest.trim();
                        if param.constraint.is_none() {
                            param.constraint = Some(text.to_string());
                        } else if let Some(c) = param.constraint.as_mut() {
                            c.push(' ');
                            c.push_str(text);
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("range:") {
                        let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                        if parts.len() >= 2 {
                            param.min_value = parts[0].parse().ok();
                            param.max_value = parts[1].parse().ok();
                            param.constraint_type = 1; // KAPI_CONSTRAINT_RANGE
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("size-param:") {
                        param.size_param_idx = rest.trim().parse().ok();
                    } else if let Some(rest) = trimmed.strip_prefix("description:") {
                        param.description = rest.trim().to_string();
                    } else if let Some(rest) = trimmed.strip_prefix("desc:") {
                        param.description = rest.trim().to_string();
                    } else if !trimmed.contains(':') || trimmed.starts_with("  ") {
                        // Continuation of the previous attribute's value.
                        if let Some(c) = param.constraint.as_mut() {
                            c.push(' ');
                            c.push_str(trimmed);
                        }
                    }
                }
            }
            BlockContext::Error(_) => {
                if let Some(error) = current_error.as_mut() {
                    if let Some(rest) = trimmed.strip_prefix("desc:") {
                        let text = rest.trim().to_string();
                        if error.description.is_empty() {
                            error.description = text;
                        } else {
                            error.description.push(' ');
                            error.description.push_str(&text);
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("condition:") {
                        error.condition = rest.trim().to_string();
                    } else {
                        // Continuation of description
                        if !error.description.is_empty() {
                            error.description.push(' ');
                            error.description.push_str(trimmed);
                        }
                    }
                }
            }
            BlockContext::Signal => {
                if let Some(signal) = current_signal.as_mut() {
                    if let Some(rest) = trimmed.strip_prefix("direction:") {
                        signal.direction = self.parse_signal_direction(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("action:") {
                        signal.action = self.parse_signal_action(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("condition:") {
                        signal.condition = Some(rest.trim().to_string());
                    } else if let Some(rest) = trimmed.strip_prefix("desc:") {
                        let text = rest.trim().to_string();
                        if signal.description.is_none() {
                            signal.description = Some(text);
                        } else if let Some(d) = signal.description.as_mut() {
                            d.push(' ');
                            d.push_str(&text);
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("errno:") {
                        // `error:` cannot be used here because kerneldoc
                        // promotes it to a top-level section header.
                        //
                        // Accepted forms:
                        //   errno: -4         -> numeric literal, stored as-is
                        //   errno: -EINTR     -> kernel convention; resolve
                        //                       the symbol and negate
                        //   errno: EINTR      -> bare symbol; resolved value
                        //                       is already negative
                        let value = rest.trim();
                        signal.error_on_signal = if let Ok(code) = value.parse::<i32>() {
                            Some(code)
                        } else if let Some(name) = value.strip_prefix('-') {
                            // `error_name_to_code` already returns the negated
                            // code (e.g. "EINTR" -> -4), so `-EINTR` resolves
                            // to -4 too — the leading `-` on the symbolic form
                            // is kernel-source convention, not a second negation.
                            Some(self.error_name_to_code(name))
                        } else {
                            Some(self.error_name_to_code(value))
                        };
                    } else if let Some(rest) = trimmed.strip_prefix("timing:") {
                        signal.timing = self.parse_signal_timing(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("restartable:") {
                        let val = rest.trim().to_lowercase();
                        signal.restartable = matches!(val.as_str(), "yes" | "true" | "1");
                    } else if let Some(rest) = trimmed.strip_prefix("interruptible:") {
                        let val = rest.trim().to_lowercase();
                        signal.interruptible = matches!(val.as_str(), "yes" | "true" | "1");
                    } else if let Some(rest) = trimmed.strip_prefix("priority:") {
                        signal.priority = rest.trim().parse().unwrap_or(0);
                    } else if let Some(rest) = trimmed.strip_prefix("target:") {
                        signal.target = Some(rest.trim().to_string());
                    } else if let Some(rest) = trimmed.strip_prefix("queue:") {
                        signal.queue = Some(rest.trim().to_string());
                    } else if let Some(rest) = trimmed
                        .strip_prefix("transform-to:")
                        .or_else(|| trimmed.strip_prefix("transform_to:"))
                    {
                        // transform-to: takes a signal constant (e.g.
                        // SIGKILL) or a numeric literal. Only a numeric
                        // literal fills `transform_to`; symbolic values
                        // cannot be resolved portably in userspace
                        // because signal numbers are arch-dependent and
                        // we have no access to the target arch's
                        // <asm/signal.h>. Report such cases to stderr so
                        // they are not silently lost, and point the user
                        // at --vmlinux / --debugfs, which consult the
                        // compiled struct where the C preprocessor has
                        // already baked in the correct value.
                        //
                        // Assign unconditionally so the last line in
                        // the kerneldoc wins and an intended symbolic
                        // override doesn't silently leave a stale
                        // numeric value from an earlier line. The
                        // warning is deferred until flush_block() so a
                        // subsequent numeric line can cancel it; if the
                        // last line was still symbolic we report it
                        // then.
                        let v = rest.trim();
                        let parsed = v.parse::<i32>().ok();
                        signal.transform_to = parsed;
                        if parsed.is_some() {
                            *pending_transform_warning = None;
                        } else if !v.is_empty() {
                            *pending_transform_warning = Some(v.to_string());
                        }
                    } else if let Some(rest) = trimmed
                        .strip_prefix("sa-flags-required:")
                        .or_else(|| trimmed.strip_prefix("sa_flags_required:"))
                    {
                        signal.sa_flags_required = self.parse_hex_or_bitmask(rest.trim());
                    } else if let Some(rest) = trimmed
                        .strip_prefix("sa-flags-forbidden:")
                        .or_else(|| trimmed.strip_prefix("sa_flags_forbidden:"))
                    {
                        signal.sa_flags_forbidden = self.parse_hex_or_bitmask(rest.trim());
                    } else if let Some(rest) = trimmed
                        .strip_prefix("state-required:")
                        .or_else(|| trimmed.strip_prefix("state_required:"))
                    {
                        signal.state_required = self.parse_signal_state_mask(rest.trim());
                    } else if let Some(rest) = trimmed
                        .strip_prefix("state-forbidden:")
                        .or_else(|| trimmed.strip_prefix("state_forbidden:"))
                    {
                        signal.state_forbidden = self.parse_signal_state_mask(rest.trim());
                    } else {
                        // Continuation of description
                        if let Some(d) = signal.description.as_mut() {
                            d.push(' ');
                            d.push_str(trimmed);
                        }
                    }
                }
            }
            BlockContext::Capability => {
                if let Some(cap) = current_capability.as_mut() {
                    if let Some(rest) = trimmed.strip_prefix("type:") {
                        cap.action = canon_kapi_cap_action(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("allows:") {
                        cap.allows = rest.trim().to_string();
                    } else if let Some(rest) = trimmed.strip_prefix("without:") {
                        cap.without_cap = rest.trim().to_string();
                    } else if let Some(rest) = trimmed.strip_prefix("condition:") {
                        cap.check_condition = Some(rest.trim().to_string());
                    } else if let Some(rest) = trimmed.strip_prefix("priority:") {
                        cap.priority = rest.trim().parse().ok();
                    }
                }
            }
            BlockContext::SideEffect => {
                if let Some(effect) = current_side_effect.as_mut() {
                    if let Some(rest) = trimmed.strip_prefix("target:") {
                        effect.target = rest.trim().to_string();
                    } else if let Some(rest) = trimmed.strip_prefix("condition:") {
                        effect.condition = Some(rest.trim().to_string());
                    } else if let Some(rest) = trimmed.strip_prefix("desc:") {
                        let text = rest.trim().to_string();
                        if effect.description.is_empty() {
                            effect.description = text;
                        } else {
                            effect.description.push(' ');
                            effect.description.push_str(&text);
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("reversible:") {
                        let val = rest.trim().to_lowercase();
                        effect.reversible = matches!(val.as_str(), "yes" | "true" | "1");
                    } else {
                        // Continuation of description
                        if !effect.description.is_empty() {
                            effect.description.push(' ');
                            effect.description.push_str(trimmed);
                        }
                    }
                }
            }
            BlockContext::Constraint => {
                if let Some(constraint) = current_constraint.as_mut() {
                    if let Some(rest) = trimmed.strip_prefix("desc:") {
                        let text = rest.trim().to_string();
                        if constraint.description.is_empty() {
                            constraint.description = text;
                        } else {
                            constraint.description.push(' ');
                            constraint.description.push_str(&text);
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("expr:") {
                        constraint.expression = Some(rest.trim().to_string());
                    } else {
                        // Continuation of description
                        if !constraint.description.is_empty() {
                            constraint.description.push(' ');
                            constraint.description.push_str(trimmed);
                        }
                    }
                }
            }
            BlockContext::Lock => {
                if let Some(lock) = current_lock.as_mut() {
                    if let Some(rest) = trimmed.strip_prefix("type:") {
                        lock.lock_type = self.parse_lock_type(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("scope:") {
                        lock.scope = match rest.trim() {
                            "internal" => super::KAPI_LOCK_INTERNAL,
                            "acquires" => super::KAPI_LOCK_ACQUIRES,
                            "releases" => super::KAPI_LOCK_RELEASES,
                            "caller_held" => super::KAPI_LOCK_CALLER_HELD,
                            _ => super::KAPI_LOCK_INTERNAL,
                        };
                    } else if let Some(rest) = trimmed.strip_prefix("desc:") {
                        let text = rest.trim().to_string();
                        if lock.description.is_empty() {
                            lock.description = text;
                        } else {
                            lock.description.push(' ');
                            lock.description.push_str(&text);
                        }
                    } else if trimmed.starts_with("acquired:") {
                        // KAPI_LOCK_ACQUIRED macro sets scope = ACQUIRES.
                        lock.scope = super::KAPI_LOCK_ACQUIRES;
                    } else if trimmed.starts_with("released:") {
                        // KAPI_LOCK_RELEASED macro sets scope = RELEASES,
                        // overriding any earlier scope. The generated
                        // apispec.h emits these in source order, so
                        // last-write-wins matches the binary layout.
                        lock.scope = super::KAPI_LOCK_RELEASES;
                    } else {
                        // Continuation of description
                        if !lock.description.is_empty() {
                            lock.description.push(' ');
                            lock.description.push_str(trimmed);
                        }
                    }
                }
            }
            BlockContext::Return => {
                if let Some(ret) = current_return.as_mut() {
                    if let Some(rest) = trimmed.strip_prefix("type:") {
                        let raw = rest.trim();
                        ret.type_name = canon_kapi_type_name(raw);
                        ret.return_type = self.parse_param_type(raw);
                    } else if let Some(rest) = trimmed.strip_prefix("check-type:") {
                        ret.check_type = self.parse_return_check_type(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("success:") {
                        // Accepts "= 0", ">= 0", bare integer.
                        let val = rest
                            .trim()
                            .trim_start_matches(|c: char| !c.is_ascii_digit() && c != '-');
                        ret.success_value = val.parse().ok();
                    } else if let Some(rest) = trimmed.strip_prefix("desc:") {
                        let text = rest.trim().to_string();
                        if ret.description.is_empty() {
                            ret.description = text;
                        } else {
                            ret.description.push(' ');
                            ret.description.push_str(&text);
                        }
                    } else {
                        // Continuation of description
                        if !ret.description.is_empty() {
                            ret.description.push(' ');
                            ret.description.push_str(trimmed);
                        }
                    }
                }
            }
            BlockContext::StateTransition | BlockContext::None => {}
        }
    }

    /// Flush the current block, pushing items into the spec
    #[allow(clippy::too_many_arguments)]
    fn flush_block(
        &self,
        block: &mut BlockContext,
        spec: &mut ApiSpec,
        current_error: &mut Option<ErrorSpec>,
        current_signal: &mut Option<SignalSpec>,
        current_capability: &mut Option<CapabilitySpec>,
        current_side_effect: &mut Option<SideEffectSpec>,
        current_constraint: &mut Option<ConstraintSpec>,
        current_lock: &mut Option<LockSpec>,
        current_return: &mut Option<ReturnSpec>,
    ) {
        match block {
            BlockContext::Error(_) => {
                if let Some(error) = current_error.take() {
                    spec.errors.push(error);
                }
            }
            BlockContext::Signal => {
                if let Some(signal) = current_signal.take() {
                    spec.signals.push(signal);
                }
            }
            BlockContext::Capability => {
                if let Some(cap) = current_capability.take() {
                    spec.capabilities.push(cap);
                }
            }
            BlockContext::SideEffect => {
                if let Some(effect) = current_side_effect.take() {
                    spec.side_effects.push(effect);
                }
            }
            BlockContext::Constraint => {
                if let Some(constraint) = current_constraint.take() {
                    spec.constraints.push(constraint);
                }
            }
            BlockContext::Lock => {
                if let Some(lock) = current_lock.take() {
                    spec.locks.push(lock);
                }
            }
            BlockContext::Return => {
                if let Some(ret) = current_return.take() {
                    spec.return_spec = Some(ret);
                }
            }
            _ => {}
        }
        *block = BlockContext::None;
    }

    /// Extract parameter type names from SYSCALL_DEFINE signature
    fn extract_types_from_signature(&self, sig: &str) -> HashMap<String, String> {
        let mut types = HashMap::new();

        // Find content between outermost parens
        let content = if let Some(start) = sig.find('(') {
            let end = sig.rfind(')').unwrap_or(sig.len());
            &sig[start + 1..end]
        } else {
            return types;
        };

        // Split by comma and process type/name pairs
        // SYSCALL_DEFINE format: (syscall_name, type1, name1, type2, name2, ...)
        let parts: Vec<&str> = content.split(',').map(|s| s.trim()).collect();

        // Skip first part (syscall name), then process pairs
        let mut i = 1;
        while i + 1 < parts.len() {
            let type_part = parts[i].trim();
            let name_part = parts[i + 1].trim();

            // Build the type_name string: "type name"
            let type_name = format!("{} {}", type_part, name_part);
            types.insert(name_part.to_string(), type_name);

            i += 2;
        }

        types
    }

    fn collect_multiline_value(
        &self,
        lines: &[&str],
        start_idx: usize,
        first_part: &str,
    ) -> (String, usize) {
        let mut result = String::from(first_part.trim());
        let mut i = start_idx + 1;

        while i < lines.len() {
            let line = lines[i];

            if self.is_annotation_line(line) {
                break;
            }

            if !line.trim().is_empty() && line.starts_with("  ") {
                if !result.is_empty() {
                    result.push(' ');
                }
                result.push_str(line.trim());
            } else if line.trim().is_empty() {
                i += 1;
                continue;
            } else {
                break;
            }

            i += 1;
        }

        (result, i)
    }

    fn is_annotation_line(&self, line: &str) -> bool {
        let trimmed = line.trim_start();
        if !trimmed.contains(':') {
            return false;
        }
        let annotations = [
            "param:",
            "param-",
            "error:",
            "error-",
            "lock:",
            "lock-",
            "signal:",
            "signal-",
            "side-effect:",
            "state-trans:",
            "capability:",
            "capability-",
            "constraint:",
            "constraint-",
            "struct-",
            "return:",
            "return-",
            "examples:",
            "notes:",
            "since-",
            "context-",
            "long-desc:",
            "api-type:",
        ];

        for ann in &annotations {
            if trimmed.starts_with(ann) {
                return true;
            }
        }
        false
    }

    /// Parse a constraint expression and apply it to `param`.
    /// Shapes:
    ///   NAME                         (e.g. "user_path", "nonzero")
    ///   NAME ( ARG (, ARG)* )        (e.g. "range(0, 4096)", "buffer(2)")
    /// Returns true if the expression matched a known constraint kind,
    /// populating `param`'s numeric fields. Returns false if the text
    /// is free-form, leaving `param` untouched.
    fn apply_constraint_expr(&self, param: &mut ParamSpec, text: &str) -> bool {
        let t = text.trim();
        if t.is_empty() {
            return false;
        }
        // Split NAME ( ARGS ) — no nesting, no escaping.
        let (name, args): (&str, Option<&str>) = match (t.find('('), t.rfind(')')) {
            (Some(lp), Some(rp)) if rp > lp => (t[..lp].trim(), Some(t[lp + 1..rp].trim())),
            _ => (t, None),
        };
        // Bail out on anything that looks like free text (spaces inside the
        // name part) so we don't swallow existing textual constraints.
        if name.contains(char::is_whitespace) || name.is_empty() {
            return false;
        }
        let name_lc = name.to_ascii_lowercase();
        let split_args = || -> Vec<String> {
            args.map(|a| a.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default()
        };
        match name_lc.as_str() {
            "range" => {
                let a = split_args();
                if a.len() != 2 {
                    return false;
                }
                param.min_value = a[0].parse().ok();
                param.max_value = a[1].parse().ok();
                param.constraint_type = 1; // KAPI_CONSTRAINT_RANGE
                true
            }
            "mask" => {
                let a = split_args();
                if a.len() != 1 {
                    return false;
                }
                // Symbolic masks (e.g. "O_RDONLY | O_WRONLY | ...") can't
                // be resolved at parse time — leave valid_mask as None so
                // downstream consumers treat the mask as unknown, matching
                // the long-form `valid-mask:` handler (which also leaves
                // the slot untouched when the value isn't a literal).
                param.valid_mask = parse_u64_literal(&a[0]);
                param.constraint_type = 2; // KAPI_CONSTRAINT_MASK
                true
            }
            "enum" => {
                let a = split_args();
                if a.is_empty() {
                    return false;
                }
                param.enum_values = a;
                param.constraint_type = 3; // KAPI_CONSTRAINT_ENUM
                true
            }
            "alignment" | "align" => {
                let a = split_args();
                if a.len() != 1 {
                    return false;
                }
                param.alignment = a[0].parse().ok();
                param.constraint_type = 4; // KAPI_CONSTRAINT_ALIGNMENT
                true
            }
            "power_of_two" => {
                if args.is_some() {
                    return false;
                }
                param.constraint_type = 5; // KAPI_CONSTRAINT_POWER_OF_TWO
                true
            }
            "page_aligned" => {
                if args.is_some() {
                    return false;
                }
                param.constraint_type = 6; // KAPI_CONSTRAINT_PAGE_ALIGNED
                true
            }
            "nonzero" => {
                if args.is_some() {
                    return false;
                }
                param.constraint_type = 7; // KAPI_CONSTRAINT_NONZERO
                true
            }
            "user_string" => {
                // Optional size argument: user_string(N)
                if let Some(arg) = args {
                    if let Ok(n) = arg.trim().parse::<u32>() {
                        param.size = Some(n);
                    }
                }
                param.constraint_type = 8; // KAPI_CONSTRAINT_USER_STRING
                true
            }
            "user_path" => {
                if args.is_some() {
                    return false;
                }
                param.constraint_type = 9; // KAPI_CONSTRAINT_USER_PATH
                true
            }
            "user_ptr" => {
                if args.is_some() {
                    return false;
                }
                param.constraint_type = 10; // KAPI_CONSTRAINT_USER_PTR
                true
            }
            "buffer" => {
                // buffer(size_param_idx) — capture the index into
                // param.size_param_idx so it matches the long-form
                // `size-param: N` handler below (and the C struct
                // field populated by KAPI_PARAM_SIZE_PARAM()).
                let a = split_args();
                if a.len() != 1 {
                    return false;
                }
                param.size_param_idx = a[0].parse().ok();
                param.constraint_type = 11; // KAPI_CONSTRAINT_BUFFER
                true
            }
            "custom" => {
                // custom(fn_name) — record function name as free-text constraint
                // so downstream tooling can wire it up.
                if let Some(arg) = args {
                    param.constraint = Some(arg.trim().to_string());
                }
                param.constraint_type = 12; // KAPI_CONSTRAINT_CUSTOM
                true
            }
            _ => false,
        }
    }

    fn parse_context_flags(&self, flags: &str) -> Vec<String> {
        flags
            .split('|')
            .map(|f| self.ctx_alias(f.trim()).to_string())
            .filter(|f| !f.is_empty())
            .collect()
    }

    /// Parse a comma-separated short-form context list
    /// (e.g. "process, sleepable" -> ["KAPI_CTX_PROCESS", "KAPI_CTX_SLEEPABLE"]).
    /// Tokens that already look like KAPI_CTX_* are passed through.
    fn parse_context_list(&self, flags: &str) -> Vec<String> {
        flags
            .split(',')
            .map(|f| self.ctx_alias(f.trim()).to_string())
            .filter(|f| !f.is_empty())
            .collect()
    }

    /// Canonicalise a single context token to its KAPI_CTX_* spelling.
    /// Short aliases are case-insensitive. Unknown tokens pass through
    /// verbatim so mixed/long-form input keeps working.
    fn ctx_alias(&self, tok: &str) -> String {
        let t = tok.trim();
        if t.is_empty() {
            return String::new();
        }
        match t.to_ascii_lowercase().as_str() {
            "process" => "KAPI_CTX_PROCESS".to_string(),
            "softirq" => "KAPI_CTX_SOFTIRQ".to_string(),
            "hardirq" => "KAPI_CTX_HARDIRQ".to_string(),
            "nmi" => "KAPI_CTX_NMI".to_string(),
            "atomic" => "KAPI_CTX_ATOMIC".to_string(),
            "sleepable" => "KAPI_CTX_SLEEPABLE".to_string(),
            "preempt_disabled" => "KAPI_CTX_PREEMPT_DISABLED".to_string(),
            "irq_disabled" => "KAPI_CTX_IRQ_DISABLED".to_string(),
            _ => t.to_string(),
        }
    }

    fn error_name_to_code(&self, name: &str) -> i32 {
        match name {
            "EPERM" => -1,
            "ENOENT" => -2,
            "ESRCH" => -3,
            "EINTR" => -4,
            "EIO" => -5,
            "ENXIO" => -6,
            "E2BIG" => -7,
            "ENOEXEC" => -8,
            "EBADF" => -9,
            "ECHILD" => -10,
            "EAGAIN" | "EWOULDBLOCK" => -11,
            "ENOMEM" => -12,
            "EACCES" => -13,
            "EFAULT" => -14,
            "ENOTBLK" => -15,
            "EBUSY" => -16,
            "EEXIST" => -17,
            "EXDEV" => -18,
            "ENODEV" => -19,
            "ENOTDIR" => -20,
            "EISDIR" => -21,
            "EINVAL" => -22,
            "ENFILE" => -23,
            "EMFILE" => -24,
            "ENOTTY" => -25,
            "ETXTBSY" => -26,
            "EFBIG" => -27,
            "ENOSPC" => -28,
            "ESPIPE" => -29,
            "EROFS" => -30,
            "EMLINK" => -31,
            "EPIPE" => -32,
            "EDOM" => -33,
            "ERANGE" => -34,
            "EDEADLK" => -35,
            "ENAMETOOLONG" => -36,
            "ENOLCK" => -37,
            "ENOSYS" => -38,
            "ENOTEMPTY" => -39,
            "ELOOP" => -40,
            "ENOMSG" => -42,
            "ENODATA" => -61,
            "ENOLINK" => -67,
            "EPROTO" => -71,
            "EOVERFLOW" => -75,
            "ELIBBAD" => -80,
            "EILSEQ" => -84,
            "ENOTSOCK" => -88,
            "EDESTADDRREQ" => -89,
            "EMSGSIZE" => -90,
            "EPROTOTYPE" => -91,
            "ENOPROTOOPT" => -92,
            "EPROTONOSUPPORT" => -93,
            "EOPNOTSUPP" | "ENOTSUP" => -95,
            "EADDRINUSE" => -98,
            "EADDRNOTAVAIL" => -99,
            "ENETDOWN" => -100,
            "ENETUNREACH" => -101,
            "ENETRESET" => -102,
            "ECONNABORTED" => -103,
            "ECONNRESET" => -104,
            "ENOBUFS" => -105,
            "EISCONN" => -106,
            "ENOTCONN" => -107,
            "ETIMEDOUT" => -110,
            "ECONNREFUSED" => -111,
            "EALREADY" => -114,
            "EINPROGRESS" => -115,
            "ESTALE" => -116,
            "EDQUOT" => -122,
            "ENOMEDIUM" => -123,
            "ENOKEY" => -126,
            "ERESTARTSYS" => -512,
            _ => 0,
        }
    }

    /// Map a KAPI_TYPE_* token (or its short-form alias) to the numeric
    /// value declared in `enum kapi_param_type` in
    /// `include/linux/kernel_api_spec.h`.
    fn parse_param_type(&self, type_str: &str) -> u32 {
        let s = type_str.trim();
        match s {
            "KAPI_TYPE_VOID" => 0,
            "KAPI_TYPE_INT" => 1,
            "KAPI_TYPE_UINT" => 2,
            "KAPI_TYPE_PTR" => 3,
            "KAPI_TYPE_STRUCT" => 4,
            "KAPI_TYPE_UNION" => 5,
            "KAPI_TYPE_ENUM" => 6,
            "KAPI_TYPE_FUNC_PTR" => 7,
            "KAPI_TYPE_ARRAY" => 8,
            "KAPI_TYPE_FD" => 9,
            "KAPI_TYPE_USER_PTR" => 10,
            "KAPI_TYPE_PATH" => 11,
            "KAPI_TYPE_CUSTOM" => 12,
            _ => match s.to_ascii_lowercase().as_str() {
                "void" => 0,
                "int" => 1,
                "uint" => 2,
                "ptr" => 3,
                "struct" => 4,
                "union" => 5,
                "enum" => 6,
                "func_ptr" => 7,
                "array" => 8,
                "fd" => 9,
                "user_ptr" | "uptr" => 10,
                "path" => 11,
                "custom" => 12,
                _ => 0,
            },
        }
    }

    /// Map a KAPI_CONSTRAINT_* token to the numeric value declared in
    /// `enum kapi_constraint_type` in `include/linux/kernel_api_spec.h`.
    fn parse_constraint_type(&self, type_str: &str) -> u32 {
        let s = type_str.trim();
        match s {
            "KAPI_CONSTRAINT_NONE" => 0,
            "KAPI_CONSTRAINT_RANGE" => 1,
            "KAPI_CONSTRAINT_MASK" => 2,
            "KAPI_CONSTRAINT_ENUM" => 3,
            "KAPI_CONSTRAINT_ALIGNMENT" => 4,
            "KAPI_CONSTRAINT_POWER_OF_TWO" => 5,
            "KAPI_CONSTRAINT_PAGE_ALIGNED" => 6,
            "KAPI_CONSTRAINT_NONZERO" => 7,
            "KAPI_CONSTRAINT_USER_STRING" => 8,
            "KAPI_CONSTRAINT_USER_PATH" => 9,
            "KAPI_CONSTRAINT_USER_PTR" => 10,
            "KAPI_CONSTRAINT_BUFFER" => 11,
            "KAPI_CONSTRAINT_CUSTOM" => 12,
            _ => 0,
        }
    }

    fn parse_field_type(&self, type_str: &str) -> u32 {
        match type_str {
            "__s32" | "int" => 1,
            "__u32" | "unsigned int" => 2,
            "__s64" | "long" => 3,
            "__u64" | "unsigned long" => 4,
            _ => 0,
        }
    }

    fn parse_param_flags(&self, flags: &str) -> u32 {
        flags
            .split('|')
            .map(|f| self.parse_param_flag_token(f.trim()))
            .fold(0, |acc, bit| acc | bit)
    }

    /// Parse one flag token (long or short form, case-insensitive for
    /// short form). Returns 0 for unknown tokens.
    fn parse_param_flag_token(&self, tok: &str) -> u32 {
        let t = tok.trim();
        // Long / existing short forms first.
        match t {
            "KAPI_PARAM_IN" | "IN" => return 1,
            "KAPI_PARAM_OUT" | "OUT" => return 2,
            "KAPI_PARAM_INOUT" | "INOUT" => return 3,
            "KAPI_PARAM_OPTIONAL" | "OPTIONAL" => return 1 << 3,
            "KAPI_PARAM_CONST" | "CONST" => return 1 << 4,
            "KAPI_PARAM_VOLATILE" | "VOLATILE" => return 1 << 5,
            "KAPI_PARAM_USER" | "USER" => return 1 << 6,
            "KAPI_PARAM_DMA" | "DMA" => return 1 << 7,
            "KAPI_PARAM_ALIGNED" | "ALIGNED" => return 1 << 8,
            _ => {}
        }
        // English short aliases (case-insensitive).
        match t.to_ascii_lowercase().as_str() {
            "input" => 1,
            "output" => 2,
            "inout" => 3,
            "optional" => 1 << 3,
            "const" => 1 << 4,
            "volatile" => 1 << 5,
            "user" => 1 << 6,
            "dma" => 1 << 7,
            "aligned" => 1 << 8,
            _ => 0,
        }
    }

    /// Map a KAPI_LOCK_* token to the numeric value declared in
    /// `enum kapi_lock_type` in `include/linux/kernel_api_spec.h`.
    fn parse_lock_type(&self, type_str: &str) -> u32 {
        let s = type_str.trim();
        match s {
            "KAPI_LOCK_NONE" => 0,
            "KAPI_LOCK_MUTEX" => 1,
            "KAPI_LOCK_SPINLOCK" => 2,
            "KAPI_LOCK_RWLOCK" => 3,
            "KAPI_LOCK_SEQLOCK" => 4,
            "KAPI_LOCK_RCU" => 5,
            "KAPI_LOCK_SEMAPHORE" => 6,
            "KAPI_LOCK_CUSTOM" => 7,
            _ => match s.to_ascii_lowercase().as_str() {
                "none" => 0,
                "mutex" => 1,
                "spinlock" => 2,
                "rwlock" => 3,
                "seqlock" => 4,
                "rcu" => 5,
                "semaphore" => 6,
                "custom" => 7,
                _ => 0,
            },
        }
    }

    fn parse_signal_direction(&self, dir: &str) -> u32 {
        let s = dir.trim();
        match s {
            "KAPI_SIGNAL_RECEIVE" => 1,
            "KAPI_SIGNAL_SEND" => 2,
            "KAPI_SIGNAL_HANDLE" => 4,
            "KAPI_SIGNAL_BLOCK" => 8,
            "KAPI_SIGNAL_IGNORE" => 16,
            _ => match s.to_ascii_lowercase().as_str() {
                "receive" => 1,
                "send" => 2,
                "handle" => 4,
                "block" => 8,
                "ignore" => 16,
                _ => 0,
            },
        }
    }

    fn parse_signal_action(&self, action: &str) -> u32 {
        let s = action.trim();
        match s {
            "KAPI_SIGNAL_ACTION_DEFAULT" => 0,
            "KAPI_SIGNAL_ACTION_TERMINATE" => 1,
            "KAPI_SIGNAL_ACTION_COREDUMP" => 2,
            "KAPI_SIGNAL_ACTION_STOP" => 3,
            "KAPI_SIGNAL_ACTION_CONTINUE" => 4,
            "KAPI_SIGNAL_ACTION_CUSTOM" => 5,
            "KAPI_SIGNAL_ACTION_RETURN" => 6,
            "KAPI_SIGNAL_ACTION_RESTART" => 7,
            "KAPI_SIGNAL_ACTION_QUEUE" => 8,
            "KAPI_SIGNAL_ACTION_DISCARD" => 9,
            "KAPI_SIGNAL_ACTION_TRANSFORM" => 10,
            _ => match s.to_ascii_lowercase().as_str() {
                "default" => 0,
                "terminate" => 1,
                "coredump" => 2,
                "stop" => 3,
                "continue" => 4,
                "custom" => 5,
                "return" => 6,
                "restart" => 7,
                "queue" => 8,
                "discard" => 9,
                "transform" => 10,
                _ => 0,
            },
        }
    }

    fn parse_signal_timing(&self, timing: &str) -> u32 {
        let s = timing.trim();
        match s {
            "KAPI_SIGNAL_TIME_BEFORE" => 0,
            "KAPI_SIGNAL_TIME_DURING" => 1,
            "KAPI_SIGNAL_TIME_AFTER" => 2,
            _ => match s.to_ascii_lowercase().as_str() {
                "before" => 0,
                "during" => 1,
                "after" => 2,
                _ => 0,
            },
        }
    }

    fn parse_signal_state(&self, state: &str) -> u32 {
        match state {
            "KAPI_SIGNAL_STATE_RUNNING" => 1,
            "KAPI_SIGNAL_STATE_SLEEPING" => 2,
            _ => 0,
        }
    }

    /// Accept a hex literal ("0x4"), a decimal literal ("4"), or a '|'-separated
    /// bitmask expression. Unknown tokens contribute 0.
    fn parse_hex_or_bitmask(&self, value: &str) -> u32 {
        let v = value.trim();
        if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
            if let Ok(n) = u32::from_str_radix(hex, 16) {
                return n;
            }
        }
        if let Ok(n) = v.parse::<u32>() {
            return n;
        }
        let mut acc = 0u32;
        for part in v.split(['|', ',']) {
            let t = part.trim();
            if t.is_empty() {
                continue;
            }
            if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                if let Ok(n) = u32::from_str_radix(hex, 16) {
                    acc |= n;
                    continue;
                }
            }
            if let Ok(n) = t.parse::<u32>() {
                acc |= n;
            }
        }
        acc
    }

    /// Parse a '|'-separated list of KAPI_SIGNAL_STATE_* tokens (or short
    /// names like "RUNNING") and OR their bit values together. Matches the
    /// BIT(N) definitions in kernel_api_spec.h.
    fn parse_signal_state_mask(&self, value: &str) -> u32 {
        let mut acc = 0u32;
        for part in value.split(['|', ',']) {
            let t = part.trim().trim_start_matches("KAPI_SIGNAL_STATE_");
            let bit = match t.to_ascii_uppercase().as_str() {
                "RUNNING" => 1 << 0,
                "SLEEPING" => 1 << 1,
                "STOPPED" => 1 << 2,
                "TRACED" => 1 << 3,
                "ZOMBIE" => 1 << 4,
                "DEAD" => 1 << 5,
                _ => 0,
            };
            acc |= bit;
        }
        acc
    }

    /// Bitmask of `KAPI_EFFECT_*` values joined by '|' or ','.
    /// Values match `enum kapi_side_effect_type` in
    /// `include/linux/kernel_api_spec.h`.
    fn parse_effect_type(&self, type_str: &str) -> u32 {
        let sep = if type_str.contains('|') || !type_str.contains(',') {
            '|'
        } else {
            ','
        };
        let mut result = 0;
        for flag in type_str.split(sep) {
            let t = flag.trim();
            let bit = match t {
                "KAPI_EFFECT_NONE" => 0,
                "KAPI_EFFECT_ALLOC_MEMORY" => 1 << 0,
                "KAPI_EFFECT_FREE_MEMORY" => 1 << 1,
                "KAPI_EFFECT_MODIFY_STATE" => 1 << 2,
                "KAPI_EFFECT_SIGNAL_SEND" => 1 << 3,
                "KAPI_EFFECT_FILE_POSITION" => 1 << 4,
                "KAPI_EFFECT_LOCK_ACQUIRE" => 1 << 5,
                "KAPI_EFFECT_LOCK_RELEASE" => 1 << 6,
                "KAPI_EFFECT_RESOURCE_CREATE" => 1 << 7,
                "KAPI_EFFECT_RESOURCE_DESTROY" => 1 << 8,
                "KAPI_EFFECT_SCHEDULE" => 1 << 9,
                "KAPI_EFFECT_HARDWARE" => 1 << 10,
                "KAPI_EFFECT_NETWORK" => 1 << 11,
                "KAPI_EFFECT_FILESYSTEM" => 1 << 12,
                "KAPI_EFFECT_PROCESS_STATE" => 1 << 13,
                "KAPI_EFFECT_IRREVERSIBLE" => 1 << 14,
                _ => match t.to_ascii_lowercase().as_str() {
                    "none" => 0,
                    "alloc_memory" => 1 << 0,
                    "free_memory" => 1 << 1,
                    "modify_state" => 1 << 2,
                    "signal_send" => 1 << 3,
                    "file_position" => 1 << 4,
                    "lock_acquire" => 1 << 5,
                    "lock_release" => 1 << 6,
                    "resource_create" => 1 << 7,
                    "resource_destroy" => 1 << 8,
                    "schedule" => 1 << 9,
                    "hardware" => 1 << 10,
                    "network" => 1 << 11,
                    "filesystem" => 1 << 12,
                    "process_state" => 1 << 13,
                    "irreversible" => 1 << 14,
                    _ => 0,
                },
            };
            result |= bit;
        }
        result
    }

    fn parse_capability_value(&self, cap: &str) -> i32 {
        match cap {
            "CAP_CHOWN" => 0,
            "CAP_DAC_OVERRIDE" => 1,
            "CAP_DAC_READ_SEARCH" => 2,
            "CAP_FOWNER" => 3,
            "CAP_FSETID" => 4,
            "CAP_KILL" => 5,
            "CAP_SETGID" => 6,
            "CAP_SETUID" => 7,
            "CAP_SETPCAP" => 8,
            "CAP_LINUX_IMMUTABLE" => 9,
            "CAP_NET_BIND_SERVICE" => 10,
            "CAP_NET_BROADCAST" => 11,
            "CAP_NET_ADMIN" => 12,
            "CAP_NET_RAW" => 13,
            "CAP_IPC_LOCK" => 14,
            "CAP_IPC_OWNER" => 15,
            "CAP_SYS_MODULE" => 16,
            "CAP_SYS_RAWIO" => 17,
            "CAP_SYS_CHROOT" => 18,
            "CAP_SYS_PTRACE" => 19,
            "CAP_SYS_PACCT" => 20,
            "CAP_SYS_ADMIN" => 21,
            "CAP_SYS_BOOT" => 22,
            "CAP_SYS_NICE" => 23,
            "CAP_SYS_RESOURCE" => 24,
            "CAP_SYS_TIME" => 25,
            "CAP_SYS_TTY_CONFIG" => 26,
            "CAP_MKNOD" => 27,
            "CAP_LEASE" => 28,
            "CAP_AUDIT_WRITE" => 29,
            "CAP_AUDIT_CONTROL" => 30,
            "CAP_SETFCAP" => 31,
            "CAP_MAC_OVERRIDE" => 32,
            "CAP_MAC_ADMIN" => 33,
            "CAP_SYSLOG" => 34,
            "CAP_WAKE_ALARM" => 35,
            "CAP_BLOCK_SUSPEND" => 36,
            "CAP_AUDIT_READ" => 37,
            "CAP_PERFMON" => 38,
            "CAP_BPF" => 39,
            "CAP_CHECKPOINT_RESTORE" => 40,
            _ => 0,
        }
    }

    /// Map a KAPI_RETURN_* token to the numeric value declared in
    /// `enum kapi_return_check_type` in `include/linux/kernel_api_spec.h`.
    fn parse_return_check_type(&self, check: &str) -> u32 {
        let s = check.trim();
        match s {
            "KAPI_RETURN_EXACT" => 0,
            "KAPI_RETURN_RANGE" => 1,
            "KAPI_RETURN_ERROR_CHECK" => 2,
            "KAPI_RETURN_FD" => 3,
            "KAPI_RETURN_CUSTOM" => 4,
            "KAPI_RETURN_NO_RETURN" => 5,
            _ => match s.to_ascii_lowercase().as_str() {
                "exact" => 0,
                "range" => 1,
                "error_check" => 2,
                "fd" => 3,
                "custom" => 4,
                "no_return" => 5,
                _ => 0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser() -> KerneldocParserImpl {
        KerneldocParserImpl::new()
    }

    #[test]
    fn parse_minimal_kerneldoc() {
        let doc = "\
sys_foo - Do something useful
context-flags: KAPI_CTX_PROCESS
param-count: 1
@fd: The file descriptor
param-type: fd, KAPI_TYPE_INT
error: EBADF, Bad file descriptor
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_foo", "syscall", None)
            .unwrap();

        assert_eq!(spec.name, "sys_foo");
        assert_eq!(spec.api_type, "syscall");
        assert_eq!(spec.description.as_deref(), Some("Do something useful"));
        assert_eq!(spec.param_count, Some(1));
        assert_eq!(spec.parameters.len(), 1);
        assert_eq!(spec.parameters[0].name, "fd");
        assert_eq!(spec.parameters[0].description, "The file descriptor");
        assert_eq!(spec.parameters[0].param_type, 1); // KAPI_TYPE_INT
        assert_eq!(spec.errors.len(), 1);
        assert_eq!(spec.errors[0].name, "EBADF");
        assert_eq!(spec.errors[0].error_code, -9);
    }

    #[test]
    fn parse_multiple_param_types() {
        let doc = "\
sys_bar - Multiple params
@fd: file descriptor arg
@buf: user buffer
@count: byte count
@flags: option flags
param-type: fd, KAPI_TYPE_FD
param-type: buf, KAPI_TYPE_USER_PTR
param-type: count, KAPI_TYPE_UINT
param-type: flags, KAPI_TYPE_UINT
";
        let sig = "(bar, int, fd, char __user *, buf, size_t, count, unsigned long, flags)";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_bar", "syscall", Some(sig))
            .unwrap();

        assert_eq!(spec.parameters.len(), 4);

        let fd_param = spec.parameters.iter().find(|p| p.name == "fd").unwrap();
        assert_eq!(fd_param.param_type, 9); // FD (kernel enum)

        let buf_param = spec.parameters.iter().find(|p| p.name == "buf").unwrap();
        assert_eq!(buf_param.param_type, 10); // USER_PTR (kernel enum)
        assert_eq!(buf_param.type_name, "char __user * buf");

        let count_param = spec.parameters.iter().find(|p| p.name == "count").unwrap();
        assert_eq!(count_param.param_type, 2); // UINT

        let flags_param = spec.parameters.iter().find(|p| p.name == "flags").unwrap();
        assert_eq!(flags_param.param_type, 2); // UINT
    }

    #[test]
    fn parse_error_codes_with_descriptions() {
        let doc = "\
sys_err - Error test
error: EBADF
  desc: Bad file descriptor
  condition: fd < 0
error: EFAULT
  desc: Bad user pointer
  condition: buf is NULL
error: EINVAL
  desc: Invalid argument
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_err", "syscall", None)
            .unwrap();

        assert_eq!(spec.errors.len(), 3);

        assert_eq!(spec.errors[0].name, "EBADF");
        assert_eq!(spec.errors[0].error_code, -9);
        assert_eq!(spec.errors[0].description, "Bad file descriptor");
        assert_eq!(spec.errors[0].condition, "fd < 0");

        assert_eq!(spec.errors[1].name, "EFAULT");
        assert_eq!(spec.errors[1].error_code, -14);
        assert_eq!(spec.errors[1].description, "Bad user pointer");

        assert_eq!(spec.errors[2].name, "EINVAL");
        assert_eq!(spec.errors[2].error_code, -22);
        assert_eq!(spec.errors[2].description, "Invalid argument");
    }

    #[test]
    fn parse_context_flags() {
        let doc = "\
sys_ctx - Context test
context-flags: KAPI_CTX_PROCESS|KAPI_CTX_SLEEPABLE
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_ctx", "syscall", None)
            .unwrap();

        assert_eq!(spec.context_flags.len(), 2);
        assert_eq!(spec.context_flags[0], "KAPI_CTX_PROCESS");
        assert_eq!(spec.context_flags[1], "KAPI_CTX_SLEEPABLE");
    }

    #[test]
    fn parse_context_list_short() {
        // "contexts: process, sleepable" -> KAPI_CTX_PROCESS | SLEEPABLE
        let doc = "\
sys_ctx - Context test
contexts: process, sleepable
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_ctx", "syscall", None)
            .unwrap();

        assert_eq!(
            spec.context_flags,
            vec![
                "KAPI_CTX_PROCESS".to_string(),
                "KAPI_CTX_SLEEPABLE".to_string(),
            ]
        );
    }

    #[test]
    fn parse_context_list_mixed() {
        // Short tokens intermixed with explicit KAPI_CTX_* still work.
        let doc = "\
sys_ctx - Context test
contexts: process, KAPI_CTX_SLEEPABLE, softirq
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_ctx", "syscall", None)
            .unwrap();

        assert_eq!(
            spec.context_flags,
            vec![
                "KAPI_CTX_PROCESS".to_string(),
                "KAPI_CTX_SLEEPABLE".to_string(),
                "KAPI_CTX_SOFTIRQ".to_string(),
            ]
        );
    }

    #[test]
    fn parse_context_flags_long_with_short_token() {
        // Long-form "context-flags:" still accepts "|"-joined short
        // aliases so mid-migration files parse correctly.
        let doc = "\
sys_ctx - Context test
context-flags: process | KAPI_CTX_SLEEPABLE
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_ctx", "syscall", None)
            .unwrap();

        assert_eq!(
            spec.context_flags,
            vec![
                "KAPI_CTX_PROCESS".to_string(),
                "KAPI_CTX_SLEEPABLE".to_string(),
            ]
        );
    }

    #[test]
    fn parse_param_type_short_combined() {
        // "type: uint, input" combines the type and flag aliases.
        let doc = "\
sys_t - Short type test
param: size
  type: uint, input
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_t", "syscall", None)
            .unwrap();

        assert_eq!(spec.parameters.len(), 1);
        assert_eq!(spec.parameters[0].param_type, 2); // KAPI_TYPE_UINT
        assert_eq!(spec.parameters[0].flags, 1); // KAPI_PARAM_IN
    }

    #[test]
    fn parse_param_type_short_multi_flag() {
        // "type: path, input, user" sets both the IN and USER flags.
        let doc = "\
sys_t - Short type test
param: filename
  type: path, input, user
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_t", "syscall", None)
            .unwrap();

        assert_eq!(spec.parameters.len(), 1);
        assert_eq!(spec.parameters[0].param_type, 11); // PATH (kernel enum)
        assert_eq!(spec.parameters[0].flags, 1 | (1 << 6)); // IN | USER
    }

    #[test]
    fn parse_constraint_type_range_expr() {
        // Short form: "constraint-type: range(0, 4096)" replaces the
        // two-line long form "constraint-type: KAPI_CONSTRAINT_RANGE"
        // + "range: 0, 4096".
        let doc = "\
sys_c - Constraint test
param: count
  type: uint, input
  constraint-type: range(0, 4096)
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_c", "syscall", None)
            .unwrap();

        let p = &spec.parameters[0];
        assert_eq!(p.constraint_type, 1); // KAPI_CONSTRAINT_RANGE
        assert_eq!(p.min_value, Some(0));
        assert_eq!(p.max_value, Some(4096));
    }

    #[test]
    fn parse_constraint_type_mask_expr() {
        let doc = "\
sys_c - Constraint test
param: flags
  type: uint, input
  constraint-type: mask(0xff)
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_c", "syscall", None)
            .unwrap();

        let p = &spec.parameters[0];
        assert_eq!(p.constraint_type, 2); // KAPI_CONSTRAINT_MASK
        assert_eq!(p.valid_mask, Some(0xff));
    }

    #[test]
    fn user_ptr_type_implies_user_flag() {
        let doc = "\
sys_u - Implicit user flag test
param: buf
  type: user_ptr, output
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_u", "syscall", None)
            .unwrap();

        let p = &spec.parameters[0];
        assert_eq!(p.param_type, 10); // KAPI_TYPE_USER_PTR
        assert_eq!(
            p.flags,
            (1 << 1) | (1 << 6), // OUT | USER
            "user_ptr type must imply KAPI_PARAM_USER"
        );
    }

    #[test]
    fn fd_type_does_not_imply_user_flag() {
        // Only user_ptr / path imply KAPI_PARAM_USER. fd, int, uint,
        // and every other non-user-space type must leave flags alone.
        let doc = "\
sys_fd - fd has no implicit user flag
param: fd
  type: fd, input
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_fd", "syscall", None)
            .unwrap();

        let p = &spec.parameters[0];
        assert_eq!(p.param_type, 9);
        assert_eq!(p.flags, 1, "fd must not auto-set KAPI_PARAM_USER");
    }

    #[test]
    fn path_type_implies_user_flag() {
        let doc = "\
sys_p - Path implicit user flag
param: filename
  type: path, input
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_p", "syscall", None)
            .unwrap();

        let p = &spec.parameters[0];
        assert_eq!(p.param_type, 11);
        assert_eq!(
            p.flags,
            1 | (1 << 6), // IN | USER
            "path type must imply KAPI_PARAM_USER"
        );
    }

    #[test]
    fn short_form_enum_equivalence() {
        // Short-form and long-form renderings of the same spec must
        // produce identical ApiSpec output across every enum family:
        // context flags, param type+flags, constraint type, lock type,
        // signal direction/action/timing, capability action, side-effect
        // bitmask, return check type.
        let long = "\
sys_x - Enum short form test
context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE

param: fd
  type: KAPI_TYPE_FD
  flags: KAPI_PARAM_IN

lock: files->file_lock
  type: KAPI_LOCK_SPINLOCK
  scope: acquires
  desc: table lock

signal: pending_signals
  direction: KAPI_SIGNAL_RECEIVE
  action: KAPI_SIGNAL_ACTION_RETURN
  timing: KAPI_SIGNAL_TIME_DURING
  desc: sig

capability: CAP_SYS_ADMIN
  type: KAPI_CAP_BYPASS_CHECK

return:
  type: KAPI_TYPE_INT
  check-type: KAPI_RETURN_FD
  desc: fd or errno

side-effect: KAPI_EFFECT_RESOURCE_CREATE | KAPI_EFFECT_ALLOC_MEMORY
  target: t
  desc: d
";
        let short = "\
sys_x - Enum short form test
contexts: process, sleepable

param: fd
  type: fd, input

lock: files->file_lock
  type: spinlock
  scope: acquires
  desc: table lock

signal: pending_signals
  direction: receive
  action: return
  timing: during
  desc: sig

capability: CAP_SYS_ADMIN
  type: bypass_check

return:
  type: int
  check-type: fd
  desc: fd or errno

side-effect: resource_create | alloc_memory
  target: t
  desc: d
";
        let sp_l = parser()
            .parse_kerneldoc(long, "sys_x", "syscall", None)
            .unwrap();
        let sp_s = parser()
            .parse_kerneldoc(short, "sys_x", "syscall", None)
            .unwrap();
        assert_eq!(
            format!("{:#?}", sp_l),
            format!("{:#?}", sp_s),
            "long-form and short-form of every enum family must normalise identically"
        );
    }

    #[test]
    fn parse_buffer_short_captures_size_param_idx() {
        let doc = "\
sys_b - Buffer test
param: buf
  type: user_ptr, output, user
  constraint-type: buffer(2)
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_b", "syscall", None)
            .unwrap();

        assert_eq!(spec.parameters[0].constraint_type, 11);
        assert_eq!(spec.parameters[0].size_param_idx, Some(2));
    }

    #[test]
    fn buffer_short_and_size_param_long_are_symmetric() {
        let short = "\
sys_b - Symmetric buffer test
param: buf
  type: user_ptr, output, user
  constraint-type: buffer(2)
";
        let long = "\
sys_b - Symmetric buffer test
param: buf
  type: KAPI_TYPE_USER_PTR
  flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
  constraint-type: KAPI_CONSTRAINT_BUFFER
  size-param: 2
";
        let sp_s = parser()
            .parse_kerneldoc(short, "sys_b", "syscall", None)
            .unwrap();
        let sp_l = parser()
            .parse_kerneldoc(long, "sys_b", "syscall", None)
            .unwrap();
        assert_eq!(format!("{:#?}", sp_s), format!("{:#?}", sp_l));
    }

    #[test]
    fn parse_constraint_type_bare_user_path() {
        let doc = "\
sys_c - Constraint test
param: filename
  type: path, input, user
  constraint-type: user_path
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_c", "syscall", None)
            .unwrap();

        assert_eq!(spec.parameters[0].constraint_type, 9); // USER_PATH
    }

    #[test]
    fn is_block_key_recognises_ident_colon() {
        // Any bare `IDENT:` indented line must end a continuation fold.
        assert!(super::is_block_key("type:"));
        assert!(super::is_block_key("constraint-type:"));
        assert!(super::is_block_key("valid-mask: 0xff"));
        assert!(super::is_block_key("error: -EINTR"));
        assert!(super::is_block_key("expr: some expression"));
        assert!(super::is_block_key("reversible: yes"));
        // Expression fragments and punctuation are not block keys.
        assert!(!super::is_block_key("O_RDONLY | O_WRONLY |"));
        assert!(!super::is_block_key(")"));
        assert!(!super::is_block_key("Must be positive."));
    }

    #[test]
    fn multiline_fold_stops_at_sibling_block_attribute() {
        // A signal: block below a param: block. The constraint-type's
        // continuation must not greedily eat the next signal block's
        // `direction:` or the final `error:` line. (Kerneldoc section
        // headers are at indent 0, which the top-level fold check stops
        // on anyway; this test asserts that sibling *indented* keys
        // also stop the fold.)
        let doc = "\
sys_y - Fold stop test
param: f
  type: int, input
  constraint-type: mask(FOO |
                        BAR)
  cdesc: something about f
  direction: KAPI_SIGNAL_RECEIVE
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_y", "syscall", None)
            .unwrap();

        assert_eq!(spec.parameters.len(), 1);
        // If the fold over-consumed, `cdesc:` would have been swallowed
        // into the mask expression and param.constraint_type would be 0.
        assert_eq!(spec.parameters[0].constraint_type, 2);
    }

    #[test]
    fn parse_constraint_type_mask_expr_multiline() {
        // Real-world sys_open/flags case: a symbolic mask split across
        // four continuation lines. The parser must fold the continuation
        // lines before running the function-call match, otherwise the
        // constraint type silently decays to 0.
        let doc = "\
sys_x - Multi-line mask test
param: f
  type: int, input
  constraint-type: mask(O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY |
                        O_TRUNC | O_APPEND | O_NONBLOCK | O_DSYNC | O_SYNC | FASYNC |
                        O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | O_NOATIME |
                        O_CLOEXEC | O_PATH | O_TMPFILE)
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_x", "syscall", None)
            .unwrap();

        assert_eq!(spec.parameters.len(), 1);
        let p = &spec.parameters[0];
        assert_eq!(p.constraint_type, 2, "multi-line mask must set MASK type");
        // Symbolic mask — must stay unresolved rather than becoming Some(0).
        assert_eq!(
            p.valid_mask, None,
            "symbolic mask values must remain None, not Some(0)"
        );
    }

    #[test]
    fn parse_constraint_long_form_still_works() {
        let doc = "\
sys_c - Constraint test
param: foo
  type: uint, input
  constraint-type: KAPI_CONSTRAINT_MASK
  valid-mask: 0xff
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_c", "syscall", None)
            .unwrap();

        let p = &spec.parameters[0];
        assert_eq!(p.constraint_type, 2); // KAPI_CONSTRAINT_MASK
    }

    #[test]
    fn parse_constraint_free_text_still_works() {
        // `constraint:` carries free-text constraint description;
        // function-call short form lives on `constraint-type:`.
        let doc = "\
sys_c - Constraint test
param: foo
  type: uint, input
  constraint: must be a valid page descriptor
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_c", "syscall", None)
            .unwrap();

        let p = &spec.parameters[0];
        assert_eq!(p.constraint_type, 0);
        assert_eq!(
            p.constraint.as_deref(),
            Some("must be a valid page descriptor")
        );
    }

    #[test]
    fn parse_description_alias_overrides_kerneldoc() {
        // `description:` inside a `param:` block is an alias for `desc:`
        // and overrides the @param description.
        let doc = "\
sys_d - Description alias test
@size: kerneldoc short description
param: size
  type: uint, input
  description: The new long form description.
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_d", "syscall", None)
            .unwrap();

        assert_eq!(spec.parameters.len(), 1);
        assert_eq!(
            spec.parameters[0].description,
            "The new long form description."
        );
    }

    #[test]
    fn canonical_equivalence_short_vs_long() {
        // The regression test for the DSL cleanup: two spellings of the
        // same spec must produce identical ApiSpec JSON.
        let long = "\
sys_open - open a file
context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE

param: filename
  type: KAPI_TYPE_PATH
  flags: KAPI_PARAM_IN | KAPI_PARAM_USER
  constraint-type: KAPI_CONSTRAINT_USER_PATH
  desc: Pathname to open

param: count
  type: KAPI_TYPE_UINT
  flags: KAPI_PARAM_IN
  constraint-type: KAPI_CONSTRAINT_RANGE
  range: 0, 4096
  desc: Byte count
";
        let short = "\
sys_open - open a file
contexts: process, sleepable

param: filename
  type: path, input, user
  constraint-type: user_path
  description: Pathname to open

param: count
  type: uint, input
  constraint-type: range(0, 4096)
  description: Byte count
";
        let long_spec = parser()
            .parse_kerneldoc(long, "sys_open", "syscall", None)
            .unwrap();
        let short_spec = parser()
            .parse_kerneldoc(short, "sys_open", "syscall", None)
            .unwrap();

        // ApiSpec isn't Serialize as a whole, so compare the Debug
        // rendering — that still proves every field canonicalises
        // identically.
        let d_long = format!("{:#?}", long_spec);
        let d_short = format!("{:#?}", short_spec);
        assert_eq!(
            d_long, d_short,
            "short-form and long-form specs must normalise identically"
        );
    }

    #[test]
    fn parse_capability_block() {
        let doc = "\
sys_cap - Capability test
capability: CAP_SYS_ADMIN
  type: required
  allows: Full system administration
  without: Operation not permitted
  condition: always
  priority: 5
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_cap", "syscall", None)
            .unwrap();

        assert_eq!(spec.capabilities.len(), 1);
        let cap = &spec.capabilities[0];
        assert_eq!(cap.capability, 21); // CAP_SYS_ADMIN
        assert_eq!(cap.action, "required");
        assert_eq!(cap.allows, "Full system administration");
        assert_eq!(cap.without_cap, "Operation not permitted");
        assert_eq!(cap.check_condition.as_deref(), Some("always"));
        assert_eq!(cap.priority, Some(5));
    }

    #[test]
    fn parse_lock_block() {
        let doc = "\
sys_lock - Lock test
lock: files_lock, KAPI_LOCK_MUTEX
  scope: acquires
  desc: Protects file table
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_lock", "syscall", None)
            .unwrap();

        assert_eq!(spec.locks.len(), 1);
        let lock = &spec.locks[0];
        assert_eq!(lock.lock_name, "files_lock");
        assert_eq!(lock.lock_type, 1); // MUTEX
        assert_eq!(lock.scope, super::super::KAPI_LOCK_ACQUIRES);
        assert_eq!(lock.description, "Protects file table");
    }

    #[test]
    fn parse_signal_block() {
        let doc = "\
sys_sig - Signal test
signal: SIGKILL
  direction: KAPI_SIGNAL_RECEIVE
  action: KAPI_SIGNAL_ACTION_TERMINATE
  timing: KAPI_SIGNAL_TIME_DURING
  priority: 3
  restartable: yes
  interruptible: yes
  desc: Process termination signal
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_sig", "syscall", None)
            .unwrap();

        assert_eq!(spec.signals.len(), 1);
        let sig = &spec.signals[0];
        assert_eq!(sig.signal_name, "SIGKILL");
        assert_eq!(sig.direction, 1); // RECEIVE
        assert_eq!(sig.action, 1); // TERMINATE
        assert_eq!(sig.timing, 1); // DURING
        assert_eq!(sig.priority, 3);
        assert!(sig.restartable);
        assert!(sig.interruptible);
        assert_eq!(
            sig.description.as_deref(),
            Some("Process termination signal")
        );
    }

    #[test]
    fn parse_signal_errno_shapes() {
        // All three accepted spellings of the signal errno field must
        // produce the same negative kernel return code.
        for (form, label) in [
            ("errno: -EINTR", "-EINTR symbolic"),
            ("errno: EINTR", "bare symbolic"),
            ("errno: -4", "numeric literal"),
        ] {
            let doc = format!(
                "sys_s - Signal errno test\n\
                 signal: SIGINT\n\
                 \x20 direction: receive\n\
                 \x20 action: return\n\
                 \x20 {}\n",
                form,
            );
            let spec = parser()
                .parse_kerneldoc(&doc, "sys_s", "syscall", None)
                .unwrap();
            assert_eq!(spec.signals.len(), 1, "{label}");
            assert_eq!(
                spec.signals[0].error_on_signal,
                Some(-4),
                "errno form {label:?} must resolve to -EINTR (-4)",
            );
        }
    }

    #[test]
    fn parse_side_effect_flat() {
        let doc = "\
sys_se - Side effect test
side-effect: KAPI_EFFECT_MODIFY_STATE, file_table, Allocates a new file descriptor
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_se", "syscall", None)
            .unwrap();

        assert_eq!(spec.side_effects.len(), 1);
        let se = &spec.side_effects[0];
        assert_eq!(se.effect_type, 1 << 2); // KAPI_EFFECT_MODIFY_STATE
        assert_eq!(se.target, "file_table");
        assert_eq!(se.description, "Allocates a new file descriptor");
    }

    #[test]
    fn parse_side_effect_block() {
        let doc = "\
sys_se2 - Side effect block test
side-effect: KAPI_EFFECT_ALLOC_MEMORY
  target: kernel_heap
  desc: Allocates kernel memory
  reversible: yes
  condition: size > 0
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_se2", "syscall", None)
            .unwrap();

        assert_eq!(spec.side_effects.len(), 1);
        let se = &spec.side_effects[0];
        assert_eq!(se.effect_type, 1 << 0); // KAPI_EFFECT_ALLOC_MEMORY
        assert_eq!(se.target, "kernel_heap");
        assert_eq!(se.description, "Allocates kernel memory");
        assert!(se.reversible);
        assert_eq!(se.condition.as_deref(), Some("size > 0"));
    }

    #[test]
    fn parse_empty_doc_no_error() {
        let doc = "";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_empty", "syscall", None)
            .unwrap();

        assert_eq!(spec.name, "sys_empty");
        assert!(spec.description.is_none());
        assert!(spec.parameters.is_empty());
        assert!(spec.errors.is_empty());
        assert!(spec.signals.is_empty());
        assert!(spec.capabilities.is_empty());
        assert!(spec.locks.is_empty());
        assert!(spec.side_effects.is_empty());
        assert!(spec.context_flags.is_empty());
    }

    #[test]
    fn parse_missing_sections_no_error() {
        // Only has a description, no KAPI annotations
        let doc = "\
sys_simple - Just a simple syscall
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_simple", "syscall", None)
            .unwrap();

        assert_eq!(spec.description.as_deref(), Some("Just a simple syscall"));
        assert!(spec.parameters.is_empty());
        assert!(spec.errors.is_empty());
        assert!(spec.context_flags.is_empty());
    }

    #[test]
    fn parse_constraint_block() {
        let doc = "\
sys_cst - Constraint test
constraint: valid_fd
  desc: File descriptor must be valid and open
  expr: fd >= 0 && fd < NR_OPEN
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_cst", "syscall", None)
            .unwrap();

        assert_eq!(spec.constraints.len(), 1);
        let cst = &spec.constraints[0];
        assert_eq!(cst.name, "valid_fd");
        assert_eq!(cst.description, "File descriptor must be valid and open");
        assert_eq!(cst.expression.as_deref(), Some("fd >= 0 && fd < NR_OPEN"));
    }

    #[test]
    fn parse_state_transition_flat() {
        let doc = "\
sys_st - State transition test
state-trans: fd, open, closed, File descriptor is closed
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_st", "syscall", None)
            .unwrap();

        assert_eq!(spec.state_transitions.len(), 1);
        let st = &spec.state_transitions[0];
        assert_eq!(st.object, "fd");
        assert_eq!(st.from_state, "open");
        assert_eq!(st.to_state, "closed");
        assert_eq!(st.description, "File descriptor is closed");
    }

    #[test]
    fn parse_param_block_with_range() {
        let doc = "\
sys_rng - Range test
@count: byte count
param: count
  type: KAPI_TYPE_UINT
  flags: IN
  range: 0, 4096
  constraint-type: KAPI_CONSTRAINT_RANGE
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_rng", "syscall", None)
            .unwrap();

        assert_eq!(spec.parameters.len(), 1);
        let p = &spec.parameters[0];
        assert_eq!(p.name, "count");
        assert_eq!(p.param_type, 2); // UINT
        assert_eq!(p.flags, 1); // IN
        assert_eq!(p.min_value, Some(0));
        assert_eq!(p.max_value, Some(4096));
        assert_eq!(p.constraint_type, 1); // RANGE
    }

    #[test]
    fn parse_return_block() {
        let doc = "\
sys_ret - Return test
return:
  type: KAPI_TYPE_INT
  check-type: KAPI_RETURN_FD
  success: 0
  desc: Returns file descriptor on success
";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_ret", "syscall", None)
            .unwrap();

        let ret = spec.return_spec.as_ref().unwrap();
        assert_eq!(ret.type_name, "KAPI_TYPE_INT");
        assert_eq!(ret.return_type, 1); // INT
        assert_eq!(ret.check_type, 3); // FD
        assert_eq!(ret.success_value, Some(0));
        assert_eq!(ret.description, "Returns file descriptor on success");
    }
}
