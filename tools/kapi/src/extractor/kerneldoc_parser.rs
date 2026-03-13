use super::{
    ApiSpec, CapabilitySpec, ConstraintSpec, ErrorSpec, LockSpec, ParamSpec,
    ReturnSpec, SideEffectSpec, SignalSpec, StateTransitionSpec, StructSpec,
    StructFieldSpec,
};
use anyhow::Result;
use std::collections::HashMap;

/// Real kerneldoc parser that extracts KAPI annotations
pub struct KerneldocParserImpl;

/// What block are we currently inside?
#[derive(Debug, Clone, PartialEq)]
enum BlockContext {
    None,
    Param(String),     // param: <name>
    Error(String),     // error: <name>
    Signal,            // signal: <name>
    Capability,        // capability: <name>
    SideEffect,        // side-effect: <type>
    StateTransition,   // state-trans: ...
    Constraint,        // constraint: <name>
    Lock,              // lock: <name>
    Return,            // return:
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

            // If indented and we're in a block, parse as block attribute
            if is_indented && block != BlockContext::None {
                self.parse_block_attribute(trimmed, &block, &mut param_map,
                    &mut current_error, &mut current_signal,
                    &mut current_capability, &mut current_side_effect,
                    &mut current_constraint, &mut current_lock,
                    &mut current_return);
                i += 1;
                continue;
            }

            // Not indented or not in block — flush current block if any
            self.flush_block(&mut block, &mut spec, &mut current_error,
                &mut current_signal, &mut current_capability,
                &mut current_side_effect, &mut current_constraint,
                &mut current_lock, &mut current_return);

            // Parse top-level annotations
            if let Some(rest) = trimmed.strip_prefix("@") {
                // @param: description — standard kerneldoc parameter
                if let Some((param_name, desc)) = rest.split_once(':') {
                    let param_name = param_name.trim();
                    let desc = desc.trim();
                    if !param_name.contains('-') {
                        let idx = param_map.len() as u32;
                        let type_name = type_map.get(param_name)
                            .cloned()
                            .unwrap_or_default();
                        param_map.insert(param_name.to_string(), ParamSpec {
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
                        });
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("long-desc:") {
                let (val, next_i) = self.collect_multiline_value(&lines, i, rest);
                spec.long_description = Some(val);
                i = next_i;
                continue;
            } else if let Some(rest) = trimmed.strip_prefix("context-flags:") {
                spec.context_flags = self.parse_context_flags(rest.trim());
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
                    let type_name = type_map.get(param_name.as_str())
                        .cloned()
                        .unwrap_or_default();
                    param_map.insert(param_name.clone(), ParamSpec {
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
                    });
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
                    if let Some(constraint) = spec.constraints.iter_mut().find(|c| c.name == parts[0]) {
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
            } else if let Some(rest) = trimmed.strip_prefix("since-version:") {
                spec.since_version = Some(rest.trim().to_string());
            }

            i += 1;
        }

        // Flush any remaining block
        self.flush_block(&mut block, &mut spec, &mut current_error,
            &mut current_signal, &mut current_capability,
            &mut current_side_effect, &mut current_constraint,
            &mut current_lock, &mut current_return);

        // Convert param_map to vec preserving order
        let mut params: Vec<ParamSpec> = param_map.into_values().collect();
        params.sort_by_key(|p| p.index);
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
    fn parse_block_attribute(
        &self,
        trimmed: &str,
        block: &BlockContext,
        param_map: &mut HashMap<String, ParamSpec>,
        current_error: &mut Option<ErrorSpec>,
        current_signal: &mut Option<SignalSpec>,
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
                        param.param_type = self.parse_param_type(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("flags:") {
                        param.flags = self.parse_param_flags(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("constraint-type:") {
                        param.constraint_type = self.parse_constraint_type(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("valid-mask:") {
                        // Don't try to parse symbolic mask values — leave for binary
                        let _ = rest; // valid-mask parsing needs constant resolution
                    } else if let Some(rest) = trimmed.strip_prefix("constraint:") {
                        // May be multiline — append
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
                    } else if let Some(rest) = trimmed.strip_prefix("desc:") {
                        param.description = rest.trim().to_string();
                    } else if !trimmed.contains(':') || trimmed.starts_with("  ") {
                        // Continuation of previous attribute (e.g., multiline constraint)
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
                    } else if let Some(rest) = trimmed.strip_prefix("error:") {
                        let code_str = rest.trim().trim_start_matches('-');
                        if let Ok(code) = code_str.parse::<i32>() {
                            signal.error_on_signal = Some(code);
                        } else {
                            signal.error_on_signal = Some(self.error_name_to_code(rest.trim().trim_start_matches('-')));
                        }
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
                        cap.action = rest.trim().to_string();
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
                    } else if trimmed.starts_with("acquired:") || trimmed.starts_with("released:") {
                        // Ignored — handled via scope
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
                        ret.type_name = rest.trim().to_string();
                        ret.return_type = self.parse_param_type(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("check-type:") {
                        ret.check_type = self.parse_return_check_type(rest.trim());
                    } else if let Some(rest) = trimmed.strip_prefix("success:") {
                        // Parse success value — could be "= 0", ">= 0", etc.
                        let val = rest.trim().trim_start_matches(|c: char| !c.is_ascii_digit() && c != '-');
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

    fn collect_multiline_value(&self, lines: &[&str], start_idx: usize, first_part: &str) -> (String, usize) {
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
            "param:", "param-", "error:", "error-", "lock:", "lock-",
            "signal:", "signal-", "side-effect:", "state-trans:",
            "capability:", "capability-", "constraint:", "constraint-",
            "struct-", "return:", "return-", "examples:", "notes:",
            "since-", "context-", "long-desc:", "api-type:",
        ];

        for ann in &annotations {
            if trimmed.starts_with(ann) {
                return true;
            }
        }
        false
    }

    fn parse_context_flags(&self, flags: &str) -> Vec<String> {
        flags.split('|')
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .collect()
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

    fn parse_param_type(&self, type_str: &str) -> u32 {
        match type_str {
            "KAPI_TYPE_INT" => 1,
            "KAPI_TYPE_UINT" => 2,
            "KAPI_TYPE_LONG" => 3,
            "KAPI_TYPE_ULONG" => 4,
            "KAPI_TYPE_STRING" => 5,
            "KAPI_TYPE_USER_PTR" => 6,
            "KAPI_TYPE_PATH" => 5, // PATH is a string type
            _ => 0,
        }
    }

    fn parse_constraint_type(&self, type_str: &str) -> u32 {
        match type_str {
            "KAPI_CONSTRAINT_RANGE" => 1,
            "KAPI_CONSTRAINT_MASK" => 2,
            "KAPI_CONSTRAINT_ENUM" => 3,
            "KAPI_CONSTRAINT_ALIGN" => 4,
            "KAPI_CONSTRAINT_CUSTOM" => 5,
            "KAPI_CONSTRAINT_STRLEN" => 6,
            "KAPI_CONSTRAINT_NULLABLE" => 7,
            "KAPI_CONSTRAINT_FD" => 8,
            "KAPI_CONSTRAINT_USER_PATH" => 9,
            "KAPI_CONSTRAINT_PID" => 10,
            "KAPI_CONSTRAINT_BUFFER" => 11,
            "KAPI_CONSTRAINT_IOCTL_CMD" => 12,
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
        let mut result = 0;
        for flag in flags.split('|') {
            match flag.trim() {
                "KAPI_PARAM_IN" | "IN" => result |= 1,
                "KAPI_PARAM_OUT" | "OUT" => result |= 2,
                "KAPI_PARAM_INOUT" | "INOUT" => result |= 3,
                "KAPI_PARAM_USER" | "USER" => result |= 64,
                _ => {}
            }
        }
        result
    }

    fn parse_lock_type(&self, type_str: &str) -> u32 {
        match type_str.trim() {
            "KAPI_LOCK_SPINLOCK" => 0,
            "KAPI_LOCK_MUTEX" => 1,
            "KAPI_LOCK_RWLOCK" => 2,
            "KAPI_LOCK_RCU" => 3,
            _ => 3,
        }
    }

    fn parse_signal_direction(&self, dir: &str) -> u32 {
        match dir {
            "KAPI_SIGNAL_RECEIVE" => 1,
            "KAPI_SIGNAL_SEND" => 2,
            "KAPI_SIGNAL_HANDLE" => 4,
            "KAPI_SIGNAL_BLOCK" => 8,
            "KAPI_SIGNAL_IGNORE" => 16,
            _ => 0,
        }
    }

    fn parse_signal_action(&self, action: &str) -> u32 {
        match action {
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
            _ => 0,
        }
    }

    fn parse_signal_timing(&self, timing: &str) -> u32 {
        match timing {
            "KAPI_SIGNAL_TIME_BEFORE" => 0,
            "KAPI_SIGNAL_TIME_DURING" => 1,
            "KAPI_SIGNAL_TIME_AFTER" => 2,
            _ => 0,
        }
    }

    fn parse_signal_state(&self, state: &str) -> u32 {
        match state {
            "KAPI_SIGNAL_STATE_RUNNING" => 1,
            "KAPI_SIGNAL_STATE_SLEEPING" => 2,
            _ => 0,
        }
    }

    fn parse_effect_type(&self, type_str: &str) -> u32 {
        let mut result = 0;
        for flag in type_str.split('|') {
            match flag.trim() {
                "KAPI_EFFECT_MODIFY_STATE" => result |= 1,
                "KAPI_EFFECT_PROCESS_STATE" => result |= 2,
                "KAPI_EFFECT_SCHEDULE" => result |= 4,
                "KAPI_EFFECT_ALLOC_MEMORY" => result |= 128,
                "KAPI_EFFECT_RESOURCE_CREATE" => result |= 1,
                "KAPI_EFFECT_FILESYSTEM" => result |= 4096,
                _ => {}
            }
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

    fn parse_return_check_type(&self, check: &str) -> u32 {
        match check {
            "KAPI_RETURN_ERROR_CHECK" => 1,
            "KAPI_RETURN_SUCCESS_CHECK" => 2,
            "KAPI_RETURN_FD" => 3,
            _ => 0,
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
param-type: fd, KAPI_TYPE_INT
param-type: buf, KAPI_TYPE_USER_PTR
param-type: count, KAPI_TYPE_UINT
param-type: flags, KAPI_TYPE_ULONG
";
        let sig = "(bar, int, fd, char __user *, buf, size_t, count, unsigned long, flags)";
        let spec = parser()
            .parse_kerneldoc(doc, "sys_bar", "syscall", Some(sig))
            .unwrap();

        assert_eq!(spec.parameters.len(), 4);

        let fd_param = spec.parameters.iter().find(|p| p.name == "fd").unwrap();
        assert_eq!(fd_param.param_type, 1); // INT

        let buf_param = spec.parameters.iter().find(|p| p.name == "buf").unwrap();
        assert_eq!(buf_param.param_type, 6); // USER_PTR
        assert_eq!(buf_param.type_name, "char __user * buf");

        let count_param = spec.parameters.iter().find(|p| p.name == "count").unwrap();
        assert_eq!(count_param.param_type, 2); // UINT

        let flags_param = spec.parameters.iter().find(|p| p.name == "flags").unwrap();
        assert_eq!(flags_param.param_type, 4); // ULONG
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
        assert_eq!(sig.action, 1);    // TERMINATE
        assert_eq!(sig.timing, 1);    // DURING
        assert_eq!(sig.priority, 3);
        assert!(sig.restartable);
        assert!(sig.interruptible);
        assert_eq!(sig.description.as_deref(), Some("Process termination signal"));
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
        assert_eq!(se.effect_type, 1); // MODIFY_STATE
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
        assert_eq!(se.effect_type, 128); // ALLOC_MEMORY
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
        assert_eq!(p.flags, 1);      // IN
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
        assert_eq!(ret.check_type, 3);  // FD
        assert_eq!(ret.success_value, Some(0));
        assert_eq!(ret.description, "Returns file descriptor on success");
    }
}
