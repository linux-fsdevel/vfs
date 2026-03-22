// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use crate::formatter::OutputFormatter;
use anyhow::Result;
use std::io::Write;

pub mod debugfs;
pub mod kerneldoc_parser;
pub mod source_parser;
pub mod vmlinux;

pub use debugfs::DebugfsExtractor;
pub use source_parser::SourceExtractor;
pub use vmlinux::VmlinuxExtractor;

/// Socket state specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct SocketStateSpec {
    pub required_states: Vec<String>,
    pub forbidden_states: Vec<String>,
    pub resulting_state: Option<String>,
    pub condition: Option<String>,
    pub applicable_protocols: Option<String>,
}

/// Protocol behavior specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProtocolBehaviorSpec {
    pub applicable_protocols: String,
    pub behavior: String,
    pub protocol_flags: Option<String>,
    pub flag_description: Option<String>,
}

/// Address family specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct AddrFamilySpec {
    pub family: i32,
    pub family_name: String,
    pub addr_struct_size: usize,
    pub min_addr_len: usize,
    pub max_addr_len: usize,
    pub addr_format: Option<String>,
    pub supports_wildcard: bool,
    pub supports_multicast: bool,
    pub supports_broadcast: bool,
    pub special_addresses: Option<String>,
    pub port_range_min: u32,
    pub port_range_max: u32,
}

/// Buffer specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct BufferSpec {
    pub buffer_behaviors: Option<String>,
    pub min_buffer_size: Option<usize>,
    pub max_buffer_size: Option<usize>,
    pub optimal_buffer_size: Option<usize>,
}

/// Async specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct AsyncSpec {
    pub supported_modes: Option<String>,
    pub nonblock_errno: Option<i32>,
}

/// Capability specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapabilitySpec {
    pub capability: i32,
    pub name: String,
    pub action: String,
    pub allows: String,
    pub without_cap: String,
    pub check_condition: Option<String>,
    pub priority: Option<u8>,
    pub alternatives: Vec<i32>,
}

/// Parameter specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct ParamSpec {
    pub index: u32,
    pub name: String,
    pub type_name: String,
    pub description: String,
    pub flags: u32,
    pub param_type: u32,
    pub constraint_type: u32,
    pub constraint: Option<String>,
    pub min_value: Option<i64>,
    pub max_value: Option<i64>,
    pub valid_mask: Option<u64>,
    pub enum_values: Vec<String>,
    pub size: Option<u32>,
    pub alignment: Option<u32>,
}

/// Return value specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReturnSpec {
    pub type_name: String,
    pub description: String,
    pub return_type: u32,
    pub check_type: u32,
    pub success_value: Option<i64>,
    pub success_min: Option<i64>,
    pub success_max: Option<i64>,
    pub error_values: Vec<i32>,
}

/// Error specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct ErrorSpec {
    pub error_code: i32,
    pub name: String,
    pub condition: String,
    pub description: String,
}

/// Signal specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignalSpec {
    pub signal_num: i32,
    pub signal_name: String,
    pub direction: u32,
    pub action: u32,
    pub target: Option<String>,
    pub condition: Option<String>,
    pub description: Option<String>,
    pub timing: u32,
    pub priority: u32,
    pub restartable: bool,
    pub interruptible: bool,
    pub queue: Option<String>,
    pub sa_flags: u32,
    pub sa_flags_required: u32,
    pub sa_flags_forbidden: u32,
    pub state_required: u32,
    pub state_forbidden: u32,
    pub error_on_signal: Option<i32>,
}

/// Signal mask specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignalMaskSpec {
    pub name: String,
    pub description: String,
}

/// Side effect specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct SideEffectSpec {
    pub effect_type: u32,
    pub target: String,
    pub condition: Option<String>,
    pub description: String,
    pub reversible: bool,
}

/// State transition specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct StateTransitionSpec {
    pub object: String,
    pub from_state: String,
    pub to_state: String,
    pub condition: Option<String>,
    pub description: String,
}

/// Constraint specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConstraintSpec {
    pub name: String,
    pub description: String,
    pub expression: Option<String>,
}

/// Lock scope enum values matching kernel enum kapi_lock_scope
pub const KAPI_LOCK_INTERNAL: u32 = 0;
pub const KAPI_LOCK_ACQUIRES: u32 = 1;
pub const KAPI_LOCK_RELEASES: u32 = 2;
pub const KAPI_LOCK_CALLER_HELD: u32 = 3;

/// Lock specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct LockSpec {
    pub lock_name: String,
    pub lock_type: u32,
    pub scope: u32,
    pub description: String,
}

/// Struct field specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct StructFieldSpec {
    pub name: String,
    pub field_type: u32,
    pub type_name: String,
    pub offset: usize,
    pub size: usize,
    pub flags: u32,
    pub constraint_type: u32,
    pub min_value: i64,
    pub max_value: i64,
    pub valid_mask: u64,
    pub description: String,
}

/// Struct specification
#[derive(Debug, Clone, serde::Serialize)]
pub struct StructSpec {
    pub name: String,
    pub size: usize,
    pub alignment: usize,
    pub field_count: u32,
    pub fields: Vec<StructFieldSpec>,
    pub description: String,
}

/// Common API specification information that all extractors should provide
#[derive(Debug, Clone, Default)]
pub struct ApiSpec {
    pub name: String,
    pub api_type: String,
    pub description: Option<String>,
    pub long_description: Option<String>,
    pub version: Option<String>,
    pub context_flags: Vec<String>,
    pub param_count: Option<u32>,
    pub error_count: Option<u32>,
    pub examples: Option<String>,
    pub notes: Option<String>,
    // Sysfs-specific fields
    pub subsystem: Option<String>,
    pub sysfs_path: Option<String>,
    pub permissions: Option<String>,
    // Networking-specific fields
    pub socket_state: Option<SocketStateSpec>,
    pub protocol_behaviors: Vec<ProtocolBehaviorSpec>,
    pub addr_families: Vec<AddrFamilySpec>,
    pub buffer_spec: Option<BufferSpec>,
    pub async_spec: Option<AsyncSpec>,
    pub net_data_transfer: Option<String>,
    pub capabilities: Vec<CapabilitySpec>,
    pub parameters: Vec<ParamSpec>,
    pub return_spec: Option<ReturnSpec>,
    pub errors: Vec<ErrorSpec>,
    pub signals: Vec<SignalSpec>,
    pub signal_masks: Vec<SignalMaskSpec>,
    pub side_effects: Vec<SideEffectSpec>,
    pub state_transitions: Vec<StateTransitionSpec>,
    pub constraints: Vec<ConstraintSpec>,
    pub locks: Vec<LockSpec>,
    pub struct_specs: Vec<StructSpec>,
}

/// Trait for extracting API specifications from different sources
pub trait ApiExtractor {
    /// Extract all API specifications from the source
    fn extract_all(&self) -> Result<Vec<ApiSpec>>;

    /// Extract a specific API specification by name
    fn extract_by_name(&self, name: &str) -> Result<Option<ApiSpec>>;

    /// Display detailed information about a specific API
    fn display_api_details(
        &self,
        api_name: &str,
        formatter: &mut dyn OutputFormatter,
        writer: &mut dyn Write,
    ) -> Result<()>;
}

/// Helper function to display an ApiSpec using a formatter
pub fn display_api_spec(
    spec: &ApiSpec,
    formatter: &mut dyn OutputFormatter,
    writer: &mut dyn Write,
) -> Result<()> {
    formatter.begin_api_details(writer, &spec.name)?;

    if let Some(desc) = &spec.description {
        formatter.description(writer, desc)?;
    }

    if let Some(long_desc) = &spec.long_description {
        formatter.long_description(writer, long_desc)?;
    }

    if !spec.context_flags.is_empty() {
        formatter.begin_context_flags(writer)?;
        for flag in &spec.context_flags {
            formatter.context_flag(writer, flag)?;
        }
        formatter.end_context_flags(writer)?;
    }

    if !spec.parameters.is_empty() {
        formatter.begin_parameters(writer, spec.parameters.len().try_into().unwrap_or(u32::MAX))?;
        for param in &spec.parameters {
            formatter.parameter(writer, param)?;
        }
        formatter.end_parameters(writer)?;
    }

    if let Some(ret) = &spec.return_spec {
        formatter.return_spec(writer, ret)?;
    }

    if !spec.errors.is_empty() {
        formatter.begin_errors(writer, spec.errors.len().try_into().unwrap_or(u32::MAX))?;
        for error in &spec.errors {
            formatter.error(writer, error)?;
        }
        formatter.end_errors(writer)?;
    }

    if let Some(notes) = &spec.notes {
        formatter.notes(writer, notes)?;
    }

    if let Some(examples) = &spec.examples {
        formatter.examples(writer, examples)?;
    }

    // Display sysfs-specific fields
    if spec.api_type == "sysfs" {
        if let Some(subsystem) = &spec.subsystem {
            formatter.sysfs_subsystem(writer, subsystem)?;
        }
        if let Some(path) = &spec.sysfs_path {
            formatter.sysfs_path(writer, path)?;
        }
        if let Some(perms) = &spec.permissions {
            formatter.sysfs_permissions(writer, perms)?;
        }
    }

    // Display networking-specific fields
    if let Some(socket_state) = &spec.socket_state {
        formatter.socket_state(writer, socket_state)?;
    }

    if !spec.protocol_behaviors.is_empty() {
        formatter.begin_protocol_behaviors(writer)?;
        for behavior in &spec.protocol_behaviors {
            formatter.protocol_behavior(writer, behavior)?;
        }
        formatter.end_protocol_behaviors(writer)?;
    }

    if !spec.addr_families.is_empty() {
        formatter.begin_addr_families(writer)?;
        for family in &spec.addr_families {
            formatter.addr_family(writer, family)?;
        }
        formatter.end_addr_families(writer)?;
    }

    if let Some(buffer_spec) = &spec.buffer_spec {
        formatter.buffer_spec(writer, buffer_spec)?;
    }

    if let Some(async_spec) = &spec.async_spec {
        formatter.async_spec(writer, async_spec)?;
    }

    if let Some(net_data_transfer) = &spec.net_data_transfer {
        formatter.net_data_transfer(writer, net_data_transfer)?;
    }

    if !spec.capabilities.is_empty() {
        formatter.begin_capabilities(writer)?;
        for cap in &spec.capabilities {
            formatter.capability(writer, cap)?;
        }
        formatter.end_capabilities(writer)?;
    }

    // Display signals
    if !spec.signals.is_empty() {
        formatter.begin_signals(writer, spec.signals.len().try_into().unwrap_or(u32::MAX))?;
        for signal in &spec.signals {
            formatter.signal(writer, signal)?;
        }
        formatter.end_signals(writer)?;
    }

    // Display signal masks
    if !spec.signal_masks.is_empty() {
        formatter.begin_signal_masks(
            writer,
            spec.signal_masks.len().try_into().unwrap_or(u32::MAX),
        )?;
        for mask in &spec.signal_masks {
            formatter.signal_mask(writer, mask)?;
        }
        formatter.end_signal_masks(writer)?;
    }

    // Display side effects
    if !spec.side_effects.is_empty() {
        formatter.begin_side_effects(
            writer,
            spec.side_effects.len().try_into().unwrap_or(u32::MAX),
        )?;
        for effect in &spec.side_effects {
            formatter.side_effect(writer, effect)?;
        }
        formatter.end_side_effects(writer)?;
    }

    // Display state transitions
    if !spec.state_transitions.is_empty() {
        formatter.begin_state_transitions(
            writer,
            spec.state_transitions.len().try_into().unwrap_or(u32::MAX),
        )?;
        for trans in &spec.state_transitions {
            formatter.state_transition(writer, trans)?;
        }
        formatter.end_state_transitions(writer)?;
    }

    // Display constraints
    if !spec.constraints.is_empty() {
        formatter.begin_constraints(
            writer,
            spec.constraints.len().try_into().unwrap_or(u32::MAX),
        )?;
        for constraint in &spec.constraints {
            formatter.constraint(writer, constraint)?;
        }
        formatter.end_constraints(writer)?;
    }

    // Display locks
    if !spec.locks.is_empty() {
        formatter.begin_locks(writer, spec.locks.len().try_into().unwrap_or(u32::MAX))?;
        for lock in &spec.locks {
            formatter.lock(writer, lock)?;
        }
        formatter.end_locks(writer)?;
    }

    // Display struct specs
    if !spec.struct_specs.is_empty() {
        formatter.begin_struct_specs(writer, spec.struct_specs.len().try_into().unwrap_or(u32::MAX))?;
        for struct_spec in &spec.struct_specs {
            formatter.struct_spec(writer, struct_spec)?;
        }
        formatter.end_struct_specs(writer)?;
    }

    formatter.end_api_details(writer)?;

    Ok(())
}
