use crate::extractor::{
    AddrFamilySpec, AsyncSpec, BufferSpec, CapabilitySpec, ConstraintSpec, ErrorSpec, LockSpec,
    ParamSpec, ProtocolBehaviorSpec, ReturnSpec, SideEffectSpec, SignalMaskSpec, SignalSpec,
    SocketStateSpec, StateTransitionSpec, StructSpec,
};
use std::io::Write;

mod json;
mod plain;
mod rst;

pub use json::JsonFormatter;
pub use plain::PlainFormatter;
pub use rst::RstFormatter;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Plain,
    Json,
    Rst,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "plain" => Ok(OutputFormat::Plain),
            "json" => Ok(OutputFormat::Json),
            "rst" => Ok(OutputFormat::Rst),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

pub trait OutputFormatter {
    fn begin_document(&mut self, w: &mut dyn Write) -> std::io::Result<()>;
    fn end_document(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn begin_api_list(&mut self, w: &mut dyn Write, title: &str) -> std::io::Result<()>;
    fn api_item(&mut self, w: &mut dyn Write, name: &str, api_type: &str) -> std::io::Result<()>;
    fn end_api_list(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn total_specs(&mut self, w: &mut dyn Write, count: usize) -> std::io::Result<()>;

    fn begin_api_details(&mut self, w: &mut dyn Write, name: &str) -> std::io::Result<()>;
    fn end_api_details(&mut self, w: &mut dyn Write) -> std::io::Result<()>;
    fn description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()>;
    fn long_description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()>;

    fn begin_context_flags(&mut self, w: &mut dyn Write) -> std::io::Result<()>;
    fn context_flag(&mut self, w: &mut dyn Write, flag: &str) -> std::io::Result<()>;
    fn end_context_flags(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn begin_parameters(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()>;
    fn parameter(&mut self, w: &mut dyn Write, param: &ParamSpec) -> std::io::Result<()>;
    fn end_parameters(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn return_spec(&mut self, w: &mut dyn Write, ret: &ReturnSpec) -> std::io::Result<()>;

    fn begin_errors(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()>;
    fn error(&mut self, w: &mut dyn Write, error: &ErrorSpec) -> std::io::Result<()>;
    fn end_errors(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn examples(&mut self, w: &mut dyn Write, examples: &str) -> std::io::Result<()>;
    fn notes(&mut self, w: &mut dyn Write, notes: &str) -> std::io::Result<()>;
    fn since_version(&mut self, w: &mut dyn Write, version: &str) -> std::io::Result<()>;

    // Sysfs-specific methods
    fn sysfs_subsystem(&mut self, w: &mut dyn Write, subsystem: &str) -> std::io::Result<()>;
    fn sysfs_path(&mut self, w: &mut dyn Write, path: &str) -> std::io::Result<()>;
    fn sysfs_permissions(&mut self, w: &mut dyn Write, perms: &str) -> std::io::Result<()>;

    // Networking-specific methods
    fn socket_state(&mut self, w: &mut dyn Write, state: &SocketStateSpec) -> std::io::Result<()>;

    fn begin_protocol_behaviors(&mut self, w: &mut dyn Write) -> std::io::Result<()>;
    fn protocol_behavior(
        &mut self,
        w: &mut dyn Write,
        behavior: &ProtocolBehaviorSpec,
    ) -> std::io::Result<()>;
    fn end_protocol_behaviors(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn begin_addr_families(&mut self, w: &mut dyn Write) -> std::io::Result<()>;
    fn addr_family(&mut self, w: &mut dyn Write, family: &AddrFamilySpec) -> std::io::Result<()>;
    fn end_addr_families(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn buffer_spec(&mut self, w: &mut dyn Write, spec: &BufferSpec) -> std::io::Result<()>;
    fn async_spec(&mut self, w: &mut dyn Write, spec: &AsyncSpec) -> std::io::Result<()>;
    fn net_data_transfer(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()>;

    fn begin_capabilities(&mut self, w: &mut dyn Write) -> std::io::Result<()>;
    fn capability(&mut self, w: &mut dyn Write, cap: &CapabilitySpec) -> std::io::Result<()>;
    fn end_capabilities(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    // Signal-related methods
    fn begin_signals(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()>;
    fn signal(&mut self, w: &mut dyn Write, signal: &SignalSpec) -> std::io::Result<()>;
    fn end_signals(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn begin_signal_masks(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()>;
    fn signal_mask(&mut self, w: &mut dyn Write, mask: &SignalMaskSpec) -> std::io::Result<()>;
    fn end_signal_masks(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    // Side effects and state transitions
    fn begin_side_effects(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()>;
    fn side_effect(&mut self, w: &mut dyn Write, effect: &SideEffectSpec) -> std::io::Result<()>;
    fn end_side_effects(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn begin_state_transitions(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()>;
    fn state_transition(
        &mut self,
        w: &mut dyn Write,
        trans: &StateTransitionSpec,
    ) -> std::io::Result<()>;
    fn end_state_transitions(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    // Constraints and locks
    fn begin_constraints(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()>;
    fn constraint(&mut self, w: &mut dyn Write, constraint: &ConstraintSpec)
    -> std::io::Result<()>;
    fn end_constraints(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn begin_locks(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()>;
    fn lock(&mut self, w: &mut dyn Write, lock: &LockSpec) -> std::io::Result<()>;
    fn end_locks(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn begin_struct_specs(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()>;
    fn struct_spec(&mut self, w: &mut dyn Write, spec: &StructSpec) -> std::io::Result<()>;
    fn end_struct_specs(&mut self, w: &mut dyn Write) -> std::io::Result<()>;
}

pub fn create_formatter(format: OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Plain => Box::new(PlainFormatter::new()),
        OutputFormat::Json => Box::new(JsonFormatter::new()),
        OutputFormat::Rst => Box::new(RstFormatter::new()),
    }
}
