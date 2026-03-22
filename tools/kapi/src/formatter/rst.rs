// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use super::OutputFormatter;
use crate::extractor::{
    AddrFamilySpec, AsyncSpec, BufferSpec, CapabilitySpec, ConstraintSpec, ErrorSpec, LockSpec,
    ParamSpec, ProtocolBehaviorSpec, ReturnSpec, SideEffectSpec, SignalMaskSpec, SignalSpec,
    SocketStateSpec, StateTransitionSpec,
};
use std::io::Write;

pub struct RstFormatter;

impl RstFormatter {
    pub fn new() -> Self {
        RstFormatter
    }

    fn section_char(level: usize) -> char {
        match level {
            0 => '=',
            1 => '-',
            2 => '~',
            3 => '^',
            _ => '"',
        }
    }
}

impl OutputFormatter for RstFormatter {
    fn begin_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn end_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_api_list(&mut self, w: &mut dyn Write, title: &str) -> std::io::Result<()> {
        writeln!(w, "\n{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(0).to_string().repeat(title.len())
        )?;
        writeln!(w)
    }

    fn api_item(&mut self, w: &mut dyn Write, name: &str, api_type: &str) -> std::io::Result<()> {
        writeln!(w, "* **{name}** (*{api_type}*)")
    }

    fn end_api_list(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn total_specs(&mut self, w: &mut dyn Write, count: usize) -> std::io::Result<()> {
        writeln!(w, "\n**Total specifications found:** {count}")
    }

    fn begin_api_details(&mut self, w: &mut dyn Write, name: &str) -> std::io::Result<()> {

        writeln!(w, "\n{name}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(0).to_string().repeat(name.len())
        )?;
        writeln!(w)
    }

    fn end_api_details(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w, "**{desc}**")?;
        writeln!(w)
    }

    fn long_description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w, "{desc}")?;
        writeln!(w)
    }

    fn begin_context_flags(&mut self, w: &mut dyn Write) -> std::io::Result<()> {

        let title = "Execution Context";
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)
    }

    fn context_flag(&mut self, w: &mut dyn Write, flag: &str) -> std::io::Result<()> {
        writeln!(w, "* {flag}")
    }

    fn end_context_flags(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w)
    }

    fn begin_parameters(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {

        let title = format!("Parameters ({count})");
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)
    }

    fn end_parameters(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_errors(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {

        let title = format!("Possible Errors ({count})");
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)
    }

    fn end_errors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn examples(&mut self, w: &mut dyn Write, examples: &str) -> std::io::Result<()> {

        let title = "Examples";
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)?;
        writeln!(w, ".. code-block:: c")?;
        writeln!(w)?;
        for line in examples.lines() {
            writeln!(w, "   {line}")?;
        }
        writeln!(w)
    }

    fn notes(&mut self, w: &mut dyn Write, notes: &str) -> std::io::Result<()> {

        let title = "Notes";
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)?;
        writeln!(w, "{notes}")?;
        writeln!(w)
    }

    fn sysfs_subsystem(&mut self, w: &mut dyn Write, subsystem: &str) -> std::io::Result<()> {
        writeln!(w, ":Subsystem: {subsystem}")?;
        writeln!(w)
    }

    fn sysfs_path(&mut self, w: &mut dyn Write, path: &str) -> std::io::Result<()> {
        writeln!(w, ":Sysfs Path: {path}")?;
        writeln!(w)
    }

    fn sysfs_permissions(&mut self, w: &mut dyn Write, perms: &str) -> std::io::Result<()> {
        writeln!(w, ":Permissions: {perms}")?;
        writeln!(w)
    }

    // Networking-specific methods
    fn socket_state(&mut self, w: &mut dyn Write, state: &SocketStateSpec) -> std::io::Result<()> {

        let title = "Socket State Requirements";
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)?;

        if !state.required_states.is_empty() {
            writeln!(
                w,
                "**Required states:** {}",
                state.required_states.join(", ")
            )?;
        }
        if !state.forbidden_states.is_empty() {
            writeln!(
                w,
                "**Forbidden states:** {}",
                state.forbidden_states.join(", ")
            )?;
        }
        if let Some(result) = &state.resulting_state {
            writeln!(w, "**Resulting state:** {result}")?;
        }
        if let Some(cond) = &state.condition {
            writeln!(w, "**Condition:** {cond}")?;
        }
        if let Some(protos) = &state.applicable_protocols {
            writeln!(w, "**Applicable protocols:** {protos}")?;
        }
        writeln!(w)
    }

    fn begin_protocol_behaviors(&mut self, w: &mut dyn Write) -> std::io::Result<()> {

        let title = "Protocol-Specific Behaviors";
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)
    }

    fn protocol_behavior(
        &mut self,
        w: &mut dyn Write,
        behavior: &ProtocolBehaviorSpec,
    ) -> std::io::Result<()> {
        writeln!(w, "**{}**", behavior.applicable_protocols)?;
        writeln!(w)?;
        writeln!(w, "{}", behavior.behavior)?;
        if let Some(flags) = &behavior.protocol_flags {
            writeln!(w)?;
            writeln!(w, "*Flags:* {flags}")?;
        }
        writeln!(w)
    }

    fn end_protocol_behaviors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_addr_families(&mut self, w: &mut dyn Write) -> std::io::Result<()> {

        let title = "Supported Address Families";
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)
    }

    fn addr_family(&mut self, w: &mut dyn Write, family: &AddrFamilySpec) -> std::io::Result<()> {
        writeln!(w, "**{} ({})**", family.family_name, family.family)?;
        writeln!(w)?;
        writeln!(w, "* **Struct size:** {} bytes", family.addr_struct_size)?;
        writeln!(
            w,
            "* **Address length:** {}-{} bytes",
            family.min_addr_len, family.max_addr_len
        )?;
        if let Some(format) = &family.addr_format {
            writeln!(w, "* **Format:** ``{format}``")?;
        }
        writeln!(
            w,
            "* **Features:** wildcard={}, multicast={}, broadcast={}",
            family.supports_wildcard, family.supports_multicast, family.supports_broadcast
        )?;
        if let Some(special) = &family.special_addresses {
            writeln!(w, "* **Special addresses:** {special}")?;
        }
        if family.port_range_max > 0 {
            writeln!(
                w,
                "* **Port range:** {}-{}",
                family.port_range_min, family.port_range_max
            )?;
        }
        writeln!(w)
    }

    fn end_addr_families(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn buffer_spec(&mut self, w: &mut dyn Write, spec: &BufferSpec) -> std::io::Result<()> {

        let title = "Buffer Specification";
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)?;

        if let Some(behaviors) = &spec.buffer_behaviors {
            writeln!(w, "**Behaviors:** {behaviors}")?;
        }
        if let Some(min) = spec.min_buffer_size {
            writeln!(w, "**Min size:** {min} bytes")?;
        }
        if let Some(max) = spec.max_buffer_size {
            writeln!(w, "**Max size:** {max} bytes")?;
        }
        if let Some(optimal) = spec.optimal_buffer_size {
            writeln!(w, "**Optimal size:** {optimal} bytes")?;
        }
        writeln!(w)
    }

    fn async_spec(&mut self, w: &mut dyn Write, spec: &AsyncSpec) -> std::io::Result<()> {

        let title = "Asynchronous Operation";
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)?;

        if let Some(modes) = &spec.supported_modes {
            writeln!(w, "**Supported modes:** {modes}")?;
        }
        if let Some(errno) = spec.nonblock_errno {
            writeln!(w, "**Non-blocking errno:** {errno}")?;
        }
        writeln!(w)
    }

    fn net_data_transfer(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w, "**Network Data Transfer:** {desc}")?;
        writeln!(w)
    }

    fn begin_capabilities(&mut self, w: &mut dyn Write) -> std::io::Result<()> {

        let title = "Required Capabilities";
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)
    }

    fn capability(&mut self, w: &mut dyn Write, cap: &CapabilitySpec) -> std::io::Result<()> {
        writeln!(w, "**{} ({})** - {}", cap.name, cap.capability, cap.action)?;
        writeln!(w)?;
        if !cap.allows.is_empty() {
            writeln!(w, "* **Allows:** {}", cap.allows)?;
        }
        if !cap.without_cap.is_empty() {
            writeln!(w, "* **Without capability:** {}", cap.without_cap)?;
        }
        if let Some(cond) = &cap.check_condition {
            writeln!(w, "* **Condition:** {}", cond)?;
        }
        writeln!(w)
    }

    fn end_capabilities(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn parameter(&mut self, w: &mut dyn Write, param: &ParamSpec) -> std::io::Result<()> {
        writeln!(
            w,
            "**[{}] {}** (*{}*)",
            param.index, param.name, param.type_name
        )?;
        writeln!(w)?;
        writeln!(w, "  {}", param.description)?;

        // Display flags
        let mut flags = Vec::new();
        if param.flags & 0x01 != 0 {
            flags.push("IN");
        }
        if param.flags & 0x02 != 0 {
            flags.push("OUT");
        }
        if param.flags & 0x04 != 0 {
            flags.push("USER");
        }
        if param.flags & 0x08 != 0 {
            flags.push("OPTIONAL");
        }
        if !flags.is_empty() {
            writeln!(w, "  :Flags: {}", flags.join(", "))?;
        }

        if let Some(constraint) = &param.constraint {
            writeln!(w, "  :Constraint: {}", constraint)?;
        }

        if let (Some(min), Some(max)) = (param.min_value, param.max_value) {
            writeln!(w, "  :Range: {} to {}", min, max)?;
        }

        writeln!(w)
    }

    fn return_spec(&mut self, w: &mut dyn Write, ret: &ReturnSpec) -> std::io::Result<()> {
        writeln!(w, "\nReturn Value")?;
        writeln!(w, "{}\n", Self::section_char(1).to_string().repeat(12))?;
        writeln!(w)?;
        writeln!(w, ":Type: {}", ret.type_name)?;
        writeln!(w, ":Description: {}", ret.description)?;
        if let Some(success) = ret.success_value {
            writeln!(w, ":Success value: {}", success)?;
        }
        writeln!(w)
    }

    fn error(&mut self, w: &mut dyn Write, error: &ErrorSpec) -> std::io::Result<()> {
        writeln!(w, "**{}** ({})", error.name, error.error_code)?;
        writeln!(w)?;
        writeln!(w, "  :Condition: {}", error.condition)?;
        if !error.description.is_empty() {
            writeln!(w, "  :Description: {}", error.description)?;
        }
        writeln!(w)
    }

    fn begin_signals(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {

        let title = format!("Signals ({count})");
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)
    }

    fn signal(&mut self, w: &mut dyn Write, signal: &SignalSpec) -> std::io::Result<()> {
        write!(w, "* **{}**", signal.signal_name)?;
        if signal.signal_num != 0 {
            write!(w, " ({})", signal.signal_num)?;
        }
        writeln!(w)?;

        // Direction (bitmask matching C enum kapi_signal_direction)
        let mut dirs = Vec::new();
        if signal.direction & 1 != 0 { dirs.push("receive"); }
        if signal.direction & 2 != 0 { dirs.push("send"); }
        if signal.direction & 4 != 0 { dirs.push("handle"); }
        if signal.direction & 8 != 0 { dirs.push("block"); }
        if signal.direction & 16 != 0 { dirs.push("ignore"); }
        let direction = if dirs.is_empty() { "unknown".to_string() } else { dirs.join(", ") };
        writeln!(w, "  :Direction: {}", direction)?;

        // Action (matching C enum kapi_signal_action)
        let action = match signal.action {
            0 => "default",
            1 => "terminate",
            2 => "coredump",
            3 => "stop",
            4 => "continue",
            5 => "custom",
            6 => "return",
            7 => "restart",
            8 => "queue",
            9 => "discard",
            10 => "transform",
            _ => "unknown",
        };
        writeln!(w, "  :Action: {}", action)?;

        if let Some(cond) = &signal.condition {
            writeln!(w, "  :Condition: {}", cond)?;
        }
        if let Some(desc) = &signal.description {
            writeln!(w, "  :Description: {}", desc)?;
        }
        if signal.interruptible {
            writeln!(w, "  :Interruptible: yes")?;
        }
        if signal.restartable {
            writeln!(w, "  :Restartable: yes")?;
        }
        writeln!(w)
    }

    fn end_signals(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_signal_masks(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {

        let title = format!("Signal Masks ({count})");
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)
    }

    fn signal_mask(&mut self, w: &mut dyn Write, mask: &SignalMaskSpec) -> std::io::Result<()> {
        writeln!(w, "* **{}**", mask.name)?;
        if !mask.description.is_empty() {
            writeln!(w, "  {}", mask.description)?;
        }
        writeln!(w)
    }

    fn end_signal_masks(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_side_effects(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {

        let title = format!("Side Effects ({count})");
        writeln!(w, "{}\n", title)?;
        writeln!(
            w,
            "{}\n",
            Self::section_char(1).to_string().repeat(title.len())
        )
    }

    fn side_effect(&mut self, w: &mut dyn Write, effect: &SideEffectSpec) -> std::io::Result<()> {
        write!(w, "* **{}**", effect.target)?;
        if effect.reversible {
            write!(w, " *(reversible)*")?;
        }
        writeln!(w)?;
        writeln!(w, "  {}", effect.description)?;
        if let Some(cond) = &effect.condition {
            writeln!(w, "  :Condition: {}", cond)?;
        }
        writeln!(w)
    }

    fn end_side_effects(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_state_transitions(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {

        let title = format!("State Transitions ({count})");
        writeln!(w, "{}\n", title)?;
        writeln!(
            w,
            "{}\n",
            Self::section_char(1).to_string().repeat(title.len())
        )
    }

    fn state_transition(
        &mut self,
        w: &mut dyn Write,
        trans: &StateTransitionSpec,
    ) -> std::io::Result<()> {
        writeln!(
            w,
            "* **{}**: {} → {}",
            trans.object, trans.from_state, trans.to_state
        )?;
        writeln!(w, "  {}", trans.description)?;
        if let Some(cond) = &trans.condition {
            writeln!(w, "  :Condition: {}", cond)?;
        }
        writeln!(w)
    }

    fn end_state_transitions(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_constraints(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {

        let title = format!("Constraints ({count})");
        writeln!(w, "{title}")?;
        writeln!(
            w,
            "{}",
            Self::section_char(1).to_string().repeat(title.len())
        )?;
        writeln!(w)
    }

    fn constraint(
        &mut self,
        w: &mut dyn Write,
        constraint: &ConstraintSpec,
    ) -> std::io::Result<()> {
        writeln!(w, "* **{}**", constraint.name)?;
        if !constraint.description.is_empty() {
            writeln!(w, "  {}", constraint.description)?;
        }
        if let Some(expr) = &constraint.expression {
            writeln!(w, "  :Expression: ``{}``", expr)?;
        }
        writeln!(w)
    }

    fn end_constraints(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_locks(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {

        let title = format!("Locks ({count})");
        writeln!(w, "{}\n", title)?;
        writeln!(
            w,
            "{}\n",
            Self::section_char(1).to_string().repeat(title.len())
        )
    }

    fn lock(&mut self, w: &mut dyn Write, lock: &LockSpec) -> std::io::Result<()> {
        write!(w, "* **{}**", lock.lock_name)?;
        let lock_type_str = match lock.lock_type {
            1 => " *(mutex)*",
            2 => " *(spinlock)*",
            3 => " *(rwlock)*",
            4 => " *(semaphore)*",
            5 => " *(RCU)*",
            _ => "",
        };
        writeln!(w, "{}", lock_type_str)?;
        if !lock.description.is_empty() {
            writeln!(w, "  {}", lock.description)?;
        }
        writeln!(w)
    }

    fn end_locks(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_struct_specs(&mut self, w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        writeln!(w)?;
        writeln!(w, "Structure Specifications")?;
        writeln!(w, "~~~~~~~~~~~~~~~~~~~~~~~")?;
        writeln!(w)
    }

    fn struct_spec(&mut self, w: &mut dyn Write, spec: &crate::extractor::StructSpec) -> std::io::Result<()> {
        writeln!(w, "**{}**", spec.name)?;
        writeln!(w)?;

        if !spec.description.is_empty() {
            writeln!(w, "  {}", spec.description)?;
            writeln!(w)?;
        }

        writeln!(w, "  :Size: {} bytes", spec.size)?;
        writeln!(w, "  :Alignment: {} bytes", spec.alignment)?;
        writeln!(w, "  :Fields: {}", spec.field_count)?;
        writeln!(w)?;

        if !spec.fields.is_empty() {
            for field in &spec.fields {
                writeln!(w, "  * **{}** ({})", field.name, field.type_name)?;
                if !field.description.is_empty() {
                    writeln!(w, "    {}", field.description)?;
                }
                if field.min_value != 0 || field.max_value != 0 {
                    writeln!(w, "    Range: [{}, {}]", field.min_value, field.max_value)?;
                }
            }
            writeln!(w)?;
        }

        Ok(())
    }

    fn end_struct_specs(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extractor::{ErrorSpec, ParamSpec, ReturnSpec};

    fn render_rst(f: &mut RstFormatter, sink: &mut Vec<u8>) -> String {
        f.end_document(sink).unwrap();
        String::from_utf8(sink.clone()).unwrap()
    }

    #[test]
    fn rst_api_details_has_heading() {
        let mut f = RstFormatter::new();
        let mut sink = Vec::new();

        f.begin_document(&mut sink).unwrap();
        f.begin_api_details(&mut sink, "sys_test").unwrap();
        f.description(&mut sink, "A test syscall").unwrap();
        f.end_api_details(&mut sink).unwrap();

        let out = render_rst(&mut f, &mut sink);
        assert!(out.contains("sys_test"));
        assert!(out.contains("========"));
        assert!(out.contains("**A test syscall**"));
    }

    #[test]
    fn rst_api_list() {
        let mut f = RstFormatter::new();
        let mut sink = Vec::new();

        f.begin_document(&mut sink).unwrap();
        f.begin_api_list(&mut sink, "System Calls").unwrap();
        f.api_item(&mut sink, "sys_open", "syscall").unwrap();
        f.api_item(&mut sink, "sys_read", "syscall").unwrap();
        f.end_api_list(&mut sink).unwrap();
        f.total_specs(&mut sink, 2).unwrap();

        let out = render_rst(&mut f, &mut sink);
        assert!(out.contains("sys_open"));
        assert!(out.contains("sys_read"));
    }

    #[test]
    fn rst_parameters() {
        let mut f = RstFormatter::new();
        let mut sink = Vec::new();

        f.begin_document(&mut sink).unwrap();
        f.begin_api_details(&mut sink, "sys_write").unwrap();
        f.begin_parameters(&mut sink, 1).unwrap();
        f.parameter(
            &mut sink,
            &ParamSpec {
                index: 0,
                name: "fd".to_string(),
                type_name: "unsigned int".to_string(),
                description: "file descriptor".to_string(),
                flags: 1,
                param_type: 2,
                constraint_type: 0,
                constraint: None,
                min_value: None,
                max_value: None,
                valid_mask: None,
                enum_values: vec![],
                size: None,
                alignment: None,
            },
        )
        .unwrap();
        f.end_parameters(&mut sink).unwrap();
        f.end_api_details(&mut sink).unwrap();

        let out = render_rst(&mut f, &mut sink);
        assert!(out.contains("**[0] fd**"));
        assert!(out.contains("unsigned int"));
        assert!(out.contains("file descriptor"));
    }

    #[test]
    fn rst_errors() {
        let mut f = RstFormatter::new();
        let mut sink = Vec::new();

        f.begin_document(&mut sink).unwrap();
        f.begin_api_details(&mut sink, "sys_test").unwrap();
        f.begin_errors(&mut sink, 1).unwrap();
        f.error(
            &mut sink,
            &ErrorSpec {
                error_code: -2,
                name: "ENOENT".to_string(),
                condition: "File not found".to_string(),
                description: "The file does not exist".to_string(),
            },
        )
        .unwrap();
        f.end_errors(&mut sink).unwrap();
        f.end_api_details(&mut sink).unwrap();

        let out = render_rst(&mut f, &mut sink);
        assert!(out.contains("**ENOENT**"));
        assert!(out.contains("-2"));
        assert!(out.contains("File not found"));
    }

    #[test]
    fn rst_return_spec() {
        let mut f = RstFormatter::new();
        let mut sink = Vec::new();

        f.begin_document(&mut sink).unwrap();
        f.begin_api_details(&mut sink, "sys_test").unwrap();
        f.return_spec(
            &mut sink,
            &ReturnSpec {
                type_name: "KAPI_TYPE_INT".to_string(),
                description: "Returns 0 on success".to_string(),
                return_type: 1,
                check_type: 0,
                success_value: Some(0),
                success_min: None,
                success_max: None,
                error_values: vec![],
            },
        )
        .unwrap();
        f.end_api_details(&mut sink).unwrap();

        let out = render_rst(&mut f, &mut sink);
        assert!(out.contains("KAPI_TYPE_INT"));
        assert!(out.contains("Returns 0 on success"));
        assert!(out.contains("Return Value"));
    }

    #[test]
    fn rst_context_flags() {
        let mut f = RstFormatter::new();
        let mut sink = Vec::new();

        f.begin_document(&mut sink).unwrap();
        f.begin_api_details(&mut sink, "sys_test").unwrap();
        f.begin_context_flags(&mut sink).unwrap();
        f.context_flag(&mut sink, "KAPI_CTX_PROCESS").unwrap();
        f.context_flag(&mut sink, "KAPI_CTX_SLEEPABLE").unwrap();
        f.end_context_flags(&mut sink).unwrap();
        f.end_api_details(&mut sink).unwrap();

        let out = render_rst(&mut f, &mut sink);
        assert!(out.contains("KAPI_CTX_PROCESS"));
        assert!(out.contains("KAPI_CTX_SLEEPABLE"));
        assert!(out.contains("Execution Context"));
    }
}
