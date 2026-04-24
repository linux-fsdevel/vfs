// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use super::{
    ApiExtractor, ApiSpec, CapabilitySpec, ConstraintSpec, ErrorSpec, LockSpec, ParamSpec,
    ReturnSpec, SideEffectSpec, SignalMaskSpec, SignalSpec, StateTransitionSpec, StructFieldSpec,
    StructSpec,
};
use crate::formatter::OutputFormatter;
use anyhow::{Context, Result};
use goblin::elf::Elf;
use std::fs;
use std::io::Write;

mod binary_utils;
mod magic_finder;
use binary_utils::{
    signal_mask_spec_layout_size, sizes, struct_field_layout_size, DataReader, Endian,
};

// Helper to convert empty strings to None
fn opt_string(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

pub struct VmlinuxExtractor {
    vmlinux: Vec<u8>,
    specs: Vec<KapiSpec>,
    endian: Endian,
    is_64bit: bool,
}

#[derive(Debug)]
struct KapiSpec {
    name: String,
    api_type: String,
    /// File offset in the vmlinux buffer where this spec's
    /// `struct kernel_api_spec` begins.
    file_offset: usize,
}

impl VmlinuxExtractor {
    pub fn new(vmlinux_path: &str) -> Result<Self> {
        let vmlinux = fs::read(vmlinux_path)
            .with_context(|| format!("Failed to read vmlinux file: {vmlinux_path}"))?;

        let elf = Elf::parse(&vmlinux).context("Failed to parse ELF file")?;
        let endian = if elf.little_endian {
            Endian::Little
        } else {
            Endian::Big
        };
        let is_64bit = elf.is_64;

        // Locate the .kapi_specs section boundaries.
        let mut start_addr = None;
        let mut stop_addr = None;
        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                match name {
                    "__start_kapi_specs" => start_addr = Some(sym.st_value),
                    "__stop_kapi_specs" => stop_addr = Some(sym.st_value),
                    _ => {}
                }
            }
        }
        let start = start_addr.context("Could not find __start_kapi_specs symbol")?;
        let stop = stop_addr.context("Could not find __stop_kapi_specs symbol")?;
        if stop <= start {
            anyhow::bail!("No kernel API specifications found in vmlinux");
        }

        // `.kapi_specs` is a tightly-packed array of `struct kernel_api_spec *`
        // pointers; walk them to find each real spec's vaddr, then resolve to
        // a file offset inside `vmlinux`. Pointer width tracks the target
        // (4 bytes for 32-bit, 8 bytes for 64-bit).
        let ptr_size = if is_64bit { 8usize } else { 4 };
        let ptr_count = ((stop - start) as usize) / ptr_size;
        let ptr_file_off =
            vaddr_to_file_offset(&elf, start).context("Could not locate .kapi_specs in file")?;

        let read_ptr = |raw: &[u8]| -> u64 {
            match (endian, is_64bit) {
                (Endian::Little, true) => u64::from_le_bytes(raw.try_into().unwrap()),
                (Endian::Big, true) => u64::from_be_bytes(raw.try_into().unwrap()),
                (Endian::Little, false) => u32::from_le_bytes(raw.try_into().unwrap()) as u64,
                (Endian::Big, false) => u32::from_be_bytes(raw.try_into().unwrap()) as u64,
            }
        };

        let mut specs = Vec::with_capacity(ptr_count);
        for i in 0..ptr_count {
            let p = ptr_file_off + i * ptr_size;
            if p + ptr_size > vmlinux.len() {
                break;
            }
            let spec_vaddr = read_ptr(&vmlinux[p..p + ptr_size]);
            if spec_vaddr == 0 {
                continue;
            }
            let Some(spec_file_off) = vaddr_to_file_offset(&elf, spec_vaddr) else {
                continue;
            };
            // The first field of `struct kernel_api_spec` is `const char *name`.
            if spec_file_off + ptr_size > vmlinux.len() {
                continue;
            }
            let name_vaddr = read_ptr(&vmlinux[spec_file_off..spec_file_off + ptr_size]);
            let name =
                binary_utils::resolve_vaddr_string(&elf, &vmlinux, name_vaddr).unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let api_type = if name.starts_with("sys_") {
                "syscall"
            } else if name.ends_with("_ioctl") {
                "ioctl"
            } else {
                "function"
            }
            .to_string();
            specs.push(KapiSpec {
                name,
                api_type,
                file_offset: spec_file_off,
            });
        }

        Ok(VmlinuxExtractor {
            vmlinux,
            specs,
            endian,
            is_64bit,
        })
    }
}

/// Map a virtual address to a file offset inside the raw vmlinux bytes.
fn vaddr_to_file_offset(elf: &Elf, vaddr: u64) -> Option<usize> {
    for sh in &elf.section_headers {
        let start = sh.sh_addr;
        let end = start.checked_add(sh.sh_size)?;
        if vaddr >= start && vaddr < end {
            if sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
                return None;
            }
            return Some((sh.sh_offset + (vaddr - start)) as usize);
        }
    }
    None
}

impl VmlinuxExtractor {
    fn parse_at(&self, file_offset: usize) -> Result<ApiSpec> {
        parse_binary_to_api_spec(&self.vmlinux, file_offset, self.endian, self.is_64bit)
    }
}

impl ApiExtractor for VmlinuxExtractor {
    fn extract_all(&self) -> Result<Vec<ApiSpec>> {
        Ok(self
            .specs
            .iter()
            .map(|spec| {
                self.parse_at(spec.file_offset).unwrap_or_else(|_| ApiSpec {
                    name: spec.name.clone(),
                    api_type: spec.api_type.clone(),
                    ..Default::default()
                })
            })
            .collect())
    }

    fn extract_by_name(&self, api_name: &str) -> Result<Option<ApiSpec>> {
        if let Some(spec) = self.specs.iter().find(|s| s.name == api_name) {
            Ok(Some(self.parse_at(spec.file_offset)?))
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
        if let Some(spec) = self.specs.iter().find(|s| s.name == api_name) {
            let api_spec = self.parse_at(spec.file_offset)?;
            super::display_api_spec(&api_spec, formatter, writer)?;
        }
        Ok(())
    }
}

/// Helper to read count and parse array items with optional magic offset
fn parse_array_with_magic<T, F>(
    reader: &mut DataReader,
    magic_offset: Option<usize>,
    max_items: u32,
    parse_fn: F,
) -> Vec<T>
where
    F: Fn(&mut DataReader, usize) -> Option<T>,
{
    // Read count - position at magic+4 if magic offset exists
    let count = if let Some(offset) = magic_offset {
        reader.pos = offset + 4;
        reader.read_u32()
    } else {
        reader.read_u32()
    };

    let mut items = Vec::new();
    if let Some(count) = count {
        // Position at start of array data if magic offset exists
        if let Some(offset) = magic_offset {
            reader.pos = offset + 8; // +4 for magic, +4 for count
        }
        // Parse items up to max_items. Each element-parse is followed
        // by align_to(ptr_size) so the next element starts on the
        // struct's natural alignment boundary (kernel structs are no
        // longer __packed, so the compiler may insert trailing
        // padding after bools / u8 fields).
        let align = reader.ptr_size();
        for i in 0..count.min(max_items) as usize {
            if let Some(item) = parse_fn(reader, i) {
                items.push(item);
            }
            reader.align_to(align);
        }
    }
    items
}

fn parse_binary_to_api_spec(
    data: &[u8],
    offset: usize,
    endian: Endian,
    is_64bit: bool,
) -> Result<ApiSpec> {
    let elf = Elf::parse(data).context("Failed to re-parse ELF for string resolution")?;
    let resolver = binary_utils::StringResolver {
        elf: &elf,
        vmlinux: data,
    };
    let mut reader = DataReader::new(data, offset, endian, is_64bit).with_resolver(resolver);

    // Bound magic-marker search to roughly sizeof(struct kernel_api_spec).
    // The packed-const-char-pointer layout is ~25 KB per spec; 32 KB gives
    // headroom without letting the finder leak into the next spec (or
    // unrelated rodata) and pick up stray magic markers.
    let search_end = (offset + 0x8000).min(data.len());
    let spec_data = &data[offset..search_end];
    let magic_offsets = magic_finder::MagicOffsets::find_in_data(spec_data, offset, endian);

    // Read fields in exact order of struct kernel_api_spec.
    // Every string field is a `const char *` pointer resolved via the
    // StringResolver attached to the DataReader.
    let name = reader
        .read_optional_string(sizes::NAME)
        .ok_or_else(|| anyhow::anyhow!("Failed to read API name"))?;

    // Determine API type
    let api_type = if name.starts_with("sys_") {
        "syscall"
    } else if name.ends_with("_ioctl") {
        "ioctl"
    } else if name.contains("sysfs") {
        "sysfs"
    } else {
        "function"
    }
    .to_string();

    // Read version (u32)
    let version = reader.read_u32().map(|v| v.to_string());

    // Read description (512 bytes)
    let description = reader
        .read_optional_string(sizes::DESC)
        .filter(|s| !s.is_empty());

    // Read long_description (2048 bytes)
    let long_description = reader
        .read_optional_string(sizes::DESC)
        .filter(|s| !s.is_empty());

    // Read context_flags (u32)
    let context_flags = parse_context_flags(&mut reader);

    // Parse params array
    let parameters = parse_array_with_magic(
        &mut reader,
        magic_offsets.param_offset,
        sizes::MAX_PARAMS as u32,
        parse_param,
    );

    // Read return_spec - position using magic offset if available
    if let Some(offset) = magic_offsets.return_offset {
        reader.pos = offset + 4; // skip past the return_magic u32
    }
    let return_spec = parse_return_spec(&mut reader);

    // Parse errors array
    let errors = parse_array_with_magic(
        &mut reader,
        magic_offsets.error_offset,
        sizes::MAX_ERRORS as u32,
        |r, _| parse_error(r),
    );

    // Parse locks array
    let locks = parse_array_with_magic(
        &mut reader,
        magic_offsets.lock_offset,
        sizes::MAX_LOCKS as u32,
        |r, _| parse_lock(r),
    );

    // Parse constraints array
    let constraints = parse_array_with_magic(
        &mut reader,
        magic_offsets.constraint_offset,
        sizes::MAX_CONSTRAINTS as u32,
        |r, _| parse_constraint(r),
    );

    // Read examples and notes - position reader at info section if magic found
    let (examples, notes) = if let Some(info_offset) = magic_offsets.info_offset {
        reader.pos = info_offset + 4; // +4 to skip magic
        let examples = reader
            .read_optional_string(sizes::DESC)
            .filter(|s| !s.is_empty());
        let notes = reader
            .read_optional_string(sizes::DESC)
            .filter(|s| !s.is_empty());
        (examples, notes)
    } else {
        let examples = reader
            .read_optional_string(sizes::DESC)
            .filter(|s| !s.is_empty());
        let notes = reader
            .read_optional_string(sizes::DESC)
            .filter(|s| !s.is_empty());
        (examples, notes)
    };

    // Parse signals array
    let signals = parse_array_with_magic(
        &mut reader,
        magic_offsets.signal_offset,
        sizes::MAX_SIGNALS as u32,
        |r, _| parse_signal(r),
    );

    // Read signal_mask_count (u32)
    let signal_mask_count = reader.read_u32();

    // Parse signal_masks array
    let mut signal_masks = Vec::new();
    if let Some(count) = signal_mask_count {
        for i in 0..sizes::MAX_SIGNALS {
            if i < count as usize {
                if let Some(mask) = parse_signal_mask(&mut reader) {
                    signal_masks.push(mask);
                }
            } else {
                reader.skip(signal_mask_spec_layout_size());
            }
        }
    } else {
        reader.skip(signal_mask_spec_layout_size() * sizes::MAX_SIGNALS);
    }

    // Parse struct_specs array
    let struct_specs = parse_array_with_magic(
        &mut reader,
        magic_offsets.struct_offset,
        sizes::MAX_STRUCT_SPECS as u32,
        |r, _| parse_struct_spec(r),
    );

    // According to the C struct, the order is:
    // side_effect_count, side_effects array, state_trans_count, state_transitions array,
    // capability_count, capabilities array

    // Parse side_effects array
    let side_effects = parse_array_with_magic(
        &mut reader,
        magic_offsets.effect_offset,
        sizes::MAX_SIDE_EFFECTS as u32,
        |r, _| parse_side_effect(r),
    );

    // Parse state_transitions array
    let state_transitions = parse_array_with_magic(
        &mut reader,
        magic_offsets.trans_offset,
        sizes::MAX_STATE_TRANS as u32,
        |r, _| parse_state_transition(r),
    );

    // Parse capabilities array
    let capabilities = parse_array_with_magic(
        &mut reader,
        magic_offsets.cap_offset,
        sizes::MAX_CAPABILITIES as u32,
        |r, _| parse_capability(r),
    );

    Ok(ApiSpec {
        name,
        api_type,
        description,
        long_description,
        version,
        context_flags,
        param_count: if parameters.is_empty() {
            None
        } else {
            Some(parameters.len() as u32)
        },
        error_count: if errors.is_empty() {
            None
        } else {
            Some(errors.len() as u32)
        },
        examples,
        notes,
        subsystem: None,
        sysfs_path: None,
        permissions: None,
        capabilities,
        parameters,
        return_spec,
        errors,
        signals,
        signal_masks,
        side_effects,
        state_transitions,
        constraints,
        locks,
        struct_specs,
    })
}

// Helper parsing functions

fn parse_context_flags(reader: &mut DataReader) -> Vec<String> {
    const KAPI_CTX_PROCESS: u32 = 1 << 0;
    const KAPI_CTX_SOFTIRQ: u32 = 1 << 1;
    const KAPI_CTX_HARDIRQ: u32 = 1 << 2;
    const KAPI_CTX_NMI: u32 = 1 << 3;
    const KAPI_CTX_ATOMIC: u32 = 1 << 4;
    const KAPI_CTX_SLEEPABLE: u32 = 1 << 5;
    const KAPI_CTX_PREEMPT_DISABLED: u32 = 1 << 6;
    const KAPI_CTX_IRQ_DISABLED: u32 = 1 << 7;

    if let Some(flags) = reader.read_u32() {
        let mut parts = Vec::new();

        if flags & KAPI_CTX_PROCESS != 0 {
            parts.push("KAPI_CTX_PROCESS");
        }
        if flags & KAPI_CTX_SOFTIRQ != 0 {
            parts.push("KAPI_CTX_SOFTIRQ");
        }
        if flags & KAPI_CTX_HARDIRQ != 0 {
            parts.push("KAPI_CTX_HARDIRQ");
        }
        if flags & KAPI_CTX_NMI != 0 {
            parts.push("KAPI_CTX_NMI");
        }
        if flags & KAPI_CTX_ATOMIC != 0 {
            parts.push("KAPI_CTX_ATOMIC");
        }
        if flags & KAPI_CTX_SLEEPABLE != 0 {
            parts.push("KAPI_CTX_SLEEPABLE");
        }
        if flags & KAPI_CTX_PREEMPT_DISABLED != 0 {
            parts.push("KAPI_CTX_PREEMPT_DISABLED");
        }
        if flags & KAPI_CTX_IRQ_DISABLED != 0 {
            parts.push("KAPI_CTX_IRQ_DISABLED");
        }

        parts.into_iter().map(|s| s.to_string()).collect()
    } else {
        vec![]
    }
}

fn parse_param(reader: &mut DataReader, index: usize) -> Option<ParamSpec> {
    let name = reader.read_optional_string(sizes::NAME)?;
    let type_name = reader.read_optional_string(sizes::NAME)?;
    let param_type = reader.read_u32()?;
    let flags = reader.read_u32()?;
    let size = reader.read_usize()?;
    let alignment = reader.read_usize()?;
    let min_value = reader.read_i64()?;
    let max_value = reader.read_i64()?;
    let valid_mask = reader.read_u64()?;

    // Skip enum_values pointer (8 bytes)
    reader.skip(8);
    let _enum_count = reader.read_u32()?; // Must use ? to propagate errors
    let constraint_type = reader.read_u32()?;
    // Skip validate function pointer (8 bytes)
    reader.skip(8);

    let description = reader.read_string_or_default(sizes::DESC);
    let constraint = reader.read_optional_string(sizes::DESC);
    let size_param_idx_raw = reader.read_i32()?; // Must use ? to propagate errors
    let _size_multiplier = reader.read_usize()?; // Must use ? to propagate errors

    // In the C struct, size_param_idx is stored 1-based; 0 means
    // "no size-carrying param". Surface the real (0-based) index as
    // `Option<u32>`.
    let size_param_idx = if size_param_idx_raw > 0 {
        Some((size_param_idx_raw - 1) as u32)
    } else {
        None
    };

    Some(ParamSpec {
        index: index as u32,
        name,
        type_name,
        description,
        flags,
        param_type,
        constraint_type,
        constraint,
        min_value: Some(min_value),
        max_value: Some(max_value),
        valid_mask: Some(valid_mask),
        enum_values: vec![],
        size: Some(size as u32),
        alignment: Some(alignment as u32),
        size_param_idx,
    })
}

fn parse_return_spec(reader: &mut DataReader) -> Option<ReturnSpec> {
    // Read type_name, but treat empty as valid (will be empty string)
    let type_name = reader.read_string_or_default(sizes::NAME);

    // Read return_type and check_type
    let return_type = reader.read_u32().unwrap_or(0);
    let check_type = reader.read_u32().unwrap_or(0);
    let success_value = reader.read_i64().unwrap_or(0);
    let success_min = reader.read_i64().unwrap_or(0);
    let success_max = reader.read_i64().unwrap_or(0);

    // Skip error_values pointer (8 bytes)
    reader.skip(8);
    let _error_count = reader.read_u32().unwrap_or(0); // Don't fail on return spec
                                                       // Skip is_success function pointer (8 bytes)
    reader.skip(8);

    let description = reader.read_string_or_default(sizes::DESC);

    // Return a spec even if type_name is empty, as long as we have some data
    // The type_name might be a string like "KAPI_TYPE_INT" that gets stored literally
    if type_name.is_empty() && return_type == 0 && check_type == 0 && success_value == 0 {
        // No return spec at all
        return None;
    }

    Some(ReturnSpec {
        type_name,
        description,
        return_type,
        check_type,
        success_value: Some(success_value),
        success_min: Some(success_min),
        success_max: Some(success_max),
        error_values: vec![],
    })
}

fn parse_error(reader: &mut DataReader) -> Option<ErrorSpec> {
    let error_code = reader.read_i32()?;
    let name = reader.read_optional_string(sizes::NAME)?;
    let condition = reader.read_string_or_default(sizes::DESC);
    let description = reader.read_string_or_default(sizes::DESC);

    Some(ErrorSpec {
        error_code,
        name,
        condition,
        description,
    })
}

fn parse_lock(reader: &mut DataReader) -> Option<LockSpec> {
    let lock_name = reader.read_optional_string(sizes::NAME)?;
    let lock_type = reader.read_u32()?;
    let scope = reader.read_u32()?;
    let description = reader.read_string_or_default(sizes::DESC);

    Some(LockSpec {
        lock_name,
        lock_type,
        scope,
        description,
    })
}

fn parse_constraint(reader: &mut DataReader) -> Option<ConstraintSpec> {
    let name = reader.read_optional_string(sizes::NAME)?;
    let description = reader.read_string_or_default(sizes::DESC);
    let expression = reader.read_string_or_default(sizes::DESC);

    // No function pointer in packed struct

    Some(ConstraintSpec {
        name,
        description,
        expression: opt_string(expression),
    })
}

fn parse_signal(reader: &mut DataReader) -> Option<SignalSpec> {
    // Matches `struct kapi_signal_spec`. All string fields are pointers.
    let signal_num = reader.read_i32()?;
    let signal_name = reader.read_optional_string(sizes::NAME).unwrap_or_default();
    let direction = reader.read_u32()?;
    let action = reader.read_u32()?;
    let target = reader.read_optional_string(sizes::DESC);
    let condition = reader.read_optional_string(sizes::DESC);
    let description = reader.read_optional_string(sizes::DESC);
    let restartable = reader.read_bool()?;
    let sa_flags_required = reader.read_u32()?;
    let sa_flags_forbidden = reader.read_u32()?;
    let error_on_signal = reader.read_i32()?;
    let transform_to = reader.read_i32()?;
    // Read the symbolic timing token (const char *) and map it to the
    // numeric timing code used by downstream consumers.
    let timing_str = reader.read_optional_string(sizes::NAME).unwrap_or_default();
    let timing = match timing_str.as_str() {
        "KAPI_SIGNAL_TIME_BEFORE" | "before" => 0u32,
        "KAPI_SIGNAL_TIME_DURING" | "during" => 1,
        "KAPI_SIGNAL_TIME_AFTER" | "after" => 2,
        _ => 0,
    };
    let priority = reader.read_u8()?;
    let interruptible = reader.read_bool()?;
    let queue_behavior = reader.read_optional_string(sizes::NAME);
    let state_required = reader.read_u32()?;
    let state_forbidden = reader.read_u32()?;

    Some(SignalSpec {
        signal_num,
        signal_name,
        direction,
        action,
        target,
        condition,
        description,
        timing,
        priority: priority as u32,
        restartable,
        interruptible,
        queue: queue_behavior,
        sa_flags: 0, // Not a field of struct kapi_signal_spec
        sa_flags_required,
        sa_flags_forbidden,
        state_required,
        state_forbidden,
        // `error_on_signal` of 0 means "no errno returned"; surface
        // that as None to match the source-parser convention.
        error_on_signal: if error_on_signal != 0 {
            Some(error_on_signal)
        } else {
            None
        },
        transform_to: if transform_to != 0 {
            // The compiled struct holds the numeric value; the C
            // preprocessor already resolved any signal symbol.
            Some(transform_to)
        } else {
            None
        },
    })
}

fn parse_signal_mask(reader: &mut DataReader) -> Option<SignalMaskSpec> {
    let name = reader.read_optional_string(sizes::NAME)?;
    let description = reader.read_string_or_default(sizes::DESC);

    // Skip signals array
    for _ in 0..sizes::MAX_SIGNALS {
        reader.read_i32();
    }

    let _signal_count = reader.read_u32()?;

    Some(SignalMaskSpec { name, description })
}

fn parse_struct_field(reader: &mut DataReader) -> Option<StructFieldSpec> {
    let name = reader.read_optional_string(sizes::NAME)?;
    let field_type = reader.read_u32()?;
    let type_name = reader.read_optional_string(sizes::NAME)?;
    let offset = reader.read_usize()?;
    let size = reader.read_usize()?;
    let flags = reader.read_u32()?;
    let constraint_type = reader.read_u32()?;
    let min_value = reader.read_i64()?;
    let max_value = reader.read_i64()?;
    let valid_mask = reader.read_u64()?;
    // Skip enum_values field (512 bytes)
    let _enum_values = reader.read_optional_string(sizes::DESC); // Don't fail on optional field
    let description = reader.read_string_or_default(sizes::DESC);

    Some(StructFieldSpec {
        name,
        field_type,
        type_name,
        offset,
        size,
        flags,
        constraint_type,
        min_value,
        max_value,
        valid_mask,
        description,
    })
}

fn parse_struct_spec(reader: &mut DataReader) -> Option<StructSpec> {
    let name = reader.read_optional_string(sizes::NAME)?;
    let size = reader.read_usize()?;
    let alignment = reader.read_usize()?;
    let field_count = reader.read_u32()?;

    // Parse fields array
    let mut fields = Vec::new();
    for _ in 0..field_count.min(sizes::MAX_PARAMS as u32) {
        if let Some(field) = parse_struct_field(reader) {
            fields.push(field);
        } else {
            // Skip this field if we can't parse it
            reader.skip(struct_field_layout_size());
        }
    }

    // Skip remaining fields if any
    let remaining = sizes::MAX_PARAMS as u32 - field_count.min(sizes::MAX_PARAMS as u32);
    for _ in 0..remaining {
        reader.skip(struct_field_layout_size());
    }

    let description = reader.read_string_or_default(sizes::DESC);

    Some(StructSpec {
        name,
        size,
        alignment,
        field_count,
        fields,
        description,
    })
}

fn parse_side_effect(reader: &mut DataReader) -> Option<SideEffectSpec> {
    let effect_type = reader.read_u32()?;
    let target = reader.read_optional_string(sizes::NAME)?;
    let condition = reader.read_string_or_default(sizes::DESC);
    let description = reader.read_string_or_default(sizes::DESC);
    let reversible = reader.read_bool()?;
    // No padding needed for packed struct

    Some(SideEffectSpec {
        effect_type,
        target,
        condition: opt_string(condition),
        description,
        reversible,
    })
}

fn parse_state_transition(reader: &mut DataReader) -> Option<StateTransitionSpec> {
    let from_state = reader.read_optional_string(sizes::NAME)?;
    let to_state = reader.read_optional_string(sizes::NAME)?;
    let condition = reader.read_string_or_default(sizes::DESC);
    let object = reader.read_optional_string(sizes::NAME)?;
    let description = reader.read_string_or_default(sizes::DESC);

    Some(StateTransitionSpec {
        object,
        from_state,
        to_state,
        condition: opt_string(condition),
        description,
    })
}

fn parse_capability(reader: &mut DataReader) -> Option<CapabilitySpec> {
    // Struct layout matches `struct kapi_capability_spec`:
    //   int capability; const char *cap_name; enum action;
    //   const char *allows; const char *without_cap;
    //   const char *check_condition; u8 priority;
    //   int alternative[KAPI_MAX_CAPABILITIES]; u32 alternative_count;
    let capability = reader.read_i32()?;
    let cap_name = reader.read_optional_string(sizes::NAME)?;
    let action = reader.read_u32()?;
    let allows = reader.read_string_or_default(sizes::DESC);
    let without_cap = reader.read_string_or_default(sizes::DESC);
    let check_condition = reader.read_optional_string(sizes::DESC);
    let priority = reader.read_u8()?;

    let mut alternatives = Vec::new();
    for _ in 0..sizes::MAX_CAPABILITIES {
        if let Some(alt) = reader.read_i32() {
            if alt != 0 {
                alternatives.push(alt);
            }
        }
    }

    let _alternative_count = reader.read_u32()?;

    Some(CapabilitySpec {
        capability,
        name: cap_name,
        action: capability_action_to_string(action),
        allows,
        without_cap,
        check_condition,
        priority: Some(priority),
        alternatives,
    })
}

/// Map the `enum kapi_capability_action` numeric value to its symbolic
/// spelling, matching `include/linux/kernel_api_spec.h`.
fn capability_action_to_string(n: u32) -> String {
    match n {
        0 => "KAPI_CAP_BYPASS_CHECK",
        1 => "KAPI_CAP_INCREASE_LIMIT",
        2 => "KAPI_CAP_OVERRIDE_RESTRICTION",
        3 => "KAPI_CAP_GRANT_PERMISSION",
        4 => "KAPI_CAP_MODIFY_BEHAVIOR",
        5 => "KAPI_CAP_ACCESS_RESOURCE",
        6 => "KAPI_CAP_PERFORM_OPERATION",
        _ => return n.to_string(),
    }
    .to_string()
}
