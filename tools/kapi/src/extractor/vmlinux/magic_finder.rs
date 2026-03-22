// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

use super::binary_utils::Endian;

// Magic markers for each section
pub const MAGIC_PARAM: u32 = 0x4B415031;    // 'KAP1'
pub const MAGIC_RETURN: u32 = 0x4B415232;   // 'KAR2'
pub const MAGIC_ERROR: u32 = 0x4B414533;    // 'KAE3'
pub const MAGIC_LOCK: u32 = 0x4B414C34;     // 'KAL4'
pub const MAGIC_CONSTRAINT: u32 = 0x4B414335; // 'KAC5'
pub const MAGIC_INFO: u32 = 0x4B414936;     // 'KAI6'
pub const MAGIC_SIGNAL: u32 = 0x4B415337;   // 'KAS7'
pub const MAGIC_SIGMASK: u32 = 0x4B414D38;  // 'KAM8'
pub const MAGIC_STRUCT: u32 = 0x4B415439;   // 'KAT9'
pub const MAGIC_EFFECT: u32 = 0x4B414641;   // 'KAFA'
pub const MAGIC_TRANS: u32 = 0x4B415442;    // 'KATB'
pub const MAGIC_CAP: u32 = 0x4B414343;      // 'KACC'

fn read_u32_endian(bytes: &[u8], endian: Endian) -> u32 {
    let b = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match endian {
        Endian::Little => u32::from_le_bytes(b),
        Endian::Big => u32::from_be_bytes(b),
    }
}

pub struct MagicOffsets {
    pub param_offset: Option<usize>,
    pub return_offset: Option<usize>,
    pub error_offset: Option<usize>,
    pub lock_offset: Option<usize>,
    pub constraint_offset: Option<usize>,
    pub info_offset: Option<usize>,
    pub signal_offset: Option<usize>,
    pub sigmask_offset: Option<usize>,
    pub struct_offset: Option<usize>,
    pub effect_offset: Option<usize>,
    pub trans_offset: Option<usize>,
    pub cap_offset: Option<usize>,
}

impl MagicOffsets {
    /// Find magic markers in the provided data slice
    /// data: slice of data to search (typically one spec's worth)
    /// base_offset: absolute offset where this slice starts in the full buffer
    pub fn find_in_data(data: &[u8], base_offset: usize, endian: Endian) -> Self {
        let mut offsets = MagicOffsets {
            param_offset: None,
            return_offset: None,
            error_offset: None,
            lock_offset: None,
            constraint_offset: None,
            info_offset: None,
            signal_offset: None,
            sigmask_offset: None,
            struct_offset: None,
            effect_offset: None,
            trans_offset: None,
            cap_offset: None,
        };

        // Scan through data looking for magic markers
        // Only find the first occurrence of each magic to avoid cross-spec contamination
        let mut i = 0;
        while i + 4 <= data.len() {
            let bytes = &data[i..i + 4];
            let value = read_u32_endian(bytes, endian);

            match value {
                MAGIC_PARAM if offsets.param_offset.is_none() => {
                    offsets.param_offset = Some(base_offset + i);
                },
                MAGIC_RETURN if offsets.return_offset.is_none() => {
                    offsets.return_offset = Some(base_offset + i);
                },
                MAGIC_ERROR if offsets.error_offset.is_none() => {
                    offsets.error_offset = Some(base_offset + i);
                },
                MAGIC_LOCK if offsets.lock_offset.is_none() => {
                    offsets.lock_offset = Some(base_offset + i);
                },
                MAGIC_CONSTRAINT if offsets.constraint_offset.is_none() => {
                    offsets.constraint_offset = Some(base_offset + i);
                },
                MAGIC_INFO if offsets.info_offset.is_none() => {
                    offsets.info_offset = Some(base_offset + i);
                },
                MAGIC_SIGNAL if offsets.signal_offset.is_none() => {
                    offsets.signal_offset = Some(base_offset + i);
                },
                MAGIC_SIGMASK if offsets.sigmask_offset.is_none() => {
                    offsets.sigmask_offset = Some(base_offset + i);
                },
                MAGIC_STRUCT if offsets.struct_offset.is_none() => {
                    offsets.struct_offset = Some(base_offset + i);
                },
                MAGIC_EFFECT if offsets.effect_offset.is_none() => {
                    offsets.effect_offset = Some(base_offset + i);
                },
                MAGIC_TRANS if offsets.trans_offset.is_none() => {
                    offsets.trans_offset = Some(base_offset + i);
                },
                MAGIC_CAP if offsets.cap_offset.is_none() => {
                    offsets.cap_offset = Some(base_offset + i);
                },
                _ => {}
            }

            i += 1;
        }

        offsets
    }
}