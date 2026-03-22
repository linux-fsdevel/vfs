// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Sasha Levin <sashal@kernel.org>

// Constants for all structure field sizes
pub mod sizes {
    pub const NAME: usize = 128;
    pub const DESC: usize = 512;
    pub const MAX_PARAMS: usize = 16;
    pub const MAX_ERRORS: usize = 32;
    pub const MAX_CONSTRAINTS: usize = 32;
    pub const MAX_CAPABILITIES: usize = 8;
    pub const MAX_SIGNALS: usize = 32;
    pub const MAX_STRUCT_SPECS: usize = 8;
    pub const MAX_SIDE_EFFECTS: usize = 32;
    pub const MAX_STATE_TRANS: usize = 8;
    pub const MAX_PROTOCOL_BEHAVIORS: usize = 8;
    pub const MAX_ADDR_FAMILIES: usize = 8;
}

/// Endianness of the target ELF binary
#[derive(Clone, Copy, PartialEq)]
pub enum Endian {
    Little,
    Big,
}

// Helper for reading data at specific offsets
pub struct DataReader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
    pub endian: Endian,
    /// true for 64-bit ELF, false for 32-bit
    pub is_64bit: bool,
}

impl<'a> DataReader<'a> {
    pub fn new(data: &'a [u8], offset: usize, endian: Endian, is_64bit: bool) -> Self {
        Self {
            data,
            pos: offset,
            endian,
            is_64bit,
        }
    }

    pub fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.pos + len <= self.data.len() {
            let bytes = &self.data[self.pos..self.pos + len];
            self.pos += len;
            Some(bytes)
        } else {
            None
        }
    }

    pub fn read_cstring(&mut self, max_len: usize) -> Option<String> {
        let bytes = self.read_bytes(max_len)?;
        if let Some(null_pos) = bytes.iter().position(|&b| b == 0) {
            if null_pos > 0 {
                if let Ok(s) = std::str::from_utf8(&bytes[..null_pos]) {
                    return Some(s.to_string());
                }
            }
        }
        None
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        let b: [u8; 4] = self.read_bytes(4)?.try_into().unwrap();
        Some(match self.endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        })
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        self.read_bytes(1).map(|b| b[0])
    }

    pub fn read_i32(&mut self) -> Option<i32> {
        let b: [u8; 4] = self.read_bytes(4)?.try_into().unwrap();
        Some(match self.endian {
            Endian::Little => i32::from_le_bytes(b),
            Endian::Big => i32::from_be_bytes(b),
        })
    }

    pub fn read_u64(&mut self) -> Option<u64> {
        let b: [u8; 8] = self.read_bytes(8)?.try_into().unwrap();
        Some(match self.endian {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        })
    }

    pub fn read_i64(&mut self) -> Option<i64> {
        let b: [u8; 8] = self.read_bytes(8)?.try_into().unwrap();
        Some(match self.endian {
            Endian::Little => i64::from_le_bytes(b),
            Endian::Big => i64::from_be_bytes(b),
        })
    }

    /// Read a target-sized unsigned value (4 bytes for 32-bit, 8 bytes for 64-bit)
    pub fn read_usize(&mut self) -> Option<usize> {
        if self.is_64bit {
            self.read_u64().map(|v| v as usize)
        } else {
            self.read_u32().map(|v| v as usize)
        }
    }

    pub fn skip(&mut self, len: usize) {
        self.pos = (self.pos + len).min(self.data.len());
    }

    // Helper methods for common patterns
    pub fn read_bool(&mut self) -> Option<bool> {
        self.read_u8().map(|v| v != 0)
    }

    pub fn read_optional_string(&mut self, max_len: usize) -> Option<String> {
        self.read_cstring(max_len).filter(|s| !s.is_empty())
    }

    pub fn read_string_or_default(&mut self, max_len: usize) -> String {
        self.read_cstring(max_len).unwrap_or_default()
    }

    // Skip and discard - advances position by reading and discarding
    pub fn discard_cstring(&mut self, max_len: usize) {
        let _ = self.read_cstring(max_len);
    }

}

// Structure layout definitions for calculating sizes
pub fn signal_mask_spec_layout_size() -> usize {
    // Packed structure from struct kapi_signal_mask_spec
    sizes::NAME + // mask_name
    4 * sizes::MAX_SIGNALS + // signals array
    4 + // signal_count
    sizes::DESC // description
}

pub fn struct_field_layout_size() -> usize {
    // Packed structure from struct kapi_struct_field
    sizes::NAME + // name
    4 + // type (enum)
    sizes::NAME + // type_name
    8 + // offset (size_t)
    8 + // size (size_t)
    4 + // flags
    4 + // constraint_type (enum)
    8 + // min_value (s64)
    8 + // max_value (s64)
    8 + // valid_mask (u64)
    sizes::DESC + // enum_values
    sizes::DESC // description
}

pub fn socket_state_spec_layout_size() -> usize {
    // struct kapi_socket_state_spec
    sizes::NAME * sizes::MAX_CONSTRAINTS + // required_states array
    sizes::NAME * sizes::MAX_CONSTRAINTS + // forbidden_states array
    sizes::NAME + // resulting_state
    sizes::DESC + // condition
    sizes::NAME + // applicable_protocols
    4 + // required_count
    4 // forbidden_count
}

pub fn protocol_behavior_spec_layout_size() -> usize {
    // struct kapi_protocol_behavior
    sizes::NAME + // applicable_protocols
    sizes::DESC + // behavior
    sizes::NAME + // protocol_flags
    sizes::DESC // flag_description
}

pub fn buffer_spec_layout_size() -> usize {
    // struct kapi_buffer_spec
    sizes::DESC + // buffer_behaviors
    8 + // min_buffer_size (size_t)
    8 + // max_buffer_size (size_t)
    8 // optimal_buffer_size (size_t)
}

pub fn async_spec_layout_size() -> usize {
    // struct kapi_async_spec
    sizes::NAME + // supported_modes
    4 // nonblock_errno (int)
}

pub fn addr_family_spec_layout_size() -> usize {
    // struct kapi_addr_family_spec
    4 + // family (int)
    sizes::NAME + // family_name
    8 + // addr_struct_size (size_t)
    8 + // min_addr_len (size_t)
    8 + // max_addr_len (size_t)
    sizes::DESC + // addr_format
    1 + // supports_wildcard (bool)
    1 + // supports_multicast (bool)
    1 + // supports_broadcast (bool)
    sizes::DESC + // special_addresses
    4 + // port_range_min (u32)
    4 // port_range_max (u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- DataReader little-endian tests ----

    #[test]
    fn read_u32_little_endian() {
        let data = [0x78, 0x56, 0x34, 0x12];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_u32(), Some(0x12345678));
    }

    #[test]
    fn read_u32_big_endian() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let mut reader = DataReader::new(&data, 0, Endian::Big, true);
        assert_eq!(reader.read_u32(), Some(0x12345678));
    }

    #[test]
    fn read_u64_little_endian() {
        let data = 0xDEADBEEFCAFEBABEu64.to_le_bytes();
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_u64(), Some(0xDEADBEEFCAFEBABE));
    }

    #[test]
    fn read_u64_big_endian() {
        let data = 0xDEADBEEFCAFEBABEu64.to_be_bytes();
        let mut reader = DataReader::new(&data, 0, Endian::Big, true);
        assert_eq!(reader.read_u64(), Some(0xDEADBEEFCAFEBABE));
    }

    #[test]
    fn read_i32_little_endian_negative() {
        let val: i32 = -42;
        let data = val.to_le_bytes();
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_i32(), Some(-42));
    }

    #[test]
    fn read_i32_big_endian_negative() {
        let val: i32 = -1;
        let data = val.to_be_bytes();
        let mut reader = DataReader::new(&data, 0, Endian::Big, true);
        assert_eq!(reader.read_i32(), Some(-1));
    }

    #[test]
    fn read_i64_little_endian() {
        let val: i64 = -9999999999;
        let data = val.to_le_bytes();
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_i64(), Some(-9999999999));
    }

    #[test]
    fn read_i64_big_endian() {
        let val: i64 = i64::MIN;
        let data = val.to_be_bytes();
        let mut reader = DataReader::new(&data, 0, Endian::Big, true);
        assert_eq!(reader.read_i64(), Some(i64::MIN));
    }

    // ---- read_cstring tests ----

    #[test]
    fn read_cstring_nul_at_start() {
        let data = [0u8, b'h', b'e', b'l', b'l', b'o'];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        // NUL at position 0 means null_pos == 0, so the function returns None
        assert_eq!(reader.read_cstring(6), None);
    }

    #[test]
    fn read_cstring_nul_in_middle() {
        let data = [b'h', b'i', 0, b'x', b'y'];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_cstring(5), Some("hi".to_string()));
    }

    #[test]
    fn read_cstring_nul_at_end() {
        let data = [b'a', b'b', b'c', b'd', 0];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_cstring(5), Some("abcd".to_string()));
    }

    #[test]
    fn read_cstring_no_nul_returns_none() {
        let data = [b'x', b'y', b'z'];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        // No NUL terminator in the 3 bytes -> None
        assert_eq!(reader.read_cstring(3), None);
    }

    // ---- read_usize tests ----

    #[test]
    fn read_usize_64bit() {
        let val: u64 = 0x00000000FFFFFFFF;
        let data = val.to_le_bytes();
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_usize(), Some(0xFFFFFFFF));
    }

    #[test]
    fn read_usize_32bit() {
        let val: u32 = 0xABCD1234;
        let data = val.to_le_bytes();
        let mut reader = DataReader::new(&data, 0, Endian::Little, false);
        assert_eq!(reader.read_usize(), Some(0xABCD1234));
    }

    #[test]
    fn read_usize_32bit_does_not_consume_8_bytes() {
        // In 32-bit mode, read_usize should only consume 4 bytes
        let mut data = [0u8; 8];
        data[..4].copy_from_slice(&42u32.to_le_bytes());
        data[4..8].copy_from_slice(&99u32.to_le_bytes());
        let mut reader = DataReader::new(&data, 0, Endian::Little, false);
        assert_eq!(reader.read_usize(), Some(42));
        // After reading 4 bytes, pos should be at 4
        assert_eq!(reader.pos, 4);
        assert_eq!(reader.read_usize(), Some(99));
    }

    // ---- Bounds checking ----

    #[test]
    fn read_u32_past_end_returns_none() {
        let data = [0x01, 0x02, 0x03]; // only 3 bytes, need 4
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_u32(), None);
    }

    #[test]
    fn read_u64_past_end_returns_none() {
        let data = [0u8; 7]; // only 7 bytes, need 8
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_u64(), None);
    }

    #[test]
    fn read_bytes_past_end_returns_none() {
        let data = [0u8; 4];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_bytes(5), None);
    }

    #[test]
    fn read_at_offset() {
        let data = [0x00, 0x00, 0x78, 0x56, 0x34, 0x12];
        let mut reader = DataReader::new(&data, 2, Endian::Little, true);
        assert_eq!(reader.read_u32(), Some(0x12345678));
    }

    #[test]
    fn read_bool_values() {
        let data = [0, 1, 255];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_bool(), Some(false));
        assert_eq!(reader.read_bool(), Some(true));
        assert_eq!(reader.read_bool(), Some(true)); // any non-zero is true
    }

    #[test]
    fn skip_advances_position() {
        let data = [0u8; 20];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        reader.skip(10);
        assert_eq!(reader.pos, 10);
        reader.skip(5);
        assert_eq!(reader.pos, 15);
    }

    #[test]
    fn skip_clamps_to_data_len() {
        let data = [0u8; 10];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        reader.skip(100);
        assert_eq!(reader.pos, 10);
    }

    #[test]
    fn sequential_reads_advance_position() {
        let mut data = [0u8; 12];
        data[..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..8].copy_from_slice(&2u32.to_le_bytes());
        data[8..12].copy_from_slice(&3u32.to_le_bytes());
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_u32(), Some(1));
        assert_eq!(reader.read_u32(), Some(2));
        assert_eq!(reader.read_u32(), Some(3));
        assert_eq!(reader.pos, 12);
    }

    // ---- is_valid_api_name tests (from vmlinux/mod.rs) ----
    // We test it via the super module since it's defined in vmlinux/mod.rs

    #[test]
    fn read_optional_string_empty_returns_none() {
        // A string buffer that is just NUL
        let data = [0u8; 10];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        // read_cstring returns None when null_pos == 0
        // read_optional_string filters empty strings, but read_cstring won't return empty
        assert_eq!(reader.read_optional_string(10), None);
    }

    #[test]
    fn read_string_or_default_with_empty() {
        let data = [0u8; 10];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_string_or_default(10), "");
    }

    #[test]
    fn read_u8_value() {
        let data = [0x42];
        let mut reader = DataReader::new(&data, 0, Endian::Little, true);
        assert_eq!(reader.read_u8(), Some(0x42));
    }
}

/// Tests for is_valid_api_name (defined in vmlinux/mod.rs, tested here
/// since binary_utils is its sibling module)
#[cfg(test)]
mod api_name_tests {
    use super::super::is_valid_api_name;

    #[test]
    fn valid_syscall_name() {
        assert!(is_valid_api_name("sys_open"));
        assert!(is_valid_api_name("sys_read"));
        assert!(is_valid_api_name("sys_write"));
    }

    #[test]
    fn valid_ioctl_name() {
        assert!(is_valid_api_name("vfs_ioctl"));
        assert!(is_valid_api_name("drm_ioctl"));
    }

    #[test]
    fn valid_dunder_name() {
        assert!(is_valid_api_name("__do_sys_open"));
        assert!(is_valid_api_name("__x64_sys_read"));
    }

    #[test]
    fn empty_name_is_invalid() {
        assert!(!is_valid_api_name(""));
    }

    #[test]
    fn too_short_name_is_invalid() {
        assert!(!is_valid_api_name("ab")); // len < 3
    }

    #[test]
    fn too_long_name_is_invalid() {
        let long_name = "a".repeat(101);
        assert!(!is_valid_api_name(&long_name));
    }

    #[test]
    fn name_starting_with_digit_is_invalid() {
        assert!(!is_valid_api_name("3func_test"));
    }

    #[test]
    fn name_with_special_chars_is_invalid() {
        assert!(!is_valid_api_name("sys-open")); // dash not allowed
        assert!(!is_valid_api_name("sys.open")); // dot not allowed
        assert!(!is_valid_api_name("sys open")); // space not allowed
    }

    #[test]
    fn name_with_underscore_is_valid() {
        assert!(is_valid_api_name("do_some_thing"));
        assert!(is_valid_api_name("_internal_func"));
    }

    #[test]
    fn long_name_without_underscore_is_valid_if_gt_6() {
        // name.len() > 6 is the fallback condition
        assert!(is_valid_api_name("longname")); // 8 chars, no underscore but len > 6
    }

    #[test]
    fn short_name_without_pattern_may_be_invalid() {
        // "abc" has len 3, no underscore, no prefix match, len <= 6
        assert!(!is_valid_api_name("abc"));
    }
}
