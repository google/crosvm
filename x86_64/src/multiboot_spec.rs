// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Multiboot specification 0.6.96 definitions
//!
//! <https://www.gnu.org/software/grub/manual/multiboot/multiboot.html>

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

/// Magic value stored in EAX to indicate bootloader is Multiboot compliant.
pub const MULTIBOOT_BOOTLOADER_MAGIC: u32 = 0x2BADB002;

#[derive(Debug, Default, AsBytes, FromBytes, FromZeroes)]
#[repr(C, packed)]
pub struct MultibootInfo {
    pub flags: u32,

    pub mem_lower: u32,
    pub mem_upper: u32,

    pub boot_device: u32,

    pub cmdline: u32,

    pub mods_count: u32,
    pub mods_addr: u32,

    // TODO: add union for ELF + a.out symbols if needed
    pub syms: [u32; 4],

    pub mmap_length: u32,
    pub mmap_addr: u32,

    pub drives_length: u32,
    pub drives_addr: u32,

    pub config_table: u32,

    pub boot_loader_name: u32,

    pub apm_table: u32,

    pub vbe_control_info: u32,
    pub vbe_mode_info: u32,
    pub vbe_mode: u16,
    pub vbe_interface_seg: u16,
    pub vbe_interface_off: u16,
    pub vbe_interface_len: u16,

    pub framebuffer_addr: u64,
    pub framebuffer_pitch: u32,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_bpp: u8,
    pub framebuffer_type: u8,

    // TODO: add union for palette + RGB color info if needed
    pub color_info: [u8; 6],
}

impl MultibootInfo {
    pub const F_MEM: u32 = 1 << 0;
    pub const F_BOOT_DEVICE: u32 = 1 << 1;
    pub const F_CMDLINE: u32 = 1 << 2;
    pub const F_MODS: u32 = 1 << 3;
    pub const F_SYMS_AOUT: u32 = 1 << 4;
    pub const F_SYMS_ELF: u32 = 1 << 5;
    pub const F_MMAP: u32 = 1 << 6;
    pub const F_DRIVES: u32 = 1 << 7;
    pub const F_CONFIG_TABLE: u32 = 1 << 8;
    pub const F_BOOT_LOADER_NAME: u32 = 1 << 9;
    pub const F_APM_TABLE: u32 = 1 << 10;
    pub const F_VBE: u32 = 1 << 11;
    pub const F_FRAMEBUFFER: u32 = 1 << 12;
}

#[derive(Debug, Default, AsBytes, FromBytes, FromZeroes)]
#[repr(C, packed)]
pub struct MultibootMmapEntry {
    pub size: u32,
    pub base_addr: u64,
    pub length: u64,
    pub type_: u32,
}

#[cfg(test)]
mod tests {
    use std::mem::offset_of;
    use std::mem::size_of;

    use super::*;

    #[test]
    fn test_multiboot_info_offsets() {
        // Validate that multiboot_info field offsets match the spec.
        assert_eq!(0, offset_of!(MultibootInfo, flags));
        assert_eq!(4, offset_of!(MultibootInfo, mem_lower));
        assert_eq!(8, offset_of!(MultibootInfo, mem_upper));
        assert_eq!(8, offset_of!(MultibootInfo, mem_upper));
        assert_eq!(12, offset_of!(MultibootInfo, boot_device));
        assert_eq!(16, offset_of!(MultibootInfo, cmdline));
        assert_eq!(20, offset_of!(MultibootInfo, mods_count));
        assert_eq!(24, offset_of!(MultibootInfo, mods_addr));
        assert_eq!(28, offset_of!(MultibootInfo, syms));
        assert_eq!(44, offset_of!(MultibootInfo, mmap_length));
        assert_eq!(48, offset_of!(MultibootInfo, mmap_addr));
        assert_eq!(52, offset_of!(MultibootInfo, drives_length));
        assert_eq!(56, offset_of!(MultibootInfo, drives_addr));
        assert_eq!(60, offset_of!(MultibootInfo, config_table));
        assert_eq!(64, offset_of!(MultibootInfo, boot_loader_name));
        assert_eq!(68, offset_of!(MultibootInfo, apm_table));
        assert_eq!(72, offset_of!(MultibootInfo, vbe_control_info));
        assert_eq!(76, offset_of!(MultibootInfo, vbe_mode_info));
        assert_eq!(80, offset_of!(MultibootInfo, vbe_mode));
        assert_eq!(82, offset_of!(MultibootInfo, vbe_interface_seg));
        assert_eq!(84, offset_of!(MultibootInfo, vbe_interface_off));
        assert_eq!(86, offset_of!(MultibootInfo, vbe_interface_len));
        assert_eq!(88, offset_of!(MultibootInfo, framebuffer_addr));
        assert_eq!(96, offset_of!(MultibootInfo, framebuffer_pitch));
        assert_eq!(100, offset_of!(MultibootInfo, framebuffer_width));
        assert_eq!(104, offset_of!(MultibootInfo, framebuffer_height));
        assert_eq!(108, offset_of!(MultibootInfo, framebuffer_bpp));
        assert_eq!(109, offset_of!(MultibootInfo, framebuffer_type));
        assert_eq!(110, offset_of!(MultibootInfo, color_info));

        assert_eq!(size_of::<MultibootInfo>(), 116);
    }

    #[test]
    fn test_multiboot_mmap_entry_offsets() {
        // The spec defines the mmap entry structure in a confusing way (`size` at offset -4 and
        // `base_addr` at offset 0), but this does not match how both bootloaders and kernels have
        // implemented Multiboot (`size` at offset 0), so this does not exactly match the table in
        // the spec.
        assert_eq!(0, offset_of!(MultibootMmapEntry, size));
        assert_eq!(4, offset_of!(MultibootMmapEntry, base_addr));
        assert_eq!(12, offset_of!(MultibootMmapEntry, length));
        assert_eq!(20, offset_of!(MultibootMmapEntry, type_));

        assert_eq!(size_of::<MultibootMmapEntry>(), 24); // 20-byte e820 data + 4 bytes for size
    }
}
