// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Multiboot kernel loader
//!
//! Only Multiboot (version 0.6.96) is supported, not Multiboot2.

use std::fs::File;
use std::mem::size_of;
use std::num::NonZeroU32;

use base::error;
use base::trace;
use base::FileReadWriteAtVolatile;
use base::VolatileSlice;
use resources::AddressRange;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::Error;
use crate::LoadedKernel;
use crate::Result;

/// Multiboot header retrieved from a kernel image.
#[derive(Clone, Debug)]
pub struct MultibootKernel {
    /// Byte offset of the beginning of the multiboot header in the kernel image.
    pub offset: u32,

    /// Kernel requires that boot modules are aligned to 4 KB.
    pub boot_modules_page_aligned: bool,

    /// Kernel requires available memory information (`mem_*` fields).
    pub need_available_memory: bool,

    /// Kernel load address.
    ///
    /// If present, this overrides any other executable format headers (e.g. ELF).
    pub load: Option<MultibootLoad>,

    /// Kernel preferred video mode.
    ///
    /// If present, the kernel also requires information about the video mode table.
    pub preferred_video_mode: Option<MultibootVideoMode>,
}

/// Multiboot kernel load parameters.
#[derive(Clone, Debug)]
pub struct MultibootLoad {
    /// File byte offset to load the kernel's code and initialized data from.
    pub file_load_offset: u64,

    /// Number of bytes to read from the file at `file_load_offset`.
    pub file_load_size: usize,

    /// Physical memory address where the kernel should be loaded.
    pub load_addr: GuestAddress,

    /// Physical address of the kernel entry point.
    pub entry_addr: GuestAddress,

    /// BSS physical memory starting address to zero fill, if present in kernel.
    pub bss_addr: Option<GuestAddress>,

    /// BSS size in bytes (0 if no BSS region is present).
    pub bss_size: usize,
}

/// Multiboot kernel video mode specification.
#[derive(Clone, Debug)]
pub struct MultibootVideoMode {
    /// Preferred video mode type (text or graphics).
    pub mode_type: MultibootVideoModeType,

    /// Width of the requested mode.
    ///
    /// For text modes, this is in units of characters. For graphics modes, this is in units of
    /// pixels.
    pub width: Option<NonZeroU32>,

    /// Height of the requested mode.
    ///
    /// For text modes, this is in units of characters. For graphics modes, this is in units of
    /// pixels.
    pub height: Option<NonZeroU32>,

    /// Requested bits per pixel (only relevant in graphics modes).
    pub depth: Option<NonZeroU32>,
}

#[derive(Copy, Clone, Debug)]
pub enum MultibootVideoModeType {
    LinearGraphics,
    EgaText,
    Other(u32),
}

/// Scan the provided kernel file to find a Multiboot header, if present.
///
/// # Returns
///
/// - `Ok(None)`: kernel file did not contain a Multiboot header.
/// - `Ok(Some(...))`: kernel file contained a valid Multiboot header, which is returned.
/// - `Err(...)`: kernel file contained a Multiboot header with a valid checksum but other fields in
///   the header were invalid.
pub fn multiboot_header_from_file(kernel_file: &mut File) -> Result<Option<MultibootKernel>> {
    const MIN_HEADER_SIZE: usize = 3 * size_of::<u32>();
    const ALIGNMENT: usize = 4;

    // Read up to 8192 bytes from the beginning of the file.
    let kernel_file_len = kernel_file.metadata().map_err(|_| Error::ReadHeader)?.len();
    let kernel_prefix_len = kernel_file_len.min(8192) as usize;

    if kernel_prefix_len < MIN_HEADER_SIZE {
        return Ok(None);
    }

    let mut kernel_bytes = vec![0u8; kernel_prefix_len];
    kernel_file
        .read_exact_at_volatile(VolatileSlice::new(&mut kernel_bytes), 0)
        .map_err(|_| Error::ReadHeader)?;

    for offset in (0..kernel_prefix_len).step_by(ALIGNMENT) {
        let Some(hdr) = kernel_bytes.get(offset..) else {
            break;
        };
        match multiboot_header(hdr, offset as u64, kernel_file_len) {
            Ok(None) => continue,
            Ok(Some(multiboot)) => return Ok(Some(multiboot)),
            Err(e) => return Err(e),
        }
    }

    // The file did not contain a valid Multiboot header.
    Ok(None)
}

/// Attempt to parse a Multiboot header from the prefix of a slice.
///
/// # Returns
///
/// - `Ok(None)`: no multiboot header here.
/// - `Ok(Some(...))`: valid multiboot header is returned.
/// - `Err(...)`: valid multiboot header checksum at this position in the file (meaning this is the
///   real header location), but there is an invalid field later in the multiboot header (e.g. an
///   impossible combination of load addresses).
fn multiboot_header(
    hdr: &[u8],
    offset: u64,
    kernel_file_len: u64,
) -> Result<Option<MultibootKernel>> {
    const MAGIC: u32 = 0x1BADB002;

    let Ok(magic) = get_le32(hdr, 0) else {
        return Ok(None);
    };
    if magic != MAGIC {
        return Ok(None);
    }

    // Failing to read these fields means we ran out of data at the end of the slice and did not
    // actually find a Multiboot header, so return `Ok(None)` to indicate no Multiboot header was
    // found instead of using `?`, which would return an error.
    let Ok(flags) = get_le32(hdr, 4) else {
        return Ok(None);
    };
    let Ok(checksum) = get_le32(hdr, 8) else {
        return Ok(None);
    };

    if magic.wrapping_add(flags).wrapping_add(checksum) != 0 {
        // Checksum did not match, so this is not a real Multiboot header. Keep searching.
        return Ok(None);
    }

    trace!("found Multiboot header with valid checksum at {offset:#X}");

    const F_BOOT_MODULE_PAGE_ALIGN: u32 = 1 << 0;
    const F_AVAILABLE_MEMORY: u32 = 1 << 1;
    const F_VIDEO_MODE: u32 = 1 << 2;
    const F_ADDRESS: u32 = 1 << 16;

    const KNOWN_FLAGS: u32 =
        F_BOOT_MODULE_PAGE_ALIGN | F_AVAILABLE_MEMORY | F_VIDEO_MODE | F_ADDRESS;

    let unknown_flags = flags & !KNOWN_FLAGS;
    if unknown_flags != 0 {
        error!("unknown flags {unknown_flags:#X}");
        return Err(Error::InvalidFlags);
    }

    let boot_modules_page_aligned = flags & F_BOOT_MODULE_PAGE_ALIGN != 0;
    let need_available_memory = flags & F_AVAILABLE_MEMORY != 0;
    let need_video_mode_table = flags & F_VIDEO_MODE != 0;
    let load_address_available = flags & F_ADDRESS != 0;

    let load = if load_address_available {
        let header_addr = get_le32(hdr, 12)?;
        let load_addr = get_le32(hdr, 16)?;
        let load_end_addr = get_le32(hdr, 20)?;
        let bss_end_addr = get_le32(hdr, 24)?;
        let entry_addr = get_le32(hdr, 28)?;

        if header_addr < load_addr {
            error!("header_addr {header_addr:#X} < load_addr {load_addr:#X}");
            return Err(Error::InvalidKernelOffset);
        }

        // The beginning of the area to load from the file starts `load_offset` bytes before the
        // multiboot header.
        let load_offset = u64::from(header_addr - load_addr);
        if load_offset > offset {
            error!("load_offset {load_offset:#X} > offset {offset:#X}");
            return Err(Error::InvalidKernelOffset);
        }
        let file_load_offset = offset - load_offset;

        let file_load_size = if load_end_addr == 0 {
            // Zero `load_end_addr` means the loadable data extends to the end of the file.
            (kernel_file_len - file_load_offset)
                .try_into()
                .map_err(|_| Error::InvalidKernelOffset)?
        } else if load_end_addr < load_addr {
            error!("load_end_addr {load_end_addr:#X} < load_addr {load_addr:#X}");
            return Err(Error::InvalidKernelOffset);
        } else {
            load_end_addr - load_addr
        };

        let load_end_addr = load_addr
            .checked_add(file_load_size)
            .ok_or(Error::InvalidKernelOffset)?;

        // The bss region immediately follows the load-from-file region in memory.
        let bss_addr = load_addr + file_load_size;

        let bss_size = if bss_end_addr == 0 {
            // Zero `bss_end_addr` means no bss segment is present.
            0
        } else if bss_end_addr < bss_addr {
            error!("bss_end_addr {bss_end_addr:#X} < bss_addr {bss_addr:#X}");
            return Err(Error::InvalidKernelOffset);
        } else {
            bss_end_addr - bss_addr
        };

        let bss_addr = if bss_size > 0 {
            Some(GuestAddress(bss_addr.into()))
        } else {
            None
        };

        if entry_addr < load_addr || entry_addr >= load_end_addr {
            error!(
                "entry_addr {entry_addr:#X} not in load range {load_addr:#X}..{load_end_addr:#X}"
            );
            return Err(Error::InvalidKernelOffset);
        }

        Some(MultibootLoad {
            file_load_offset,
            file_load_size: file_load_size as usize,
            load_addr: GuestAddress(load_addr.into()),
            entry_addr: GuestAddress(entry_addr.into()),
            bss_addr,
            bss_size: bss_size as usize,
        })
    } else {
        None
    };

    let preferred_video_mode = if need_video_mode_table {
        let mode_type = get_le32(hdr, 32)?;
        let width = get_le32(hdr, 36)?;
        let height = get_le32(hdr, 40)?;
        let depth = get_le32(hdr, 44)?;

        let mode_type = match mode_type {
            0 => MultibootVideoModeType::LinearGraphics,
            1 => MultibootVideoModeType::EgaText,
            _ => MultibootVideoModeType::Other(mode_type),
        };

        Some(MultibootVideoMode {
            mode_type,
            width: NonZeroU32::new(width),
            height: NonZeroU32::new(height),
            depth: NonZeroU32::new(depth),
        })
    } else {
        None
    };

    let multiboot = MultibootKernel {
        offset: offset as u32,
        boot_modules_page_aligned,
        need_available_memory,
        load,
        preferred_video_mode,
    };

    trace!("validated header: {multiboot:?}");

    Ok(Some(multiboot))
}

fn get_le32(bytes: &[u8], offset: usize) -> Result<u32> {
    let le32_bytes = bytes.get(offset..offset + 4).ok_or(Error::ReadHeader)?;
    // This can't fail because the slice is always 4 bytes long.
    let le32_array: [u8; 4] = le32_bytes.try_into().unwrap();
    Ok(u32::from_le_bytes(le32_array))
}

/// Load a Multiboot kernel image into memory.
///
/// The `MultibootLoad` information can be retrieved from the optional `load` field of a
/// `MultibootKernel` returned by [`multiboot_header_from_file()`].
pub fn load_multiboot<F>(
    guest_mem: &GuestMemory,
    kernel_image: &mut F,
    multiboot_load: &MultibootLoad,
) -> Result<LoadedKernel>
where
    F: FileReadWriteAtVolatile,
{
    let guest_slice = guest_mem
        .get_slice_at_addr(multiboot_load.load_addr, multiboot_load.file_load_size)
        .map_err(|_| Error::ReadKernelImage)?;
    kernel_image
        .read_exact_at_volatile(guest_slice, multiboot_load.file_load_offset)
        .map_err(|_| Error::ReadKernelImage)?;

    if let Some(bss_addr) = multiboot_load.bss_addr {
        let bss_slice = guest_mem
            .get_slice_at_addr(bss_addr, multiboot_load.bss_size)
            .map_err(|_| Error::ReadKernelImage)?;
        bss_slice.write_bytes(0);
    }

    let size: u64 = multiboot_load
        .file_load_size
        .checked_add(multiboot_load.bss_size)
        .ok_or(Error::InvalidProgramHeaderSize)?
        .try_into()
        .map_err(|_| Error::InvalidProgramHeaderSize)?;

    let address_range = AddressRange::from_start_and_size(multiboot_load.load_addr.offset(), size)
        .ok_or(Error::InvalidProgramHeaderSize)?;

    Ok(LoadedKernel {
        address_range,
        size,
        entry: multiboot_load.entry_addr,
    })
}
