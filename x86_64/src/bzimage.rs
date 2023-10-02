// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Loader for bzImage-format Linux kernels as described in
//! <https://www.kernel.org/doc/Documentation/x86/boot.txt>

use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use base::debug;
use base::AsRawDescriptor;
use memoffset::offset_of;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;
use zerocopy::AsBytes;

use crate::bootparam::boot_params;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("bad kernel header signature")]
    BadSignature,
    #[error("invalid setup_header_end value {0}")]
    InvalidSetupHeaderEnd(usize),
    #[error("invalid setup_sects value {0}")]
    InvalidSetupSects(u8),
    #[error("invalid syssize value {0}")]
    InvalidSysSize(u32),
    #[error("unable to read boot_params: {0}")]
    ReadBootParams(io::Error),
    #[error("unable to read header size: {0}")]
    ReadHeaderSize(io::Error),
    #[error("unable to read kernel image: {0}")]
    ReadKernelImage(GuestMemoryError),
    #[error("unable to seek to boot_params: {0}")]
    SeekBootParams(io::Error),
    #[error("unable to seek to header size byte: {0}")]
    SeekHeaderSize(io::Error),
    #[error("unable to seek to kernel start: {0}")]
    SeekKernelStart(io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Loads a kernel from a bzImage to a slice
///
/// # Arguments
///
/// * `guest_mem` - The guest memory region the kernel is written to.
/// * `kernel_start` - The offset into `guest_mem` at which to load the kernel.
/// * `kernel_image` - Input bzImage.
pub fn load_bzimage<F>(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    kernel_image: &mut F,
) -> Result<(boot_params, u64)>
where
    F: Read + Seek + AsRawDescriptor,
{
    let mut params = boot_params::default();

    // The start of setup header is defined by its offset within boot_params (0x01f1).
    let setup_header_start = offset_of!(boot_params, hdr);

    // Per x86 Linux 64-bit boot protocol:
    // "The end of setup header can be calculated as follows: 0x0202 + byte value at offset 0x0201"
    let mut setup_size_byte = 0u8;
    kernel_image
        .seek(SeekFrom::Start(0x0201))
        .map_err(Error::SeekHeaderSize)?;
    kernel_image
        .read_exact(setup_size_byte.as_bytes_mut())
        .map_err(Error::ReadHeaderSize)?;
    let setup_header_end = 0x0202 + usize::from(setup_size_byte);

    debug!(
        "setup_header file offset range: 0x{:04x}..0x{:04x}",
        setup_header_start, setup_header_end,
    );

    // Read `setup_header` into `boot_params`. The bzImage may have a different size of
    // `setup_header`, so read directly into a byte slice of the outer `boot_params` structure
    // rather than reading into `params.hdr`. The bounds check in `.get_mut()` will ensure we do not
    // read beyond the end of `boot_params`.
    let setup_header_slice = params
        .as_bytes_mut()
        .get_mut(setup_header_start..setup_header_end)
        .ok_or(Error::InvalidSetupHeaderEnd(setup_header_end))?;

    kernel_image
        .seek(SeekFrom::Start(setup_header_start as u64))
        .map_err(Error::SeekBootParams)?;
    kernel_image
        .read_exact(setup_header_slice)
        .map_err(Error::ReadBootParams)?;

    // bzImage header signature "HdrS"
    if params.hdr.header != 0x53726448 {
        return Err(Error::BadSignature);
    }

    let setup_sects = if params.hdr.setup_sects == 0 {
        4u64
    } else {
        params.hdr.setup_sects as u64
    };

    let kernel_offset = setup_sects
        .checked_add(1)
        .and_then(|sectors| sectors.checked_mul(512))
        .ok_or(Error::InvalidSetupSects(params.hdr.setup_sects))?;
    let kernel_size = (params.hdr.syssize as usize)
        .checked_mul(16)
        .ok_or(Error::InvalidSysSize(params.hdr.syssize))?;

    kernel_image
        .seek(SeekFrom::Start(kernel_offset))
        .map_err(Error::SeekKernelStart)?;

    // Load the whole kernel image to kernel_start
    guest_mem
        .read_to_memory(kernel_start, kernel_image, kernel_size)
        .map_err(Error::ReadKernelImage)?;

    Ok((params, kernel_start.offset() + kernel_size as u64))
}
