// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Loader for bzImage-format Linux kernels as described in
// https://www.kernel.org/doc/Documentation/x86/boot.txt

use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use base::AsRawDescriptor;
use data_model::DataInit;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::bootparam::boot_params;

#[sorted]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("bad kernel header signature")]
    BadSignature,
    #[error("invalid setup_sects value")]
    InvalidSetupSects,
    #[error("invalid syssize value")]
    InvalidSysSize,
    #[error("unable to read boot_params")]
    ReadBootParams,
    #[error("unable to read kernel image")]
    ReadKernelImage,
    #[error("unable to seek to boot_params")]
    SeekBootParams,
    #[error("unable to seek to kernel start")]
    SeekKernelStart,
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
    mut kernel_image: &mut F,
) -> Result<(boot_params, u64)>
where
    F: Read + Seek + AsRawDescriptor,
{
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekBootParams)?;
    let params = boot_params::from_reader(&mut kernel_image).map_err(|_| Error::ReadBootParams)?;

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
        .ok_or(Error::InvalidSetupSects)?
        .checked_mul(512)
        .ok_or(Error::InvalidSetupSects)?;
    let kernel_size = (params.hdr.syssize as usize)
        .checked_mul(16)
        .ok_or(Error::InvalidSysSize)?;

    kernel_image
        .seek(SeekFrom::Start(kernel_offset))
        .map_err(|_| Error::SeekKernelStart)?;

    // Load the whole kernel image to kernel_start
    guest_mem
        .read_to_memory(kernel_start, kernel_image, kernel_size)
        .map_err(|_| Error::ReadKernelImage)?;

    Ok((params, kernel_start.offset() + kernel_size as u64))
}
