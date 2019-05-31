// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Loader for bzImage-format Linux kernels as described in
// https://www.kernel.org/doc/Documentation/x86/boot.txt

use std::fmt::{self, Display};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::AsRawFd;

use sys_util::{GuestAddress, GuestMemory};

use crate::bootparam::boot_params;

#[derive(Debug, PartialEq)]
pub enum Error {
    BadSignature,
    InvalidSetupSects,
    InvalidSysSize,
    ReadBootParams,
    ReadKernelImage,
    SeekBootParams,
    SeekKernelStart,
}
pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        let description = match self {
            BadSignature => "bad kernel header signature",
            InvalidSetupSects => "invalid setup_sects value",
            InvalidSysSize => "invalid syssize value",
            ReadBootParams => "unable to read boot_params",
            ReadKernelImage => "unable to read kernel image",
            SeekBootParams => "unable to seek to boot_params",
            SeekKernelStart => "unable to seek to kernel start",
        };

        write!(f, "bzImage loader: {}", description)
    }
}

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
    F: Read + Seek + AsRawFd,
{
    let mut params: boot_params = Default::default();
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekBootParams)?;
    unsafe {
        // read_struct is safe when reading a POD struct.  It can be used and dropped without issue.
        sys_util::read_struct(kernel_image, &mut params).map_err(|_| Error::ReadBootParams)?;
    }

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
