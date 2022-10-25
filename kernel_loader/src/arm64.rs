// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux arm64 kernel loader.
//! <https://www.kernel.org/doc/Documentation/arm64/booting.txt>

use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use base::AsRawDescriptor;
use data_model::DataInit;
use data_model::Le32;
use data_model::Le64;
use resources::AddressRange;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::Error;
use crate::LoadedKernel;
use crate::Result;

#[derive(Copy, Clone)]
#[allow(unused)]
#[repr(C)]
struct Arm64ImageHeader {
    code0: Le32,
    code1: Le32,
    text_offset: Le64,
    image_size: Le64,
    flags: Le64,
    res2: Le64,
    res3: Le64,
    res4: Le64,
    magic: Le32,
    res5: Le32,
}

// Arm64ImageHeader is plain old data with no implicit padding.
unsafe impl data_model::DataInit for Arm64ImageHeader {}

const ARM64_IMAGE_MAGIC: u32 = 0x644d5241; // "ARM\x64"

const ARM64_IMAGE_FLAG_BE_MASK: u64 = 0x1;

const ARM64_TEXT_OFFSET_DEFAULT: u64 = 0x80000;

pub fn load_arm64_kernel<F>(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    mut kernel_image: &mut F,
) -> Result<LoadedKernel>
where
    F: Read + Seek + AsRawDescriptor,
{
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelStart)?;

    let header = Arm64ImageHeader::from_reader(&mut kernel_image).map_err(|_| Error::ReadHeader)?;

    let magic: u32 = header.magic.into();
    if magic != ARM64_IMAGE_MAGIC {
        return Err(Error::InvalidMagicNumber);
    }

    let flags: u64 = header.flags.into();
    if flags & ARM64_IMAGE_FLAG_BE_MASK != 0 {
        return Err(Error::BigEndianOnLittle);
    }

    let file_size = kernel_image
        .seek(SeekFrom::End(0))
        .map_err(|_| Error::SeekKernelEnd)?;
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelStart)?;

    let mut text_offset: u64 = header.text_offset.into();
    let image_size: u64 = header.image_size.into();

    if image_size == 0 {
        // arm64/booting.txt: "Where image_size is zero, text_offset can be assumed to be 0x80000."
        text_offset = ARM64_TEXT_OFFSET_DEFAULT;
    }

    // Load the image into guest memory at `text_offset` bytes past `kernel_start`.
    let load_addr = kernel_start
        .checked_add(text_offset)
        .ok_or(Error::InvalidKernelOffset)?;
    let load_size = usize::try_from(file_size).map_err(|_| Error::InvalidKernelSize)?;
    guest_mem
        .read_to_memory(load_addr, kernel_image, load_size)
        .map_err(|_| Error::ReadKernelImage)?;

    Ok(LoadedKernel {
        size: file_size,
        address_range: AddressRange::from_start_and_size(load_addr.offset(), file_size)
            .ok_or(Error::InvalidKernelSize)?,
        entry: load_addr,
    })
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;

    use tempfile::tempfile;
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;

    use crate::load_arm64_kernel;
    use crate::Error;

    const MEM_SIZE: u64 = 0x200_0000;

    fn create_guest_mem() -> GuestMemory {
        GuestMemory::new(&[(GuestAddress(0x0), MEM_SIZE)]).unwrap()
    }

    #[allow(clippy::unusual_byte_groupings)]
    fn write_valid_kernel() -> File {
        let mut f = tempfile().expect("failed to create tempfile");

        f.write_all(&[0x00, 0xC0, 0x2E, 0x14]).unwrap(); // code0
        f.write_all(&[0x00, 0x00, 0x00, 0x00]).unwrap(); // code1
        f.write_all(&0x00000000_00E70000u64.to_le_bytes()).unwrap(); // text_offset
        f.write_all(&0x00000000_0000000Au64.to_le_bytes()).unwrap(); // image_size
        f.write_all(&0x00000000_00000000u64.to_le_bytes()).unwrap(); // flags
        f.write_all(&0x00000000_00000000u64.to_le_bytes()).unwrap(); // res2
        f.write_all(&0x00000000_00000000u64.to_le_bytes()).unwrap(); // res3
        f.write_all(&0x00000000_00000000u64.to_le_bytes()).unwrap(); // res4
        f.write_all(&0x644D5241u32.to_le_bytes()).unwrap(); // magic
        f.write_all(&0x00000000u32.to_le_bytes()).unwrap(); // res5

        f.set_len(0xDC3808).unwrap();
        f
    }

    fn mutate_file(mut f: &File, offset: u64, val: &[u8]) {
        f.seek(SeekFrom::Start(offset))
            .expect("failed to seek file");
        f.write_all(val)
            .expect("failed to write mutated value to file");
    }

    #[test]
    fn load_arm64_valid() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(2 * 1024 * 1024);
        let mut f = write_valid_kernel();
        let kernel = load_arm64_kernel(&gm, kernel_addr, &mut f).unwrap();
        assert_eq!(kernel.address_range.start, 0x107_0000);
        assert_eq!(kernel.address_range.end, 0x1E3_3807);
        assert_eq!(kernel.size, 0xDC_3808);
        assert_eq!(kernel.entry, GuestAddress(0x107_0000));
    }

    #[test]
    fn load_arm64_image_size_zero() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(2 * 1024 * 1024);
        let mut f = write_valid_kernel();

        // Set image_size = 0 and validate the default text_offset is applied.
        mutate_file(&f, 16, &0u64.to_le_bytes());

        let kernel = load_arm64_kernel(&gm, kernel_addr, &mut f).unwrap();
        assert_eq!(kernel.address_range.start, 0x28_0000);
        assert_eq!(kernel.address_range.end, 0x104_3807);
        assert_eq!(kernel.size, 0xDC_3808);
        assert_eq!(kernel.entry, GuestAddress(0x28_0000));
    }

    #[test]
    fn load_arm64_bad_magic() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(2 * 1024 * 1024);
        let mut f = write_valid_kernel();

        // Mutate magic number so it doesn't match
        mutate_file(&f, 56, &[0xCC, 0xCC, 0xCC, 0xCC]);

        assert_eq!(
            load_arm64_kernel(&gm, kernel_addr, &mut f),
            Err(Error::InvalidMagicNumber)
        );
    }
}
