// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux arm64 kernel loader.
//! <https://www.kernel.org/doc/Documentation/arm64/booting.txt>

use std::cmp::max;
use std::io;
use std::io::BufRead;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem::size_of_val;

use base::warn;
use base::FileGetLen;
use base::FileReadWriteAtVolatile;
use base::VolatileSlice;
use data_model::Le32;
use data_model::Le64;
use lz4_flex::frame::FrameDecoder as Lz4FrameDecoder;
use resources::AddressRange;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::Error;
use crate::LoadedKernel;
use crate::Result;

#[derive(Copy, Clone, AsBytes, FromZeroes, FromBytes)]
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

const ARM64_IMAGE_MAGIC: u32 = 0x644d5241; // "ARM\x64"

const ARM64_IMAGE_FLAG_BE_MASK: u64 = 0x1;

const ARM64_TEXT_OFFSET_DEFAULT: u64 = 0x80000;

impl Arm64ImageHeader {
    fn parse_load_addr(&self, kernel_start: GuestAddress) -> Result<GuestAddress> {
        let magic: u32 = self.magic.into();
        if magic != ARM64_IMAGE_MAGIC {
            return Err(Error::InvalidMagicNumber);
        }

        let flags: u64 = self.flags.into();
        if flags & ARM64_IMAGE_FLAG_BE_MASK != 0 {
            return Err(Error::BigEndianOnLittle);
        }

        let mut text_offset: u64 = self.text_offset.into();
        let image_size: u64 = self.image_size.into();

        if image_size == 0 {
            warn!("arm64 Image header has an effective size of zero");
            // arm64/booting.txt:
            // "Where image_size is zero, text_offset can be assumed to be 0x80000."
            text_offset = ARM64_TEXT_OFFSET_DEFAULT;
        }

        // Load the image into guest memory at `text_offset` bytes past `kernel_start`.
        kernel_start
            .checked_add(text_offset)
            .ok_or(Error::InvalidKernelOffset)
    }
}

pub fn load_arm64_kernel<F>(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    kernel_image: &mut F,
) -> Result<LoadedKernel>
where
    F: FileReadWriteAtVolatile + FileGetLen,
{
    let mut header = Arm64ImageHeader::new_zeroed();
    kernel_image
        .read_exact_at_volatile(VolatileSlice::new(header.as_bytes_mut()), 0)
        .map_err(|_| Error::ReadHeader)?;
    let load_addr = header.parse_load_addr(kernel_start)?;

    let file_size = kernel_image.get_len().map_err(|_| Error::SeekKernelEnd)?;
    let load_size = usize::try_from(file_size).map_err(|_| Error::InvalidKernelSize)?;
    let range_size = max(file_size, u64::from(header.image_size));

    let guest_slice = guest_mem
        .get_slice_at_addr(load_addr, load_size)
        .map_err(|_| Error::ReadKernelImage)?;
    kernel_image
        .read_exact_at_volatile(guest_slice, 0)
        .map_err(|_| Error::ReadKernelImage)?;

    Ok(LoadedKernel {
        size: file_size,
        address_range: AddressRange::from_start_and_size(load_addr.offset(), range_size)
            .ok_or(Error::InvalidKernelSize)?,
        entry: load_addr,
    })
}

fn load_arm64_kernel_from_reader<F: BufRead>(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    mut kernel_image: F,
) -> Result<LoadedKernel> {
    let mut header = Arm64ImageHeader::new_zeroed();
    let header_size = u64::try_from(size_of_val(&header)).unwrap();

    // Read and parse the kernel header.
    kernel_image
        .read_exact(header.as_bytes_mut())
        .map_err(|_| Error::ReadHeader)?;
    let load_addr = header.parse_load_addr(kernel_start)?;

    // Write the parsed kernel header to memory. Avoid rewinding the reader back to the start.
    guest_mem
        .write_all_at_addr(header.as_bytes(), load_addr)
        .map_err(|_| Error::ReadKernelImage)?;

    // Continue reading from the source and copy the kernel image into GuestMemory.
    let mut current_addr = load_addr
        .checked_add(header_size)
        .ok_or(Error::InvalidKernelSize)?;
    loop {
        let buf = match kernel_image.fill_buf() {
            Ok([]) => break,
            Ok(buf) => buf,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::ReadKernelImage),
        };

        guest_mem
            .write_all_at_addr(buf, current_addr)
            .map_err(|_| Error::ReadKernelImage)?;

        let consumed = buf.len();
        kernel_image.consume(consumed);

        let offset = u64::try_from(consumed).map_err(|_| Error::InvalidKernelSize)?;
        current_addr = current_addr
            .checked_add(offset)
            .ok_or(Error::InvalidKernelSize)?;
    }

    let file_size = current_addr.offset_from(load_addr);
    let range_size = max(file_size, u64::from(header.image_size));
    Ok(LoadedKernel {
        size: file_size,
        address_range: AddressRange::from_start_and_size(load_addr.offset(), range_size)
            .ok_or(Error::InvalidKernelSize)?,
        entry: load_addr,
    })
}

pub fn load_arm64_kernel_lz4<F: Read + Seek>(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    mut kernel_image: F,
) -> Result<LoadedKernel> {
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelStart)?;
    load_arm64_kernel_from_reader(
        guest_mem,
        kernel_start,
        &mut Lz4FrameDecoder::new(kernel_image),
    )
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
    use crate::load_arm64_kernel_lz4;
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

    fn write_valid_kernel_lz4() -> File {
        let mut f = tempfile().expect("failed to create tempfile");

        f.write_all(&0x184d2204u32.to_le_bytes()).unwrap(); // magic
        f.write_all(&[0x44, 0x70, 0x1d]).unwrap(); // flg, bd, hc

        // Compressed block #1.
        f.write_all(&0x00004065u32.to_le_bytes()).unwrap();
        f.write_all(&[
            0x51, 0x00, 0xc0, 0x2e, 0x14, 0x00, 0x01, 0x00, 0x11, 0xe7, 0x06, 0x00, 0x11, 0x0a,
            0x06, 0x00, 0x0f, 0x02, 0x00, 0x0f, 0x4f, 0x41, 0x52, 0x4d, 0x64, 0x26, 0x00, 0x0f,
            0x0f, 0x02, 0x00,
        ])
        .unwrap();
        f.write_all(&[0xff; 16447]).unwrap();

        // Compressed block #2.
        f.write_all(&0x000050c9u32.to_le_bytes()).unwrap();
        f.write_all(&[
            0x00, 0x00, 0x00, 0x4b, 0x40, 0x00, 0x00, 0x1f, 0x00, 0x01, 0x00,
        ])
        .unwrap();
        f.write_all(&[0xff; 16448]).unwrap();

        // Compressed block #3.
        f.write_all(&0x00005027u32.to_le_bytes()).unwrap();
        f.write_all(&[
            0x00, 0x00, 0x00, 0x4b, 0x40, 0x00, 0x00, 0x1f, 0x00, 0x01, 0x00,
        ])
        .unwrap();
        f.write_all(&[0xff; 16448]).unwrap();

        // Compressed block #4.
        f.write_all(&0x00005027u32.to_le_bytes()).unwrap();
        f.write_all(&[
            0x00, 0x00, 0x00, 0x5f, 0x1c, 0x00, 0x00, 0x1f, 0x00, 0x01, 0x00,
        ])
        .unwrap();
        f.write_all(&[0xff; 7252]).unwrap();
        f.write_all(&[0x43, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00])
            .unwrap();

        // EndMark
        f.write_all(&0x00000000u32.to_le_bytes()).unwrap();

        // Checksum
        f.write_all(&0x22a9944cu32.to_le_bytes()).unwrap();

        f
    }

    fn write_valid_kernel_lz4_legacy() -> File {
        let mut f = tempfile().expect("failed to create tempfile");

        f.write_all(&0x184c2102u32.to_le_bytes()).unwrap(); // magic

        // Compressed block #1.
        f.write_all(&0x000080a6u32.to_le_bytes()).unwrap();
        f.write_all(&[
            0x51, 0x00, 0xc0, 0x2e, 0x14, 0x00, 0x01, 0x00, 0x11, 0xe7, 0x06, 0x00, 0x11, 0x0a,
            0x06, 0x00, 0x0f, 0x02, 0x00, 0x0f, 0x4f, 0x41, 0x52, 0x4d, 0x64, 0x26, 0x00, 0x0f,
            0x0f, 0x02, 0x00,
        ])
        .unwrap();
        f.write_all(&[0xff; 32896]).unwrap();

        // Compressed block #2.
        f.write_all(&0x0000500au32.to_le_bytes()).unwrap();
        f.write_all(&[
            0x00, 0x00, 0x00, 0x9f, 0x5c, 0x00, 0x00, 0x1f, 0x00, 0x01, 0x00,
        ])
        .unwrap();
        f.write_all(&[0xff; 23700]).unwrap();
        f.write_all(&[0x83, 0x50, 0x00]).unwrap();

        // EndMark
        f.write_all(&[0x00, 0x00, 0x00, 0x00]).unwrap();

        f
    }

    #[test]
    fn load_arm64_lz4_valid() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(2 * 1024 * 1024);
        let mut f = write_valid_kernel_lz4();
        let kernel = load_arm64_kernel_lz4(&gm, kernel_addr, &mut f).unwrap();
        assert_eq!(kernel.address_range.start, 0x107_0000);
        assert_eq!(kernel.address_range.end, 0x1E3_3807);
        assert_eq!(kernel.size, 0xDC_3808);
        assert_eq!(kernel.entry, GuestAddress(0x107_0000));
    }

    #[test]
    fn load_arm64_lz4_bad_magic() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(2 * 1024 * 1024);
        let mut f = write_valid_kernel_lz4();

        mutate_file(&f, 0, &[0xCC, 0xCC, 0xCC, 0xCC]);

        assert_eq!(
            load_arm64_kernel_lz4(&gm, kernel_addr, &mut f),
            Err(Error::ReadHeader)
        );
    }

    #[test]
    fn load_arm64_lz4_bad_block() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(2 * 1024 * 1024);
        let mut f = write_valid_kernel_lz4();

        mutate_file(&f, 7, &[0xCC, 0xCC, 0xCC, 0xCC]);

        assert_eq!(
            load_arm64_kernel_lz4(&gm, kernel_addr, &mut f),
            Err(Error::ReadHeader)
        );
    }

    #[test]
    fn load_arm64_lz4_legacy_valid() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(2 * 1024 * 1024);
        let mut f = write_valid_kernel_lz4_legacy();
        let kernel = load_arm64_kernel_lz4(&gm, kernel_addr, &mut f).unwrap();
        assert_eq!(kernel.address_range.start, 0x107_0000);
        assert_eq!(kernel.address_range.end, 0x1E3_3807);
        assert_eq!(kernel.size, 0xDC_3808);
        assert_eq!(kernel.entry, GuestAddress(0x107_0000));
    }

    #[test]
    fn load_arm64_lz4_legacy_bad_magic() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(2 * 1024 * 1024);
        let mut f = write_valid_kernel_lz4_legacy();

        mutate_file(&f, 0, &[0xCC, 0xCC, 0xCC, 0xCC]);

        assert_eq!(
            load_arm64_kernel_lz4(&gm, kernel_addr, &mut f),
            Err(Error::ReadHeader)
        );
    }

    #[test]
    fn load_arm64_lz4_legacy_bad_block() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(2 * 1024 * 1024);
        let mut f = write_valid_kernel_lz4_legacy();

        mutate_file(&f, 4, &[0xCC, 0xCC, 0xCC, 0xCC]);

        assert_eq!(
            load_arm64_kernel_lz4(&gm, kernel_addr, &mut f),
            Err(Error::ReadHeader)
        );
    }
}
