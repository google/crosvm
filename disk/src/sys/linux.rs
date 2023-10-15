// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use cros_async::Executor;

use crate::Error;
use crate::Result;
use crate::SingleFileDisk;

pub fn apply_raw_disk_file_options(_raw_image: &File, _is_sparse_file: bool) -> Result<()> {
    // No op on unix.
    Ok(())
}

pub fn read_from_disk(
    mut file: &File,
    offset: u64,
    buf: &mut [u8],
    _overlapped_mode: bool,
) -> Result<()> {
    file.seek(SeekFrom::Start(offset))
        .map_err(Error::SeekingFile)?;
    file.read_exact(buf).map_err(Error::ReadingHeader)
}

impl SingleFileDisk {
    pub fn new(disk: File, ex: &Executor) -> Result<Self> {
        ex.async_from(disk)
            .map_err(Error::CreateSingleFileDisk)
            .map(|inner| SingleFileDisk { inner })
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::Write;

    use base::pagesize;
    use cros_async::Executor;
    use cros_async::MemRegion;
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;

    use crate::*;

    #[test]
    fn read_async() {
        async fn read_zeros_async(ex: &Executor) {
            let guest_mem =
                Arc::new(GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap());
            let f = File::open("/dev/zero").unwrap();
            let async_file = SingleFileDisk::new(f, ex).unwrap();
            let result = async_file
                .read_to_mem(
                    0,
                    guest_mem,
                    MemRegionIter::new(&[MemRegion { offset: 0, len: 48 }]),
                )
                .await;
            assert_eq!(48, result.unwrap());
        }

        let ex = Executor::new().unwrap();
        ex.run_until(read_zeros_async(&ex)).unwrap();
    }

    #[test]
    fn write_async() {
        async fn write_zeros_async(ex: &Executor) {
            let guest_mem =
                Arc::new(GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap());
            let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
            let async_file = SingleFileDisk::new(f, ex).unwrap();
            let result = async_file
                .write_from_mem(
                    0,
                    guest_mem,
                    MemRegionIter::new(&[MemRegion { offset: 0, len: 48 }]),
                )
                .await;
            assert_eq!(48, result.unwrap());
        }

        let ex = Executor::new().unwrap();
        ex.run_until(write_zeros_async(&ex)).unwrap();
    }

    #[test]
    fn detect_image_type_raw() {
        let mut t = tempfile::tempfile().unwrap();
        // Fill the first block of the file with "random" data.
        let buf = "ABCD".as_bytes().repeat(1024);
        t.write_all(&buf).unwrap();
        let image_type = detect_image_type(&t, false).expect("failed to detect image type");
        assert_eq!(image_type, ImageType::Raw);
    }

    #[test]
    #[cfg(feature = "qcow")]
    fn detect_image_type_qcow2() {
        let mut t = tempfile::tempfile().unwrap();
        // Write the qcow2 magic signature. The rest of the header is not filled in, so if
        // detect_image_type is ever updated to validate more of the header, this test would need
        // to be updated.
        let buf: &[u8] = &[0x51, 0x46, 0x49, 0xfb];
        t.write_all(buf).unwrap();
        let image_type = detect_image_type(&t, false).expect("failed to detect image type");
        assert_eq!(image_type, ImageType::Qcow2);
    }

    #[test]
    #[cfg(feature = "android-sparse")]
    fn detect_image_type_android_sparse() {
        let mut t = tempfile::tempfile().unwrap();
        // Write the Android sparse magic signature. The rest of the header is not filled in, so if
        // detect_image_type is ever updated to validate more of the header, this test would need
        // to be updated.
        let buf: &[u8] = &[0x3a, 0xff, 0x26, 0xed];
        t.write_all(buf).unwrap();
        let image_type = detect_image_type(&t, false).expect("failed to detect image type");
        assert_eq!(image_type, ImageType::AndroidSparse);
    }

    #[test]
    #[cfg(feature = "composite-disk")]
    fn detect_image_type_composite() {
        let mut t = tempfile::tempfile().unwrap();
        // Write the composite disk magic signature. The rest of the header is not filled in, so if
        // detect_image_type is ever updated to validate more of the header, this test would need
        // to be updated.
        let buf = "composite_disk\x1d".as_bytes();
        t.write_all(buf).unwrap();
        let image_type = detect_image_type(&t, false).expect("failed to detect image type");
        assert_eq!(image_type, ImageType::CompositeDisk);
    }

    #[test]
    fn detect_image_type_small_file() {
        let mut t = tempfile::tempfile().unwrap();
        // Write a file smaller than the four-byte qcow2/sparse magic to ensure the small file logic
        // works correctly and handles it as a raw file.
        let buf: &[u8] = &[0xAA, 0xBB];
        t.write_all(buf).unwrap();
        let image_type = detect_image_type(&t, false).expect("failed to detect image type");
        assert_eq!(image_type, ImageType::Raw);
    }
}
