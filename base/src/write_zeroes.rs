// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io;
use std::io::Error;
use std::io::ErrorKind;

/// A trait for deallocating space in a file.
pub trait PunchHole {
    /// Replace a range of bytes with a hole.
    fn punch_hole(&self, offset: u64, length: u64) -> io::Result<()>;
}

impl PunchHole for File {
    fn punch_hole(&self, offset: u64, length: u64) -> io::Result<()> {
        crate::platform::file_punch_hole(self, offset, length)
    }
}

/// A trait for writing zeroes to an arbitrary position in a file.
pub trait WriteZeroesAt {
    /// Write up to `length` bytes of zeroes starting at `offset`, returning how many bytes were
    /// written.
    fn write_zeroes_at(&mut self, offset: u64, length: usize) -> io::Result<usize>;

    /// Write zeroes starting at `offset` until `length` bytes have been written.
    ///
    /// This method will continuously call `write_zeroes_at` until the requested
    /// `length` is satisfied or an error is encountered.
    fn write_zeroes_all_at(&mut self, mut offset: u64, mut length: usize) -> io::Result<()> {
        while length > 0 {
            match self.write_zeroes_at(offset, length) {
                Ok(0) => return Err(Error::from(ErrorKind::WriteZero)),
                Ok(bytes_written) => {
                    length = length
                        .checked_sub(bytes_written)
                        .ok_or_else(|| Error::from(ErrorKind::Other))?;
                    offset = offset
                        .checked_add(bytes_written as u64)
                        .ok_or_else(|| Error::from(ErrorKind::Other))?;
                }
                Err(e) => {
                    if e.kind() != ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }
}

impl WriteZeroesAt for File {
    fn write_zeroes_at(&mut self, offset: u64, length: usize) -> io::Result<usize> {
        crate::platform::file_write_zeroes_at(self, offset, length)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;

    use tempfile::tempfile;

    use super::*;

    #[test]
    fn simple_test() {
        let mut f = tempfile().unwrap();

        // Extend and fill the file with zero bytes.
        // This is not using set_len() because that fails on wine.
        let init_data = [0x00u8; 16384];
        f.write_all(&init_data).unwrap();

        // Write buffer of non-zero bytes to offset 1234
        let orig_data = [0x55u8; 5678];
        f.seek(SeekFrom::Start(1234)).unwrap();
        f.write_all(&orig_data).unwrap();

        // Read back the data plus some overlap on each side
        let mut readback = [0u8; 16384];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read_exact(&mut readback).unwrap();
        // Bytes before the write should still be 0
        for read in &readback[0..1234] {
            assert_eq!(*read, 0);
        }
        // Bytes that were just written should be 0x55
        for read in &readback[1234..(1234 + 5678)] {
            assert_eq!(*read, 0x55);
        }
        // Bytes after the written area should still be 0
        for read in &readback[(1234 + 5678)..] {
            assert_eq!(*read, 0);
        }

        // Overwrite some of the data with zeroes
        f.write_zeroes_all_at(2345, 4321)
            .expect("write_zeroes failed");

        // Read back the data and verify that it is now zero
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read_exact(&mut readback).unwrap();
        // Bytes before the write should still be 0
        for read in &readback[0..1234] {
            assert_eq!(*read, 0);
        }
        // Original data should still exist before the write_zeroes region
        for read in &readback[1234..2345] {
            assert_eq!(*read, 0x55);
        }
        // The write_zeroes region should now be zero
        for read in &readback[2345..(2345 + 4321)] {
            assert_eq!(*read, 0);
        }
        // Original data should still exist after the write_zeroes region
        for read in &readback[(2345 + 4321)..(1234 + 5678)] {
            assert_eq!(*read, 0x55);
        }
        // The rest of the file should still be 0
        for read in &readback[(1234 + 5678)..] {
            assert_eq!(*read, 0);
        }
    }

    #[test]
    fn large_write_zeroes() {
        let mut f = tempfile().unwrap();

        // Extend and fill the file with zero bytes.
        // This is not using set_len() because that fails on wine.
        let init_data = [0x00u8; 16384];
        f.write_all(&init_data).unwrap();

        // Write buffer of non-zero bytes
        let orig_data = [0x55u8; 0x20000];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&orig_data).unwrap();

        // Overwrite some of the data with zeroes
        f.write_zeroes_all_at(0, 0x10001)
            .expect("write_zeroes failed");

        // Read back the data and verify that it is now zero
        let mut readback = [0u8; 0x20000];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read_exact(&mut readback).unwrap();
        // The write_zeroes region should now be zero
        for read in &readback[0..0x10001] {
            assert_eq!(*read, 0);
        }
        // Original data should still exist after the write_zeroes region
        for read in &readback[0x10001..0x20000] {
            assert_eq!(*read, 0x55);
        }
    }
}
