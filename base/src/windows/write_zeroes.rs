// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    fs::File,
    io::{
        Error, ErrorKind, Seek, SeekFrom, {self},
    },
};

#[path = "win/punch_hole.rs"]
mod punch_hole;

#[path = "win/write_zeros.rs"]
mod write_zeros;

use super::write_zeroes::punch_hole::execute_punch_hole;

/// A trait for deallocating space in a file.
pub trait PunchHole {
    /// Replace a range of bytes with a hole.
    fn punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()>;
}

impl PunchHole for File {
    fn punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()> {
        execute_punch_hole(self, offset, length)
    }
}

/// A trait for writing zeroes to a stream.
pub trait WriteZeroes {
    /// Write up to `length` bytes of zeroes to the stream, returning how many bytes were written.
    fn write_zeroes(&mut self, length: usize) -> io::Result<usize>;

    /// Write zeroes to the stream until `length` bytes have been written.
    ///
    /// This method will continuously call `write_zeroes` until the requested
    /// `length` is satisfied or an error is encountered.
    fn write_zeroes_all(&mut self, mut length: usize) -> io::Result<()> {
        while length > 0 {
            match self.write_zeroes(length) {
                Ok(0) => return Err(Error::from(ErrorKind::WriteZero)),
                Ok(bytes_written) => {
                    length = length
                        .checked_sub(bytes_written)
                        .ok_or_else(|| Error::from(ErrorKind::Other))?
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

impl<T: WriteZeroesAt + Seek> WriteZeroes for T {
    fn write_zeroes(&mut self, length: usize) -> io::Result<usize> {
        let offset = self.seek(SeekFrom::Current(0))?;
        let nwritten = self.write_zeroes_at(offset, length)?;
        // Advance the seek cursor as if we had done a real write().
        self.seek(SeekFrom::Current(nwritten as i64))?;
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom, Write},
    };
    use tempfile::TempDir;

    #[test]
    fn simple_test() {
        let tempdir = TempDir::new().unwrap();
        let mut path = tempdir.path().to_owned();
        path.push("file");
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .unwrap();
        f.set_len(16384).unwrap();

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
        f.seek(SeekFrom::Start(2345)).unwrap();
        f.write_zeroes_all(4321).expect("write_zeroes failed");
        // Verify seek position after write_zeroes_all()
        assert_eq!(f.seek(SeekFrom::Current(0)).unwrap(), 2345 + 4321);

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
        let tempdir = TempDir::new().unwrap();
        let mut path = tempdir.path().to_owned();
        path.push("file");
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .unwrap();
        f.set_len(16384).unwrap();

        // Write buffer of non-zero bytes
        let orig_data = [0x55u8; 0x20000];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&orig_data).unwrap();

        // Overwrite some of the data with zeroes
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_zeroes_all(0x10001).expect("write_zeroes failed");
        // Verify seek position after write_zeroes_all()
        assert_eq!(f.seek(SeekFrom::Current(0)).unwrap(), 0x10001);

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
