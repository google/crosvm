// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    cmp::min,
    fs::File,
    io::{
        Error, ErrorKind, Seek, SeekFrom, {self},
    },
    os::unix::fs::FileExt,
};

use super::{fallocate, FallocateMode};

/// A trait for deallocating space in a file.
pub trait PunchHole {
    /// Replace a range of bytes with a hole.
    fn punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()>;
}

impl PunchHole for File {
    fn punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()> {
        fallocate(self, FallocateMode::PunchHole, true, offset, length as u64)
            .map_err(|e| io::Error::from_raw_os_error(e.errno()))
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

impl WriteZeroesAt for File {
    fn write_zeroes_at(&mut self, offset: u64, length: usize) -> io::Result<usize> {
        // Try to use fallocate() first.
        if fallocate(self, FallocateMode::ZeroRange, true, offset, length as u64).is_ok() {
            return Ok(length);
        }

        // fall back to write()
        // fallocate() failed; fall back to writing a buffer of zeroes
        // until we have written up to length.
        let buf_size = min(length, 0x10000);
        let buf = vec![0u8; buf_size];
        let mut nwritten: usize = 0;
        while nwritten < length {
            let remaining = length - nwritten;
            let write_size = min(remaining, buf_size);
            nwritten += self.write_at(&buf[0..write_size], offset + nwritten as u64)?;
        }
        Ok(length)
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
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::tempfile;

    #[test]
    fn simple_test() {
        let mut f = tempfile().unwrap();
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
        let mut f = tempfile().unwrap();
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
