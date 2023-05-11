// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;

use data_model::VolatileSlice;

/// A trait for flushing the contents of a file to disk.
/// This is equivalent to File's `sync_all` and `sync_data` methods, but wrapped in a trait so that
/// it can be implemented for other types.
pub trait FileSync {
    // Flush buffers related to this file to disk.
    fn fsync(&mut self) -> Result<()>;

    // Flush buffers related to this file's data to disk, avoiding updating extra metadata. Note
    // that an implementation may simply implement fsync for fdatasync.
    fn fdatasync(&mut self) -> Result<()>;
}

impl FileSync for File {
    fn fsync(&mut self) -> Result<()> {
        self.sync_all()
    }

    fn fdatasync(&mut self) -> Result<()> {
        self.sync_data()
    }
}

/// A trait for setting the size of a file.
/// This is equivalent to File's `set_len` method, but
/// wrapped in a trait so that it can be implemented for
/// other types.
pub trait FileSetLen {
    // Set the size of this file.
    // This is the moral equivalent of `ftruncate()`.
    fn set_len(&self, _len: u64) -> Result<()>;
}

impl FileSetLen for File {
    fn set_len(&self, len: u64) -> Result<()> {
        File::set_len(self, len)
    }
}

/// A trait for allocating disk space in a sparse file.
/// This is equivalent to fallocate() with no special flags.
pub trait FileAllocate {
    /// Allocate storage for the region of the file starting at `offset` and extending `len` bytes.
    fn allocate(&mut self, offset: u64, len: u64) -> Result<()>;
}

/// A trait for getting the size of a file.
/// This is equivalent to File's metadata().len() method,
/// but wrapped in a trait so that it can be implemented for
/// other types.
pub trait FileGetLen {
    /// Get the current length of the file in bytes.
    fn get_len(&self) -> Result<u64>;
}

impl FileGetLen for File {
    fn get_len(&self) -> Result<u64> {
        Ok(self.metadata()?.len())
    }
}

/// A trait similar to `Read` and `Write`, but uses volatile memory as buffers.
pub trait FileReadWriteVolatile {
    /// Read bytes from this file into the given slice, returning the number of bytes read on
    /// success.
    fn read_volatile(&mut self, slice: VolatileSlice) -> Result<usize>;

    /// Like `read_volatile`, except it reads to a slice of buffers. Data is copied to fill each
    /// buffer in order, with the final buffer written to possibly being only partially filled. This
    /// method must behave as a single call to `read_volatile` with the buffers concatenated would.
    /// The default implementation calls `read_volatile` with either the first nonempty buffer
    /// provided, or returns `Ok(0)` if none exists.
    fn read_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> Result<usize> {
        bufs.iter()
            .find(|b| b.size() > 0)
            .map(|&b| self.read_volatile(b))
            .unwrap_or(Ok(0))
    }

    /// Reads bytes from this into the given slice until all bytes in the slice are written, or an
    /// error is returned.
    fn read_exact_volatile(&mut self, mut slice: VolatileSlice) -> Result<()> {
        while slice.size() > 0 {
            let bytes_read = self.read_volatile(slice)?;
            if bytes_read == 0 {
                return Err(Error::from(ErrorKind::UnexpectedEof));
            }
            // Will panic if read_volatile read more bytes than we gave it, which would be worthy of
            // a panic.
            slice = slice.offset(bytes_read).unwrap();
        }
        Ok(())
    }

    /// Write bytes from the slice to the given file, returning the number of bytes written on
    /// success.
    fn write_volatile(&mut self, slice: VolatileSlice) -> Result<usize>;

    /// Like `write_volatile`, except that it writes from a slice of buffers. Data is copied from
    /// each buffer in order, with the final buffer read from possibly being only partially
    /// consumed. This method must behave as a call to `write_volatile` with the buffers
    /// concatenated would. The default implementation calls `write_volatile` with either the first
    /// nonempty buffer provided, or returns `Ok(0)` if none exists.
    fn write_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> Result<usize> {
        bufs.iter()
            .find(|b| b.size() > 0)
            .map(|&b| self.write_volatile(b))
            .unwrap_or(Ok(0))
    }

    /// Write bytes from the slice to the given file until all the bytes from the slice have been
    /// written, or an error is returned.
    fn write_all_volatile(&mut self, mut slice: VolatileSlice) -> Result<()> {
        while slice.size() > 0 {
            let bytes_written = self.write_volatile(slice)?;
            if bytes_written == 0 {
                return Err(Error::from(ErrorKind::WriteZero));
            }
            // Will panic if read_volatile read more bytes than we gave it, which would be worthy of
            // a panic.
            slice = slice.offset(bytes_written).unwrap();
        }
        Ok(())
    }
}

impl<'a, T: FileReadWriteVolatile + ?Sized> FileReadWriteVolatile for &'a mut T {
    fn read_volatile(&mut self, slice: VolatileSlice) -> Result<usize> {
        (**self).read_volatile(slice)
    }

    fn read_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> Result<usize> {
        (**self).read_vectored_volatile(bufs)
    }

    fn read_exact_volatile(&mut self, slice: VolatileSlice) -> Result<()> {
        (**self).read_exact_volatile(slice)
    }

    fn write_volatile(&mut self, slice: VolatileSlice) -> Result<usize> {
        (**self).write_volatile(slice)
    }

    fn write_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> Result<usize> {
        (**self).write_vectored_volatile(bufs)
    }

    fn write_all_volatile(&mut self, slice: VolatileSlice) -> Result<()> {
        (**self).write_all_volatile(slice)
    }
}

/// A trait similar to the unix `ReadExt` and `WriteExt` traits, but for volatile memory.
pub trait FileReadWriteAtVolatile {
    /// Reads bytes from this file at `offset` into the given slice, returning the number of bytes
    /// read on success. On Windows file pointer will update with the read, but on Linux the
    /// file pointer will not change.
    fn read_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize>;

    /// Like `read_at_volatile`, except it reads to a slice of buffers. Data is copied to fill each
    /// buffer in order, with the final buffer written to possibly being only partially filled. This
    /// method must behave as a single call to `read_at_volatile` with the buffers concatenated
    /// would. The default implementation calls `read_at_volatile` with either the first nonempty
    /// buffer provided, or returns `Ok(0)` if none exists.
    /// On Windows file pointer will update with the read, but on Linux the file pointer will not change.
    fn read_vectored_at_volatile(&mut self, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        if let Some(&slice) = bufs.first() {
            self.read_at_volatile(slice, offset)
        } else {
            Ok(0)
        }
    }

    /// Reads bytes from this file at `offset` into the given slice until all bytes in the slice are
    /// read, or an error is returned. On Windows file pointer will update with the read, but on Linux the
    /// file pointer will not change.
    fn read_exact_at_volatile(&mut self, mut slice: VolatileSlice, mut offset: u64) -> Result<()> {
        while slice.size() > 0 {
            match self.read_at_volatile(slice, offset) {
                Ok(0) => return Err(Error::from(ErrorKind::UnexpectedEof)),
                Ok(n) => {
                    slice = slice.offset(n).unwrap();
                    offset = offset.checked_add(n as u64).unwrap();
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Writes bytes to this file at `offset` from the given slice, returning the number of bytes
    /// written on success. On Windows file pointer will update with the write, but on Linux the
    /// file pointer will not change.
    fn write_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize>;

    /// Like `write_at_volatile`, except that it writes from a slice of buffers. Data is copied
    /// from each buffer in order, with the final buffer read from possibly being only partially
    /// consumed. This method must behave as a call to `write_at_volatile` with the buffers
    /// concatenated would. The default implementation calls `write_at_volatile` with either the
    /// first nonempty buffer provided, or returns `Ok(0)` if none exists.
    /// On Windows file pointer will update with the write, but on Linux the file pointer will not change.
    fn write_vectored_at_volatile(&mut self, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        if let Some(&slice) = bufs.first() {
            self.write_at_volatile(slice, offset)
        } else {
            Ok(0)
        }
    }

    /// Writes bytes to this file at `offset` from the given slice until all bytes in the slice
    /// are written, or an error is returned. On Windows file pointer will update with the write,
    /// but on Linux the file pointer will not change.
    fn write_all_at_volatile(&mut self, mut slice: VolatileSlice, mut offset: u64) -> Result<()> {
        while slice.size() > 0 {
            match self.write_at_volatile(slice, offset) {
                Ok(0) => return Err(Error::from(ErrorKind::WriteZero)),
                Ok(n) => {
                    slice = slice.offset(n).unwrap();
                    offset = offset.checked_add(n as u64).unwrap();
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl<'a, T: FileReadWriteAtVolatile + ?Sized> FileReadWriteAtVolatile for &'a mut T {
    fn read_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize> {
        (**self).read_at_volatile(slice, offset)
    }

    fn read_vectored_at_volatile(&mut self, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        (**self).read_vectored_at_volatile(bufs, offset)
    }

    fn read_exact_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<()> {
        (**self).read_exact_at_volatile(slice, offset)
    }

    fn write_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize> {
        (**self).write_at_volatile(slice, offset)
    }

    fn write_vectored_at_volatile(&mut self, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        (**self).write_vectored_at_volatile(bufs, offset)
    }

    fn write_all_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<()> {
        (**self).write_all_at_volatile(slice, offset)
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
    fn read_file() -> Result<()> {
        let mut f = tempfile()?;
        f.write_all(b"AAAAAAAAAAbbbbbbbbbbAAAAA")
            .expect("Failed to write bytes");
        f.seek(SeekFrom::Start(0))?;

        let mut omem = [0u8; 30];
        let om = &mut omem[..];
        let buf = VolatileSlice::new(om);
        f.read_volatile(buf).expect("read_volatile failed.");

        f.seek(SeekFrom::Start(0))?;

        let mut mem = [0u8; 30];
        let (m1, rest) = mem.split_at_mut(10);
        let (m2, m3) = rest.split_at_mut(10);
        let buf1 = VolatileSlice::new(m1);
        let buf2 = VolatileSlice::new(m2);
        let buf3 = VolatileSlice::new(m3);
        let bufs = [buf1, buf2, buf3];

        f.read_vectored_volatile(&bufs)
            .expect("read_vectored_volatile failed.");

        assert_eq!(&mem[..], b"AAAAAAAAAAbbbbbbbbbbAAAAA\0\0\0\0\0");
        Ok(())
    }

    #[test]
    fn write_file() -> Result<()> {
        let mut f = tempfile()?;

        let mut omem = [0u8; 25];
        let om = &mut omem[..];
        let buf = VolatileSlice::new(om);
        buf.write_bytes(65);
        f.write_volatile(buf).expect("write_volatile failed.");

        f.seek(SeekFrom::Start(0))?;

        let mut filebuf = [0u8; 25];
        f.read_exact(&mut filebuf).expect("Failed to read filebuf");
        assert_eq!(&filebuf, b"AAAAAAAAAAAAAAAAAAAAAAAAA");
        Ok(())
    }

    #[test]
    fn write_vectored_file() -> Result<()> {
        let mut f = tempfile()?;

        let mut mem = [0u8; 30];
        let (m1, rest) = mem.split_at_mut(10);
        let (m2, m3) = rest.split_at_mut(10);
        let buf1 = VolatileSlice::new(m1);
        let buf2 = VolatileSlice::new(m2);
        let buf3 = VolatileSlice::new(m3);
        buf1.write_bytes(65);
        buf2.write_bytes(98);
        buf3.write_bytes(65);
        let bufs = [buf1, buf2, buf3];
        f.write_vectored_volatile(&bufs)
            .expect("write_vectored_volatile failed.");

        f.seek(SeekFrom::Start(0))?;

        let mut filebuf = [0u8; 30];
        f.read_exact(&mut filebuf).expect("Failed to read filebuf.");
        assert_eq!(&filebuf, b"AAAAAAAAAAbbbbbbbbbbAAAAAAAAAA");
        Ok(())
    }

    #[test]
    fn read_at_file() -> Result<()> {
        let mut f = tempfile()?;
        f.write_all(b"AAAAAAAAAAbbbbbbbbbbAAAAA")
            .expect("Failed to write bytes.");

        let mut omem = [0u8; 20];
        let om = &mut omem[..];
        let buf = VolatileSlice::new(om);
        f.read_at_volatile(buf, 10)
            .expect("read_at_volatile failed.");

        assert_eq!(om, b"bbbbbbbbbbAAAAA\0\0\0\0\0");

        let mut mem = [0u8; 20];
        let (m1, m2) = mem.split_at_mut(10);
        let buf1 = VolatileSlice::new(m1);
        let buf2 = VolatileSlice::new(m2);
        let bufs = [buf1, buf2];

        f.read_vectored_at_volatile(&bufs, 10)
            .expect("read_vectored_at_volatile failed.");

        assert_eq!(&mem[..], b"bbbbbbbbbbAAAAA\0\0\0\0\0");
        Ok(())
    }

    #[test]
    fn write_at_file() -> Result<()> {
        let mut f = tempfile()?;
        f.write_all(b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
            .expect("Failed to write bytes");

        let mut omem = [0u8; 15];
        let om = &mut omem[..];
        let buf = VolatileSlice::new(om);
        buf.write_bytes(65);
        f.write_at_volatile(buf, 10)
            .expect("write_at_volatile failed.");

        f.seek(SeekFrom::Start(0))?;

        let mut filebuf = [0u8; 30];
        f.read_exact(&mut filebuf).expect("Failed to read filebuf.");
        assert_eq!(&filebuf, b"ZZZZZZZZZZAAAAAAAAAAAAAAAZZZZZ");
        Ok(())
    }

    #[test]
    fn write_vectored_at_file() -> Result<()> {
        let mut f = tempfile()?;
        f.write_all(b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
            .expect("Failed to write bytes");

        let mut mem = [0u8; 30];
        let (m1, m2) = mem.split_at_mut(10);
        let buf1 = VolatileSlice::new(m1);
        let buf2 = VolatileSlice::new(m2);
        buf1.write_bytes(65);
        buf2.write_bytes(98);
        let bufs = [buf1, buf2];
        f.write_vectored_at_volatile(&bufs, 10)
            .expect("write_vectored_at_volatile failed.");

        f.seek(SeekFrom::Start(0))?;

        let mut filebuf = [0u8; 30];
        f.read_exact(&mut filebuf).expect("Failed to read filebuf.");
        assert_eq!(&filebuf, b"ZZZZZZZZZZAAAAAAAAAAbbbbbbbbbb");
        Ok(())
    }
}
