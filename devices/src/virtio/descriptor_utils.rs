// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::borrow::Cow;
use std::cmp;
use std::convert::TryInto;
use std::fmt::{self, Display};
use std::io::{self, Read, Write};
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::mem::{size_of, MaybeUninit};
use std::ptr::copy_nonoverlapping;
use std::result;

use data_model::{DataInit, Le16, Le32, Le64, VolatileMemoryError, VolatileSlice};
use sys_util::{FileReadWriteAtVolatile, FileReadWriteVolatile, GuestAddress, GuestMemory};

use super::DescriptorChain;

#[derive(Debug)]
pub enum Error {
    DescriptorChainOverflow,
    GuestMemoryError(sys_util::GuestMemoryError),
    InvalidChain,
    IoError(io::Error),
    SplitOutOfBounds(usize),
    VolatileMemoryError(VolatileMemoryError),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            DescriptorChainOverflow => write!(
                f,
                "the combined length of all the buffers in a `DescriptorChain` would overflow"
            ),
            GuestMemoryError(e) => write!(f, "descriptor guest memory error: {}", e),
            InvalidChain => write!(f, "invalid descriptor chain"),
            IoError(e) => write!(f, "descriptor I/O error: {}", e),
            SplitOutOfBounds(off) => write!(f, "`DescriptorChain` split is out of bounds: {}", off),
            VolatileMemoryError(e) => write!(f, "volatile memory error: {}", e),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

impl std::error::Error for Error {}

#[derive(Clone)]
struct DescriptorChainConsumer<'a> {
    buffers: Vec<VolatileSlice<'a>>,
    current: usize,
    bytes_consumed: usize,
}

impl<'a> DescriptorChainConsumer<'a> {
    fn available_bytes(&self) -> usize {
        // This is guaranteed not to overflow because the total length of the chain
        // is checked during all creations of `DescriptorChainConsumer` (see
        // `Reader::new()` and `Writer::new()`).
        self.get_remaining()
            .iter()
            .fold(0usize, |count, buf| count + buf.size())
    }

    fn bytes_consumed(&self) -> usize {
        self.bytes_consumed
    }

    /// Returns all the remaining buffers in the `DescriptorChain`. Calling this function does not
    /// consume any bytes from the `DescriptorChain`. Instead callers should use the `consume`
    /// method to advance the `DescriptorChain`. Multiple calls to `get` with no intervening calls
    /// to `consume` will return the same data.
    fn get_remaining(&self) -> &[VolatileSlice] {
        &self.buffers[self.current..]
    }

    /// Like `get_remaining` but guarantees that the combined length of all the returned iovecs is
    /// not greater than `count`. The combined length of the returned iovecs may be less than
    /// `count` but will always be greater than 0 as long as there is still space left in the
    /// `DescriptorChain`.
    fn get_remaining_with_count(&self, count: usize) -> Cow<[VolatileSlice]> {
        let iovs = self.get_remaining();
        let mut iov_count = 0;
        let mut rem = count;
        for iov in iovs {
            if rem < iov.size() {
                break;
            }

            iov_count += 1;
            rem -= iov.size();
        }

        // Special case where the number of bytes to be copied is smaller than the `size()` of the
        // first iovec.
        if iov_count == 0 && iovs.len() > 0 && count > 0 {
            debug_assert!(count < iovs[0].size());
            // Safe because we know that count is smaller than the length of the first slice.
            Cow::Owned(vec![iovs[0].sub_slice(0, count).unwrap()])
        } else {
            Cow::Borrowed(&iovs[..iov_count])
        }
    }

    /// Consumes `count` bytes from the `DescriptorChain`. If `count` is larger than
    /// `self.available_bytes()` then all remaining bytes in the `DescriptorChain` will be consumed.
    ///
    /// # Errors
    ///
    /// Returns an error if the total bytes consumed by this `DescriptorChainConsumer` overflows a
    /// usize.
    fn consume(&mut self, mut count: usize) {
        // The implementation is adapted from `IoSlice::advance` in libstd. We can't use
        // `get_remaining` here because then the compiler complains that `self.current` is already
        // borrowed and doesn't allow us to modify it.  We also need to borrow the iovecs mutably.
        let current = self.current;
        for buf in &mut self.buffers[current..] {
            if count == 0 {
                break;
            }

            let consumed = if count < buf.size() {
                // Safe because we know that the iovec pointed to valid memory and we are adding a
                // value that is smaller than the length of the memory.
                *buf = buf.offset(count).unwrap();
                count
            } else {
                self.current += 1;
                buf.size()
            };

            // This shouldn't overflow because `consumed <= buf.size()` and we already verified
            // that adding all `buf.size()` values will not overflow when the Reader/Writer was
            // constructed.
            self.bytes_consumed += consumed;
            count -= consumed;
        }
    }

    fn split_at(&mut self, offset: usize) -> DescriptorChainConsumer<'a> {
        let mut other = self.clone();
        other.consume(offset);
        other.bytes_consumed = 0;

        let mut rem = offset;
        let mut end = self.current;
        for buf in &mut self.buffers[self.current..] {
            if rem < buf.size() {
                // Safe because we are creating a smaller sub-slice.
                *buf = buf.sub_slice(0, rem).unwrap();
                break;
            }

            end += 1;
            rem -= buf.size();
        }

        self.buffers.truncate(end + 1);

        other
    }
}

/// Provides high-level interface over the sequence of memory regions
/// defined by readable descriptors in the descriptor chain.
///
/// Note that virtio spec requires driver to place any device-writable
/// descriptors after any device-readable descriptors (2.6.4.2 in Virtio Spec v1.1).
/// Reader will skip iterating over descriptor chain when first writable
/// descriptor is encountered.
#[derive(Clone)]
pub struct Reader<'a> {
    buffer: DescriptorChainConsumer<'a>,
}

/// An iterator over `DataInit` objects on readable descriptors in the descriptor chain.
pub struct ReaderIterator<'a, T: DataInit> {
    reader: &'a mut Reader<'a>,
    phantom: PhantomData<T>,
}

impl<'a, T: DataInit> Iterator for ReaderIterator<'a, T> {
    type Item = io::Result<T>;

    fn next(&mut self) -> Option<io::Result<T>> {
        if self.reader.available_bytes() == 0 {
            None
        } else {
            Some(self.reader.read_obj())
        }
    }
}

impl<'a> Reader<'a> {
    /// Construct a new Reader wrapper over `desc_chain`.
    pub fn new(mem: &'a GuestMemory, desc_chain: DescriptorChain<'a>) -> Result<Reader<'a>> {
        // TODO(jstaron): Update this code to take the indirect descriptors into account.
        let mut total_len: usize = 0;
        let buffers = desc_chain
            .into_iter()
            .readable()
            .map(|desc| {
                // Verify that summing the descriptor sizes does not overflow.
                // This can happen if a driver tricks a device into reading more data than
                // fits in a `usize`.
                total_len = total_len
                    .checked_add(desc.len as usize)
                    .ok_or(Error::DescriptorChainOverflow)?;

                mem.get_slice_at_addr(
                    desc.addr,
                    desc.len.try_into().expect("u32 doesn't fit in usize"),
                )
                .map_err(Error::GuestMemoryError)
            })
            .collect::<Result<Vec<VolatileSlice>>>()?;
        Ok(Reader {
            buffer: DescriptorChainConsumer {
                buffers,
                current: 0,
                bytes_consumed: 0,
            },
        })
    }

    /// Reads an object from the descriptor chain buffer.
    pub fn read_obj<T: DataInit>(&mut self) -> io::Result<T> {
        let mut obj = MaybeUninit::<T>::uninit();

        // Safe because `MaybeUninit` guarantees that the pointer is valid for
        // `size_of::<T>()` bytes.
        let buf = unsafe {
            ::std::slice::from_raw_parts_mut(obj.as_mut_ptr() as *mut u8, size_of::<T>())
        };

        self.read_exact(buf)?;

        // Safe because any type that implements `DataInit` can be considered initialized
        // even if it is filled with random data.
        Ok(unsafe { obj.assume_init() })
    }

    /// Reads objects by consuming all the remaining data in the descriptor chain buffer and returns
    /// them as a collection. Returns an error if the size of the remaining data is indivisible by
    /// the size of an object of type `T`.
    pub fn collect<C: FromIterator<io::Result<T>>, T: DataInit>(&'a mut self) -> C {
        C::from_iter(self.iter())
    }

    /// Creates an iterator for sequentially reading `DataInit` objects from the `Reader`. Unlike
    /// `collect`, this doesn't consume all the remaining data in the `Reader` and doesn't require
    /// the objects to be stored in a separate collection.
    pub fn iter<T: DataInit>(&'a mut self) -> ReaderIterator<'a, T> {
        ReaderIterator {
            reader: self,
            phantom: PhantomData,
        }
    }

    /// Reads data from the descriptor chain buffer into a file descriptor.
    /// Returns the number of bytes read from the descriptor chain buffer.
    /// The number of bytes read can be less than `count` if there isn't
    /// enough data in the descriptor chain buffer.
    pub fn read_to<F: FileReadWriteVolatile>(
        &mut self,
        mut dst: F,
        count: usize,
    ) -> io::Result<usize> {
        let iovs = self.buffer.get_remaining_with_count(count);
        let written = dst.write_vectored_volatile(&iovs[..])?;
        self.buffer.consume(written);
        Ok(written)
    }

    /// Reads data from the descriptor chain buffer into a File at offset `off`.
    /// Returns the number of bytes read from the descriptor chain buffer.
    /// The number of bytes read can be less than `count` if there isn't
    /// enough data in the descriptor chain buffer.
    pub fn read_to_at<F: FileReadWriteAtVolatile>(
        &mut self,
        mut dst: F,
        count: usize,
        off: u64,
    ) -> io::Result<usize> {
        let iovs = self.buffer.get_remaining_with_count(count);
        let written = dst.write_vectored_at_volatile(&iovs[..], off)?;
        self.buffer.consume(written);
        Ok(written)
    }

    pub fn read_exact_to<F: FileReadWriteVolatile>(
        &mut self,
        mut dst: F,
        mut count: usize,
    ) -> io::Result<()> {
        while count > 0 {
            match self.read_to(&mut dst, count) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    ))
                }
                Ok(n) => count -= n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    pub fn read_exact_to_at<F: FileReadWriteAtVolatile>(
        &mut self,
        mut dst: F,
        mut count: usize,
        mut off: u64,
    ) -> io::Result<()> {
        while count > 0 {
            match self.read_to_at(&mut dst, count, off) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    ))
                }
                Ok(n) => {
                    count -= n;
                    off += n as u64;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Returns number of bytes available for reading.  May return an error if the combined
    /// lengths of all the buffers in the DescriptorChain would cause an integer overflow.
    pub fn available_bytes(&self) -> usize {
        self.buffer.available_bytes()
    }

    /// Returns number of bytes already read from the descriptor chain buffer.
    pub fn bytes_read(&self) -> usize {
        self.buffer.bytes_consumed()
    }

    /// Returns a `&[VolatileSlice]` that represents all the remaining data in this `Reader`.
    /// Calling this method does not actually consume any data from the `Reader` and callers should
    /// call `consume` to advance the `Reader`.
    pub fn get_remaining(&self) -> &[VolatileSlice] {
        self.buffer.get_remaining()
    }

    /// Consumes `amt` bytes from the underlying descriptor chain. If `amt` is larger than the
    /// remaining data left in this `Reader`, then all remaining data will be consumed.
    pub fn consume(&mut self, amt: usize) {
        self.buffer.consume(amt)
    }

    /// Splits this `Reader` into two at the given offset in the `DescriptorChain` buffer. After the
    /// split, `self` will be able to read up to `offset` bytes while the returned `Reader` can read
    /// up to `available_bytes() - offset` bytes. If `offset > self.available_bytes()`, then the
    /// returned `Reader` will not be able to read any bytes.
    pub fn split_at(&mut self, offset: usize) -> Reader<'a> {
        Reader {
            buffer: self.buffer.split_at(offset),
        }
    }
}

impl<'a> io::Read for Reader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rem = buf;
        let mut total = 0;
        for b in self.buffer.get_remaining() {
            if rem.len() == 0 {
                break;
            }

            let count = cmp::min(rem.len(), b.size());

            // Safe because we have already verified that `b` points to valid memory.
            unsafe {
                copy_nonoverlapping(b.as_ptr(), rem.as_mut_ptr(), count);
            }
            rem = &mut rem[count..];
            total += count;
        }

        self.buffer.consume(total);
        Ok(total)
    }
}

/// Provides high-level interface over the sequence of memory regions
/// defined by writable descriptors in the descriptor chain.
///
/// Note that virtio spec requires driver to place any device-writable
/// descriptors after any device-readable descriptors (2.6.4.2 in Virtio Spec v1.1).
/// Writer will start iterating the descriptors from the first writable one and will
/// assume that all following descriptors are writable.
#[derive(Clone)]
pub struct Writer<'a> {
    buffer: DescriptorChainConsumer<'a>,
}

impl<'a> Writer<'a> {
    /// Construct a new Writer wrapper over `desc_chain`.
    pub fn new(mem: &'a GuestMemory, desc_chain: DescriptorChain<'a>) -> Result<Writer<'a>> {
        let mut total_len: usize = 0;
        let buffers = desc_chain
            .into_iter()
            .writable()
            .map(|desc| {
                // Verify that summing the descriptor sizes does not overflow.
                // This can happen if a driver tricks a device into writing more data than
                // fits in a `usize`.
                total_len = total_len
                    .checked_add(desc.len as usize)
                    .ok_or(Error::DescriptorChainOverflow)?;

                mem.get_slice_at_addr(
                    desc.addr,
                    desc.len.try_into().expect("u32 doesn't fit in usize"),
                )
                .map_err(Error::GuestMemoryError)
            })
            .collect::<Result<Vec<VolatileSlice>>>()?;
        Ok(Writer {
            buffer: DescriptorChainConsumer {
                buffers,
                current: 0,
                bytes_consumed: 0,
            },
        })
    }

    /// Writes an object to the descriptor chain buffer.
    pub fn write_obj<T: DataInit>(&mut self, val: T) -> io::Result<()> {
        self.write_all(val.as_slice())
    }

    /// Writes all objects produced by `iter` into the descriptor chain buffer. Unlike `consume`,
    /// this doesn't require the values to be stored in an intermediate collection first. It also
    /// allows callers to choose which elements in a collection to write, for example by using the
    /// `filter` or `take` methods of the `Iterator` trait.
    pub fn write_iter<T: DataInit, I: Iterator<Item = T>>(&mut self, iter: I) -> io::Result<()> {
        iter.map(|v| self.write_obj(v)).collect()
    }

    /// Writes a collection of objects into the descriptor chain buffer.
    pub fn consume<T: DataInit, C: IntoIterator<Item = T>>(&mut self, vals: C) -> io::Result<()> {
        self.write_iter(vals.into_iter())
    }

    /// Returns number of bytes available for writing.  May return an error if the combined
    /// lengths of all the buffers in the DescriptorChain would cause an overflow.
    pub fn available_bytes(&self) -> usize {
        self.buffer.available_bytes()
    }

    /// Writes data to the descriptor chain buffer from a file descriptor.
    /// Returns the number of bytes written to the descriptor chain buffer.
    /// The number of bytes written can be less than `count` if
    /// there isn't enough data in the descriptor chain buffer.
    pub fn write_from<F: FileReadWriteVolatile>(
        &mut self,
        mut src: F,
        count: usize,
    ) -> io::Result<usize> {
        let iovs = self.buffer.get_remaining_with_count(count);
        let read = src.read_vectored_volatile(&iovs[..])?;
        self.buffer.consume(read);
        Ok(read)
    }

    /// Writes data to the descriptor chain buffer from a File at offset `off`.
    /// Returns the number of bytes written to the descriptor chain buffer.
    /// The number of bytes written can be less than `count` if
    /// there isn't enough data in the descriptor chain buffer.
    pub fn write_from_at<F: FileReadWriteAtVolatile>(
        &mut self,
        mut src: F,
        count: usize,
        off: u64,
    ) -> io::Result<usize> {
        let iovs = self.buffer.get_remaining_with_count(count);
        let read = src.read_vectored_at_volatile(&iovs[..], off)?;
        self.buffer.consume(read);
        Ok(read)
    }

    pub fn write_all_from<F: FileReadWriteVolatile>(
        &mut self,
        mut src: F,
        mut count: usize,
    ) -> io::Result<()> {
        while count > 0 {
            match self.write_from(&mut src, count) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ))
                }
                Ok(n) => count -= n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    pub fn write_all_from_at<F: FileReadWriteAtVolatile>(
        &mut self,
        mut src: F,
        mut count: usize,
        mut off: u64,
    ) -> io::Result<()> {
        while count > 0 {
            match self.write_from_at(&mut src, count, off) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ))
                }
                Ok(n) => {
                    count -= n;
                    off += n as u64;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Returns number of bytes already written to the descriptor chain buffer.
    pub fn bytes_written(&self) -> usize {
        self.buffer.bytes_consumed()
    }

    /// Splits this `Writer` into two at the given offset in the `DescriptorChain` buffer. After the
    /// split, `self` will be able to write up to `offset` bytes while the returned `Writer` can
    /// write up to `available_bytes() - offset` bytes. If `offset > self.available_bytes()`, then
    /// the returned `Writer` will not be able to write any bytes.
    pub fn split_at(&mut self, offset: usize) -> Writer<'a> {
        Writer {
            buffer: self.buffer.split_at(offset),
        }
    }
}

impl<'a> io::Write for Writer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut rem = buf;
        let mut total = 0;
        for b in self.buffer.get_remaining() {
            if rem.len() == 0 {
                break;
            }

            let count = cmp::min(rem.len(), b.size());
            // Safe because we have already verified that `vs` points to valid memory.
            unsafe {
                copy_nonoverlapping(rem.as_ptr(), b.as_mut_ptr(), count);
            }
            rem = &rem[count..];
            total += count;
        }

        self.buffer.consume(total);
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Nothing to flush since the writes go straight into the buffer.
        Ok(())
    }
}

const VIRTQ_DESC_F_NEXT: u16 = 0x1;
const VIRTQ_DESC_F_WRITE: u16 = 0x2;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum DescriptorType {
    Readable,
    Writable,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct virtq_desc {
    addr: Le64,
    len: Le32,
    flags: Le16,
    next: Le16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtq_desc {}

/// Test utility function to create a descriptor chain in guest memory.
pub fn create_descriptor_chain(
    memory: &GuestMemory,
    descriptor_array_addr: GuestAddress,
    mut buffers_start_addr: GuestAddress,
    descriptors: Vec<(DescriptorType, u32)>,
    spaces_between_regions: u32,
) -> Result<DescriptorChain> {
    let descriptors_len = descriptors.len();
    for (index, (type_, size)) in descriptors.into_iter().enumerate() {
        let mut flags = 0;
        if let DescriptorType::Writable = type_ {
            flags |= VIRTQ_DESC_F_WRITE;
        }
        if index + 1 < descriptors_len {
            flags |= VIRTQ_DESC_F_NEXT;
        }

        let index = index as u16;
        let desc = virtq_desc {
            addr: buffers_start_addr.offset().into(),
            len: size.into(),
            flags: flags.into(),
            next: (index + 1).into(),
        };

        let offset = size + spaces_between_regions;
        buffers_start_addr = buffers_start_addr
            .checked_add(offset as u64)
            .ok_or(Error::InvalidChain)?;

        let _ = memory.write_obj_at_addr(
            desc,
            descriptor_array_addr
                .checked_add(index as u64 * std::mem::size_of::<virtq_desc>() as u64)
                .ok_or(Error::InvalidChain)?,
        );
    }

    DescriptorChain::checked_new(memory, descriptor_array_addr, 0x100, 0, 0)
        .ok_or(Error::InvalidChain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, OpenOptions};
    use tempfile::TempDir;

    #[test]
    fn reader_test_simple_chain() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![
                (Readable, 8),
                (Readable, 16),
                (Readable, 18),
                (Readable, 64),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut reader = Reader::new(&memory, chain).expect("failed to create Reader");
        assert_eq!(reader.available_bytes(), 106);
        assert_eq!(reader.bytes_read(), 0);

        let mut buffer = [0 as u8; 64];
        if let Err(_) = reader.read_exact(&mut buffer) {
            panic!("read_exact should not fail here");
        }

        assert_eq!(reader.available_bytes(), 42);
        assert_eq!(reader.bytes_read(), 64);

        match reader.read(&mut buffer) {
            Err(_) => panic!("read should not fail here"),
            Ok(length) => assert_eq!(length, 42),
        }

        assert_eq!(reader.available_bytes(), 0);
        assert_eq!(reader.bytes_read(), 106);
    }

    #[test]
    fn writer_test_simple_chain() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![
                (Writable, 8),
                (Writable, 16),
                (Writable, 18),
                (Writable, 64),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut writer = Writer::new(&memory, chain).expect("failed to create Writer");
        assert_eq!(writer.available_bytes(), 106);
        assert_eq!(writer.bytes_written(), 0);

        let mut buffer = [0 as u8; 64];
        if let Err(_) = writer.write_all(&mut buffer) {
            panic!("write_all should not fail here");
        }

        assert_eq!(writer.available_bytes(), 42);
        assert_eq!(writer.bytes_written(), 64);

        match writer.write(&mut buffer) {
            Err(_) => panic!("write should not fail here"),
            Ok(length) => assert_eq!(length, 42),
        }

        assert_eq!(writer.available_bytes(), 0);
        assert_eq!(writer.bytes_written(), 106);
    }

    #[test]
    fn reader_test_incompatible_chain() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 8)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut reader = Reader::new(&memory, chain).expect("failed to create Reader");
        assert_eq!(reader.available_bytes(), 0);
        assert_eq!(reader.bytes_read(), 0);

        assert!(reader.read_obj::<u8>().is_err());

        assert_eq!(reader.available_bytes(), 0);
        assert_eq!(reader.bytes_read(), 0);
    }

    #[test]
    fn writer_test_incompatible_chain() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 8)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut writer = Writer::new(&memory, chain).expect("failed to create Writer");
        assert_eq!(writer.available_bytes(), 0);
        assert_eq!(writer.bytes_written(), 0);

        assert!(writer.write_obj(0u8).is_err());

        assert_eq!(writer.available_bytes(), 0);
        assert_eq!(writer.bytes_written(), 0);
    }

    #[test]
    fn reader_failing_io() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 256), (Readable, 256)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let mut reader = Reader::new(&memory, chain).expect("failed to create Reader");

        // Open a file in read-only mode so writes to it to trigger an I/O error.
        let mut ro_file = File::open("/dev/zero").expect("failed to open /dev/zero");

        reader
            .read_exact_to(&mut ro_file, 512)
            .expect_err("successfully read more bytes than SharedMemory size");

        // The write above should have failed entirely, so we end up not writing any bytes at all.
        assert_eq!(reader.available_bytes(), 512);
        assert_eq!(reader.bytes_read(), 0);
    }

    #[test]
    fn writer_failing_io() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 256), (Writable, 256)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let mut writer = Writer::new(&memory, chain).expect("failed to create Writer");

        let tempdir = TempDir::new().unwrap();
        let mut path = tempdir.path().to_owned();
        path.push("test_file");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("failed to create temp file");

        file.set_len(384).unwrap();

        writer
            .write_all_from(&mut file, 512)
            .expect_err("successfully wrote more bytes than in SharedMemory");

        assert_eq!(writer.available_bytes(), 128);
        assert_eq!(writer.bytes_written(), 384);
    }

    #[test]
    fn reader_writer_shared_chain() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![
                (Readable, 16),
                (Readable, 16),
                (Readable, 96),
                (Writable, 64),
                (Writable, 1),
                (Writable, 3),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut reader = Reader::new(&memory, chain.clone()).expect("failed to create Reader");
        let mut writer = Writer::new(&memory, chain).expect("failed to create Writer");

        assert_eq!(reader.bytes_read(), 0);
        assert_eq!(writer.bytes_written(), 0);

        let mut buffer = Vec::with_capacity(200);

        assert_eq!(
            reader
                .read_to_end(&mut buffer)
                .expect("read should not fail here"),
            128
        );

        // The writable descriptors are only 68 bytes long.
        writer
            .write_all(&buffer[..68])
            .expect("write should not fail here");

        assert_eq!(reader.available_bytes(), 0);
        assert_eq!(reader.bytes_read(), 128);
        assert_eq!(writer.available_bytes(), 0);
        assert_eq!(writer.bytes_written(), 68);
    }

    #[test]
    fn reader_writer_shattered_object() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let secret: Le32 = 0x12345678.into();

        // Create a descriptor chain with memory regions that are properly separated.
        let chain_writer = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 1), (Writable, 1), (Writable, 1), (Writable, 1)],
            123,
        )
        .expect("create_descriptor_chain failed");
        let mut writer = Writer::new(&memory, chain_writer).expect("failed to create Writer");
        if let Err(_) = writer.write_obj(secret) {
            panic!("write_obj should not fail here");
        }

        // Now create new descriptor chain pointing to the same memory and try to read it.
        let chain_reader = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 1), (Readable, 1), (Readable, 1), (Readable, 1)],
            123,
        )
        .expect("create_descriptor_chain failed");
        let mut reader = Reader::new(&memory, chain_reader).expect("failed to create Reader");
        match reader.read_obj::<Le32>() {
            Err(_) => panic!("read_obj should not fail here"),
            Ok(read_secret) => assert_eq!(read_secret, secret),
        }
    }

    #[test]
    fn reader_unexpected_eof() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 256), (Readable, 256)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let mut reader = Reader::new(&memory, chain).expect("failed to create Reader");

        let mut buf = Vec::with_capacity(1024);
        buf.resize(1024, 0);

        assert_eq!(
            reader
                .read_exact(&mut buf[..])
                .expect_err("read more bytes than available")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn split_border() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![
                (Readable, 16),
                (Readable, 16),
                (Readable, 96),
                (Writable, 64),
                (Writable, 1),
                (Writable, 3),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut reader = Reader::new(&memory, chain).expect("failed to create Reader");

        let other = reader.split_at(32);
        assert_eq!(reader.available_bytes(), 32);
        assert_eq!(other.available_bytes(), 96);
    }

    #[test]
    fn split_middle() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![
                (Readable, 16),
                (Readable, 16),
                (Readable, 96),
                (Writable, 64),
                (Writable, 1),
                (Writable, 3),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut reader = Reader::new(&memory, chain).expect("failed to create Reader");

        let other = reader.split_at(24);
        assert_eq!(reader.available_bytes(), 24);
        assert_eq!(other.available_bytes(), 104);
    }

    #[test]
    fn split_end() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![
                (Readable, 16),
                (Readable, 16),
                (Readable, 96),
                (Writable, 64),
                (Writable, 1),
                (Writable, 3),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut reader = Reader::new(&memory, chain).expect("failed to create Reader");

        let other = reader.split_at(128);
        assert_eq!(reader.available_bytes(), 128);
        assert_eq!(other.available_bytes(), 0);
    }

    #[test]
    fn split_beginning() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![
                (Readable, 16),
                (Readable, 16),
                (Readable, 96),
                (Writable, 64),
                (Writable, 1),
                (Writable, 3),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut reader = Reader::new(&memory, chain).expect("failed to create Reader");

        let other = reader.split_at(0);
        assert_eq!(reader.available_bytes(), 0);
        assert_eq!(other.available_bytes(), 128);
    }

    #[test]
    fn split_outofbounds() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![
                (Readable, 16),
                (Readable, 16),
                (Readable, 96),
                (Writable, 64),
                (Writable, 1),
                (Writable, 3),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut reader = Reader::new(&memory, chain).expect("failed to create Reader");

        let other = reader.split_at(256);
        assert_eq!(
            other.available_bytes(),
            0,
            "Reader returned from out-of-bounds split still has available bytes"
        );
    }

    #[test]
    fn read_full() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 16), (Readable, 16), (Readable, 16)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut reader = Reader::new(&memory, chain).expect("failed to create Reader");

        let mut buf = vec![0u8; 64];
        assert_eq!(
            reader.read(&mut buf[..]).expect("failed to read to buffer"),
            48
        );
    }

    #[test]
    fn write_full() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 16), (Writable, 16), (Writable, 16)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut writer = Writer::new(&memory, chain).expect("failed to create Writer");

        let buf = vec![0xdeu8; 64];
        assert_eq!(
            writer.write(&buf[..]).expect("failed to write from buffer"),
            48
        );
    }

    #[test]
    fn consume_collect() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();
        let vs: Vec<Le64> = vec![
            0x0101010101010101.into(),
            0x0202020202020202.into(),
            0x0303030303030303.into(),
        ];

        let write_chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 24)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut writer = Writer::new(&memory, write_chain).expect("failed to create Writer");
        writer
            .consume(vs.clone())
            .expect("failed to consume() a vector");

        let read_chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 24)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let mut reader = Reader::new(&memory, read_chain).expect("failed to create Reader");
        let vs_read = reader
            .collect::<io::Result<Vec<Le64>>, _>()
            .expect("failed to collect() values");
        assert_eq!(vs, vs_read);
    }

    #[test]
    fn get_remaining_with_count() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&vec![(memory_start_addr, 0x10000)]).unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![
                (Readable, 16),
                (Readable, 16),
                (Readable, 96),
                (Writable, 64),
                (Writable, 1),
                (Writable, 3),
            ],
            0,
        )
        .expect("create_descriptor_chain failed");

        let Reader { mut buffer } = Reader::new(&memory, chain).expect("failed to create Reader");

        let drain = buffer
            .get_remaining_with_count(::std::usize::MAX)
            .iter()
            .fold(0usize, |total, iov| total + iov.size());
        assert_eq!(drain, 128);

        let exact = buffer
            .get_remaining_with_count(32)
            .iter()
            .fold(0usize, |total, iov| total + iov.size());
        assert!(exact > 0);
        assert!(exact <= 32);

        let split = buffer
            .get_remaining_with_count(24)
            .iter()
            .fold(0usize, |total, iov| total + iov.size());
        assert!(split > 0);
        assert!(split <= 24);

        buffer.consume(64);

        let first = buffer
            .get_remaining_with_count(8)
            .iter()
            .fold(0usize, |total, iov| total + iov.size());
        assert!(first > 0);
        assert!(first <= 8);
    }
}
