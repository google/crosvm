// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::io;
use std::io::Write;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::ptr::copy_nonoverlapping;
use std::sync::Arc;

use anyhow::Context;
use base::FileReadWriteAtVolatile;
use base::FileReadWriteVolatile;
use cros_async::MemRegion;
use cros_async::MemRegionIter;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use data_model::VolatileSlice;
use disk::AsyncDisk;
use smallvec::SmallVec;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use super::DescriptorChain;
use crate::virtio::SplitDescriptorChain;

struct DescriptorChainRegions {
    regions: SmallVec<[MemRegion; 2]>,

    // Index of the current region in `regions`.
    current_region_index: usize,

    // Number of bytes consumed in the current region.
    current_region_offset: usize,

    // Total bytes consumed in the entire descriptor chain.
    bytes_consumed: usize,
}

impl DescriptorChainRegions {
    fn new(regions: SmallVec<[MemRegion; 2]>) -> Self {
        DescriptorChainRegions {
            regions,
            current_region_index: 0,
            current_region_offset: 0,
            bytes_consumed: 0,
        }
    }

    fn available_bytes(&self) -> usize {
        // This is guaranteed not to overflow because the total length of the chain is checked
        // during all creations of `DescriptorChain` (see `DescriptorChain::new()`).
        self.get_remaining_regions()
            .fold(0usize, |count, region| count + region.len)
    }

    fn bytes_consumed(&self) -> usize {
        self.bytes_consumed
    }

    /// Returns all the remaining buffers in the `DescriptorChain`. Calling this function does not
    /// consume any bytes from the `DescriptorChain`. Instead callers should use the `consume`
    /// method to advance the `DescriptorChain`. Multiple calls to `get` with no intervening calls
    /// to `consume` will return the same data.
    fn get_remaining_regions(&self) -> MemRegionIter {
        MemRegionIter::new(&self.regions[self.current_region_index..])
            .skip_bytes(self.current_region_offset)
    }

    /// Like `get_remaining_regions` but guarantees that the combined length of all the returned
    /// iovecs is not greater than `count`. The combined length of the returned iovecs may be less
    /// than `count` but will always be greater than 0 as long as there is still space left in the
    /// `DescriptorChain`.
    fn get_remaining_regions_with_count(&self, count: usize) -> MemRegionIter {
        MemRegionIter::new(&self.regions[self.current_region_index..])
            .skip_bytes(self.current_region_offset)
            .take_bytes(count)
    }

    /// Returns all the remaining buffers in the `DescriptorChain` as `VolatileSlice`s of the given
    /// `GuestMemory`. Calling this function does not consume any bytes from the `DescriptorChain`.
    /// Instead callers should use the `consume` method to advance the `DescriptorChain`. Multiple
    /// calls to `get` with no intervening calls to `consume` will return the same data.
    fn get_remaining<'mem>(&self, mem: &'mem GuestMemory) -> SmallVec<[VolatileSlice<'mem>; 16]> {
        self.get_remaining_regions()
            .filter_map(|region| {
                mem.get_slice_at_addr(GuestAddress(region.offset), region.len)
                    .ok()
            })
            .collect()
    }

    /// Like 'get_remaining_with_count' except convert the offsets to volatile slices in the
    /// 'GuestMemory' given by 'mem'.
    fn get_remaining_with_count<'mem>(
        &self,
        mem: &'mem GuestMemory,
        count: usize,
    ) -> SmallVec<[VolatileSlice<'mem>; 16]> {
        self.get_remaining_regions_with_count(count)
            .filter_map(|region| {
                mem.get_slice_at_addr(GuestAddress(region.offset), region.len)
                    .ok()
            })
            .collect()
    }

    /// Consumes `count` bytes from the `DescriptorChain`. If `count` is larger than
    /// `self.available_bytes()` then all remaining bytes in the `DescriptorChain` will be consumed.
    fn consume(&mut self, mut count: usize) {
        while let Some(region) = self.regions.get(self.current_region_index) {
            let region_remaining = region.len - self.current_region_offset;
            if count < region_remaining {
                // The remaining count to consume is less than the remaining un-consumed length of
                // the current region. Adjust the region offset without advancing to the next region
                // and stop.
                self.current_region_offset += count;
                self.bytes_consumed += count;
                return;
            }

            // The current region has been exhausted. Advance to the next region.
            self.current_region_index += 1;
            self.current_region_offset = 0;

            self.bytes_consumed += region_remaining;
            count -= region_remaining;
        }
    }

    fn split_at(&mut self, offset: usize) -> DescriptorChainRegions {
        let mut other = DescriptorChainRegions {
            regions: self.regions.clone(),
            current_region_index: self.current_region_index,
            current_region_offset: self.current_region_offset,
            bytes_consumed: self.bytes_consumed,
        };
        other.consume(offset);
        other.bytes_consumed = 0;

        let mut rem = offset;
        let mut end = self.current_region_index;
        for region in &mut self.regions[self.current_region_index..] {
            if rem <= region.len {
                region.len = rem;
                break;
            }

            end += 1;
            rem -= region.len;
        }

        self.regions.truncate(end + 1);

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
pub struct Reader {
    mem: GuestMemory,
    regions: DescriptorChainRegions,
}

/// An iterator over `FromBytes` objects on readable descriptors in the descriptor chain.
pub struct ReaderIterator<'a, T: FromBytes> {
    reader: &'a mut Reader,
    phantom: PhantomData<T>,
}

impl<'a, T: FromBytes> Iterator for ReaderIterator<'a, T> {
    type Item = io::Result<T>;

    fn next(&mut self) -> Option<io::Result<T>> {
        if self.reader.available_bytes() == 0 {
            None
        } else {
            Some(self.reader.read_obj())
        }
    }
}

impl Reader {
    /// Construct a new Reader wrapper over `readable_regions`.
    pub fn new_from_regions(
        mem: &GuestMemory,
        readable_regions: SmallVec<[MemRegion; 2]>,
    ) -> Reader {
        Reader {
            mem: mem.clone(),
            regions: DescriptorChainRegions::new(readable_regions),
        }
    }

    /// Reads an object from the descriptor chain buffer without consuming it.
    pub fn peek_obj<T: FromBytes>(&self) -> io::Result<T> {
        let mut obj = MaybeUninit::uninit();

        // SAFETY: We pass a valid pointer and size of `obj`.
        let copied = unsafe {
            copy_regions_to_mut_ptr(
                &self.mem,
                self.get_remaining_regions(),
                obj.as_mut_ptr() as *mut u8,
                size_of::<T>(),
            )?
        };
        if copied != size_of::<T>() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        // SAFETY: `FromBytes` guarantees any set of initialized bytes is a valid value for `T`, and
        // we initialized all bytes in `obj` in the copy above.
        Ok(unsafe { obj.assume_init() })
    }

    /// Reads and consumes an object from the descriptor chain buffer.
    pub fn read_obj<T: FromBytes>(&mut self) -> io::Result<T> {
        let obj = self.peek_obj::<T>()?;
        self.consume(size_of::<T>());
        Ok(obj)
    }

    /// Reads objects by consuming all the remaining data in the descriptor chain buffer and returns
    /// them as a collection. Returns an error if the size of the remaining data is indivisible by
    /// the size of an object of type `T`.
    pub fn collect<C: FromIterator<io::Result<T>>, T: FromBytes>(&mut self) -> C {
        self.iter().collect()
    }

    /// Creates an iterator for sequentially reading `FromBytes` objects from the `Reader`.
    /// Unlike `collect`, this doesn't consume all the remaining data in the `Reader` and
    /// doesn't require the objects to be stored in a separate collection.
    pub fn iter<T: FromBytes>(&mut self) -> ReaderIterator<T> {
        ReaderIterator {
            reader: self,
            phantom: PhantomData,
        }
    }

    /// Reads data into a volatile slice up to the minimum of the slice's length or the number of
    /// bytes remaining. Returns the number of bytes read.
    pub fn read_to_volatile_slice(&mut self, slice: VolatileSlice) -> usize {
        let mut read = 0usize;
        let mut dst = slice;
        for src in self.get_remaining() {
            src.copy_to_volatile_slice(dst);
            let copied = std::cmp::min(src.size(), dst.size());
            read += copied;
            dst = match dst.offset(copied) {
                Ok(v) => v,
                Err(_) => break, // The slice is fully consumed
            };
        }
        self.regions.consume(read);
        read
    }

    /// Reads data from the descriptor chain buffer and passes the `VolatileSlice`s to the callback
    /// `cb`.
    pub fn read_to_cb<C: FnOnce(&[VolatileSlice]) -> usize>(
        &mut self,
        cb: C,
        count: usize,
    ) -> usize {
        let iovs = self.regions.get_remaining_with_count(&self.mem, count);
        let written = cb(&iovs[..]);
        self.regions.consume(written);
        written
    }

    /// Reads data from the descriptor chain buffer into a writable object.
    /// Returns the number of bytes read from the descriptor chain buffer.
    /// The number of bytes read can be less than `count` if there isn't
    /// enough data in the descriptor chain buffer.
    pub fn read_to<F: FileReadWriteVolatile>(
        &mut self,
        mut dst: F,
        count: usize,
    ) -> io::Result<usize> {
        let iovs = self.regions.get_remaining_with_count(&self.mem, count);
        let written = dst.write_vectored_volatile(&iovs[..])?;
        self.regions.consume(written);
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
        let iovs = self.regions.get_remaining_with_count(&self.mem, count);
        let written = dst.write_vectored_at_volatile(&iovs[..], off)?;
        self.regions.consume(written);
        Ok(written)
    }

    /// Reads data from the descriptor chain similar to 'read_to' except reading 'count' or
    /// returning an error if 'count' bytes can't be read.
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

    /// Reads data from the descriptor chain similar to 'read_to_at' except reading 'count' or
    /// returning an error if 'count' bytes can't be read.
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

    /// Reads data from the descriptor chain buffer into an `AsyncDisk` at offset `off`.
    /// Returns the number of bytes read from the descriptor chain buffer.
    /// The number of bytes read can be less than `count` if there isn't
    /// enough data in the descriptor chain buffer.
    pub async fn read_to_at_fut<F: AsyncDisk + ?Sized>(
        &mut self,
        dst: &F,
        count: usize,
        off: u64,
    ) -> disk::Result<usize> {
        let written = dst
            .write_from_mem(
                off,
                Arc::new(self.mem.clone()),
                self.regions.get_remaining_regions_with_count(count),
            )
            .await?;
        self.regions.consume(written);
        Ok(written)
    }

    /// Reads exactly `count` bytes from the chain to the disk asynchronously or returns an error if
    /// not enough data can be read.
    pub async fn read_exact_to_at_fut<F: AsyncDisk + ?Sized>(
        &mut self,
        dst: &F,
        mut count: usize,
        mut off: u64,
    ) -> disk::Result<()> {
        while count > 0 {
            let nread = self.read_to_at_fut(dst, count, off).await?;
            if nread == 0 {
                return Err(disk::Error::ReadingData(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to write whole buffer",
                )));
            }
            count -= nread;
            off += nread as u64;
        }

        Ok(())
    }

    /// Returns number of bytes available for reading.  May return an error if the combined
    /// lengths of all the buffers in the DescriptorChain would cause an integer overflow.
    pub fn available_bytes(&self) -> usize {
        self.regions.available_bytes()
    }

    /// Returns number of bytes already read from the descriptor chain buffer.
    pub fn bytes_read(&self) -> usize {
        self.regions.bytes_consumed()
    }

    pub fn get_remaining_regions(&self) -> MemRegionIter {
        self.regions.get_remaining_regions()
    }

    /// Returns a `&[VolatileSlice]` that represents all the remaining data in this `Reader`.
    /// Calling this method does not actually consume any data from the `Reader` and callers should
    /// call `consume` to advance the `Reader`.
    pub fn get_remaining(&self) -> SmallVec<[VolatileSlice; 16]> {
        self.regions.get_remaining(&self.mem)
    }

    /// Consumes `amt` bytes from the underlying descriptor chain. If `amt` is larger than the
    /// remaining data left in this `Reader`, then all remaining data will be consumed.
    pub fn consume(&mut self, amt: usize) {
        self.regions.consume(amt)
    }

    /// Splits this `Reader` into two at the given offset in the `DescriptorChain` buffer. After the
    /// split, `self` will be able to read up to `offset` bytes while the returned `Reader` can read
    /// up to `available_bytes() - offset` bytes. If `offset > self.available_bytes()`, then the
    /// returned `Reader` will not be able to read any bytes.
    pub fn split_at(&mut self, offset: usize) -> Reader {
        Reader {
            mem: self.mem.clone(),
            regions: self.regions.split_at(offset),
        }
    }
}

/// Copy up to `size` bytes from `src` into `dst`.
///
/// Returns the total number of bytes copied.
///
/// # Safety
///
/// The caller must ensure that it is safe to write `size` bytes of data into `dst`.
///
/// After the function returns, it is only safe to assume that the number of bytes indicated by the
/// return value (which may be less than the requested `size`) have been initialized. Bytes beyond
/// that point are not initialized by this function.
unsafe fn copy_regions_to_mut_ptr(
    mem: &GuestMemory,
    src: MemRegionIter,
    dst: *mut u8,
    size: usize,
) -> io::Result<usize> {
    let mut copied = 0;
    for src_region in src {
        if copied >= size {
            break;
        }

        let remaining = size - copied;
        let count = cmp::min(remaining, src_region.len);

        let vslice = mem
            .get_slice_at_addr(GuestAddress(src_region.offset), count)
            .map_err(|_e| io::Error::from(io::ErrorKind::InvalidData))?;

        // SAFETY: `get_slice_at_addr()` verified that the region points to valid memory, and
        // the `count` calculation ensures we will write at most `size` bytes into `dst`.
        unsafe {
            copy_nonoverlapping(vslice.as_ptr(), dst.add(copied), count);
        }

        copied += count;
    }

    Ok(copied)
}

impl io::Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: We pass a valid pointer and size combination derived from `buf`.
        let total = unsafe {
            copy_regions_to_mut_ptr(
                &self.mem,
                self.regions.get_remaining_regions(),
                buf.as_mut_ptr(),
                buf.len(),
            )?
        };
        self.regions.consume(total);
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
pub struct Writer {
    mem: GuestMemory,
    regions: DescriptorChainRegions,
}

impl Writer {
    /// Construct a new Writer wrapper over `writable_regions`.
    pub fn new_from_regions(
        mem: &GuestMemory,
        writable_regions: SmallVec<[MemRegion; 2]>,
    ) -> Writer {
        Writer {
            mem: mem.clone(),
            regions: DescriptorChainRegions::new(writable_regions),
        }
    }

    /// Writes an object to the descriptor chain buffer.
    pub fn write_obj<T: AsBytes>(&mut self, val: T) -> io::Result<()> {
        self.write_all(val.as_bytes())
    }

    /// Writes all objects produced by `iter` into the descriptor chain buffer. Unlike `consume`,
    /// this doesn't require the values to be stored in an intermediate collection first. It also
    /// allows callers to choose which elements in a collection to write, for example by using the
    /// `filter` or `take` methods of the `Iterator` trait.
    pub fn write_iter<T: AsBytes, I: Iterator<Item = T>>(&mut self, mut iter: I) -> io::Result<()> {
        iter.try_for_each(|v| self.write_obj(v))
    }

    /// Writes a collection of objects into the descriptor chain buffer.
    pub fn consume<T: AsBytes, C: IntoIterator<Item = T>>(&mut self, vals: C) -> io::Result<()> {
        self.write_iter(vals.into_iter())
    }

    /// Returns number of bytes available for writing.  May return an error if the combined
    /// lengths of all the buffers in the DescriptorChain would cause an overflow.
    pub fn available_bytes(&self) -> usize {
        self.regions.available_bytes()
    }

    /// Reads data into a volatile slice up to the minimum of the slice's length or the number of
    /// bytes remaining. Returns the number of bytes read.
    pub fn write_from_volatile_slice(&mut self, slice: VolatileSlice) -> usize {
        let mut written = 0usize;
        let mut src = slice;
        for dst in self.get_remaining() {
            src.copy_to_volatile_slice(dst);
            let copied = std::cmp::min(src.size(), dst.size());
            written += copied;
            src = match src.offset(copied) {
                Ok(v) => v,
                Err(_) => break, // The slice is fully consumed
            };
        }
        self.regions.consume(written);
        written
    }

    /// Writes data to the descriptor chain buffer from a readable object.
    /// Returns the number of bytes written to the descriptor chain buffer.
    /// The number of bytes written can be less than `count` if
    /// there isn't enough data in the descriptor chain buffer.
    pub fn write_from<F: FileReadWriteVolatile>(
        &mut self,
        mut src: F,
        count: usize,
    ) -> io::Result<usize> {
        let iovs = self.regions.get_remaining_with_count(&self.mem, count);
        let read = src.read_vectored_volatile(&iovs[..])?;
        self.regions.consume(read);
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
        let iovs = self.regions.get_remaining_with_count(&self.mem, count);
        let read = src.read_vectored_at_volatile(&iovs[..], off)?;
        self.regions.consume(read);
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
    /// Writes data to the descriptor chain buffer from an `AsyncDisk` at offset `off`.
    /// Returns the number of bytes written to the descriptor chain buffer.
    /// The number of bytes written can be less than `count` if
    /// there isn't enough data in the descriptor chain buffer.
    pub async fn write_from_at_fut<F: AsyncDisk + ?Sized>(
        &mut self,
        src: &F,
        count: usize,
        off: u64,
    ) -> disk::Result<usize> {
        let read = src
            .read_to_mem(
                off,
                Arc::new(self.mem.clone()),
                self.regions.get_remaining_regions_with_count(count),
            )
            .await?;
        self.regions.consume(read);
        Ok(read)
    }

    pub async fn write_all_from_at_fut<F: AsyncDisk + ?Sized>(
        &mut self,
        src: &F,
        mut count: usize,
        mut off: u64,
    ) -> disk::Result<()> {
        while count > 0 {
            let nwritten = self.write_from_at_fut(src, count, off).await?;
            if nwritten == 0 {
                return Err(disk::Error::WritingData(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to write whole buffer",
                )));
            }
            count -= nwritten;
            off += nwritten as u64;
        }
        Ok(())
    }

    /// Returns number of bytes already written to the descriptor chain buffer.
    pub fn bytes_written(&self) -> usize {
        self.regions.bytes_consumed()
    }

    pub fn get_remaining_regions(&self) -> MemRegionIter {
        self.regions.get_remaining_regions()
    }

    /// Returns a `&[VolatileSlice]` that represents all the remaining data in this `Writer`.
    /// Calling this method does not actually advance the current position of the `Writer` in the
    /// buffer and callers should call `consume_bytes` to advance the `Writer`. Not calling
    /// `consume_bytes` with the amount of data copied into the returned `VolatileSlice`s will
    /// result in that that data being overwritten the next time data is written into the `Writer`.
    pub fn get_remaining(&self) -> SmallVec<[VolatileSlice; 16]> {
        self.regions.get_remaining(&self.mem)
    }

    /// Consumes `amt` bytes from the underlying descriptor chain. If `amt` is larger than the
    /// remaining data left in this `Reader`, then all remaining data will be consumed.
    pub fn consume_bytes(&mut self, amt: usize) {
        self.regions.consume(amt)
    }

    /// Splits this `Writer` into two at the given offset in the `DescriptorChain` buffer. After the
    /// split, `self` will be able to write up to `offset` bytes while the returned `Writer` can
    /// write up to `available_bytes() - offset` bytes. If `offset > self.available_bytes()`, then
    /// the returned `Writer` will not be able to write any bytes.
    pub fn split_at(&mut self, offset: usize) -> Writer {
        Writer {
            mem: self.mem.clone(),
            regions: self.regions.split_at(offset),
        }
    }
}

impl io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut rem = buf;
        let mut total = 0;
        for b in self.regions.get_remaining(&self.mem) {
            if rem.is_empty() {
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

        self.regions.consume(total);
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

#[derive(Copy, Clone, Debug, FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
struct virtq_desc {
    addr: Le64,
    len: Le32,
    flags: Le16,
    next: Le16,
}

/// Test utility function to create a descriptor chain in guest memory.
pub fn create_descriptor_chain(
    memory: &GuestMemory,
    descriptor_array_addr: GuestAddress,
    mut buffers_start_addr: GuestAddress,
    descriptors: Vec<(DescriptorType, u32)>,
    spaces_between_regions: u32,
) -> anyhow::Result<DescriptorChain> {
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
            .context("Invalid buffers_start_addr)")?;

        let _ = memory.write_obj_at_addr(
            desc,
            descriptor_array_addr
                .checked_add(index as u64 * std::mem::size_of::<virtq_desc>() as u64)
                .context("Invalid descriptor_array_addr")?,
        );
    }

    let chain = SplitDescriptorChain::new(memory, descriptor_array_addr, 0x100, 0);
    DescriptorChain::new(chain, memory, 0)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;

    use cros_async::Executor;
    use tempfile::tempfile;
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn reader_test_simple_chain() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
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
        let reader = &mut chain.reader;
        assert_eq!(reader.available_bytes(), 106);
        assert_eq!(reader.bytes_read(), 0);

        let mut buffer = [0u8; 64];
        reader
            .read_exact(&mut buffer)
            .expect("read_exact should not fail here");

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
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
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
        let writer = &mut chain.writer;
        assert_eq!(writer.available_bytes(), 106);
        assert_eq!(writer.bytes_written(), 0);

        let buffer = [0; 64];
        writer
            .write_all(&buffer)
            .expect("write_all should not fail here");

        assert_eq!(writer.available_bytes(), 42);
        assert_eq!(writer.bytes_written(), 64);

        match writer.write(&buffer) {
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
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 8)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let reader = &mut chain.reader;
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
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 8)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let writer = &mut chain.writer;
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
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 256), (Readable, 256)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let reader = &mut chain.reader;

        // Open a file in read-only mode so writes to it to trigger an I/O error.
        let device_file = if cfg!(windows) { "NUL" } else { "/dev/zero" };
        let mut ro_file = File::open(device_file).expect("failed to open device file");

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
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 256), (Writable, 256)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let writer = &mut chain.writer;

        let mut file = tempfile().unwrap();

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
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
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
        let reader = &mut chain.reader;
        let writer = &mut chain.writer;

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
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let secret: Le32 = 0x12345678.into();

        // Create a descriptor chain with memory regions that are properly separated.
        let mut chain_writer = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 1), (Writable, 1), (Writable, 1), (Writable, 1)],
            123,
        )
        .expect("create_descriptor_chain failed");
        let writer = &mut chain_writer.writer;
        writer
            .write_obj(secret)
            .expect("write_obj should not fail here");

        // Now create new descriptor chain pointing to the same memory and try to read it.
        let mut chain_reader = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 1), (Readable, 1), (Readable, 1), (Readable, 1)],
            123,
        )
        .expect("create_descriptor_chain failed");
        let reader = &mut chain_reader.reader;
        match reader.read_obj::<Le32>() {
            Err(_) => panic!("read_obj should not fail here"),
            Ok(read_secret) => assert_eq!(read_secret, secret),
        }
    }

    #[test]
    fn reader_unexpected_eof() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 256), (Readable, 256)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let reader = &mut chain.reader;

        let mut buf = vec![0; 1024];

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
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
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
        let reader = &mut chain.reader;

        let other = reader.split_at(32);
        assert_eq!(reader.available_bytes(), 32);
        assert_eq!(other.available_bytes(), 96);
    }

    #[test]
    fn split_middle() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
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
        let reader = &mut chain.reader;

        let other = reader.split_at(24);
        assert_eq!(reader.available_bytes(), 24);
        assert_eq!(other.available_bytes(), 104);
    }

    #[test]
    fn split_end() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
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
        let reader = &mut chain.reader;

        let other = reader.split_at(128);
        assert_eq!(reader.available_bytes(), 128);
        assert_eq!(other.available_bytes(), 0);
    }

    #[test]
    fn split_beginning() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
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
        let reader = &mut chain.reader;

        let other = reader.split_at(0);
        assert_eq!(reader.available_bytes(), 0);
        assert_eq!(other.available_bytes(), 128);
    }

    #[test]
    fn split_outofbounds() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
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
        let reader = &mut chain.reader;

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
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 16), (Readable, 16), (Readable, 16)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let reader = &mut chain.reader;

        let mut buf = [0u8; 64];
        assert_eq!(
            reader.read(&mut buf[..]).expect("failed to read to buffer"),
            48
        );
    }

    #[test]
    fn write_full() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 16), (Writable, 16), (Writable, 16)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let writer = &mut chain.writer;

        let buf = [0xdeu8; 64];
        assert_eq!(
            writer.write(&buf[..]).expect("failed to write from buffer"),
            48
        );
    }

    #[test]
    fn consume_collect() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();
        let vs: Vec<Le64> = vec![
            0x0101010101010101.into(),
            0x0202020202020202.into(),
            0x0303030303030303.into(),
        ];

        let mut write_chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 24)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let writer = &mut write_chain.writer;
        writer
            .consume(vs.clone())
            .expect("failed to consume() a vector");

        let mut read_chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 24)],
            0,
        )
        .expect("create_descriptor_chain failed");
        let reader = &mut read_chain.reader;
        let vs_read = reader
            .collect::<io::Result<Vec<Le64>>, _>()
            .expect("failed to collect() values");
        assert_eq!(vs, vs_read);
    }

    #[test]
    fn get_remaining_region_with_count() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

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

        let Reader {
            mem: _,
            mut regions,
        } = chain.reader;

        let drain = regions
            .get_remaining_regions_with_count(::std::usize::MAX)
            .fold(0usize, |total, region| total + region.len);
        assert_eq!(drain, 128);

        let exact = regions
            .get_remaining_regions_with_count(32)
            .fold(0usize, |total, region| total + region.len);
        assert!(exact > 0);
        assert!(exact <= 32);

        let split = regions
            .get_remaining_regions_with_count(24)
            .fold(0usize, |total, region| total + region.len);
        assert!(split > 0);
        assert!(split <= 24);

        regions.consume(64);

        let first = regions
            .get_remaining_regions_with_count(8)
            .fold(0usize, |total, region| total + region.len);
        assert!(first > 0);
        assert!(first <= 8);
    }

    #[test]
    fn get_remaining_with_count() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

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
        let Reader {
            mem: _,
            mut regions,
        } = chain.reader;

        let drain = regions
            .get_remaining_with_count(&memory, ::std::usize::MAX)
            .iter()
            .fold(0usize, |total, iov| total + iov.size());
        assert_eq!(drain, 128);

        let exact = regions
            .get_remaining_with_count(&memory, 32)
            .iter()
            .fold(0usize, |total, iov| total + iov.size());
        assert!(exact > 0);
        assert!(exact <= 32);

        let split = regions
            .get_remaining_with_count(&memory, 24)
            .iter()
            .fold(0usize, |total, iov| total + iov.size());
        assert!(split > 0);
        assert!(split <= 24);

        regions.consume(64);

        let first = regions
            .get_remaining_with_count(&memory, 8)
            .iter()
            .fold(0usize, |total, iov| total + iov.size());
        assert!(first > 0);
        assert!(first <= 8);
    }

    #[test]
    fn reader_peek_obj() {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        // Write test data to memory.
        memory
            .write_obj_at_addr(Le16::from(0xBEEF), GuestAddress(0x100))
            .unwrap();
        memory
            .write_obj_at_addr(Le16::from(0xDEAD), GuestAddress(0x200))
            .unwrap();

        let mut chain_reader = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 2), (Readable, 2)],
            0x100 - 2,
        )
        .expect("create_descriptor_chain failed");
        let reader = &mut chain_reader.reader;

        // peek_obj() at the beginning of the chain should return the first object.
        let peek1 = reader.peek_obj::<Le16>().unwrap();
        assert_eq!(peek1, Le16::from(0xBEEF));

        // peek_obj() again should return the same object, since it was not consumed.
        let peek2 = reader.peek_obj::<Le16>().unwrap();
        assert_eq!(peek2, Le16::from(0xBEEF));

        // peek_obj() of an object spanning two descriptors should copy from both.
        let peek3 = reader.peek_obj::<Le32>().unwrap();
        assert_eq!(peek3, Le32::from(0xDEADBEEF));

        // read_obj() should return the first object.
        let read1 = reader.read_obj::<Le16>().unwrap();
        assert_eq!(read1, Le16::from(0xBEEF));

        // peek_obj() of a value that is larger than the rest of the chain should fail.
        reader
            .peek_obj::<Le32>()
            .expect_err("peek_obj past end of chain");

        // read_obj() again should return the second object.
        let read2 = reader.read_obj::<Le16>().unwrap();
        assert_eq!(read2, Le16::from(0xDEAD));

        // peek_obj() should fail at the end of the chain.
        reader
            .peek_obj::<Le16>()
            .expect_err("peek_obj past end of chain");
    }

    #[test]
    fn region_reader_failing_io() {
        let ex = Executor::new().unwrap();
        ex.run_until(region_reader_failing_io_async(&ex)).unwrap();
    }
    async fn region_reader_failing_io_async(ex: &Executor) {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Readable, 256), (Readable, 256)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let reader = &mut chain.reader;

        // Open a file in read-only mode so writes to it to trigger an I/O error.
        let named_temp_file = NamedTempFile::new().expect("failed to create temp file");
        let ro_file =
            File::open(named_temp_file.path()).expect("failed to open temp file read only");
        let async_ro_file = disk::SingleFileDisk::new(ro_file, ex).expect("Failed to crate SFD");

        reader
            .read_exact_to_at_fut(&async_ro_file, 512, 0)
            .await
            .expect_err("successfully read more bytes than SingleFileDisk size");

        // The write above should have failed entirely, so we end up not writing any bytes at all.
        assert_eq!(reader.available_bytes(), 512);
        assert_eq!(reader.bytes_read(), 0);
    }

    #[test]
    fn region_writer_failing_io() {
        let ex = Executor::new().unwrap();
        ex.run_until(region_writer_failing_io_async(&ex)).unwrap()
    }
    async fn region_writer_failing_io_async(ex: &Executor) {
        use DescriptorType::*;

        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();

        let mut chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(Writable, 256), (Writable, 256)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let writer = &mut chain.writer;

        let file = tempfile().expect("failed to create temp file");

        file.set_len(384).unwrap();
        let async_file = disk::SingleFileDisk::new(file, ex).expect("Failed to crate SFD");

        writer
            .write_all_from_at_fut(&async_file, 512, 0)
            .await
            .expect_err("successfully wrote more bytes than in SingleFileDisk");

        assert_eq!(writer.available_bytes(), 128);
        assert_eq!(writer.bytes_written(), 384);
    }
}
