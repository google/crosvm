// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::fmt::{self, Display};
use std::io;
use std::os::unix::io::AsRawFd;
use std::result;

use data_model::DataInit;
use sys_util::guest_memory::Error as GuestMemoryError;
use sys_util::{GuestAddress, GuestMemory};

use super::DescriptorChain;

#[derive(Debug)]
pub enum Error {
    GuestMemoryError(sys_util::GuestMemoryError),
    IoError(io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            GuestMemoryError(e) => write!(f, "descriptor guest memory error: {}", e),
            IoError(e) => write!(f, "descriptor I/O error: {}", e),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

impl std::error::Error for Error {}

#[derive(PartialEq, Eq)]
enum DescriptorFilter {
    OnlyReadable,
    OnlyWritable,
}

struct DescriptorChainConsumer<'a> {
    offset: usize,
    desc_chain: Option<DescriptorChain<'a>>,
    bytes_consumed: usize,
    avail_bytes: Option<usize>,
    filter: DescriptorFilter,
}

impl<'a> DescriptorChainConsumer<'a> {
    fn new(
        desc_chain: Option<DescriptorChain<'a>>,
        filter: DescriptorFilter,
    ) -> DescriptorChainConsumer<'a> {
        DescriptorChainConsumer {
            offset: 0,
            desc_chain,
            bytes_consumed: 0,
            avail_bytes: None,
            filter,
        }
    }

    fn available_bytes(&mut self) -> usize {
        if let Some(bytes) = self.avail_bytes {
            bytes
        } else {
            let mut chain = self.desc_chain.clone();
            let mut count = 0;
            while let Some(desc) = chain {
                count += desc.len as usize;
                chain = self.advance(desc);
            }
            let bytes = count - self.offset;
            self.avail_bytes = Some(bytes);
            bytes
        }
    }

    fn bytes_consumed(&self) -> usize {
        self.bytes_consumed
    }

    fn consume<F>(&mut self, mut fnc: F, mut count: usize) -> Result<usize>
    where
        F: FnMut(GuestAddress, usize) -> Result<()>,
    {
        let mut bytes_consumed = 0;
        while count > 0 {
            if let Some(current) = &self.desc_chain {
                let addr = current
                    .addr
                    .checked_add(self.offset as u64)
                    .ok_or_else(|| {
                        Error::GuestMemoryError(GuestMemoryError::InvalidGuestAddress(current.addr))
                    })?;
                let len = cmp::min(count, current.len as usize - self.offset);
                fnc(addr, len)?;

                self.offset += len;
                self.avail_bytes = self.avail_bytes.map(|av| av - len);
                self.bytes_consumed += len;
                bytes_consumed += len;
                count -= len;

                if self.offset == current.len as usize {
                    self.offset = 0;
                    if let Some(desc_chain) = self.desc_chain.take() {
                        self.desc_chain = self.advance(desc_chain);
                    }
                }
            } else {
                // Nothing left to read.
                break;
            }
        }
        Ok(bytes_consumed)
    }

    fn advance(&self, desc_chain: DescriptorChain<'a>) -> Option<DescriptorChain<'a>> {
        let mut desc_chain = desc_chain.next_descriptor();
        // TODO(jstaron): Update this code to take the indirect descriptors into account.
        if self.filter == DescriptorFilter::OnlyReadable {
            // When encounter first write-only descriptor set `desc_chain` to None to stop
            // further processing.
            desc_chain = desc_chain.filter(DescriptorChain::is_read_only);
        }
        desc_chain
    }
}

/// Provides high-level interface over the sequence of memory regions
/// defined by readable descriptors in the descriptor chain.
///
/// Note that virtio spec requires driver to place any device-writable
/// descriptors after any device-readable descriptors (2.6.4.2 in Virtio Spec v1.1).
/// Reader will skip iterating over descriptor chain when first writable
/// descriptor is encountered.
pub struct Reader<'a> {
    mem: &'a GuestMemory,
    buffer: DescriptorChainConsumer<'a>,
}

impl<'a> Reader<'a> {
    /// Construct a new Reader wrapper over `desc_chain`.
    pub fn new(mem: &'a GuestMemory, desc_chain: DescriptorChain<'a>) -> Reader<'a> {
        // TODO(jstaron): Update this code to take the indirect descriptors into account.
        let desc_chain = if desc_chain.is_read_only() {
            Some(desc_chain)
        } else {
            None
        };
        Reader {
            mem,
            buffer: DescriptorChainConsumer::new(desc_chain, DescriptorFilter::OnlyReadable),
        }
    }

    /// Reads to a slice from the descriptor chain buffer.
    /// Reads as many bytes as necessary to completely fill
    /// the specified slice or to consume all bytes from the
    /// descriptor chain buffer. Returns number of copied bytes.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mem = self.mem;
        let len = buf.len();
        let mut read_count = 0;
        self.buffer.consume(
            move |addr, count| {
                let result = mem.read_exact_at_addr(&mut buf[read_count..read_count + count], addr);
                if result.is_ok() {
                    read_count += count;
                }
                result.map_err(Error::GuestMemoryError)
            },
            len,
        )
    }

    /// Reads to a slice from the descriptor chain.
    /// Returns an error if there isn't enough data in the
    /// descriptor chain buffer to fill the entire slice. Part of
    /// the slice may have been filled nevertheless.
    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let count = self.read(buf)?;
        if count == buf.len() {
            Ok(())
        } else {
            Err(Error::GuestMemoryError(GuestMemoryError::ShortRead {
                expected: buf.len(),
                completed: count,
            }))
        }
    }

    /// Reads an object from the descriptor chain buffer.
    pub fn read_obj<T: DataInit + Default>(&mut self) -> Result<T> {
        let mut object: T = Default::default();
        self.read_exact(object.as_mut_slice()).map(|_| object)
    }

    /// Reads data from the descriptor chain buffer into a file descriptor.
    /// Returns the number of bytes read from the descriptor chain buffer.
    /// The number of bytes read can be less than `count` if there isn't
    /// enough data in the descriptor chain buffer.
    pub fn read_to(&mut self, dst: &dyn AsRawFd, count: usize) -> Result<usize> {
        let mem = self.mem;
        self.buffer.consume(
            |addr, count| {
                mem.write_from_memory(addr, dst, count)
                    .map_err(Error::GuestMemoryError)
            },
            count,
        )
    }

    /// Returns number of bytes available for reading.
    pub fn available_bytes(&mut self) -> usize {
        self.buffer.available_bytes()
    }

    /// Returns number of bytes already read from the descriptor chain buffer.
    pub fn bytes_read(&self) -> usize {
        self.buffer.bytes_consumed()
    }
}

/// Provides high-level interface over the sequence of memory regions
/// defined by writable descriptors in the descriptor chain.
///
/// Note that virtio spec requires driver to place any device-writable
/// descriptors after any device-readable descriptors (2.6.4.2 in Virtio Spec v1.1).
/// Writer will start iterating the descriptors from the first writable one and will
/// assume that all following descriptors are writable.
pub struct Writer<'a> {
    mem: &'a GuestMemory,
    buffer: DescriptorChainConsumer<'a>,
}

impl<'a> Writer<'a> {
    /// Construct a new Writer wrapper over `desc_chain`.
    pub fn new(mem: &'a GuestMemory, desc_chain: DescriptorChain<'a>) -> Writer<'a> {
        // Skip all readable descriptors and get first writable one.
        let desc_chain = desc_chain.into_iter().writable().next();
        Writer {
            mem,
            buffer: DescriptorChainConsumer::new(desc_chain, DescriptorFilter::OnlyWritable),
        }
    }

    /// Writes a slice to the descriptor chain buffer.
    /// Returns the number of bytes written. The number of bytes written
    /// can be less than the length of the slice if there isn't enough
    /// space in the descriptor chain buffer.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mem = self.mem;
        let len = buf.len();
        let mut write_count = 0;
        self.buffer.consume(
            move |addr, count| {
                let result = mem.write_all_at_addr(&buf[write_count..write_count + count], addr);
                if result.is_ok() {
                    write_count += count;
                }
                result.map_err(Error::GuestMemoryError)
            },
            len,
        )
    }

    /// Writes the entire contents of a slice to descriptor chain buffer.
    /// Returns an error if there isn't enough room in the descriptor chain buffer
    /// to complete the entire write. Part of the data may have been written
    /// nevertheless.
    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        let count = self.write(buf)?;
        if count == buf.len() {
            Ok(())
        } else {
            Err(Error::GuestMemoryError(GuestMemoryError::ShortRead {
                expected: buf.len(),
                completed: count,
            }))
        }
    }

    /// Writes an object to the descriptor chain buffer.
    pub fn write_obj<T: DataInit>(&mut self, val: T) -> Result<()> {
        self.write_all(val.as_slice())
    }

    /// Returns number of bytes available for writing.
    pub fn available_bytes(&mut self) -> usize {
        self.buffer.available_bytes()
    }

    /// Writes data to the descriptor chain buffer from a file descriptor.
    /// Returns the number of bytes written to the descriptor chain buffer.
    /// The number of bytes written can be less than `count` if
    /// there isn't enough data in the descriptor chain buffer.
    pub fn write_from(&mut self, src: &dyn AsRawFd, count: usize) -> Result<usize> {
        let mem = self.mem;
        self.buffer.consume(
            |addr, count| {
                mem.read_to_memory(addr, src, count)
                    .map_err(Error::GuestMemoryError)
            },
            count,
        )
    }

    /// Returns number of bytes already written to the descriptor chain buffer.
    pub fn bytes_written(&self) -> usize {
        self.buffer.bytes_consumed()
    }
}

impl<'a> io::Read for Reader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read(buf)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }
}

impl<'a> io::Write for Writer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write(buf)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    fn flush(&mut self) -> io::Result<()> {
        // Nothing to flush since the writes go straight into the buffer.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_model::{Le16, Le32, Le64};
    use sys_util::{MemfdSeals, SharedMemory};

    const VIRTQ_DESC_F_NEXT: u16 = 0x1;
    const VIRTQ_DESC_F_WRITE: u16 = 0x2;

    #[derive(Copy, Clone, PartialEq, Eq)]
    enum DescriptorType {
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

    fn create_descriptor_chain(
        memory: &GuestMemory,
        descriptor_array_addr: GuestAddress,
        mut buffers_start_addr: GuestAddress,
        descriptors: Vec<(DescriptorType, u32)>,
        spaces_between_regions: u32,
    ) -> DescriptorChain {
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
            buffers_start_addr = buffers_start_addr.checked_add(offset as u64).unwrap();

            let _ = memory.write_obj_at_addr(
                desc,
                descriptor_array_addr
                    .checked_add(index as u64 * std::mem::size_of::<virtq_desc>() as u64)
                    .unwrap(),
            );
        }

        DescriptorChain::checked_new(memory, descriptor_array_addr, 0x100, 0).unwrap()
    }

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
        );
        let mut reader = Reader::new(&memory, chain);
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
        );
        let mut writer = Writer::new(&memory, chain);
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
        );
        let mut reader = Reader::new(&memory, chain);
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
        );
        let mut writer = Writer::new(&memory, chain);
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
        );

        let mut reader = Reader::new(&memory, chain);

        // GuestMemory's write_from_memory requires raw file descriptor.
        let mut shm = SharedMemory::new(None).unwrap();
        shm.set_size(384).unwrap();

        // Prevent shared memory from growing on `write` call.
        let mut fd_seals = MemfdSeals::new();
        fd_seals.set_grow_seal();
        shm.add_seals(fd_seals).unwrap();

        if let Ok(_) = reader.read_to(&shm, 512) {
            panic!("read_to should fail here, got Ok(_) instead");
        }

        assert!(reader.available_bytes() < 512);
        assert!(reader.available_bytes() > 0);
        assert!(reader.bytes_read() < 512);
        assert!(reader.bytes_read() > 0);
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
        );

        let mut writer = Writer::new(&memory, chain);

        // GuestMemory's read_to_memory requires raw file descriptor.
        let mut shm = SharedMemory::new(None).unwrap();
        shm.set_size(384).unwrap();

        if let Ok(_) = writer.write_from(&shm, 512) {
            panic!("write_from should fail here, got Ok(_) instead");
        }

        assert!(writer.available_bytes() < 512);
        assert!(writer.available_bytes() > 0);
        assert!(writer.bytes_written() < 512);
        assert!(writer.bytes_written() > 0);
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
        );
        let mut reader = Reader::new(&memory, chain.clone());
        let mut writer = Writer::new(&memory, chain);

        assert_eq!(reader.bytes_read(), 0);
        assert_eq!(writer.bytes_written(), 0);

        let mut buffer = [0 as u8; 200];

        match reader.read(&mut buffer) {
            Err(_) => panic!("read should not fail here"),
            Ok(length) => assert_eq!(length, 128),
        }

        match writer.write(&mut buffer) {
            Err(_) => panic!("write should not fail here"),
            Ok(length) => assert_eq!(length, 68),
        }

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
        );
        let mut writer = Writer::new(&memory, chain_writer);
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
        );
        let mut reader = Reader::new(&memory, chain_reader);
        match reader.read_obj::<Le32>() {
            Err(_) => panic!("read_obj should not fail here"),
            Ok(read_secret) => assert_eq!(read_secret, secret),
        }
    }
}
