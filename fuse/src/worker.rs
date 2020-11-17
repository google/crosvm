// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::mem::size_of;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;

use crate::filesystem::{FileSystem, ZeroCopyReader, ZeroCopyWriter};
use crate::server::{Mapper, Reader, Server, Writer};
use crate::sys;
use crate::{Error, Result};

struct DevFuseReader<'a> {
    // File representing /dev/fuse for reading, with sufficient buffer to accommodate a FUSE read
    // transaction.
    reader: &'a mut BufReader<File>,
}

impl<'a> DevFuseReader<'a> {
    pub fn new(reader: &'a mut BufReader<File>) -> Self {
        DevFuseReader { reader }
    }
}

impl Read for DevFuseReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Reader for DevFuseReader<'_> {}

impl ZeroCopyReader for DevFuseReader<'_> {
    fn read_to(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize> {
        let buf = self.reader.fill_buf()?;
        let end = std::cmp::min(count, buf.len());
        let written = f.write_at(&buf[..end], off)?;
        self.reader.consume(written);
        Ok(written)
    }
}

struct DevFuseWriter<'a> {
    // File representing /dev/fuse for writing.
    dev_fuse: &'a mut File,

    // An internal buffer to allow generating data and header out of order, such that they can be
    // flushed at once. This is wrapped by a cursor for tracking the current written position.
    write_buf: &'a mut Cursor<Vec<u8>>,
}

impl<'a> DevFuseWriter<'a> {
    pub fn new(dev_fuse: &'a mut File, write_buf: &'a mut Cursor<Vec<u8>>) -> Self {
        debug_assert_eq!(write_buf.position(), 0);

        DevFuseWriter {
            dev_fuse,
            write_buf,
        }
    }
}

impl Write for DevFuseWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_buf.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.dev_fuse.write_all(&self.write_buf.get_ref()[..])?;
        self.write_buf.set_position(0);
        self.write_buf.get_mut().clear();
        Ok(())
    }
}

impl Writer for DevFuseWriter<'_> {
    fn write_at<F>(&mut self, offset: usize, f: F) -> io::Result<usize>
    where
        F: Fn(&mut Self) -> io::Result<usize>,
    {
        // Restore the cursor for idempotent.
        let original = self.write_buf.position();
        self.write_buf.set_position(offset as u64);
        let r = f(self);
        self.write_buf.set_position(original);
        r
    }

    fn has_sufficient_buffer(&self, size: u32) -> bool {
        (self.write_buf.position() as usize + size as usize) < self.write_buf.get_ref().capacity()
    }
}

impl ZeroCopyWriter for DevFuseWriter<'_> {
    fn write_from(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize> {
        let pos = self.write_buf.position() as usize;
        let end = pos + count;
        let buf = self.write_buf.get_mut();

        let old_end = buf.len();
        buf.resize(end, 0);
        let read = f.read_at(&mut buf[pos..end], off)?;

        let new_end = pos + read;
        debug_assert!(new_end >= old_end);
        buf.truncate(new_end);
        self.write_buf.set_position(new_end as u64);
        Ok(read)
    }
}

struct DevFuseMapper;

impl DevFuseMapper {
    fn new() -> Self {
        Self {}
    }
}

impl Mapper for DevFuseMapper {
    fn map(
        &self,
        _mem_offset: u64,
        _size: usize,
        _fd: &dyn AsRawFd,
        _file_offset: u64,
        _prot: u32,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn unmap(&self, _offset: u64, _size: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }
}

/// Start the FUSE message handling loop. Returns when an error happens.
pub fn start_message_loop<F: FileSystem + Sync>(
    dev_fuse: File,
    max_write: u32,
    max_read: u32,
    fs: F,
) -> Result<()> {
    let server = Server::new(fs);
    let mut buf_reader = BufReader::with_capacity(
        max_write as usize + size_of::<sys::InHeader>() + size_of::<sys::WriteIn>(),
        dev_fuse.try_clone().map_err(Error::EndpointSetup)?,
    );

    let mut write_buf = Cursor::new(Vec::with_capacity(max_read as usize));
    let mut wfile = dev_fuse.try_clone().map_err(Error::EndpointSetup)?;
    loop {
        let dev_fuse_reader = DevFuseReader::new(&mut buf_reader);
        let dev_fuse_writer = DevFuseWriter::new(&mut wfile, &mut write_buf);
        let dev_fuse_mapper = DevFuseMapper::new();

        if let Err(e) = server.handle_message(dev_fuse_reader, dev_fuse_writer, &dev_fuse_mapper) {
            return Err(e);
        }
    }
}
