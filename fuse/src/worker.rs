// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::mem::size_of;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use base::Protection;

use crate::filesystem::FileSystem;
use crate::filesystem::ZeroCopyReader;
use crate::filesystem::ZeroCopyWriter;
use crate::server::Mapper;
use crate::server::Reader;
use crate::server::Server;
use crate::server::Writer;
use crate::sys;
use crate::Error;
use crate::Result;

struct DevFuseReader {
    // File representing /dev/fuse for reading, with sufficient buffer to accommodate a FUSE read
    // transaction.
    reader: BufReader<File>,
}

impl DevFuseReader {
    pub fn new(reader: BufReader<File>) -> Self {
        DevFuseReader { reader }
    }

    fn drain(&mut self) {
        self.reader.consume(self.reader.buffer().len());
    }
}

impl Read for DevFuseReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Reader for DevFuseReader {}

impl ZeroCopyReader for DevFuseReader {
    fn read_to(&mut self, f: &mut File, count: usize, off: u64) -> io::Result<usize> {
        let buf = self.reader.fill_buf()?;
        let end = std::cmp::min(count, buf.len());
        let written = f.write_at(&buf[..end], off)?;
        self.reader.consume(written);
        Ok(written)
    }
}

struct DevFuseWriter {
    // File representing /dev/fuse for writing.
    dev_fuse: File,

    // An internal buffer to allow generating data and header out of order, such that they can be
    // flushed at once. This is wrapped by a cursor for tracking the current written position.
    write_buf: Cursor<Vec<u8>>,
}

impl DevFuseWriter {
    pub fn new(dev_fuse: File, write_buf: Cursor<Vec<u8>>) -> Self {
        debug_assert_eq!(write_buf.position(), 0);

        DevFuseWriter {
            dev_fuse,
            write_buf,
        }
    }
}

impl Write for DevFuseWriter {
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

impl Writer for DevFuseWriter {
    type ClosureWriter = Self;

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

impl ZeroCopyWriter for DevFuseWriter {
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
        _prot: Protection,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn unmap(&self, _offset: u64, _size: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }
}

/// Start the FUSE message handling loop. Returns when an error happens.
///
/// # Arguments
///
/// * `dev_fuse` - A `File` object of /dev/fuse
/// * `input_buffer_size` - Maximum bytes of the buffer when reads from /dev/fuse.
/// * `output_buffer_size` - Maximum bytes of the buffer when writes to /dev/fuse. Must be large
///   enough (usually equal) to `n` in `MountOption::MaxRead(n)`.
///
/// [deprecated(note="Please migrate to the `FuseConfig` builder API"]
pub fn start_message_loop<F: FileSystem + Sync>(
    dev_fuse: File,
    input_buffer_size: u32,
    output_buffer_size: u32,
    fs: F,
) -> Result<()> {
    let server = Server::new(fs);
    do_start_message_loop(dev_fuse, input_buffer_size, output_buffer_size, &server)
}

fn do_start_message_loop<F: FileSystem + Sync>(
    dev_fuse: File,
    input_buffer_size: u32,
    output_buffer_size: u32,
    server: &Server<F>,
) -> Result<()> {
    let mut dev_fuse_reader = {
        let rfile = dev_fuse.try_clone().map_err(Error::EndpointSetup)?;
        let buf_reader = BufReader::with_capacity(
            input_buffer_size as usize + size_of::<sys::InHeader>() + size_of::<sys::WriteIn>(),
            rfile,
        );
        DevFuseReader::new(buf_reader)
    };
    let mut dev_fuse_writer = {
        let wfile = dev_fuse;
        let write_buf = Cursor::new(Vec::with_capacity(output_buffer_size as usize));
        DevFuseWriter::new(wfile, write_buf)
    };
    let dev_fuse_mapper = DevFuseMapper::new();
    loop {
        server.handle_message(&mut dev_fuse_reader, &mut dev_fuse_writer, &dev_fuse_mapper)?;

        // Since we're reusing the buffer to avoid repeated allocation, drain the possible
        // residual from the buffer.
        dev_fuse_reader.drain();
    }
}

// TODO: Remove worker and this namespace from public
pub mod internal {
    use crossbeam_utils::thread;

    use super::*;

    /// Start the FUSE message handling loops in multiple threads. Returns when an error happens.
    ///
    /// # Arguments
    ///
    /// * `dev_fuse` - A `File` object of /dev/fuse
    /// * `input_buffer_size` - Maximum bytes of the buffer when reads from /dev/fuse.
    /// * `output_buffer_size` - Maximum bytes of the buffer when writes to /dev/fuse.
    ///
    /// [deprecated(note="Please migrate to the `FuseConfig` builder API"]
    pub fn start_message_loop_mt<F: FileSystem + Sync + Send>(
        dev_fuse: File,
        input_buffer_size: u32,
        output_buffer_size: u32,
        thread_numbers: usize,
        fs: F,
    ) -> Result<()> {
        let result = thread::scope(|s| {
            let server = Arc::new(Server::new(fs));
            for _ in 0..thread_numbers {
                let dev_fuse = dev_fuse
                    .try_clone()
                    .map_err(Error::EndpointSetup)
                    .expect("Failed to clone /dev/fuse FD");
                let server = server.clone();
                s.spawn(move |_| {
                    do_start_message_loop(dev_fuse, input_buffer_size, output_buffer_size, &server)
                });
            }
        });

        unreachable!("Threads exited or crashed unexpectedly: {:?}", result);
    }
}
