// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::BufRead;
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;
use std::io::Read;
use std::io::Result as IoResult;
use std::mem::size_of;

use zerocopy::AsBytes;
use zerocopy::FromBytes;

pub struct Reader<'slice> {
    data: &'slice [u8],
}

impl<'slice> Reader<'slice> {
    /// Construct a new Reader wrapper over `data`.
    pub fn new(data: &[u8]) -> Reader {
        Reader { data }
    }

    /// Reads and consumes an object from the buffer.
    pub fn read_obj<T: FromBytes>(&mut self) -> IoResult<T> {
        let obj = <T>::read_from_prefix(self.data.as_bytes())
            .ok_or(IoError::from(IoErrorKind::UnexpectedEof))?;
        self.consume(size_of::<T>());
        Ok(obj)
    }

    #[allow(dead_code)]
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.data.read(buf)
    }

    pub fn available_bytes(&self) -> usize {
        self.data.len()
    }

    /// Reads an object from the buffer without consuming it.
    pub fn peek_obj<T: FromBytes>(&self) -> IoResult<T> {
        let obj = <T>::read_from_prefix(self.data.as_bytes())
            .ok_or(IoError::from(IoErrorKind::UnexpectedEof))?;
        Ok(obj)
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> IoResult<()> {
        self.data.read_exact(buf)
    }

    /// Consumes `amt` bytes from the underlying buffer. If `amt` is larger than the
    /// remaining data left in this `Reader`, then all remaining data will be consumed.
    pub fn consume(&mut self, amt: usize) {
        self.data.consume(amt);
    }
}

pub struct Writer<'slice> {
    data: &'slice mut [u8],
    index: usize,
}

impl<'slice> Writer<'slice> {
    pub fn new(data: &mut [u8]) -> Writer {
        Writer { data, index: 0 }
    }

    /// Writes an object to the buffer.
    pub fn write_obj<T: FromBytes + AsBytes>(&mut self, val: T) -> IoResult<()> {
        self.write_all(val.as_bytes())
    }

    pub fn write_all(&mut self, buf: &[u8]) -> IoResult<()> {
        let new_index = self.index + buf.len();

        if new_index >= self.data.len() {
            return Err(IoError::from(IoErrorKind::UnexpectedEof));
        }

        self.data[self.index..new_index].copy_from_slice(buf);
        self.index = new_index;
        Ok(())
    }

    pub fn bytes_written(&self) -> usize {
        self.index
    }
}
