// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use std::io::BufRead;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::mem::size_of;

use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

pub struct Reader<'slice> {
    data: &'slice [u8],
}

impl<'slice> Reader<'slice> {
    /// Construct a new Reader wrapper over `data`.
    pub fn new(data: &[u8]) -> Reader {
        Reader { data }
    }

    /// Reads and consumes an object from the buffer.
    pub fn read_obj<T: FromBytes>(&mut self) -> Result<T> {
        let obj = <T>::read_from_prefix(self.data.as_bytes())
            .map_err(|_e| Error::from(ErrorKind::UnexpectedEof))?;
        self.consume(size_of::<T>());
        Ok(obj.0)
    }

    #[allow(dead_code)]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.data.read(buf)
    }

    pub fn available_bytes(&self) -> usize {
        self.data.len()
    }

    /// Reads an object from the buffer without consuming it.
    pub fn peek_obj<T: FromBytes>(&self) -> Result<T> {
        let obj = <T>::read_from_prefix(self.data.as_bytes())
            .map_err(|_e| Error::from(ErrorKind::UnexpectedEof))?;
        Ok(obj.0)
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
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
    pub fn write_obj<T: FromBytes + IntoBytes + Immutable>(&mut self, val: T) -> Result<()> {
        self.write_all(val.as_bytes())
    }

    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        let new_index = self.index + buf.len();

        let Some(data) = self.data.get_mut(self.index..new_index) else {
            return Err(Error::from(ErrorKind::UnexpectedEof));
        };

        data.copy_from_slice(buf);
        self.index = new_index;
        Ok(())
    }

    pub fn bytes_written(&self) -> usize {
        self.index
    }
}
