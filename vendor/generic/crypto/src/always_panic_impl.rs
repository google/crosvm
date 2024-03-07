// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements CryptReader/Writer by always panicking. Vendors are expected to
//! implement their own encryption schemes.

#![allow(dead_code)]

use std::io::Read;
use std::io::Seek;
use std::io::Write;

use crate::CryptKey;

/// Interface used for file encryption.
pub struct CryptWriter<T: Write> {
    _writer: T,
}

impl<T: Write> CryptWriter<T> {
    /// Creates a new writer using an internally randomly generated key.
    fn new(_inner_writable: T, _chunk_size_bytes: usize) -> anyhow::Result<Box<Self>> {
        panic!("no crypto support was compiled in this build");
    }

    /// Creates a new writer using the provided key and encrypted chunk size. Generally, larger
    /// chunks are more performant but have buffering cost of O(chunk_size).
    fn new_from_key(
        _inner_writable: T,
        _chunk_size_bytes: usize,
        _key: &CryptKey,
    ) -> anyhow::Result<Box<Self>> {
        panic!("no crypto support was compiled in this build");
    }
}

impl<T: Write> Write for CryptWriter<T> {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        panic!("no crypto support was compiled in this build");
    }

    fn flush(&mut self) -> std::io::Result<()> {
        panic!("no crypto support was compiled in this build");
    }
}

/// Interface used for file decryption.
pub struct CryptReader<T: Read + Seek> {
    _reader: T,
}

impl<T> CryptReader<T>
where
    T: Read + Seek,
{
    /// Given a newly opened file previously written by a `CryptWriter`, extracts the encryption key
    /// used to write the file.
    fn extract_key(_inner_readable: T) -> anyhow::Result<CryptKey> {
        panic!("no crypto support was compiled in this build");
    }

    /// Creates a CryptReader over a file given a key.
    fn from_file_and_key(_inner_readable: T, _key: &CryptKey) -> anyhow::Result<Box<Self>> {
        panic!("no crypto support was compiled in this build");
    }
}

impl<T> Read for CryptReader<T>
where
    T: Read + Seek,
{
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        panic!("no crypto support was compiled in this build");
    }
}

/// Generates a random key usable with `CryptWriter` & `CryptReader`.
pub fn generate_random_key() -> CryptKey {
    panic!("no crypto support was compiled in this build");
}
