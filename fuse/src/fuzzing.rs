// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::os::unix::io::AsRawFd;

use crate::filesystem::DirEntry;
use crate::filesystem::DirectoryIterator;
use crate::filesystem::FileSystem;
use crate::filesystem::ZeroCopyReader;
use crate::filesystem::ZeroCopyWriter;
use crate::server::Mapper;
use crate::server::Reader;
use crate::server::Server;
use crate::server::Writer;

// Use a file system that does nothing since we are fuzzing the server implementation.
struct NullFs;
impl FileSystem for NullFs {
    type Inode = u64;
    type Handle = u64;
    type DirIter = NullIter;
}

struct NullIter;
impl DirectoryIterator for NullIter {
    fn next(&mut self) -> Option<DirEntry> {
        None
    }
}

struct NullMapper;
impl Mapper for NullMapper {
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

/// Fuzz the server implementation.
pub fn fuzz_server<R: Reader + ZeroCopyReader, W: Writer + ZeroCopyWriter>(r: R, w: W) {
    let server = Server::new(NullFs);
    let mapper = NullMapper {};

    let _ = server.handle_message(r, w, mapper);
}
