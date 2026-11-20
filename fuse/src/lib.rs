// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! FUSE (Filesystem in Userspace) server and filesystem mounting support.

#![cfg(any(target_os = "android", target_os = "linux"))]

use std::ffi::FromBytesWithNulError;
use std::fs::File;
use std::io;

use remain::sorted;
use thiserror::Error as ThisError;

pub mod filesystem;
pub mod fuzzing;
pub mod mount;
mod server;
#[allow(dead_code)]
pub mod sys;
pub mod worker;

use filesystem::FileSystem;
pub use mount::mount;
pub use server::Mapper;
pub use server::Reader;
pub use server::Server;
pub use server::Writer;

/// Errors that may occur during the creation or operation of an Fs device.
#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// A request is missing readable descriptors.
    /// Failed to decode protocol messages.
    #[error("failed to decode fuse message: {0}")]
    DecodeMessage(io::Error),
    /// Failed to encode protocol messages.
    #[error("failed to encode fuse message: {0}")]
    EncodeMessage(io::Error),
    /// Failed to set up FUSE endpoint to talk with.
    #[error("failed to set up FUSE endpoint to talk with: {0}")]
    EndpointSetup(io::Error),
    /// Failed to flush protocol messages.
    #[error("failed to flush fuse message: {0}")]
    FlushMessage(io::Error),
    /// A C string parameter is invalid.
    #[error("a c string parameter is invalid: {0}")]
    InvalidCString(FromBytesWithNulError),
    /// The `len` field of the header is too small.
    #[error("the `len` field of the header is too small")]
    InvalidHeaderLength,
    /// The `size` field of the `SetxattrIn` message does not match the length
    /// of the decoded value.
    #[error(
        "The `size` field of the `SetxattrIn` message does not match the\
             length of the decoded value: size = {0}, value.len() = {1}"
    )]
    InvalidXattrSize(u32, usize),
    /// One or more parameters are missing.
    #[error("one or more parameters are missing")]
    MissingParameter,
    /// Thread exited
    #[error("Thread exited")]
    ThreadExited,
    /// Requested too many `iovec`s for an `ioctl` retry.
    #[error(
        "requested too many `iovec`s for an `ioctl` retry reply: requested\
            {0}, max: {1}"
    )]
    TooManyIovecs(usize, usize),
}

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Default)]
pub struct FuseConfig {
    dev_fuse_file: Option<File>,
    max_write_bytes: Option<u32>,
    max_read_bytes: Option<u32>,
    num_of_threads: Option<usize>,
}

impl FuseConfig {
    pub fn new() -> Self {
        FuseConfig {
            ..Default::default()
        }
    }

    /// Set the FUSE device.
    pub fn dev_fuse(&mut self, file: File) -> &mut Self {
        self.dev_fuse_file = Some(file);
        self
    }

    /// Set the maximum data in a read request. Must be large enough (usually equal) to `n` in
    /// `MountOption::MaxRead(n)`.
    pub fn max_read(&mut self, bytes: u32) -> &mut Self {
        self.max_read_bytes = Some(bytes);
        self
    }

    /// Set the maximum data in a write request.
    pub fn max_write(&mut self, bytes: u32) -> &mut Self {
        self.max_write_bytes = Some(bytes);
        self
    }

    /// Set the number of threads to run the `FileSystem`.
    pub fn num_threads(&mut self, num: usize) -> &mut Self {
        self.num_of_threads = Some(num);
        self
    }

    pub fn enter_message_loop<F: FileSystem + Sync + Send>(self, fs: F) -> Result<()> {
        let FuseConfig {
            dev_fuse_file,
            max_write_bytes,
            max_read_bytes,
            num_of_threads,
        } = self;
        let num = num_of_threads.unwrap_or(1);
        if num == 1 {
            worker::start_message_loop(
                dev_fuse_file.ok_or(Error::MissingParameter)?,
                max_write_bytes.ok_or(Error::MissingParameter)?,
                max_read_bytes.ok_or(Error::MissingParameter)?,
                fs,
            )
        } else {
            worker::internal::start_message_loop_mt(
                dev_fuse_file.ok_or(Error::MissingParameter)?,
                max_write_bytes.ok_or(Error::MissingParameter)?,
                max_read_bytes.ok_or(Error::MissingParameter)?,
                num,
                fs,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Write;
    use std::mem::size_of;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use zerocopy::FromBytes;
    use zerocopy::IntoBytes;

    use super::*;
    use crate::filesystem::Context;
    use crate::filesystem::DirEntry;
    use crate::filesystem::DirectoryIterator;
    use crate::sys::InHeader;
    use crate::sys::InitIn;
    use crate::sys::InitOut;
    use crate::sys::Opcode;
    use crate::sys::OutHeader;
    use crate::sys::ReadIn;
    use crate::sys::KERNEL_MINOR_VERSION;
    use crate::sys::KERNEL_VERSION;

    struct EmptyDirIter;

    impl DirectoryIterator for EmptyDirIter {
        fn next(&mut self) -> Option<DirEntry> {
            None
        }
    }

    struct ReadOnlyDirFs;

    impl FileSystem for ReadOnlyDirFs {
        type Inode = u64;
        type Handle = u64;
        type DirIter = EmptyDirIter;

        fn readdir(
            &self,
            _ctx: Context,
            _inode: Self::Inode,
            _handle: Self::Handle,
            _size: u32,
            _offset: u64,
        ) -> io::Result<Self::DirIter> {
            Ok(EmptyDirIter)
        }
    }

    #[test]
    fn fuse_config_readdir_exceeding_max_write_and_matching_max_read() {
        const MAX_WRITE: u32 = 8 * 1024;
        const MAX_READ: u32 = 64 * 1024;
        const PAGE_SIZE_16K: u32 = 16 * 1024;

        let (mut kernel_sock, daemon_sock) = UnixStream::pair().unwrap();
        let dev_fuse = File::from(OwnedFd::from(daemon_sock));

        let server_thread = std::thread::spawn(move || {
            let mut config = FuseConfig::new();
            config
                .dev_fuse(dev_fuse)
                .max_write(MAX_WRITE)
                .max_read(MAX_READ);
            config.enter_message_loop(ReadOnlyDirFs)
        });

        for (unique, opcode, req_size, expected_error) in [
            (1_u64, Opcode::Readdir, PAGE_SIZE_16K, 0),
            (2_u64, Opcode::Readdir, MAX_READ, 0),
            (3_u64, Opcode::Readdir, MAX_READ + 1, -libc::ENOMEM),
            (4_u64, Opcode::Readdirplus, MAX_READ, 0),
            (5_u64, Opcode::Readdirplus, MAX_READ + 1, -libc::ENOMEM),
        ] {
            let in_header = InHeader {
                len: (size_of::<InHeader>() + size_of::<ReadIn>()) as u32,
                opcode: opcode as u32,
                unique,
                nodeid: 1,
                uid: 0,
                gid: 0,
                pid: 1,
                padding: 0,
            };
            let read_in = ReadIn {
                fh: 1,
                offset: 0,
                size: req_size,
                read_flags: 0,
                lock_owner: 0,
                flags: 0,
                padding: 0,
            };
            kernel_sock.write_all(in_header.as_bytes()).unwrap();
            kernel_sock.write_all(read_in.as_bytes()).unwrap();

            let mut reply = [0_u8; size_of::<OutHeader>()];
            kernel_sock.read_exact(&mut reply).unwrap();
            let out_header = OutHeader::read_from_bytes(&reply).unwrap();
            assert_eq!(out_header.unique, unique);
            assert_eq!(out_header.error, expected_error);
            assert_eq!(out_header.len, size_of::<OutHeader>() as u32);
        }

        drop(kernel_sock);
        let res = server_thread.join().unwrap();
        assert!(matches!(res, Err(Error::DecodeMessage(_))));
    }

    #[test]
    fn fuse_config_init_clamps_max_write_to_configured_value() {
        const MAX_WRITE: u32 = 8 * 1024;
        const MAX_READ: u32 = 64 * 1024;
        assert!(MAX_WRITE < ReadOnlyDirFs.max_buffer_size());

        let (mut kernel_sock, daemon_sock) = UnixStream::pair().unwrap();
        let dev_fuse = File::from(OwnedFd::from(daemon_sock));

        let server_thread = std::thread::spawn(move || {
            let mut config = FuseConfig::new();
            config
                .dev_fuse(dev_fuse)
                .max_write(MAX_WRITE)
                .max_read(MAX_READ);
            config.enter_message_loop(ReadOnlyDirFs)
        });

        let in_header = InHeader {
            len: (size_of::<InHeader>() + size_of::<InitIn>()) as u32,
            opcode: Opcode::Init as u32,
            unique: 1,
            nodeid: 0,
            uid: 0,
            gid: 0,
            pid: 1,
            padding: 0,
        };
        let init_in = InitIn {
            major: KERNEL_VERSION,
            minor: KERNEL_MINOR_VERSION,
            max_readahead: MAX_READ,
            flags: 0,
        };
        kernel_sock.write_all(in_header.as_bytes()).unwrap();
        kernel_sock.write_all(init_in.as_bytes()).unwrap();

        let mut reply = [0_u8; size_of::<OutHeader>() + size_of::<InitOut>()];
        kernel_sock.read_exact(&mut reply).unwrap();
        let (hdr_bytes, body_bytes) = reply.split_at(size_of::<OutHeader>());
        let out_header = OutHeader::read_from_bytes(hdr_bytes).unwrap();
        let init_out = InitOut::read_from_bytes(body_bytes).unwrap();
        assert_eq!(out_header.unique, 1);
        assert_eq!(out_header.error, 0);
        assert_eq!(
            out_header.len,
            (size_of::<OutHeader>() + size_of::<InitOut>()) as u32
        );
        assert_eq!(init_out.max_write, MAX_WRITE);

        drop(kernel_sock);
        let res = server_thread.join().unwrap();
        assert!(matches!(res, Err(Error::DecodeMessage(_))));
    }
}
