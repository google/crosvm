// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{cmp::min, convert::TryFrom, fs::File as StdFile, io, path::Path, sync::Arc};

use sys_util::{AsRawDescriptor, SafeDescriptor};

use super::io_driver;
use crate::{AsIoBufs, OwnedIoBuf};

#[derive(Debug)]
pub struct File {
    fd: Arc<SafeDescriptor>,
}

impl File {
    pub fn open<P: AsRef<Path>>(p: P) -> anyhow::Result<File> {
        let f = StdFile::open(p)?;
        File::try_from(f)
    }

    pub fn create<P: AsRef<Path>>(p: P) -> anyhow::Result<File> {
        let f = StdFile::create(p)?;
        File::try_from(f)
    }

    pub async fn read(&self, buf: &mut [u8], offset: Option<u64>) -> anyhow::Result<usize> {
        io_driver::read(&self.fd, buf, offset).await
    }

    pub async fn read_iobuf<B: AsIoBufs + Unpin + 'static>(
        &self,
        buf: B,
        offset: Option<u64>,
    ) -> (anyhow::Result<usize>, B) {
        io_driver::read_iobuf(&self.fd, buf, offset).await
    }

    pub async fn write(&self, buf: &[u8], offset: Option<u64>) -> anyhow::Result<usize> {
        io_driver::write(&self.fd, buf, offset).await
    }

    pub async fn write_iobuf<B: AsIoBufs + Unpin + 'static>(
        &self,
        buf: B,
        offset: Option<u64>,
    ) -> (anyhow::Result<usize>, B) {
        io_driver::write_iobuf(&self.fd, buf, offset).await
    }

    pub async fn punch_hole(&self, offset: u64, len: u64) -> anyhow::Result<()> {
        io_driver::fallocate(
            &self.fd,
            offset,
            len,
            (libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE) as u32,
        )
        .await
    }

    pub async fn write_zeroes(&self, offset: u64, len: u64) -> anyhow::Result<()> {
        let res = io_driver::fallocate(
            &self.fd,
            offset,
            len,
            (libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE) as u32,
        )
        .await;
        match res {
            Ok(()) => Ok(()),
            Err(_) => {
                // Fall back to writing zeros if fallocate doesn't work.
                let buf_size = min(len, 0x10000);
                let mut buf = OwnedIoBuf::new(vec![0u8; buf_size as usize]);
                let mut nwritten = 0;
                while nwritten < len {
                    buf.reset();
                    let remaining = len - nwritten;
                    let write_size = min(remaining, buf_size) as usize;
                    buf.truncate(write_size);

                    let (res, b) = self.write_iobuf(buf, Some(offset + nwritten as u64)).await;
                    nwritten += res? as u64;
                    buf = b;
                }
                Ok(())
            }
        }
    }

    pub async fn allocate(&self, offset: u64, len: u64) -> anyhow::Result<()> {
        io_driver::fallocate(&self.fd, offset, len, 0).await
    }

    pub async fn get_len(&self) -> anyhow::Result<u64> {
        io_driver::stat(&self.fd).await.map(|st| st.st_size as u64)
    }

    pub async fn set_len(&self, len: u64) -> anyhow::Result<()> {
        io_driver::ftruncate(&self.fd, len).await
    }

    pub async fn sync_all(&self) -> anyhow::Result<()> {
        io_driver::fsync(&self.fd, false).await
    }

    pub async fn sync_data(&self) -> anyhow::Result<()> {
        io_driver::fsync(&self.fd, true).await
    }

    pub fn try_clone(&self) -> anyhow::Result<File> {
        self.fd
            .try_clone()
            .map(|fd| File { fd: Arc::new(fd) })
            .map_err(io::Error::from)
            .map_err(From::from)
    }
}

impl TryFrom<StdFile> for File {
    type Error = anyhow::Error;

    fn try_from(f: StdFile) -> anyhow::Result<Self> {
        io_driver::prepare(&f)?;
        Ok(File {
            fd: Arc::new(f.into()),
        })
    }
}

impl TryFrom<File> for StdFile {
    type Error = File;
    fn try_from(f: File) -> Result<StdFile, File> {
        Arc::try_unwrap(f.fd)
            .map(From::from)
            .map_err(|fd| File { fd })
    }
}

impl AsRawDescriptor for File {
    fn as_raw_descriptor(&self) -> sys_util::RawDescriptor {
        self.fd.as_raw_descriptor()
    }
}
