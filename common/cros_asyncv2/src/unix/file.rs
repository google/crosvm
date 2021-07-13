// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{convert::TryFrom, fs::File as StdFile, io, path::Path, sync::Arc};

use sys_util::SafeDescriptor;

use super::io_driver;
use crate::AsIoBufs;

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

    pub async fn read_iobuf<B: AsIoBufs + 'static>(
        &self,
        buf: B,
        offset: Option<u64>,
    ) -> (anyhow::Result<usize>, B) {
        io_driver::read_iobuf(&self.fd, buf, offset).await
    }

    pub async fn write(&self, buf: &[u8], offset: Option<u64>) -> anyhow::Result<usize> {
        io_driver::write(&self.fd, buf, offset).await
    }

    pub async fn write_iobuf<B: AsIoBufs + 'static>(
        &self,
        buf: B,
        offset: Option<u64>,
    ) -> (anyhow::Result<usize>, B) {
        io_driver::write_iobuf(&self.fd, buf, offset).await
    }

    pub async fn fallocate(&self, file_offset: u64, len: u64, mode: u32) -> anyhow::Result<()> {
        io_driver::fallocate(&self.fd, file_offset, len, mode).await
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
