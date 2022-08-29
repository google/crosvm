// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::io;
use std::mem::size_of;
use std::sync::Arc;

use anyhow::ensure;
use anyhow::Context;
use base::SafeDescriptor;

use super::io_driver;

#[derive(Debug)]
pub struct Event {
    fd: Arc<SafeDescriptor>,
}

impl Event {
    pub fn new() -> anyhow::Result<Event> {
        base::Event::new()
            .map_err(io::Error::from)
            .context("failed to create eventfd")
            .and_then(Event::try_from)
    }

    pub async fn next_val(&self) -> anyhow::Result<u64> {
        let mut buf = 0u64.to_ne_bytes();
        let count = io_driver::read(&self.fd, &mut buf, None).await?;

        ensure!(
            count == size_of::<u64>(),
            io::Error::from(io::ErrorKind::UnexpectedEof)
        );

        Ok(u64::from_ne_bytes(buf))
    }

    pub async fn notify(&self) -> anyhow::Result<()> {
        let buf = 1u64.to_ne_bytes();
        let count = io_driver::write(&self.fd, &buf, None).await?;

        ensure!(
            count == size_of::<u64>(),
            io::Error::from(io::ErrorKind::WriteZero)
        );

        Ok(())
    }

    pub fn try_clone(&self) -> anyhow::Result<Event> {
        self.fd
            .try_clone()
            .map(|fd| Event { fd: Arc::new(fd) })
            .map_err(io::Error::from)
            .map_err(From::from)
    }
}

impl TryFrom<base::Event> for Event {
    type Error = anyhow::Error;

    fn try_from(evt: base::Event) -> anyhow::Result<Event> {
        io_driver::prepare(&evt)?;
        Ok(Event {
            fd: Arc::new(SafeDescriptor::from(evt)),
        })
    }
}
