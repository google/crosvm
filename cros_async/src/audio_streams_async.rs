// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the interface required by `audio_streams` using the cros_async Executor.
//!
//! It implements the `AudioStreamsExecutor` trait for `Executor`, so it can be passed into
//! the audio_streams API.
use std::io::Result;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use std::os::windows::io::RawHandle;
use std::time::Duration;

use async_trait::async_trait;
#[cfg(unix)]
use audio_streams::async_api::AsyncStream;
use audio_streams::async_api::AudioStreamsExecutor;
use audio_streams::async_api::EventAsyncWrapper;
use audio_streams::async_api::ReadAsync;
use audio_streams::async_api::ReadWriteAsync;
use audio_streams::async_api::WriteAsync;
#[cfg(unix)]
use base::Descriptor;
#[cfg(unix)]
use base::RawDescriptor;
#[cfg(windows)]
use base::{Event, FromRawDescriptor};

#[cfg(unix)]
use super::AsyncWrapper;
use crate::EventAsync;
use crate::IntoAsync;
use crate::IoSourceExt;
use crate::TimerAsync;

/// A wrapper around IoSourceExt that is compatible with the audio_streams traits.
pub struct IoSourceWrapper<T: IntoAsync + Send> {
    source: Box<dyn IoSourceExt<T> + Send>,
}

#[async_trait(?Send)]
impl<T: IntoAsync + Send> ReadAsync for IoSourceWrapper<T> {
    async fn read_to_vec<'a>(
        &'a self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> Result<(usize, Vec<u8>)> {
        self.source
            .read_to_vec(file_offset, vec)
            .await
            .map_err(Into::into)
    }
}

#[async_trait(?Send)]
impl<T: IntoAsync + Send> WriteAsync for IoSourceWrapper<T> {
    async fn write_from_vec<'a>(
        &'a self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> Result<(usize, Vec<u8>)> {
        self.source
            .write_from_vec(file_offset, vec)
            .await
            .map_err(Into::into)
    }
}

#[async_trait(?Send)]
impl<T: IntoAsync + Send> ReadWriteAsync for IoSourceWrapper<T> {}

#[async_trait(?Send)]
impl EventAsyncWrapper for EventAsync {
    async fn wait(&self) -> Result<u64> {
        self.next_val().await.map_err(Into::into)
    }
}

#[async_trait(?Send)]
impl AudioStreamsExecutor for super::Executor {
    #[cfg(unix)]
    fn async_unix_stream(&self, stream: UnixStream) -> Result<AsyncStream> {
        Ok(Box::new(IoSourceWrapper {
            source: self.async_from(AsyncWrapper::new(stream))?,
        }))
    }

    /// # Safety
    /// This is only safe if `event` is a handle to a Windows Event.
    #[cfg(windows)]
    unsafe fn async_event(&self, event: RawHandle) -> Result<Box<dyn EventAsyncWrapper>> {
        Ok(Box::new(
            EventAsync::new(Event::from_raw_descriptor(event), self)
                .map_err(std::io::Error::from)?,
        ))
    }

    async fn delay(&self, dur: Duration) -> Result<()> {
        TimerAsync::sleep(self, dur).await.map_err(Into::into)
    }

    #[cfg(unix)]
    async fn wait_fd_readable(&self, fd: RawDescriptor) -> Result<()> {
        self.async_from(AsyncWrapper::new(Descriptor(fd)))?
            .wait_readable()
            .await
            .map_err(Into::into)
    }
}
