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
use std::time::Duration;

use async_trait::async_trait;
#[cfg(unix)]
use audio_streams::async_api::AsyncStream;
use audio_streams::async_api::AudioStreamsExecutor;
use audio_streams::async_api::ReadAsync;
use audio_streams::async_api::ReadWriteAsync;
use audio_streams::async_api::WriteAsync;

#[cfg(unix)]
use super::AsyncWrapper;
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
impl AudioStreamsExecutor for super::Executor {
    #[cfg(unix)]
    fn async_unix_stream(&self, stream: UnixStream) -> Result<AsyncStream> {
        return Ok(Box::new(IoSourceWrapper {
            source: self.async_from(AsyncWrapper::new(stream))?,
        }));
    }

    async fn delay(&self, dur: Duration) -> Result<()> {
        TimerAsync::sleep(self, dur).await.map_err(Into::into)
    }
}
