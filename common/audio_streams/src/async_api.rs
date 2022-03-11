// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Traits required by `audio_streams` to perform async operations.
//!
//! Consumers must provide an implementation of `AudioStreamsExecutor` to allow the
//! async `audio_streams` interface to do async io on the Executor provided by the consumer.
//!
//! These traits follow the interface of `cros_async`, since it is used by both crosvm and libcras
//! to implement them.
//!
//! The implementation is provided in `cros_async::audio_streams_async`.

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use async_trait::async_trait;
use std::io::Result;
use std::time::Duration;

#[async_trait(?Send)]
pub trait ReadAsync {
    /// Read asynchronously into the provided Vec.
    ///
    /// The ownership of the Vec is returned after the operation completes, along with the number of
    /// bytes read.
    async fn read_to_vec<'a>(
        &'a self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> Result<(usize, Vec<u8>)>;
}

#[async_trait(?Send)]
pub trait WriteAsync {
    /// Write asynchronously from the provided Vec.
    ///
    /// The ownership of the Vec is returned after the operation completes, along with the number of
    /// bytes written.
    async fn write_from_vec<'a>(
        &'a self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> Result<(usize, Vec<u8>)>;
}

pub trait ReadWriteAsync: ReadAsync + WriteAsync {}

pub type AsyncStream = Box<dyn ReadWriteAsync + Send>;

/// Trait of Executor functionality used by `audio_streams`.
#[async_trait(?Send)]
pub trait AudioStreamsExecutor {
    /// Create an object to allow async reads/writes from the specified UnixStream.
    #[cfg(unix)]
    fn async_unix_stream(&self, f: UnixStream) -> Result<AsyncStream>;

    /// Returns a future that resolves after the specified time.
    async fn delay(&self, dur: Duration) -> Result<()>;
}

#[cfg(test)]
pub mod test {
    use super::*;

    /// Stub implementation of the AudioStreamsExecutor to use in unit tests.
    pub struct TestExecutor {}

    #[async_trait(?Send)]
    impl AudioStreamsExecutor for TestExecutor {
        #[cfg(unix)]
        fn async_unix_stream(&self, _f: UnixStream) -> Result<AsyncStream> {
            panic!("Not Implemented");
        }

        async fn delay(&self, dur: Duration) -> Result<()> {
            // Simulates the delay by blocking to satisfy behavior expected in unit tests.
            std::thread::sleep(dur);
            return Ok(());
        }
    }
}
