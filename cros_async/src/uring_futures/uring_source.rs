// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryInto;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::AsRawFd;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::io_source::IoSource;
use crate::uring_executor::{self, Error, PendingOperation, RegisteredSource, Result};
use crate::uring_futures;
use crate::uring_mem::{BackingMemory, MemRegion};
use crate::AsyncError;
use crate::AsyncResult;
use async_trait::async_trait;

/// `UringSource` wraps FD backed IO sources for use with io_uring. It is a thin wrapper around
/// registering an IO source with the uring that provides an `IoSource` implementation.
/// Most useful functions are provided by 'IoSourceExt'.
///
/// # Example
/// ```rust
/// use std::fs::File;
/// use cros_async::{UringSource, ReadAsync};
///
/// async fn read_four_bytes(source: &UringSource<File>) -> (usize, Vec<u8>) {
///    let mem = vec![0u8; 4];
///    source.read_to_vec(0, mem).await.unwrap()
/// }
///
/// fn read_file(f: File) -> Result<(), Box<dyn std::error::Error>> {
///     let async_source = UringSource::new(f)?;
///     let read_future = read_four_bytes(&async_source);
///     futures::pin_mut!(read_future);
///     let (nread, vec) = cros_async::run_one_uring(read_future)?;
///     assert_eq!(nread, 4);
///     assert_eq!(vec.len(), 4);
///     Ok(())
/// }
/// ```
pub struct UringSource<F: AsRawFd> {
    registered_source: RegisteredSource,
    source: F,
}

impl<F: AsRawFd> UringSource<F> {
    /// Creates a new `UringSource` that wraps the given `io_source` object.
    pub fn new(io_source: F) -> Result<UringSource<F>> {
        let r = uring_executor::register_source(&io_source)?;
        Ok(UringSource {
            registered_source: r,
            source: io_source,
        })
    }

    /// Consume `self` and return the object used to create it.
    pub fn into_source(self) -> F {
        self.source
    }
}

impl<F: AsRawFd> IoSource for UringSource<F> {
    fn read_to_mem(
        &self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &[MemRegion],
    ) -> Result<PendingOperation> {
        self.registered_source
            .start_read_to_mem(file_offset, mem, mem_offsets)
    }

    fn write_from_mem(
        &self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &[MemRegion],
    ) -> Result<PendingOperation> {
        self.registered_source
            .start_write_from_mem(file_offset, mem, mem_offsets)
    }

    fn fallocate(&self, file_offset: u64, len: u64, mode: u32) -> Result<PendingOperation> {
        self.registered_source
            .start_fallocate(file_offset, len, mode)
    }

    fn fsync(&self) -> Result<PendingOperation> {
        self.registered_source.start_fsync()
    }

    // wait for the inner source to be readable and return a refernce to it.
    fn wait_readable(&self) -> Result<PendingOperation> {
        self.registered_source.poll_fd_readable()
    }

    fn poll_complete(&self, cx: &mut Context, token: &mut PendingOperation) -> Poll<Result<u32>> {
        self.registered_source.poll_complete(cx, token)
    }
}

#[async_trait(?Send)]
impl<F: AsRawFd> crate::ReadAsync for UringSource<F> {
    /// Reads from the iosource at `file_offset` and fill the given `vec`.
    async fn read_to_vec<'a>(
        &'a self,
        file_offset: u64,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        uring_futures::ReadVec::new(self, file_offset, vec)
            .await
            .map(|(n, vec)| (n as usize, vec))
            .map_err(AsyncError::Uring)
    }

    /// Wait for the FD of `self` to be readable.
    async fn wait_readable(&self) -> AsyncResult<()> {
        uring_futures::PollFd::new(self)
            .await
            .map_err(AsyncError::Uring)
    }

    /// Reads a single u64 (e.g. from an eventfd).
    async fn read_u64(&self) -> AsyncResult<u64> {
        let bytes = 0u64.to_ne_bytes().to_vec();
        let (len, bytes) = self.read_to_vec(0, bytes).await?;
        if len != bytes.len() {
            Err(AsyncError::Uring(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("expected to read {} bytes, but read {}", bytes.len(), len),
            ))))
        } else {
            // Will never panic because bytes is of the appropriate size.
            Ok(u64::from_ne_bytes(bytes[..].try_into().unwrap()))
        }
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    async fn read_to_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        uring_futures::ReadMem::new(self, file_offset, mem, mem_offsets)
            .await
            .map(|n| n as usize)
            .map_err(AsyncError::Uring)
    }
}

#[async_trait(?Send)]
impl<F: AsRawFd> crate::WriteAsync for UringSource<F> {
    /// Writes from the given `vec` to the file starting at `file_offset`.
    async fn write_from_vec<'a>(
        &'a self,
        file_offset: u64,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        uring_futures::WriteVec::new(self, file_offset, vec)
            .await
            .map(|(n, vec)| (n as usize, vec))
            .map_err(AsyncError::Uring)
    }

    /// Writes from the given `mem` from the given offsets to the file starting at `file_offset`.
    async fn write_from_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        uring_futures::WriteMem::new(self, file_offset, mem, mem_offsets)
            .await
            .map(|n| n as usize)
            .map_err(AsyncError::Uring)
    }

    /// See `fallocate(2)`. Note this op is synchronous when using the Polled backend.
    async fn fallocate(&self, file_offset: u64, len: u64, mode: u32) -> AsyncResult<()> {
        uring_futures::Fallocate::new(self, file_offset, len, mode)
            .await
            .map_err(AsyncError::Uring)
    }

    /// Sync all completed write operations to the backing storage.
    async fn fsync(&self) -> AsyncResult<()> {
        uring_futures::Fsync::new(self)
            .await
            .map_err(AsyncError::Uring)
    }
}

#[async_trait(?Send)]
impl<F: AsRawFd> crate::IoSourceExt<F> for UringSource<F> {
    /// Yields the underlying IO source.
    fn into_source(self: Box<Self>) -> F {
        self.source
    }

    /// Provides a mutable ref to the underlying IO source.
    fn as_source(&self) -> &F {
        &self.source
    }

    /// Provides a ref to the underlying IO source.
    fn as_source_mut(&mut self) -> &mut F {
        &mut self.source
    }
}

impl<F: AsRawFd> Deref for UringSource<F> {
    type Target = F;

    fn deref(&self) -> &Self::Target {
        &self.source
    }
}

impl<F: AsRawFd> DerefMut for UringSource<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.source
    }
}

#[cfg(test)]
mod tests {
    use futures::pin_mut;
    use std::future::Future;
    use std::pin::Pin;

    use super::*;

    enum MemTestState<'a> {
        Init {
            file_offset: u64,
            mem: Rc<dyn BackingMemory>,
            mem_offsets: &'a [MemRegion],
        },
        Wait {
            token: PendingOperation,
        },
        Idle,
    }

    pub struct TestRead<'a, F: AsRawFd + Unpin> {
        inner: &'a UringSource<F>,
        state: MemTestState<'a>,
    }

    impl<'a, F: AsRawFd + Unpin> TestRead<'a, F> {
        fn new(
            io: &'a UringSource<F>,
            file_offset: u64,
            mem: Rc<dyn BackingMemory>,
            mem_offsets: &'a [MemRegion],
        ) -> Self {
            TestRead {
                inner: io,
                state: MemTestState::Init {
                    file_offset,
                    mem,
                    mem_offsets,
                },
            }
        }
    }

    impl<'a, F: AsRawFd + Unpin> Future for TestRead<'a, F> {
        type Output = Result<u32>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            use MemTestState::*;

            let mut state = match std::mem::replace(&mut self.state, Idle) {
                Init {
                    file_offset,
                    mem,
                    mem_offsets,
                } => match Pin::new(self.inner).read_to_mem(file_offset, mem, mem_offsets) {
                    Ok(token) => Wait { token },
                    Err(e) => return Poll::Ready(Err(e)),
                },
                Idle => Idle,
                Wait { token } => Wait { token },
            };

            let ret = match &mut state {
                Wait { token } => Pin::new(self.inner).poll_complete(cx, token),
                _ => panic!("Invalid state in future"),
            };
            self.state = state;
            ret
        }
    }

    #[test]
    fn read_to_mem() {
        use crate::uring_mem::VecIoWrapper;
        use std::io::Write;
        use tempfile::tempfile;

        let io_obj = Box::pin({
            // Use guest memory as a test file, it implements AsRawFd.
            let mut source = tempfile().unwrap();
            let data = vec![0x55; 8192];
            source.write(&data).unwrap();
            UringSource::new(source).unwrap()
        });

        // Start with memory filled with 0x44s.
        let buf: Rc<VecIoWrapper> = Rc::new(VecIoWrapper::from(vec![0x44; 8192]));

        let fut = TestRead::new(
            &io_obj,
            0,
            Rc::<VecIoWrapper>::clone(&buf),
            &[MemRegion {
                offset: 0,
                len: 8192,
            }],
        );
        pin_mut!(fut);
        assert_eq!(8192, crate::run_one_uring(fut).unwrap().unwrap());
        let vec: Vec<u8> = match Rc::try_unwrap(buf) {
            Ok(v) => v.into(),
            Err(_) => panic!("Too many vec refs"),
        };
        assert!(vec.iter().all(|&b| b == 0x55));
    }
}
