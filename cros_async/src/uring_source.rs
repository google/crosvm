// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryInto;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use async_trait::async_trait;

use crate::mem::{BackingMemory, MemRegion, VecIoWrapper};
use crate::uring_executor::{Error, RegisteredSource, Result, URingExecutor};
use crate::AsyncError;
use crate::AsyncResult;

/// `UringSource` wraps FD backed IO sources for use with io_uring. It is a thin wrapper around
/// registering an IO source with the uring that provides an `IoSource` implementation.
/// Most useful functions are provided by 'IoSourceExt'.
///
/// # Example
/// ```rust
/// use std::fs::File;
/// use cros_async::{UringSource, ReadAsync, URingExecutor};
///
/// async fn read_four_bytes(source: &UringSource<File>) -> (usize, Vec<u8>) {
///    let mem = vec![0u8; 4];
///    source.read_to_vec(0, mem).await.unwrap()
/// }
///
/// fn read_file(f: File) -> Result<(), Box<dyn std::error::Error>> {
///     let ex = URingExecutor::new()?;
///     let async_source = UringSource::new(f, &ex)?;
///     let (nread, vec) = ex.run_until(read_four_bytes(&async_source))?;
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
    pub fn new(io_source: F, ex: &URingExecutor) -> Result<UringSource<F>> {
        let r = ex.register_source(&io_source)?;
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

#[async_trait(?Send)]
impl<F: AsRawFd> crate::ReadAsync for UringSource<F> {
    /// Reads from the iosource at `file_offset` and fill the given `vec`.
    async fn read_to_vec<'a>(
        &'a self,
        file_offset: u64,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        let buf = Arc::new(VecIoWrapper::from(vec));
        let op = self.registered_source.start_read_to_mem(
            file_offset,
            buf.clone(),
            &[MemRegion {
                offset: 0,
                len: buf.len(),
            }],
        )?;
        let len = op.await?;
        let bytes = if let Ok(v) = Arc::try_unwrap(buf) {
            v.into()
        } else {
            panic!("too many refs on buf");
        };

        Ok((len as usize, bytes))
    }

    /// Wait for the FD of `self` to be readable.
    async fn wait_readable(&self) -> AsyncResult<()> {
        let op = self.registered_source.poll_fd_readable()?;
        op.await?;
        Ok(())
    }

    /// Reads a single u64 (e.g. from an eventfd).
    async fn read_u64(&self) -> AsyncResult<u64> {
        // This doesn't just forward to read_to_vec to avoid an unnecessary extra allocation from
        // async-trait.
        let buf = Arc::new(VecIoWrapper::from(0u64.to_ne_bytes().to_vec()));
        let op = self.registered_source.start_read_to_mem(
            0,
            buf.clone(),
            &[MemRegion {
                offset: 0,
                len: buf.len(),
            }],
        )?;
        let len = op.await?;
        if len != buf.len() as u32 {
            Err(AsyncError::Uring(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("expected to read {} bytes, but read {}", buf.len(), len),
            ))))
        } else {
            let bytes: Vec<u8> = if let Ok(v) = Arc::try_unwrap(buf) {
                v.into()
            } else {
                panic!("too many refs on buf");
            };

            // Will never panic because bytes is of the appropriate size.
            Ok(u64::from_ne_bytes(bytes[..].try_into().unwrap()))
        }
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    async fn read_to_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        let op = self
            .registered_source
            .start_read_to_mem(file_offset, mem, mem_offsets)?;
        let len = op.await?;
        Ok(len as usize)
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
        let buf = Arc::new(VecIoWrapper::from(vec));
        let op = self.registered_source.start_write_from_mem(
            file_offset,
            buf.clone(),
            &[MemRegion {
                offset: 0,
                len: buf.len(),
            }],
        )?;
        let len = op.await?;
        let bytes = if let Ok(v) = Arc::try_unwrap(buf) {
            v.into()
        } else {
            panic!("too many refs on buf");
        };

        Ok((len as usize, bytes))
    }

    /// Writes from the given `mem` from the given offsets to the file starting at `file_offset`.
    async fn write_from_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        let op = self
            .registered_source
            .start_write_from_mem(file_offset, mem, mem_offsets)?;
        let len = op.await?;
        Ok(len as usize)
    }

    /// See `fallocate(2)`. Note this op is synchronous when using the Polled backend.
    async fn fallocate(&self, file_offset: u64, len: u64, mode: u32) -> AsyncResult<()> {
        let op = self
            .registered_source
            .start_fallocate(file_offset, len, mode)?;
        let _ = op.await?;
        Ok(())
    }

    /// Sync all completed write operations to the backing storage.
    async fn fsync(&self) -> AsyncResult<()> {
        let op = self.registered_source.start_fsync()?;
        let _ = op.await?;
        Ok(())
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
    use std::fs::{File, OpenOptions};
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;

    use crate::io_ext::{ReadAsync, WriteAsync};
    use crate::UringSource;

    use super::*;

    #[test]
    fn read_to_mem() {
        use crate::mem::VecIoWrapper;
        use std::io::Write;
        use tempfile::tempfile;

        let ex = URingExecutor::new().unwrap();
        // Use guest memory as a test file, it implements AsRawFd.
        let mut source = tempfile().unwrap();
        let data = vec![0x55; 8192];
        source.write(&data).unwrap();

        let io_obj = UringSource::new(source, &ex).unwrap();

        // Start with memory filled with 0x44s.
        let buf: Arc<VecIoWrapper> = Arc::new(VecIoWrapper::from(vec![0x44; 8192]));

        let fut = io_obj.read_to_mem(
            0,
            Arc::<VecIoWrapper>::clone(&buf),
            &[MemRegion {
                offset: 0,
                len: 8192,
            }],
        );
        assert_eq!(8192, ex.run_until(fut).unwrap().unwrap());
        let vec: Vec<u8> = match Arc::try_unwrap(buf) {
            Ok(v) => v.into(),
            Err(_) => panic!("Too many vec refs"),
        };
        assert!(vec.iter().all(|&b| b == 0x55));
    }

    #[test]
    fn readvec() {
        async fn go(ex: &URingExecutor) {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = source.read_to_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
            assert!(ret_v.iter().all(|&b| b == 0));
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn readmulti() {
        async fn go(ex: &URingExecutor) {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 32];
            let v2 = vec![0x55u8; 32];
            let (ret, ret2) =
                futures::future::join(source.read_to_vec(0, v), source.read_to_vec(32, v2)).await;

            assert!(ret.unwrap().1.iter().all(|&b| b == 0));
            assert!(ret2.unwrap().1.iter().all(|&b| b == 0));
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    async fn read_u64<T: AsRawFd>(source: &UringSource<T>) -> u64 {
        // Init a vec that translates to u64::max;
        let u64_mem = vec![0xffu8; std::mem::size_of::<u64>()];
        let (ret, u64_mem) = source.read_to_vec(0, u64_mem).await.unwrap();
        assert_eq!(ret as usize, std::mem::size_of::<u64>());
        let mut val = 0u64.to_ne_bytes();
        val.copy_from_slice(&u64_mem);
        u64::from_ne_bytes(val)
    }

    #[test]
    fn u64_from_file() {
        let f = File::open("/dev/zero").unwrap();
        let ex = URingExecutor::new().unwrap();
        let source = UringSource::new(f, &ex).unwrap();

        assert_eq!(0u64, ex.run_until(read_u64(&source)).unwrap());
    }

    #[test]
    fn event() {
        use sys_util::EventFd;

        async fn write_event(ev: EventFd, wait: EventFd, ex: &URingExecutor) {
            let wait = UringSource::new(wait, ex).unwrap();
            ev.write(55).unwrap();
            read_u64(&wait).await;
            ev.write(66).unwrap();
            read_u64(&wait).await;
            ev.write(77).unwrap();
            read_u64(&wait).await;
        }

        async fn read_events(ev: EventFd, signal: EventFd, ex: &URingExecutor) {
            let source = UringSource::new(ev, ex).unwrap();
            assert_eq!(read_u64(&source).await, 55);
            signal.write(1).unwrap();
            assert_eq!(read_u64(&source).await, 66);
            signal.write(1).unwrap();
            assert_eq!(read_u64(&source).await, 77);
            signal.write(1).unwrap();
        }

        let event = EventFd::new().unwrap();
        let signal_wait = EventFd::new().unwrap();
        let ex = URingExecutor::new().unwrap();
        let write_task = write_event(
            event.try_clone().unwrap(),
            signal_wait.try_clone().unwrap(),
            &ex,
        );
        let read_task = read_events(event, signal_wait, &ex);
        ex.run_until(futures::future::join(read_task, write_task))
            .unwrap();
    }

    #[test]
    fn pend_on_pipe() {
        use std::io::Write;

        use futures::future::Either;

        async fn do_test(ex: &URingExecutor) {
            let (read_source, mut w) = sys_util::pipe(true).unwrap();
            let source = UringSource::new(read_source, ex).unwrap();
            let done = Box::pin(async { 5usize });
            let pending = Box::pin(read_u64(&source));
            match futures::future::select(pending, done).await {
                Either::Right((5, pending)) => {
                    // Write to the pipe so that the kernel will release the memory associated with
                    // the uring read operation.
                    w.write(&[0]).expect("failed to write to pipe");
                    ::std::mem::drop(pending);
                }
                _ => panic!("unexpected select result"),
            };
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(do_test(&ex)).unwrap();
    }

    #[test]
    fn readmem() {
        async fn go(ex: &URingExecutor) {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 64];
            let vw = Arc::new(VecIoWrapper::from(v));
            let ret = source
                .read_to_mem(
                    0,
                    Arc::<VecIoWrapper>::clone(&vw),
                    &[MemRegion { offset: 0, len: 32 }],
                )
                .await
                .unwrap();
            assert_eq!(32, ret);
            let vec: Vec<u8> = match Arc::try_unwrap(vw) {
                Ok(v) => v.into(),
                Err(_) => panic!("Too many vec refs"),
            };
            assert!(vec.iter().take(32).all(|&b| b == 0));
            assert!(vec.iter().skip(32).all(|&b| b == 0x55));

            // test second half of memory too.
            let v = vec![0x55u8; 64];
            let vw = Arc::new(VecIoWrapper::from(v));
            let ret = source
                .read_to_mem(
                    0,
                    Arc::<VecIoWrapper>::clone(&vw),
                    &[MemRegion {
                        offset: 32,
                        len: 32,
                    }],
                )
                .await
                .unwrap();
            assert_eq!(32, ret);
            let v: Vec<u8> = match Arc::try_unwrap(vw) {
                Ok(v) => v.into(),
                Err(_) => panic!("Too many vec refs"),
            };
            assert!(v.iter().take(32).all(|&b| b == 0x55));
            assert!(v.iter().skip(32).all(|&b| b == 0));
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn range_error() {
        async fn go(ex: &URingExecutor) {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 64];
            let vw = Arc::new(VecIoWrapper::from(v));
            let ret = source
                .read_to_mem(
                    0,
                    Arc::<VecIoWrapper>::clone(&vw),
                    &[MemRegion {
                        offset: 32,
                        len: 33,
                    }],
                )
                .await;
            assert!(ret.is_err());
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn fallocate() {
        async fn go(ex: &URingExecutor) {
            let dir = tempfile::TempDir::new().unwrap();
            let mut file_path = PathBuf::from(dir.path());
            file_path.push("test");

            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&file_path)
                .unwrap();
            let source = UringSource::new(f, &ex).unwrap();
            if let Err(e) = source.fallocate(0, 4096, 0).await {
                match e {
                    crate::io_ext::Error::Uring(crate::uring_executor::Error::Io(io_err)) => {
                        if io_err.kind() == std::io::ErrorKind::InvalidInput {
                            // Skip the test on kernels before fallocate support.
                            return;
                        }
                    }
                    _ => panic!("Unexpected uring error on fallocate: {}", e),
                }
            }

            let meta_data = std::fs::metadata(&file_path).unwrap();
            assert_eq!(meta_data.len(), 4096);
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn fsync() {
        async fn go(ex: &URingExecutor) {
            let f = tempfile::tempfile().unwrap();
            let source = UringSource::new(f, ex).unwrap();
            source.fsync().await.unwrap();
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn wait_read() {
        async fn go(ex: &URingExecutor) {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f, ex).unwrap();
            source.wait_readable().await.unwrap();
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn writemem() {
        async fn go(ex: &URingExecutor) {
            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .open("/tmp/write_from_vec")
                .unwrap();
            let source = UringSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 64];
            let vw = Arc::new(crate::mem::VecIoWrapper::from(v));
            let ret = source
                .write_from_mem(0, vw, &[MemRegion { offset: 0, len: 32 }])
                .await
                .unwrap();
            assert_eq!(32, ret);
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn writevec() {
        async fn go(ex: &URingExecutor) {
            let f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open("/tmp/write_from_vec")
                .unwrap();
            let source = UringSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let (ret, ret_v) = source.write_from_vec(0, v).await.unwrap();
            assert_eq!(32, ret);
            assert_eq!(v_ptr, ret_v.as_ptr());
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn writemulti() {
        async fn go(ex: &URingExecutor) {
            let f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open("/tmp/write_from_vec")
                .unwrap();
            let source = UringSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 32];
            let v2 = vec![0x55u8; 32];
            let (r, r2) =
                futures::future::join(source.write_from_vec(0, v), source.write_from_vec(32, v2))
                    .await;
            assert_eq!(32, r.unwrap().0);
            assert_eq!(32, r2.unwrap().0);
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }
}
