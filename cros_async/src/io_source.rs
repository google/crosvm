// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::AsRawDescriptor;
use std::sync::Arc;

#[cfg(unix)]
use crate::sys::unix::PollSource;
#[cfg(unix)]
use crate::sys::unix::UringSource;
#[cfg(windows)]
use crate::sys::windows::HandleSource;
#[cfg(windows)]
use crate::sys::windows::OverlappedSource;
use crate::AsyncResult;
use crate::BackingMemory;
use crate::MemRegion;

/// Associates an IO object `F` with cros_async's runtime and exposes an API to perform async IO on
/// that object's descriptor.
pub enum IoSource<F: base::AsRawDescriptor> {
    #[cfg(unix)]
    Uring(UringSource<F>),
    #[cfg(unix)]
    Epoll(PollSource<F>),
    #[cfg(windows)]
    Handle(HandleSource<F>),
    #[cfg(windows)]
    Overlapped(OverlappedSource<F>),
}

pub enum AllocateMode {
    #[cfg(unix)]
    Allocate,
    PunchHole,
    ZeroRange,
}

// This assume we always want KEEP_SIZE
#[cfg(unix)]
impl From<AllocateMode> for u32 {
    fn from(value: AllocateMode) -> Self {
        match value {
            AllocateMode::Allocate => 0,
            AllocateMode::PunchHole => {
                (libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE) as u32
            }
            AllocateMode::ZeroRange => {
                (libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE) as u32
            }
        }
    }
}

/// Invoke a method on the underlying source type and await the result.
///
/// `await_on_inner(io_source, method, ...)` => `inner_source.method(...).await`
macro_rules! await_on_inner {
    ($x:ident, $method:ident $(, $args:expr)*) => {
        match $x {
            #[cfg(unix)]
            IoSource::Uring(x) => UringSource::$method(x, $($args),*).await,
            #[cfg(unix)]
            IoSource::Epoll(x) => PollSource::$method(x, $($args),*).await,
            #[cfg(windows)]
            IoSource::Handle(x) => HandleSource::$method(x, $($args),*).await,
            #[cfg(windows)]
            IoSource::Overlapped(x) => OverlappedSource::$method(x, $($args),*).await,
        }
    };
}

/// Invoke a method on the underlying source type.
///
/// `on_inner(io_source, method, ...)` => `inner_source.method(...)`
macro_rules! on_inner {
    ($x:ident, $method:ident $(, $args:expr)*) => {
        match $x {
            #[cfg(unix)]
            IoSource::Uring(x) => UringSource::$method(x, $($args),*),
            #[cfg(unix)]
            IoSource::Epoll(x) => PollSource::$method(x, $($args),*),
            #[cfg(windows)]
            IoSource::Handle(x) => HandleSource::$method(x, $($args),*),
            #[cfg(windows)]
            IoSource::Overlapped(x) => OverlappedSource::$method(x, $($args),*),
        }
    };
}

impl<F: AsRawDescriptor> IoSource<F> {
    /// Reads at `file_offset` and fills the given `vec`.
    pub async fn read_to_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        await_on_inner!(self, read_to_vec, file_offset, vec)
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    pub async fn read_to_mem<'a>(
        &'a self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        await_on_inner!(self, read_to_mem, file_offset, mem, mem_offsets)
    }

    /// Reads a single u64 at the current offset.
    pub async fn read_u64(&self) -> AsyncResult<u64> {
        await_on_inner!(self, read_u64)
    }

    /// Waits for the object to be readable.
    pub async fn wait_readable(&self) -> AsyncResult<()> {
        await_on_inner!(self, wait_readable)
    }

    /// Writes from the given `vec` to the file starting at `file_offset`.
    pub async fn write_from_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        await_on_inner!(self, write_from_vec, file_offset, vec)
    }

    /// Writes from the given `mem` at the given offsets to the file starting at `file_offset`.
    pub async fn write_from_mem<'a>(
        &'a self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        await_on_inner!(self, write_from_mem, file_offset, mem, mem_offsets)
    }

    /// See `fallocate(2)`. Note this op is synchronous when using the Polled backend.
    pub async fn fallocate(
        &self,
        file_offset: u64,
        len: u64,
        mode: AllocateMode,
    ) -> AsyncResult<()> {
        await_on_inner!(self, fallocate, file_offset, len, mode)
    }

    /// Sync all completed write operations to the backing storage.
    pub async fn fsync(&self) -> AsyncResult<()> {
        await_on_inner!(self, fsync)
    }

    /// Yields the underlying IO source.
    pub fn into_source(self) -> F {
        on_inner!(self, into_source)
    }

    /// Provides a ref to the underlying IO source.
    pub fn as_source(&self) -> &F {
        on_inner!(self, as_source)
    }

    /// Provides a mutable ref to the underlying IO source.
    pub fn as_source_mut(&mut self) -> &mut F {
        on_inner!(self, as_source_mut)
    }

    /// Waits on a waitable handle.
    ///
    /// Needed for Windows currently, and subject to a potential future upstream.
    pub async fn wait_for_handle(&self) -> AsyncResult<u64> {
        await_on_inner!(self, wait_for_handle)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use std::sync::Arc;

    use tempfile::tempfile;

    use super::*;
    use crate::mem::VecIoWrapper;
    #[cfg(unix)]
    use crate::sys::unix::uring_executor::is_uring_stable;
    use crate::Executor;
    use crate::ExecutorKind;
    use crate::MemRegion;

    #[cfg(unix)]
    fn all_kinds() -> Vec<ExecutorKind> {
        let mut kinds = vec![ExecutorKind::Fd];
        if is_uring_stable() {
            kinds.push(ExecutorKind::Uring);
        }
        kinds
    }
    #[cfg(windows)]
    fn all_kinds() -> Vec<ExecutorKind> {
        // TODO: Test OverlappedSource. It requires files to be opened specially, so this test
        // fixture needs to be refactored first.
        vec![ExecutorKind::Handle]
    }

    fn tmpfile_with_contents(bytes: &[u8]) -> File {
        let mut f = tempfile().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f
    }

    #[test]
    fn readvec() {
        for kind in all_kinds() {
            async fn go<F: AsRawDescriptor>(async_source: IoSource<F>) {
                let v = vec![0x55u8; 32];
                let v_ptr = v.as_ptr();
                let (n, v) = async_source.read_to_vec(None, v).await.unwrap();
                assert_eq!(v_ptr, v.as_ptr());
                assert_eq!(n, 4);
                assert_eq!(&v[..4], "data".as_bytes());
            }

            let f = tmpfile_with_contents("data".as_bytes());
            let ex = Executor::with_executor_kind(kind).unwrap();
            let source = ex.async_from(f).unwrap();
            ex.run_until(go(source)).unwrap();
        }
    }

    #[test]
    fn writevec() {
        for kind in all_kinds() {
            async fn go<F: AsRawDescriptor>(async_source: IoSource<F>) {
                let v = "data".as_bytes().to_vec();
                let v_ptr = v.as_ptr();
                let (n, v) = async_source.write_from_vec(None, v).await.unwrap();
                assert_eq!(n, 4);
                assert_eq!(v_ptr, v.as_ptr());
            }

            let mut f = tmpfile_with_contents(&[]);
            let ex = Executor::with_executor_kind(kind).unwrap();
            let source = ex.async_from(f.try_clone().unwrap()).unwrap();
            ex.run_until(go(source)).unwrap();

            f.rewind().unwrap();
            assert_eq!(std::io::read_to_string(f).unwrap(), "data");
        }
    }

    #[test]
    fn readmem() {
        for kind in all_kinds() {
            async fn go<F: AsRawDescriptor>(async_source: IoSource<F>) {
                let mem = Arc::new(VecIoWrapper::from(vec![b' '; 10]));
                let n = async_source
                    .read_to_mem(
                        None,
                        Arc::<VecIoWrapper>::clone(&mem),
                        &[
                            MemRegion { offset: 0, len: 2 },
                            MemRegion { offset: 4, len: 1 },
                        ],
                    )
                    .await
                    .unwrap();
                assert_eq!(n, 3);
                let vec: Vec<u8> = match Arc::try_unwrap(mem) {
                    Ok(v) => v.into(),
                    Err(_) => panic!("Too many vec refs"),
                };
                assert_eq!(std::str::from_utf8(&vec).unwrap(), "da  t     ");
            }

            let f = tmpfile_with_contents("data".as_bytes());
            let ex = Executor::with_executor_kind(kind).unwrap();
            let source = ex.async_from(f).unwrap();
            ex.run_until(go(source)).unwrap();
        }
    }

    #[test]
    fn writemem() {
        for kind in all_kinds() {
            async fn go<F: AsRawDescriptor>(async_source: IoSource<F>) {
                let mem = Arc::new(VecIoWrapper::from("data".as_bytes().to_vec()));
                let ret = async_source
                    .write_from_mem(
                        None,
                        Arc::<VecIoWrapper>::clone(&mem),
                        &[
                            MemRegion { offset: 0, len: 1 },
                            MemRegion { offset: 2, len: 2 },
                        ],
                    )
                    .await
                    .unwrap();
                assert_eq!(ret, 3);
            }

            let mut f = tmpfile_with_contents(&[]);
            let ex = Executor::with_executor_kind(kind).unwrap();
            let source = ex.async_from(f.try_clone().unwrap()).unwrap();
            ex.run_until(go(source)).unwrap();

            f.rewind().unwrap();
            assert_eq!(std::io::read_to_string(f).unwrap(), "dta");
        }
    }

    #[cfg(unix)] // TODO: Not implemented on windows.
    #[test]
    fn read_u64s() {
        for kind in all_kinds() {
            async fn go(source: IoSource<File>) -> u64 {
                source.read_u64().await.unwrap()
            }

            let f = tmpfile_with_contents(&42u64.to_ne_bytes());
            let ex = Executor::with_executor_kind(kind).unwrap();
            let val = ex.run_until(go(ex.async_from(f).unwrap())).unwrap();
            assert_eq!(val, 42);
        }
    }

    #[test]
    fn fsync() {
        for kind in all_kinds() {
            async fn go<F: AsRawDescriptor>(source: IoSource<F>) {
                let v = vec![0x55u8; 32];
                let v_ptr = v.as_ptr();
                let ret = source.write_from_vec(None, v).await.unwrap();
                assert_eq!(ret.0, 32);
                let ret_v = ret.1;
                assert_eq!(v_ptr, ret_v.as_ptr());
                source.fsync().await.unwrap();
            }

            let f = tempfile::tempfile().unwrap();
            let ex = Executor::with_executor_kind(kind).unwrap();
            let source = ex.async_from(f).unwrap();

            ex.run_until(go(source)).unwrap();
        }
    }
}
