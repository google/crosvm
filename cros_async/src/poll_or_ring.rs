// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Temporarily to be used to hide the poll vs uring distinction from the rest of crosvm.

use std::fmt::{self, Display};
use std::os::unix::io::AsRawFd;
use std::rc::Rc;

use crate::io_ext::IoSourceExt;
use crate::poll_source::PollSource;
use crate::uring_mem::{BackingMemory, MemRegion};
use crate::UringSource;

#[derive(Debug)]
/// Errors when executing the future.
pub enum Error {
    /// An error with a polled(FD) source.
    Poll(crate::poll_source::Error),
    /// An error reading from a wrapped source.
    ReadingInner(isize),
    /// An error with a uring source.
    Uring(crate::uring_executor::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            Poll(e) => write!(f, "An error with a poll source: {}.", e),
            ReadingInner(e) => write!(f, "An error reading from the source: {}.", e),
            Uring(e) => write!(f, "An error with a uring source: {}.", e),
        }
    }
}
impl std::error::Error for Error {}

/// Either a polled or uring driven IO source.
/// Provided to allow for a common interface while older kernels without uring support are still
/// used.
/// Because async functions aren't allowed in traits, this wrapper is needed to abstract the two
/// implementations.
///
/// # Example
/// ```rust
/// use std::fs::File;
/// use cros_async::{PollOrRing};
///
/// async fn read_four_bytes(source: &PollOrRing<File>) -> (usize, Vec<u8>) {
///    let mem = vec![0u8; 4];
///    source.read_to_vec(0, mem).await.unwrap()
/// }
///
/// fn read_file(f: File) -> Result<(), Box<dyn std::error::Error>> {
///     let async_source = PollOrRing::new(f)?;
///     let read_future = read_four_bytes(&async_source);
///     futures::pin_mut!(read_future);
///     let (nread, vec) = cros_async::run_one(read_future)?;
///     assert_eq!(nread, 4);
///     assert_eq!(vec.len(), 4);
///     Ok(())
/// }
/// ```
pub enum PollOrRing<F: AsRawFd> {
    Poll(PollSource<F>),
    Uring(UringSource<F>),
}

impl<F: AsRawFd + Unpin> PollOrRing<F> {
    /// Creates a `PollOrRing` that uses uring if available or falls back to the fd_executor if not.
    /// Note that on older kernels (pre 5.6) FDs such as event or timer FDs are unreliable when
    /// having readvwritev performed through io_uring. To deal with EventFd or TimerFd, use
    /// `U64Source` instead.
    pub fn new(f: F) -> Result<Self> {
        if crate::uring_executor::use_uring() {
            Self::new_uring(f)
        } else {
            Self::new_poll(f)
        }
    }

    /// Creates a `PollOrRing` that uses uring.
    pub fn new_uring(f: F) -> Result<Self> {
        UringSource::new(f)
            .map_err(Error::Uring)
            .map(PollOrRing::Uring)
    }

    /// Creates a `PollOrRing` that uses polled FDs.
    pub fn new_poll(f: F) -> Result<Self> {
        PollSource::new(f)
            .map_err(Error::Poll)
            .map(PollOrRing::Poll)
    }

    /// Reads from the iosource at `file_offset` and fill the given `vec`.
    pub async fn read_to_vec(&self, file_offset: u64, vec: Vec<u8>) -> Result<(usize, Vec<u8>)> {
        match &self {
            PollOrRing::Poll(s) => s
                .read_to_vec(file_offset, vec)
                .await
                .map_err(Error::Poll)
                .map(|(n, vec)| (n as usize, vec)),
            PollOrRing::Uring(s) => s
                .read_to_vec(file_offset, vec)
                .await
                .map_err(Error::Uring)
                .map(|(n, vec)| (n as usize, vec)),
        }
    }

    /// Writes from the given `vec` to the file starting at `file_offset`.
    pub async fn write_from_vec(&self, file_offset: u64, vec: Vec<u8>) -> Result<(usize, Vec<u8>)> {
        match &self {
            PollOrRing::Poll(s) => s
                .write_from_vec(file_offset, vec)
                .await
                .map_err(Error::Poll)
                .map(|(n, vec)| (n as usize, vec)),
            PollOrRing::Uring(s) => s
                .write_from_vec(file_offset, vec)
                .await
                .map_err(Error::Uring)
                .map(|(n, vec)| (n as usize, vec)),
        }
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    pub async fn read_to_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &'a [MemRegion],
    ) -> Result<usize>
    where
        Self: Unpin,
    {
        match &self {
            PollOrRing::Poll(s) => s
                .read_to_mem(file_offset, mem, mem_offsets)
                .await
                .map_err(Error::Poll)
                .map(|n| n as usize),
            PollOrRing::Uring(s) => s
                .read_to_mem(file_offset, mem, mem_offsets)
                .await
                .map_err(Error::Uring)
                .map(|n| n as usize),
        }
    }

    /// Writes from the given `mem` from the given offsets to the file starting at `file_offset`.
    pub async fn write_from_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &'a [MemRegion],
    ) -> Result<usize>
    where
        Self: Unpin,
    {
        match &self {
            PollOrRing::Poll(s) => s
                .write_from_mem(file_offset, mem, mem_offsets)
                .await
                .map_err(Error::Poll)
                .map(|n| n as usize),
            PollOrRing::Uring(s) => s
                .write_from_mem(file_offset, mem, mem_offsets)
                .await
                .map_err(Error::Uring)
                .map(|n| n as usize),
        }
    }

    /// See `fallocate(2)`. Note this op is synchronous when using the Polled backend.
    pub async fn fallocate(&self, file_offset: u64, len: u64, mode: u32) -> Result<()> {
        match &self {
            PollOrRing::Poll(s) => Ok(s.fallocate(file_offset, len, mode)),
            PollOrRing::Uring(s) => s
                .fallocate(file_offset, len, mode)
                .await
                .map_err(Error::Uring),
        }
    }

    /// Sync all completed operations to the disk. Note this op is synchronous when using the Polled
    /// backend.
    pub async fn fsync(&self) -> Result<()> {
        match &self {
            PollOrRing::Poll(s) => Ok(s.fsync()),
            PollOrRing::Uring(s) => s.fsync().await.map_err(Error::Uring),
        }
    }

    /// Wait for the soruce to be readable.
    pub async fn wait_readable(&self) -> Result<()> {
        match &self {
            PollOrRing::Poll(s) => s.wait_readable().await.map_err(Error::Poll),
            PollOrRing::Uring(s) => s.wait_readable().await.map_err(Error::Uring),
        }
    }
}

/// Convenience helper for reading a series of u64s which is common for timerfd and eventfd.
pub struct U64Source<F: AsRawFd + Unpin> {
    inner: PollOrRing<F>,
}

impl<F: AsRawFd + Unpin> U64Source<F> {
    pub fn new(source: F) -> Result<Self> {
        Ok(U64Source {
            inner: PollOrRing::new(source)?,
        })
    }

    pub fn new_poll(source: F) -> Result<Self> {
        Ok(U64Source {
            inner: PollOrRing::new_poll(source)?,
        })
    }

    pub async fn next_val(&mut self) -> Result<u64> {
        match &mut self.inner {
            PollOrRing::Poll(s) => s.read_u64().await.map_err(Error::Poll),
            PollOrRing::Uring(s) => {
                s.wait_readable().await.map_err(Error::Uring)?;
                let mut bytes = 0u64.to_ne_bytes();
                // Safe to read to the buffer of known length.
                let ret =
                    unsafe { libc::read(s.as_raw_fd(), bytes.as_mut_ptr() as *mut _, bytes.len()) };
                if ret < 0 {
                    return Err(Error::ReadingInner(ret));
                }
                Ok(u64::from_ne_bytes(bytes))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::path::PathBuf;

    use futures::pin_mut;

    use crate::uring_mem::{MemRegion, VecIoWrapper};
    use crate::Executor;

    use super::*;

    #[test]
    fn readvec() {
        async fn go<F: AsRawFd + Unpin>(async_source: PollOrRing<F>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.read_to_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
            assert!(ret_v.iter().all(|&b| b == 0));
        }

        let f = File::open("/dev/zero").unwrap();
        let uring_source = PollOrRing::new_uring(f).unwrap();
        let fut = go(uring_source);
        pin_mut!(fut);
        crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();

        let f = File::open("/dev/zero").unwrap();
        let poll_source = PollOrRing::new_poll(f).unwrap();
        let fut = go(poll_source);
        pin_mut!(fut);
        crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
    }

    #[test]
    fn writevec() {
        async fn go<F: AsRawFd + Unpin>(async_source: PollOrRing<F>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.write_from_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
        }

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let uring_source = PollOrRing::new_uring(f).unwrap();
        let fut = go(uring_source);
        pin_mut!(fut);
        crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let poll_source = PollOrRing::new_poll(f).unwrap();
        let fut = go(poll_source);
        pin_mut!(fut);
        crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
    }

    #[test]
    fn readmem() {
        async fn go<F: AsRawFd + Unpin>(async_source: PollOrRing<F>) {
            let mem = Rc::new(VecIoWrapper::from(vec![0x55u8; 8192]));
            let ret = async_source
                .read_to_mem(
                    0,
                    Rc::<VecIoWrapper>::clone(&mem),
                    &[MemRegion { offset: 0, len: 32 }],
                )
                .await
                .unwrap();
            assert_eq!(ret, 32);
            let vec: Vec<u8> = match Rc::try_unwrap(mem) {
                Ok(v) => v.into(),
                Err(_) => panic!("Too many vec refs"),
            };
            assert!(vec.iter().take(32).all(|&b| b == 0));
            assert!(vec.iter().skip(32).all(|&b| b == 0x55));
        }

        let f = File::open("/dev/zero").unwrap();
        let uring_source = PollOrRing::new_uring(f).unwrap();
        let fut = go(uring_source);
        pin_mut!(fut);
        crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();

        let f = File::open("/dev/zero").unwrap();
        let poll_source = PollOrRing::new_poll(f).unwrap();
        let fut = go(poll_source);
        pin_mut!(fut);
        crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
    }

    #[test]
    fn writemem() {
        async fn go<F: AsRawFd + Unpin>(async_source: PollOrRing<F>) {
            let mem = Rc::new(VecIoWrapper::from(vec![0x55u8; 8192]));
            let ret = async_source
                .write_from_mem(
                    0,
                    Rc::<VecIoWrapper>::clone(&mem),
                    &[MemRegion { offset: 0, len: 32 }],
                )
                .await
                .unwrap();
            assert_eq!(ret, 32);
        }

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let uring_source = PollOrRing::new_uring(f).unwrap();
        let fut = go(uring_source);
        pin_mut!(fut);
        crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let poll_source = PollOrRing::new_poll(f).unwrap();
        let fut = go(poll_source);
        pin_mut!(fut);
        crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
    }

    #[test]
    fn read_u64s() {
        async fn go<F: AsRawFd + Unpin>(async_source: F) -> u64 {
            let mut source = U64Source::new(async_source).unwrap();
            source.next_val().await.unwrap()
        }

        let f = File::open("/dev/zero").unwrap();
        let fut = go(f);
        pin_mut!(fut);
        let val = crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(val, 0);
    }

    #[test]
    fn read_eventfds() {
        use sys_util::EventFd;

        async fn go<F: AsRawFd + Unpin>(mut source: U64Source<F>) -> u64 {
            source.next_val().await.unwrap()
        }

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0x55).unwrap();
        let fut = go(U64Source::new(eventfd).unwrap());
        pin_mut!(fut);
        let val = crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(val, 0x55);

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0xaa).unwrap();
        let fut = go(U64Source::new_poll(eventfd).unwrap());
        pin_mut!(fut);
        let val = crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(val, 0xaa);
    }

    #[test]
    fn fsync() {
        async fn go<F: AsRawFd + Unpin>(source: PollOrRing<F>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = source.write_from_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
            source.fsync().await.unwrap();
        }

        let dir = tempfile::TempDir::new().unwrap();
        let mut file_path = PathBuf::from(dir.path());
        file_path.push("test");

        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        let source = PollOrRing::new(f).unwrap();

        let fut = go(source);
        pin_mut!(fut);
        crate::run_one(fut).unwrap();
    }
}
