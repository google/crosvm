// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! EXPERIMENTAL overlapped IO based async IO wrapper. Do not use in production.

use std::fs::File;
use std::io;
use std::io::Write;
use std::mem::ManuallyDrop;
use std::sync::Arc;

use base::error;
use base::AsRawDescriptor;
use base::Descriptor;
use base::FromRawDescriptor;
use base::PunchHole;
use base::RawDescriptor;
use base::WriteZeroesAt;
use thiserror::Error as ThisError;
use winapi::um::minwinbase::OVERLAPPED;

use crate::common_executor::RawExecutor;
use crate::mem::BackingMemory;
use crate::mem::MemRegion;
use crate::sys::windows::handle_executor::HandleReactor;
use crate::sys::windows::handle_executor::RegisteredOverlappedSource;
use crate::AsyncError;
use crate::AsyncResult;
use crate::BlockingPool;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("An error occurred trying to get a VolatileSlice into BackingMemory: {0}.")]
    BackingMemoryVolatileSliceFetchFailed(crate::mem::Error),
    #[error("An error occurred trying to seek: {0}.")]
    IoSeekError(io::Error),
    #[error("An error occurred trying to read: {0}.")]
    IoReadError(base::Error),
    #[error("An error occurred trying to write: {0}.")]
    IoWriteError(base::Error),
    #[error("An error occurred trying to flush: {0}.")]
    IoFlushError(io::Error),
    #[error("An error occurred trying to punch hole: {0}.")]
    IoPunchHoleError(io::Error),
    #[error("An error occurred trying to write zeroes: {0}.")]
    IoWriteZeroesError(io::Error),
    #[error("An error occurred trying to duplicate source handles: {0}.")]
    HandleDuplicationFailed(io::Error),
    #[error("A IO error occurred trying to read: {0}.")]
    StdIoReadError(io::Error),
    #[error("An IO error occurred trying to write: {0}.")]
    StdIoWriteError(io::Error),
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            BackingMemoryVolatileSliceFetchFailed(e) => io::Error::new(io::ErrorKind::Other, e),
            IoSeekError(e) => e,
            IoReadError(e) => e.into(),
            IoWriteError(e) => e.into(),
            IoFlushError(e) => e,
            IoPunchHoleError(e) => e,
            IoWriteZeroesError(e) => e,
            HandleDuplicationFailed(e) => e,
            StdIoReadError(e) => e,
            StdIoWriteError(e) => e,
        }
    }
}

impl From<Error> for AsyncError {
    fn from(e: Error) -> AsyncError {
        AsyncError::SysVariants(e.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Async IO source for Windows that uses a multi-threaded, multi-handle approach to provide fast IO
/// operations. It demuxes IO requests across a set of handles that refer to the same underlying IO
/// source, such as a file, and executes those requests across multiple threads. Benchmarks show
/// that this is the fastest method to perform IO on Windows, especially for file reads.
pub struct OverlappedSource<F: AsRawDescriptor> {
    blocking_pool: BlockingPool,
    reg_source: RegisteredOverlappedSource,
    source: F,
    seek_forbidden: bool,
}

impl<F: AsRawDescriptor> OverlappedSource<F> {
    /// Create a new `OverlappedSource` from the given IO source. The source MUST be opened in
    /// overlapped mode or undefined behavior will result.
    ///
    /// seek_forbidden should be set for non seekable types like named pipes.
    pub fn new(
        source: F,
        ex: &Arc<RawExecutor<HandleReactor>>,
        seek_forbidden: bool,
    ) -> AsyncResult<Self> {
        Ok(Self {
            blocking_pool: BlockingPool::default(),
            reg_source: ex.reactor.register_overlapped_source(ex, &source)?,
            source,
            seek_forbidden,
        })
    }
}

/// SAFETY:
/// Safety requirements:
///     Same as base::windows::read_file.
unsafe fn read(
    file: RawDescriptor,
    buf: *mut u8,
    buf_len: usize,
    overlapped: &mut OVERLAPPED,
) -> AsyncResult<()> {
    Ok(
        base::windows::read_file(&Descriptor(file), buf, buf_len, Some(overlapped))
            .map(|_len| ())
            .map_err(Error::StdIoReadError)?,
    )
}

/// SAFETY:
/// Safety requirements:
///     Same as base::windows::write_file.
unsafe fn write(
    file: RawDescriptor,
    buf: *const u8,
    buf_len: usize,
    overlapped: &mut OVERLAPPED,
) -> AsyncResult<()> {
    Ok(
        base::windows::write_file(&Descriptor(file), buf, buf_len, Some(overlapped))
            .map(|_len| ())
            .map_err(Error::StdIoWriteError)?,
    )
}

impl<F: AsRawDescriptor> OverlappedSource<F> {
    /// Reads from the iosource at `file_offset` and fill the given `vec`.
    pub async fn read_to_vec(
        &self,
        file_offset: Option<u64>,
        mut vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        if self.seek_forbidden && file_offset.is_some() {
            return Err(Error::IoSeekError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek on non-seekable handle",
            ))
            .into());
        }
        let mut overlapped_op = self.reg_source.register_overlapped_operation(file_offset)?;

        // SAFETY:
        // Safe because we pass a pointer to a valid vec and that same vector's length.
        unsafe {
            read(
                self.source.as_raw_descriptor(),
                vec.as_mut_ptr(),
                vec.len(),
                overlapped_op.get_overlapped(),
            )?
        };
        let overlapped_result = overlapped_op.await?;
        let bytes_read = overlapped_result.result.map_err(Error::IoReadError)?;
        Ok((bytes_read, vec))
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    pub async fn read_to_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let mut total_bytes_read = 0;
        let mut offset = match file_offset {
            Some(offset) if !self.seek_forbidden => Some(offset),
            None if self.seek_forbidden => None,
            // For devices that are seekable (files), we have to track the offset otherwise
            // subsequent read calls will just read the same bytes into each of the memory regions.
            None => Some(0),
            _ => {
                return Err(Error::IoSeekError(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "seek on non-seekable handle",
                ))
                .into())
            }
        };

        for region in mem_offsets.into_iter() {
            let mut overlapped_op = self.reg_source.register_overlapped_operation(offset)?;

            let slice = mem
                .get_volatile_slice(region)
                .map_err(Error::BackingMemoryVolatileSliceFetchFailed)?;

            // SAFETY:
            // Safe because we're passing a volatile slice (valid ptr), and the size of the memory
            // region it refers to.
            unsafe {
                read(
                    self.source.as_raw_descriptor(),
                    slice.as_mut_ptr(),
                    slice.size(),
                    overlapped_op.get_overlapped(),
                )?
            };
            let overlapped_result = overlapped_op.await?;
            let bytes_read = overlapped_result.result.map_err(Error::IoReadError)?;
            offset = offset.map(|offset| offset + bytes_read as u64);
            total_bytes_read += bytes_read;
        }
        Ok(total_bytes_read)
    }

    /// Wait for the handle of `self` to be readable.
    pub async fn wait_readable(&self) -> AsyncResult<()> {
        unimplemented!()
    }

    /// Reads a single u64 from the current offset.
    pub async fn read_u64(&self) -> AsyncResult<u64> {
        unimplemented!()
    }

    /// Writes from the given `vec` to the file starting at `file_offset`.
    pub async fn write_from_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        if self.seek_forbidden && file_offset.is_some() {
            return Err(Error::IoSeekError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek on non-seekable handle",
            ))
            .into());
        }
        let mut overlapped_op = self.reg_source.register_overlapped_operation(file_offset)?;

        // SAFETY:
        // Safe because we pass a pointer to a valid vec and that same vector's length.
        unsafe {
            write(
                self.source.as_raw_descriptor(),
                vec.as_ptr(),
                vec.len(),
                overlapped_op.get_overlapped(),
            )?
        };

        let bytes_written = overlapped_op.await?.result.map_err(Error::IoWriteError)?;
        Ok((bytes_written, vec))
    }

    /// Writes from the given `mem` from the given offsets to the file starting at `file_offset`.
    pub async fn write_from_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let mut total_bytes_written = 0;
        let mut offset = match file_offset {
            Some(offset) if !self.seek_forbidden => Some(offset),
            None if self.seek_forbidden => None,
            // For devices that are seekable (files), we have to track the offset otherwise
            // subsequent read calls will just read the same bytes into each of the memory regions.
            None => Some(0),
            _ => {
                return Err(Error::IoSeekError(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "seek on non-seekable handle",
                ))
                .into())
            }
        };

        for region in mem_offsets.into_iter() {
            let mut overlapped_op = self.reg_source.register_overlapped_operation(offset)?;

            let slice = mem
                .get_volatile_slice(region)
                .map_err(Error::BackingMemoryVolatileSliceFetchFailed)?;

            // SAFETY:
            // Safe because we're passing a volatile slice (valid ptr), and the size of the memory
            // region it refers to.
            unsafe {
                write(
                    self.source.as_raw_descriptor(),
                    slice.as_ptr(),
                    slice.size(),
                    overlapped_op.get_overlapped(),
                )?
            };
            let bytes_written = overlapped_op.await?.result.map_err(Error::IoReadError)?;
            offset = offset.map(|offset| offset + bytes_written as u64);
            total_bytes_written += bytes_written;
        }
        Ok(total_bytes_written)
    }

    /// Deallocates the given range of a file.
    ///
    /// TODO(nkgold): currently this is sync on the executor, which is bad / very hacky. With a
    /// little wrapper work, we can make overlapped DeviceIoControl calls instead.
    pub async fn punch_hole(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        if self.seek_forbidden {
            return Err(Error::IoSeekError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fallocate cannot be called on a non-seekable handle",
            ))
            .into());
        }
        // SAFETY:
        // Safe because self.source lives as long as file.
        let file = ManuallyDrop::new(unsafe {
            File::from_raw_descriptor(self.source.as_raw_descriptor())
        });
        file.punch_hole(file_offset, len)
            .map_err(Error::IoPunchHoleError)?;
        Ok(())
    }

    /// Fills the given range with zeroes.
    ///
    /// TODO(nkgold): currently this is sync on the executor, which is bad / very hacky. With a
    /// little wrapper work, we can make overlapped DeviceIoControl calls instead.
    pub async fn write_zeroes_at(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        if self.seek_forbidden {
            return Err(Error::IoSeekError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write_zeroes_at cannot be called on a non-seekable handle",
            ))
            .into());
        }
        // SAFETY:
        // Safe because self.source lives as long as file.
        let mut file = ManuallyDrop::new(unsafe {
            File::from_raw_descriptor(self.source.as_raw_descriptor())
        });
        // ZeroRange calls `punch_hole` which doesn't extend the File size if it needs to.
        // Will fix if it becomes a problem.
        file.write_zeroes_at(file_offset, len as usize)
            .map_err(Error::IoWriteZeroesError)?;
        Ok(())
    }

    /// Sync all completed write operations to the backing storage.
    pub async fn fsync(&self) -> AsyncResult<()> {
        // SAFETY:
        // Safe because self.source lives at least as long as the blocking pool thread. Note that
        // if the blocking pool stalls and shutdown fails, the thread could outlive the file;
        // however, this would mean things are already badly broken and we have a similar risk in
        // HandleSource.
        let mut file = unsafe {
            ManuallyDrop::new(File::from_raw_descriptor(self.source.as_raw_descriptor()))
                .try_clone()
                .map_err(Error::HandleDuplicationFailed)?
        };

        Ok(self
            .blocking_pool
            .spawn(move || file.flush().map_err(Error::IoFlushError))
            .await?)
    }

    /// Sync all data of completed write operations to the backing storage. Currently, the
    /// implementation is equivalent to fsync.
    pub async fn fdatasync(&self) -> AsyncResult<()> {
        // TODO(b/282003931): Fall back to regular fsync.
        self.fsync().await
    }

    /// Yields the underlying IO source.
    pub fn into_source(self) -> F {
        self.source
    }

    /// Provides a mutable ref to the underlying IO source.
    pub fn as_source_mut(&mut self) -> &mut F {
        &mut self.source
    }

    /// Provides a ref to the underlying IO source.
    ///
    /// In the multi-source case, the 0th source will be returned. If sources are not
    /// interchangeable, behavior is undefined.
    pub fn as_source(&self) -> &F {
        &self.source
    }

    pub async fn wait_for_handle(&self) -> AsyncResult<()> {
        let waiter = super::WaitForHandle::new(&self.source);
        Ok(waiter.await?)
    }
}

// NOTE: Prefer adding tests to io_source.rs if not backend specific.
#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::PathBuf;

    use tempfile::TempDir;
    use winapi::um::winbase::FILE_FLAG_OVERLAPPED;

    use super::*;
    use crate::mem::VecIoWrapper;

    fn tempfile_path() -> (PathBuf, TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let mut file_path = PathBuf::from(dir.path());
        file_path.push("test");
        (file_path, dir)
    }

    fn open_overlapped(path: &PathBuf) -> File {
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .open(path)
            .unwrap()
    }

    fn open_blocking(path: &PathBuf) -> File {
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    #[test]
    fn test_read_vec() {
        let (file_path, _tmpdir) = tempfile_path();
        let mut f = open_blocking(&file_path);
        f.write_all("data".as_bytes()).unwrap();
        f.flush().unwrap();
        drop(f);

        async fn read_data(src: &OverlappedSource<File>) {
            let buf: Vec<u8> = vec![0; 4];
            let (bytes_read, buf) = src.read_to_vec(Some(0), buf).await.unwrap();
            assert_eq!(bytes_read, 4);
            assert_eq!(std::str::from_utf8(buf.as_slice()).unwrap(), "data");
        }

        let ex = RawExecutor::<HandleReactor>::new().unwrap();
        let src = OverlappedSource::new(open_overlapped(&file_path), &ex, false).unwrap();
        ex.run_until(read_data(&src)).unwrap();
    }

    #[test]
    fn test_read_mem() {
        let (file_path, _tmpdir) = tempfile_path();
        let mut f = open_blocking(&file_path);
        f.write_all("data".as_bytes()).unwrap();
        f.flush().unwrap();
        drop(f);

        async fn read_data(src: &OverlappedSource<File>) {
            let mem = Arc::new(VecIoWrapper::from(vec![0; 4]));
            let bytes_read = src
                .read_to_mem(
                    Some(0),
                    Arc::<VecIoWrapper>::clone(&mem),
                    [
                        MemRegion { offset: 0, len: 2 },
                        MemRegion { offset: 2, len: 2 },
                    ],
                )
                .await
                .unwrap();
            assert_eq!(bytes_read, 4);
            let vec: Vec<u8> = match Arc::try_unwrap(mem) {
                Ok(v) => v.into(),
                Err(_) => panic!("Too many vec refs"),
            };
            assert_eq!(std::str::from_utf8(vec.as_slice()).unwrap(), "data");
        }

        let ex = RawExecutor::<HandleReactor>::new().unwrap();
        let src = OverlappedSource::new(open_overlapped(&file_path), &ex, false).unwrap();
        ex.run_until(read_data(&src)).unwrap();
    }

    #[test]
    fn test_write_vec() {
        let (file_path, _tmpdir) = tempfile_path();

        async fn write_data(src: &OverlappedSource<File>) {
            let mut buf: Vec<u8> = Vec::new();
            buf.extend_from_slice("data".as_bytes());

            let (bytes_written, _) = src.write_from_vec(Some(0), buf).await.unwrap();
            assert_eq!(bytes_written, 4);
        }

        let ex = RawExecutor::<HandleReactor>::new().unwrap();
        let f = open_overlapped(&file_path);
        let src = OverlappedSource::new(f, &ex, false).unwrap();
        ex.run_until(write_data(&src)).unwrap();
        drop(src);

        let mut buf = vec![0; 4];
        let mut f = open_blocking(&file_path);
        f.read_exact(&mut buf).unwrap();
        assert_eq!(std::str::from_utf8(buf.as_slice()).unwrap(), "data");
    }

    #[test]
    fn test_write_mem() {
        let (file_path, _tmpdir) = tempfile_path();

        async fn write_data(src: &OverlappedSource<File>) {
            let mut buf: Vec<u8> = Vec::new();
            buf.extend_from_slice("data".as_bytes());
            let mem = Arc::new(VecIoWrapper::from(buf));
            let bytes_written = src
                .write_from_mem(
                    Some(0),
                    Arc::<VecIoWrapper>::clone(&mem),
                    [
                        MemRegion { offset: 0, len: 2 },
                        MemRegion { offset: 2, len: 2 },
                    ],
                )
                .await
                .unwrap();
            assert_eq!(bytes_written, 4);
            match Arc::try_unwrap(mem) {
                Ok(_) => (),
                Err(_) => panic!("Too many vec refs"),
            };
        }

        let ex = RawExecutor::<HandleReactor>::new().unwrap();
        let f = open_overlapped(&file_path);
        let src = OverlappedSource::new(f, &ex, false).unwrap();
        ex.run_until(write_data(&src)).unwrap();
        drop(src);

        let mut buf = vec![0; 4];
        let mut f = open_blocking(&file_path);
        f.read_exact(&mut buf).unwrap();
        assert_eq!(std::str::from_utf8(buf.as_slice()).unwrap(), "data");
    }

    #[cfg_attr(all(target_os = "windows", target_env = "gnu"), ignore)]
    #[test]
    fn test_punch_holes() {
        let (file_path, _tmpdir) = tempfile_path();
        let mut temp_file = open_blocking(&file_path);
        temp_file.write_all("abcdefghijk".as_bytes()).unwrap();
        temp_file.flush().unwrap();
        drop(temp_file);

        async fn punch_hole(src: &OverlappedSource<File>) {
            let offset = 1;
            let len = 3;
            src.punch_hole(offset, len).await.unwrap();
        }

        let ex = RawExecutor::<HandleReactor>::new().unwrap();
        let f = open_overlapped(&file_path);
        let src = OverlappedSource::new(f, &ex, false).unwrap();
        ex.run_until(punch_hole(&src)).unwrap();
        drop(src);

        let mut buf = vec![0; 11];
        let mut f = open_blocking(&file_path);
        f.read_exact(&mut buf).unwrap();
        assert_eq!(
            std::str::from_utf8(buf.as_slice()).unwrap(),
            "a\0\0\0efghijk"
        );
    }

    /// Test should fail because punch hole should not be allowed to allocate more memory
    #[cfg_attr(all(target_os = "windows", target_env = "gnu"), ignore)]
    #[test]
    fn test_punch_holes_fail_out_of_bounds() {
        let (file_path, _tmpdir) = tempfile_path();
        let mut temp_file = open_blocking(&file_path);
        temp_file.write_all("abcdefghijk".as_bytes()).unwrap();
        temp_file.flush().unwrap();
        drop(temp_file);

        async fn punch_hole(src: &OverlappedSource<File>) {
            let offset = 9;
            let len = 4;
            src.punch_hole(offset, len).await.unwrap();
        }

        let ex = RawExecutor::<HandleReactor>::new().unwrap();
        let f = open_overlapped(&file_path);
        let src = OverlappedSource::new(f, &ex, false).unwrap();
        ex.run_until(punch_hole(&src)).unwrap();
        drop(src);

        let mut buf = vec![0; 13];
        let mut f = open_blocking(&file_path);
        assert!(f.read_exact(&mut buf).is_err());
    }

    // TODO(b/194338842): "ZeroRange" is supposed to allocate more memory if it goes out of the
    // bounds of the file. Determine if we need to support this, since Windows doesn't do this yet.
    // use tempfile::NamedTempFile;
    // #[test]
    // fn test_write_zeroes() {
    //     let mut temp_file = NamedTempFile::new().unwrap();
    //     temp_file.write("abcdefghijk".as_bytes()).unwrap();
    //     temp_file.flush().unwrap();
    //     temp_file.seek(SeekFrom::Start(0)).unwrap();

    //     async fn punch_hole(src: &OverlappedSource<File>) {
    //         let offset = 9;
    //         let len = 4;
    //         src
    //             .fallocate(offset, len, AllocateMode::ZeroRange)
    //             .await
    //             .unwrap();
    //     }

    //     let ex = RawExecutor::<HandleReactor>::new();
    //     let f = fs::OpenOptions::new()
    //         .write(true)
    //         .open(temp_file.path())
    //         .unwrap();
    //     let src = OverlappedSource::new(vec![f].into_boxed_slice()).unwrap();
    //     ex.run_until(punch_hole(&src)).unwrap();

    //     let mut buf = vec![0; 13];
    //     temp_file.read_exact(&mut buf).unwrap();
    //     assert_eq!(
    //         std::str::from_utf8(buf.as_slice()).unwrap(),
    //         "abcdefghi\0\0\0\0"
    //     );
    // }
}
