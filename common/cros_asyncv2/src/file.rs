// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    convert::{TryFrom, TryInto},
    fs::File as StdFile,
    io,
    path::Path,
};

use sys_util::AsRawDescriptor;

use crate::{sys, AsIoBufs};

static DOWNCAST_ERROR: &str = "inner error not downcastable to `io::Error`";

/// A reference to an open file on the filesystem.
///
/// `File` provides asynchronous functions for reading and writing data. When a `File` is dropped,
/// the underlying OS handle will be closed once there are no more pending I/O operations on it.
///
/// # Errors
///
/// Many `File` methods return an `anyhow::Result`. However, it is guaranteed that if an error is
/// returned, that error is downcastable to an `io::Error`.
///
/// # Examples
///
/// Create a new file and write data to it.
///
/// ```
/// # use cros_async::{Executor, File};
/// # use tempfile::TempDir;
/// # async fn write_all() -> anyhow::Result<()>{
/// #   let dir = TempDir::new()?;
/// #   let path = dir.path().join("test");
///     let mut f = File::create(path)?;
///     f.write_all(b"Hello, world!", None).await
/// # }
/// #
/// # Executor::new().run_until(write_all()).unwrap();
/// ```
///
/// Extract an `io::Error` from a failed operation.
///
/// ```
/// # use std::io;
/// # use cros_async::File;
/// # fn extract_io_error() -> io::Error {
///     if let Err(e) = File::open("nonexistent-filesystem-path") {
///         e.downcast::<io::Error>().expect("Error not downcastable to `io::Error`")
///     } else {
///         panic!("nonexistent path exists");
///     }
/// # }
///
/// # let _ = extract_io_error();
/// ```
#[derive(Debug)]
pub struct File {
    inner: sys::File,
}

impl File {
    /// Attempt to open a file in read-only mode.
    ///
    /// This is a convenience wrapper for the standard library `File::open` method.
    pub fn open<P: AsRef<Path>>(p: P) -> anyhow::Result<File> {
        sys::File::open(p).map(|inner| File { inner })
    }

    /// Attempt to open a file in write-only mode.
    ///
    /// This function will create a file if it does not exist, and will truncate it if it does. It
    /// is a convenience wrapper for the `File::create` method from the standard library.
    pub fn create<P: AsRef<Path>>(p: P) -> anyhow::Result<File> {
        sys::File::create(p).map(|inner| File { inner })
    }

    /// Create a `File` from a standard library file.
    ///
    /// The conversion may fail if the underlying OS handle cannot be prepared for asynchronous
    /// operation. For example on epoll-based systems, this requires making the handle non-blocking.
    pub fn from_std(f: StdFile) -> anyhow::Result<File> {
        File::try_from(f)
    }

    /// Convert a `File` back into a standard library file.
    ///
    /// The conversion may fail if there are still pending asynchronous operations on the underlying
    /// OS handle.  In this case, the original `File` is returned as the error.
    pub fn into_std(self) -> Result<StdFile, File> {
        self.try_into()
    }

    /// Read up to `buf.len()` bytes from the file starting at `offset` into `buf`, returning the
    /// number of bytes read.
    ///
    /// If `offset` is `None` then the bytes are read starting from the kernel offset for the
    /// underlying OS file handle. Callers should take care when calling this method from multiple
    /// threads without providing `offset` as the order in which the operations will execute is
    /// undefined.
    ///
    /// When using I/O drivers like `io_uring`, data may be copied from an internal buffer into
    /// `buf` so this function is best suited for reading small amounts of data. Callers that wish
    /// to avoid copying data may want to use `File::read_iobuf` instead. Additionally, dropping
    /// this async fn after it has started may not cancel the underlying asynchronous operation.
    pub async fn read(&self, buf: &mut [u8], offset: Option<u64>) -> anyhow::Result<usize> {
        self.inner.read(buf, offset).await
    }

    /// Read exactly `buf.len()` bytes from the file starting at `offset` into `buf`.
    ///
    /// This method calls `File::read` in a loop until `buf.len()` bytes have been read from the
    /// underlying file. Callers should take care when calling this method from multiple threads
    /// without providing `offset` as the order in which data is read is undefined and the data
    /// returned in `buf` may not be from contiguous regions in the underlying file.
    ///
    /// When using I/O drivers like `io_uring`, data may be copied from an internal buffer into
    /// `buf`. Callers that wish to avoid copying data may want to use `File::read_iobuf` instead.
    /// Additionally, dropping this async fn after it has started may not cancel the underlying
    /// asynchronous operation.
    ///
    /// # Errors
    ///
    /// This function will directly return any non-`io::ErrorKind::Interrupted` errors. In this
    /// case, the number of bytes read from the underlying file and the kernel offset are undefined.
    pub async fn read_exact(
        &self,
        mut buf: &mut [u8],
        mut offset: Option<u64>,
    ) -> anyhow::Result<()> {
        if let Some(off) = offset {
            debug_assert!(u64::try_from(buf.len())
                .ok()
                .and_then(|len| len.checked_add(off))
                .is_some());
        }

        while !buf.is_empty() {
            match self.read(buf, offset).await {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                Ok(n) => {
                    buf = &mut buf[n..];
                    if let Some(off) = offset {
                        offset = Some(off + n as u64);
                    }
                }
                Err(e) => {
                    let err = e.downcast_ref::<io::Error>().expect(DOWNCAST_ERROR);
                    if err.kind() != io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Reads data from the underlying data starting at `offset` into an owned buffer.
    ///
    /// This method is like `File::read` but takes ownership of the buffer. When using I/O drivers
    /// like `io_uring`, this can improve performance by avoiding the need to first read the data
    /// into an internal buffer. Dropping this async fn may not cancel the underlying I/O operation.
    ///
    /// # Examples
    ///
    /// Read file data into a `Vec<u8>`.
    ///
    /// ```
    /// # async fn read_to_vec() -> anyhow::Result<()> {
    ///     use cros_async::{File, OwnedIoBuf};
    ///
    ///     let f = File::open("/dev/zero")?;
    ///     let buf = OwnedIoBuf::new(vec![0xcc; 64]);
    ///
    ///     let (res, buf) = f.read_iobuf(buf, None).await;
    ///     let count = res?;
    ///
    ///     let orig: Vec<u8> = buf.into_inner();
    ///     assert!(count <= 64);
    ///     assert_eq!(&orig[..count], &[0u8; 64][..count]);
    /// #   Ok(())
    /// # }
    /// # cros_async::Executor::new().run_until(read_to_vec()).unwrap();
    /// ```
    pub async fn read_iobuf<B: AsIoBufs + Unpin + 'static>(
        &self,
        buf: B,
        offset: Option<u64>,
    ) -> (anyhow::Result<usize>, B) {
        self.inner.read_iobuf(buf, offset).await
    }

    /// Write up to `buf.len()` bytes from `buf` to the file starting at `offset`, returning the
    /// number of bytes written.
    ///
    /// If `offset` is `None` then the bytes are written starting from the kernel offset for the
    /// underlying OS file handle. Callers should take care when calling this method from multiple
    /// threads without providing `offset` as the order in which the operations will execute is
    /// undefined.
    ///
    /// When using I/O drivers like `io_uring`, data may be copied into an internal buffer from
    /// `buf` so this function is best suited for writing small amounts of data. Callers that wish
    /// to avoid copying data may want to use `File::write_iobuf` instead. Additionally, dropping
    /// this async fn after it has started may not cancel the underlying asynchronous operation.
    pub async fn write(&self, buf: &[u8], offset: Option<u64>) -> anyhow::Result<usize> {
        self.inner.write(buf, offset).await
    }

    /// Write all the data from `buf` into the underlying file starting at `offset`.
    ///
    /// This method calls `File::write` in a loop until `buf.len()` bytes have been written to the
    /// underlying file. Callers should take care when calling this method from multiple threads
    /// without providing `offset` as the order in which data is written is undefined and the data
    /// written to the file may not be contiguous with respect to `buf`.
    ///
    /// When using I/O drivers like `io_uring`, data may be copied into an internal buffer from
    /// `buf`. Callers that wish to avoid copying data may want to use `File::write_iobuf` instead.
    /// Additionally, dropping this async fn after it has started may not cancel the underlying
    /// asynchronous operation.
    ///
    /// # Errors
    ///
    /// This function will directly return any non-`io::ErrorKind::Interrupted` errors. In this
    /// case, the number of bytes written to the underlying file and the kernel offset are undefined.
    pub async fn write_all(&self, mut buf: &[u8], mut offset: Option<u64>) -> anyhow::Result<()> {
        if let Some(off) = offset {
            debug_assert!(u64::try_from(buf.len())
                .ok()
                .and_then(|len| len.checked_add(off))
                .is_some());
        }

        while !buf.is_empty() {
            match self.write(buf, offset).await {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(n) => {
                    buf = &buf[n..];
                    if let Some(off) = offset {
                        offset = Some(off + n as u64);
                    }
                }
                Err(e) => {
                    let err = e.downcast_ref::<io::Error>().expect(DOWNCAST_ERROR);
                    if err.kind() != io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Writes data from an owned buffer into the underlying file at `offset`.
    ///
    /// This method is like `File::write` but takes ownership of the buffer. When using I/O drivers
    /// like `io_uring`, this can improve performance by avoiding the need to first copy the data
    /// into an internal buffer. Dropping this async fn may not cancel the underlying I/O operation.
    ///
    /// # Examples
    ///
    /// Write file data from a `Vec<u8>`.
    ///
    /// ```
    /// # async fn read_to_vec() -> anyhow::Result<()> {
    ///     use cros_async::{File, OwnedIoBuf};
    ///
    ///     let f = File::open("/dev/null")?;
    ///     let buf = OwnedIoBuf::new(vec![0xcc; 64]);
    ///
    ///     let (res, buf) = f.write_iobuf(buf, None).await;
    ///     let count = res?;
    ///
    ///     let orig: Vec<u8> = buf.into_inner();
    ///     assert!(count <= 64);
    /// #   Ok(())
    /// # }
    /// # cros_async::Executor::new().run_until(read_to_vec()).unwrap();
    /// ```
    pub async fn write_iobuf<B: AsIoBufs + Unpin + 'static>(
        &self,
        buf: B,
        offset: Option<u64>,
    ) -> (anyhow::Result<usize>, B) {
        self.inner.write_iobuf(buf, offset).await
    }

    /// Creates a hole in the underlying file of `len` bytes starting at `offset`.
    pub async fn punch_hole(&self, offset: u64, len: u64) -> anyhow::Result<()> {
        self.inner.punch_hole(offset, len).await
    }

    /// Writes `len` bytes of zeroes to the underlying file at `offset`.
    pub async fn write_zeroes(&self, offset: u64, len: u64) -> anyhow::Result<()> {
        self.inner.write_zeroes(offset, len).await
    }

    /// Allocates `len` bytes of disk storage for the underlying file starting at `offset`.
    pub async fn allocate(&self, offset: u64, len: u64) -> anyhow::Result<()> {
        self.inner.allocate(offset, len).await
    }

    /// Returns the current length of the file in bytes.
    pub async fn get_len(&self) -> anyhow::Result<u64> {
        self.inner.get_len().await
    }

    /// Sets the current length of the file in bytes.
    pub async fn set_len(&self, len: u64) -> anyhow::Result<()> {
        self.inner.set_len(len).await
    }

    /// Sync all buffered data and metadata for the underlying file to the disk.
    pub async fn sync_all(&self) -> anyhow::Result<()> {
        self.inner.sync_all().await
    }

    /// Like `File::sync_all` but may not sync file metadata to the disk.
    pub async fn sync_data(&self) -> anyhow::Result<()> {
        self.inner.sync_data().await
    }

    /// Try to clone this `File`.
    ///
    /// If successful, the returned `File` will have its own unique OS handle for the underlying
    /// file.
    pub fn try_clone(&self) -> anyhow::Result<File> {
        self.inner.try_clone().map(|inner| File { inner })
    }
}

impl TryFrom<StdFile> for File {
    type Error = anyhow::Error;

    fn try_from(f: StdFile) -> anyhow::Result<Self> {
        sys::File::try_from(f).map(|inner| File { inner })
    }
}

impl TryFrom<File> for StdFile {
    type Error = File;
    fn try_from(f: File) -> Result<StdFile, File> {
        StdFile::try_from(f.inner).map_err(|inner| File { inner })
    }
}

impl AsRawDescriptor for File {
    fn as_raw_descriptor(&self) -> sys_util::RawDescriptor {
        self.inner.as_raw_descriptor()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::{
        fs::{File as StdFile, OpenOptions},
        path::PathBuf,
        thread,
    };

    use anyhow::Context;
    use futures::channel::oneshot::channel;

    use crate::{Executor, OwnedIoBuf};

    #[test]
    fn readvec() {
        async fn go() {
            let f = StdFile::open("/dev/zero")
                .context("failed to open /dev/zero")
                .and_then(File::try_from)
                .unwrap();
            let v = OwnedIoBuf::new(vec![0x55u8; 32]);

            let (res, v) = f.read_iobuf(v, None).await;
            let count = res.unwrap();
            assert_eq!(count, v.len());
            assert!(v.iter().all(|&b| b == 0));
        }

        let ex = Executor::new();
        ex.run_until(go()).unwrap();
    }

    #[test]
    fn writevec() {
        async fn go() {
            let f = OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .context("failed to open /dev/null")
                .and_then(File::try_from)
                .unwrap();
            let v = OwnedIoBuf::new(vec![0x55u8; 32]);
            let (res, _v) = f.write_iobuf(v, None).await;
            let count = res.unwrap();
            assert_eq!(count, 32);
        }

        let ex = Executor::new();
        ex.run_until(go()).unwrap();
    }

    #[test]
    fn file_is_send() {
        const TRANSFER_COUNT: usize = 24;

        let (tx, rx) = channel::<File>();
        let ex = Executor::new();

        let ex2 = ex.clone();
        let worker_thread = thread::spawn(move || {
            ex2.run_until(async move {
                let f = rx.await.unwrap();
                let buf = [0xa2; TRANSFER_COUNT];
                f.write_all(&buf, None).await.unwrap();
            })
            .unwrap();
        });

        let (pipe_out, pipe_in) = sys_util::pipe(true).unwrap();
        ex.run_until(async move {
            tx.send(File::try_from(pipe_in).unwrap()).unwrap();

            let pipe = File::try_from(pipe_out).unwrap();
            let mut buf = [0u8; TRANSFER_COUNT];
            pipe.read_exact(&mut buf, None).await.unwrap();
            assert_eq!(buf, [0xa2; TRANSFER_COUNT]);
        })
        .unwrap();

        worker_thread.join().unwrap();
    }

    #[test]
    fn fallocate() {
        let ex = Executor::new();
        ex.run_until(async {
            let dir = tempfile::TempDir::new().unwrap();
            let mut file_path = PathBuf::from(dir.path());
            file_path.push("test");

            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&file_path)
                .unwrap();
            let source = File::try_from(f).unwrap();
            source.allocate(0, 4096).await.unwrap();

            let meta_data = std::fs::metadata(&file_path).unwrap();
            assert_eq!(meta_data.len(), 4096);
        })
        .unwrap();
    }
}
