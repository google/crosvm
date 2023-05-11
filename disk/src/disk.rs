// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! VM disk image file format I/O.

use std::cmp::min;
use std::fmt::Debug;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use base::get_filesystem_type;
use base::info;
use base::AsRawDescriptors;
use base::FileAllocate;
use base::FileReadWriteAtVolatile;
use base::FileSetLen;
use base::PunchHole;
use cros_async::AllocateMode;
use cros_async::BackingMemory;
use cros_async::Executor;
use cros_async::IoSource;
use thiserror::Error as ThisError;

mod asynchronous;
#[allow(unused)]
pub(crate) use asynchronous::AsyncDiskFileWrapper;
#[cfg(feature = "qcow")]
mod qcow;
#[cfg(feature = "qcow")]
pub use qcow::QcowFile;
#[cfg(feature = "qcow")]
pub use qcow::QCOW_MAGIC;
mod sys;

#[cfg(feature = "composite-disk")]
mod composite;
#[cfg(feature = "composite-disk")]
use composite::CompositeDiskFile;
#[cfg(feature = "composite-disk")]
use composite::CDISK_MAGIC;
#[cfg(feature = "composite-disk")]
mod gpt;
#[cfg(feature = "composite-disk")]
pub use composite::create_composite_disk;
#[cfg(feature = "composite-disk")]
pub use composite::create_zero_filler;
#[cfg(feature = "composite-disk")]
pub use composite::Error as CompositeError;
#[cfg(feature = "composite-disk")]
pub use composite::ImagePartitionType;
#[cfg(feature = "composite-disk")]
pub use composite::PartitionInfo;
#[cfg(feature = "composite-disk")]
pub use gpt::Error as GptError;

#[cfg(feature = "android-sparse")]
mod android_sparse;
#[cfg(feature = "android-sparse")]
use android_sparse::AndroidSparse;
#[cfg(feature = "android-sparse")]
use android_sparse::SPARSE_HEADER_MAGIC;

/// Nesting depth limit for disk formats that can open other disk files.
pub const MAX_NESTING_DEPTH: u32 = 10;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("failed to create block device: {0}")]
    BlockDeviceNew(base::Error),
    #[error("requested file conversion not supported")]
    ConversionNotSupported,
    #[cfg(feature = "android-sparse")]
    #[error("failure in android sparse disk: {0}")]
    CreateAndroidSparseDisk(android_sparse::Error),
    #[cfg(feature = "composite-disk")]
    #[error("failure in composite disk: {0}")]
    CreateCompositeDisk(composite::Error),
    #[error("failure creating single file disk: {0}")]
    CreateSingleFileDisk(cros_async::AsyncError),
    #[error("failure with fallocate: {0}")]
    Fallocate(cros_async::AsyncError),
    #[error("failure with fdatasync: {0}")]
    Fdatasync(cros_async::AsyncError),
    #[error("failure with fsync: {0}")]
    Fsync(cros_async::AsyncError),
    #[error("failure with fdatasync: {0}")]
    IoFdatasync(io::Error),
    #[error("failure with fsync: {0}")]
    IoFsync(io::Error),
    #[error("checking host fs type: {0}")]
    HostFsType(base::Error),
    #[error("maximum disk nesting depth exceeded")]
    MaxNestingDepthExceeded,
    #[error("failure to punch hole: {0}")]
    PunchHole(io::Error),
    #[cfg(feature = "qcow")]
    #[error("failure in qcow: {0}")]
    QcowError(qcow::Error),
    #[error("failed to read data: {0}")]
    ReadingData(io::Error),
    #[error("failed to read header: {0}")]
    ReadingHeader(io::Error),
    #[error("failed to read to memory: {0}")]
    ReadToMem(cros_async::AsyncError),
    #[error("failed to seek file: {0}")]
    SeekingFile(io::Error),
    #[error("failed to set file size: {0}")]
    SettingFileSize(io::Error),
    #[error("unknown disk type")]
    UnknownType,
    #[error("failed to write from memory: {0}")]
    WriteFromMem(cros_async::AsyncError),
    #[error("failed to write from vec: {0}")]
    WriteFromVec(cros_async::AsyncError),
    #[error("failed to write zeroes: {0}")]
    WriteZeroes(io::Error),
    #[error("failed to write data: {0}")]
    WritingData(io::Error),
    #[error("failed to convert to async: {0}")]
    ToAsync(cros_async::AsyncError),
    #[cfg(windows)]
    #[error("failed to set disk file sparse: {0}")]
    SetSparseFailure(io::Error),
    #[error("failure with guest memory access: {0}")]
    GuestMemory(cros_async::mem::Error),
    #[error("unsupported operation")]
    UnsupportedOperation,
}

pub type Result<T> = std::result::Result<T, Error>;

/// A trait for getting the length of a disk image or raw block device.
pub trait DiskGetLen {
    /// Get the current length of the disk in bytes.
    fn get_len(&self) -> io::Result<u64>;
}

impl DiskGetLen for File {
    fn get_len(&self) -> io::Result<u64> {
        let mut s = self;
        let orig_seek = s.stream_position()?;
        let end = s.seek(SeekFrom::End(0))?;
        s.seek(SeekFrom::Start(orig_seek))?;
        Ok(end)
    }
}

pub trait PunchHoleMut {
    /// Replace a range of bytes with a hole.
    fn punch_hole_mut(&mut self, offset: u64, length: u64) -> io::Result<()>;
}

impl<T: PunchHole> PunchHoleMut for T {
    fn punch_hole_mut(&mut self, offset: u64, length: u64) -> io::Result<()> {
        self.punch_hole(offset, length)
    }
}

/// The prerequisites necessary to support a block device.
pub trait DiskFile:
    FileSetLen + DiskGetLen + FileReadWriteAtVolatile + ToAsyncDisk + Send + AsRawDescriptors + Debug
{
    /// Creates a new DiskFile instance that shares the same underlying disk file image. IO
    /// operations to a DiskFile should affect all DiskFile instances with the same underlying disk
    /// file image.
    ///
    /// `try_clone()` returns [`io::ErrorKind::Unsupported`] Error if a DiskFile does not support
    /// creating an instance with the same underlying disk file image.
    fn try_clone(&self) -> io::Result<Box<dyn DiskFile>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported operation",
        ))
    }
}

/// A `DiskFile` that can be converted for asychronous access.
pub trait ToAsyncDisk: AsRawDescriptors + DiskGetLen + Send {
    /// Convert a boxed self in to a box-wrapped implementaiton of AsyncDisk.
    /// Used to convert a standard disk image to an async disk image. This conversion and the
    /// inverse are needed so that the `Send` DiskImage can be given to the block thread where it is
    /// converted to a non-`Send` AsyncDisk. The AsyncDisk can then be converted back and returned
    /// to the main device thread if the block device is destroyed or reset.
    fn to_async_disk(self: Box<Self>, ex: &Executor) -> Result<Box<dyn AsyncDisk>>;
}

impl ToAsyncDisk for File {
    fn to_async_disk(self: Box<Self>, ex: &Executor) -> Result<Box<dyn AsyncDisk>> {
        Ok(Box::new(SingleFileDisk::new(*self, ex)?))
    }
}

/// The variants of image files on the host that can be used as virtual disks.
#[derive(Debug, PartialEq, Eq)]
pub enum ImageType {
    Raw,
    Qcow2,
    CompositeDisk,
    AndroidSparse,
}

fn log_host_fs_type(file: &File) -> Result<()> {
    let fstype = get_filesystem_type(file).map_err(Error::HostFsType)?;
    info!("Disk image file is hosted on file system type {:x}", fstype);
    Ok(())
}

/// Detect the type of an image file by checking for a valid header of the supported formats.
pub fn detect_image_type(file: &File) -> Result<ImageType> {
    let mut f = file;
    let disk_size = f.get_len().map_err(Error::SeekingFile)?;
    let orig_seek = f.stream_position().map_err(Error::SeekingFile)?;
    f.seek(SeekFrom::Start(0)).map_err(Error::SeekingFile)?;

    info!("disk size {}, ", disk_size);
    log_host_fs_type(f)?;
    // Try to read the disk in a nicely-aligned block size unless the whole file is smaller.
    const MAGIC_BLOCK_SIZE: usize = 4096;
    #[repr(align(4096))]
    struct BlockAlignedBuffer {
        data: [u8; MAGIC_BLOCK_SIZE],
    }
    let mut magic = BlockAlignedBuffer {
        data: [0u8; MAGIC_BLOCK_SIZE],
    };
    let magic_read_len = if disk_size > MAGIC_BLOCK_SIZE as u64 {
        MAGIC_BLOCK_SIZE
    } else {
        // This cast is safe since we know disk_size is less than MAGIC_BLOCK_SIZE (4096) and
        // therefore is representable in usize.
        disk_size as usize
    };

    f.read_exact(&mut magic.data[0..magic_read_len])
        .map_err(Error::ReadingHeader)?;
    f.seek(SeekFrom::Start(orig_seek))
        .map_err(Error::SeekingFile)?;

    #[cfg(feature = "composite-disk")]
    if let Some(cdisk_magic) = magic.data.get(0..CDISK_MAGIC.len()) {
        if cdisk_magic == CDISK_MAGIC.as_bytes() {
            return Ok(ImageType::CompositeDisk);
        }
    }

    #[allow(unused_variables)] // magic4 is only used with the qcow or android-sparse features.
    if let Some(magic4) = magic.data.get(0..4) {
        #[cfg(feature = "qcow")]
        if magic4 == QCOW_MAGIC.to_be_bytes() {
            return Ok(ImageType::Qcow2);
        }
        #[cfg(feature = "android-sparse")]
        if magic4 == SPARSE_HEADER_MAGIC.to_le_bytes() {
            return Ok(ImageType::AndroidSparse);
        }
    }

    Ok(ImageType::Raw)
}

impl DiskFile for File {
    fn try_clone(&self) -> io::Result<Box<dyn DiskFile>> {
        Ok(Box::new(self.try_clone()?))
    }
}

/// Inspect the image file type and create an appropriate disk file to match it.
pub fn create_disk_file(
    raw_image: File,
    is_sparse_file: bool,
    // max_nesting_depth is only used if the composite-disk or qcow features are enabled.
    #[allow(unused_variables)] mut max_nesting_depth: u32,
    // image_path is only used if the composite-disk feature is enabled.
    #[allow(unused_variables)] image_path: &Path,
) -> Result<Box<dyn DiskFile>> {
    if max_nesting_depth == 0 {
        return Err(Error::MaxNestingDepthExceeded);
    }
    #[allow(unused_assignments)]
    {
        max_nesting_depth -= 1;
    }

    let image_type = detect_image_type(&raw_image)?;
    Ok(match image_type {
        ImageType::Raw => {
            sys::apply_raw_disk_file_options(&raw_image, is_sparse_file)?;
            Box::new(raw_image) as Box<dyn DiskFile>
        }
        #[cfg(feature = "qcow")]
        ImageType::Qcow2 => {
            Box::new(QcowFile::from(raw_image, max_nesting_depth).map_err(Error::QcowError)?)
                as Box<dyn DiskFile>
        }
        #[cfg(feature = "composite-disk")]
        ImageType::CompositeDisk => {
            // Valid composite disk header present
            Box::new(
                CompositeDiskFile::from_file(
                    raw_image,
                    is_sparse_file,
                    max_nesting_depth,
                    image_path,
                )
                .map_err(Error::CreateCompositeDisk)?,
            ) as Box<dyn DiskFile>
        }
        #[cfg(feature = "android-sparse")]
        ImageType::AndroidSparse => {
            Box::new(AndroidSparse::from_file(raw_image).map_err(Error::CreateAndroidSparseDisk)?)
                as Box<dyn DiskFile>
        }
        #[allow(unreachable_patterns)]
        _ => return Err(Error::UnknownType),
    })
}

/// An asynchronously accessible disk.
#[async_trait(?Send)]
pub trait AsyncDisk: DiskGetLen + FileSetLen + FileAllocate {
    /// Returns the inner file consuming self.
    fn into_inner(self: Box<Self>) -> Box<dyn DiskFile>;

    /// Asynchronously fsyncs any completed operations to the disk.
    async fn fsync(&self) -> Result<()>;

    /// Asynchronously fdatasyncs any completed operations to the disk.
    /// Note that an implementation may simply call fsync for fdatasync.
    async fn fdatasync(&self) -> Result<()>;

    /// Reads from the file at 'file_offset' into memory `mem` at `mem_offsets`.
    /// `mem_offsets` is similar to an iovec except relative to the start of `mem`.
    async fn read_to_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [cros_async::MemRegion],
    ) -> Result<usize>;

    /// Writes to the file at 'file_offset' from memory `mem` at `mem_offsets`.
    async fn write_from_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [cros_async::MemRegion],
    ) -> Result<usize>;

    /// Replaces a range of bytes with a hole.
    async fn punch_hole(&self, file_offset: u64, length: u64) -> Result<()>;

    /// Writes up to `length` bytes of zeroes to the stream, returning how many bytes were written.
    async fn write_zeroes_at(&self, file_offset: u64, length: u64) -> Result<()>;

    /// Reads from the file at 'file_offset' into `buf`.
    ///
    /// Less efficient than `read_to_mem` because of extra copies and allocations.
    async fn read_double_buffered(&self, file_offset: u64, buf: &mut [u8]) -> Result<usize> {
        let backing_mem = Arc::new(cros_async::VecIoWrapper::from(vec![0u8; buf.len()]));
        let region = cros_async::MemRegion {
            offset: 0,
            len: buf.len(),
        };
        let n = self
            .read_to_mem(file_offset, backing_mem.clone(), &[region])
            .await?;
        backing_mem
            .get_volatile_slice(region)
            .expect("BUG: the VecIoWrapper shrank?")
            .sub_slice(0, n)
            .expect("BUG: read_to_mem return value too large?")
            .copy_to(buf);
        Ok(n)
    }

    /// Writes to the file at 'file_offset' from `buf`.
    ///
    /// Less efficient than `write_from_mem` because of extra copies and allocations.
    async fn write_double_buffered(&self, file_offset: u64, buf: &[u8]) -> Result<usize> {
        let backing_mem = Arc::new(cros_async::VecIoWrapper::from(buf.to_vec()));
        let region = cros_async::MemRegion {
            offset: 0,
            len: buf.len(),
        };
        self.write_from_mem(file_offset, backing_mem, &[region])
            .await
    }
}

/// A disk backed by a single file that implements `AsyncDisk` for access.
pub struct SingleFileDisk {
    inner: IoSource<File>,
}

impl SingleFileDisk {
    pub fn new(disk: File, ex: &Executor) -> Result<Self> {
        ex.async_from(disk)
            .map_err(Error::CreateSingleFileDisk)
            .map(|inner| SingleFileDisk { inner })
    }
}

impl DiskGetLen for SingleFileDisk {
    fn get_len(&self) -> io::Result<u64> {
        self.inner.as_source().get_len()
    }
}

impl FileSetLen for SingleFileDisk {
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.as_source().set_len(len)
    }
}

impl FileAllocate for SingleFileDisk {
    fn allocate(&mut self, offset: u64, len: u64) -> io::Result<()> {
        self.inner.as_source_mut().allocate(offset, len)
    }
}

#[async_trait(?Send)]
impl AsyncDisk for SingleFileDisk {
    fn into_inner(self: Box<Self>) -> Box<dyn DiskFile> {
        Box::new(self.inner.into_source())
    }

    async fn fsync(&self) -> Result<()> {
        self.inner.fsync().await.map_err(Error::Fsync)
    }

    async fn fdatasync(&self) -> Result<()> {
        self.inner.fdatasync().await.map_err(Error::Fdatasync)
    }

    async fn read_to_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [cros_async::MemRegion],
    ) -> Result<usize> {
        self.inner
            .read_to_mem(Some(file_offset), mem, mem_offsets)
            .await
            .map_err(Error::ReadToMem)
    }

    async fn write_from_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [cros_async::MemRegion],
    ) -> Result<usize> {
        self.inner
            .write_from_mem(Some(file_offset), mem, mem_offsets)
            .await
            .map_err(Error::WriteFromMem)
    }

    async fn punch_hole(&self, file_offset: u64, length: u64) -> Result<()> {
        self.inner
            .fallocate(file_offset, length, AllocateMode::PunchHole)
            .await
            .map_err(Error::Fallocate)
    }

    async fn write_zeroes_at(&self, file_offset: u64, length: u64) -> Result<()> {
        if self
            .inner
            .fallocate(file_offset, length, AllocateMode::ZeroRange)
            .await
            .is_ok()
        {
            return Ok(());
        }

        // Fall back to writing zeros if fallocate doesn't work.
        let buf_size = min(length, 0x10000);
        let mut nwritten = 0;
        while nwritten < length {
            let remaining = length - nwritten;
            let write_size = min(remaining, buf_size) as usize;
            let buf = vec![0u8; write_size];
            nwritten += self
                .inner
                .write_from_vec(Some(file_offset + nwritten), buf)
                .await
                .map(|(n, _)| n as u64)
                .map_err(Error::WriteFromVec)?;
        }
        Ok(())
    }
}
