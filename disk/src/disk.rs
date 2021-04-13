// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::fmt::{self, Debug, Display};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use async_trait::async_trait;
use base::{
    AsRawDescriptors, FileAllocate, FileReadWriteAtVolatile, FileSetLen, FileSync, PunchHole,
    SeekHole, WriteZeroesAt,
};
use cros_async::Executor;
use libc::EINVAL;
use remain::sorted;
use vm_memory::GuestMemory;

mod qcow;
pub use qcow::{QcowFile, QCOW_MAGIC};

#[cfg(feature = "composite-disk")]
mod composite;
#[cfg(feature = "composite-disk")]
use composite::{CompositeDiskFile, CDISK_MAGIC, CDISK_MAGIC_LEN};

mod android_sparse;
use android_sparse::{AndroidSparse, SPARSE_HEADER_MAGIC};

#[sorted]
#[derive(Debug)]
pub enum Error {
    BlockDeviceNew(base::Error),
    ConversionNotSupported,
    CreateAndroidSparseDisk(android_sparse::Error),
    #[cfg(feature = "composite-disk")]
    CreateCompositeDisk(composite::Error),
    CreateSingleFileDisk(cros_async::AsyncError),
    Fallocate(cros_async::AsyncError),
    Fsync(cros_async::AsyncError),
    QcowError(qcow::Error),
    ReadingData(io::Error),
    ReadingHeader(io::Error),
    ReadToMem(cros_async::AsyncError),
    SeekingFile(io::Error),
    SettingFileSize(io::Error),
    UnknownType,
    WriteFromMem(cros_async::AsyncError),
    WriteFromVec(cros_async::AsyncError),
    WritingData(io::Error),
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
        let orig_seek = s.seek(SeekFrom::Current(0))?;
        let end = s.seek(SeekFrom::End(0))? as u64;
        s.seek(SeekFrom::Start(orig_seek))?;
        Ok(end)
    }
}

/// The prerequisites necessary to support a block device.
#[rustfmt::skip] // rustfmt won't wrap the long list of trait bounds.
pub trait DiskFile:
    FileSetLen
    + DiskGetLen
    + FileSync
    + FileReadWriteAtVolatile
    + PunchHole
    + WriteZeroesAt
    + FileAllocate
    + Send
    + AsRawDescriptors
    + Debug
{
}
impl<
        D: FileSetLen
            + DiskGetLen
            + FileSync
            + PunchHole
            + FileReadWriteAtVolatile
            + WriteZeroesAt
            + FileAllocate
            + Send
            + AsRawDescriptors
            + Debug,
    > DiskFile for D
{
}

/// A `DiskFile` that can be converted for asychronous access.
pub trait ToAsyncDisk: DiskFile {
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

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            BlockDeviceNew(e) => write!(f, "failed to create block device: {}", e),
            ConversionNotSupported => write!(f, "requested file conversion not supported"),
            CreateAndroidSparseDisk(e) => write!(f, "failure in android sparse disk: {}", e),
            #[cfg(feature = "composite-disk")]
            CreateCompositeDisk(e) => write!(f, "failure in composite disk: {}", e),
            CreateSingleFileDisk(e) => write!(f, "failure creating single file disk: {}", e),
            Fallocate(e) => write!(f, "failure with fallocate: {}", e),
            Fsync(e) => write!(f, "failure with fsync: {}", e),
            QcowError(e) => write!(f, "failure in qcow: {}", e),
            ReadingData(e) => write!(f, "failed to read data: {}", e),
            ReadingHeader(e) => write!(f, "failed to read header: {}", e),
            ReadToMem(e) => write!(f, "failed to read to memory: {}", e),
            SeekingFile(e) => write!(f, "failed to seek file: {}", e),
            SettingFileSize(e) => write!(f, "failed to set file size: {}", e),
            UnknownType => write!(f, "unknown disk type"),
            WriteFromMem(e) => write!(f, "failed to write from memory: {}", e),
            WriteFromVec(e) => write!(f, "failed to write from vec: {}", e),
            WritingData(e) => write!(f, "failed to write data: {}", e),
        }
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

fn convert_copy<R, W>(reader: &mut R, writer: &mut W, offset: u64, size: u64) -> Result<()>
where
    R: Read + Seek,
    W: Write + Seek,
{
    const CHUNK_SIZE: usize = 65536;
    let mut buf = [0; CHUNK_SIZE];
    let mut read_count = 0;
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(Error::SeekingFile)?;
    writer
        .seek(SeekFrom::Start(offset))
        .map_err(Error::SeekingFile)?;
    loop {
        let this_count = min(CHUNK_SIZE as u64, size - read_count) as usize;
        let nread = reader
            .read(&mut buf[..this_count])
            .map_err(Error::ReadingData)?;
        writer.write(&buf[..nread]).map_err(Error::WritingData)?;
        read_count += nread as u64;
        if nread == 0 || read_count == size {
            break;
        }
    }

    Ok(())
}

fn convert_reader_writer<R, W>(reader: &mut R, writer: &mut W, size: u64) -> Result<()>
where
    R: Read + Seek + SeekHole,
    W: Write + Seek,
{
    let mut offset = 0;
    while offset < size {
        // Find the next range of data.
        let next_data = match reader.seek_data(offset).map_err(Error::SeekingFile)? {
            Some(o) => o,
            None => {
                // No more data in the file.
                break;
            }
        };
        let next_hole = match reader.seek_hole(next_data).map_err(Error::SeekingFile)? {
            Some(o) => o,
            None => {
                // This should not happen - there should always be at least one hole
                // after any data.
                return Err(Error::SeekingFile(io::Error::from_raw_os_error(EINVAL)));
            }
        };
        let count = next_hole - next_data;
        convert_copy(reader, writer, next_data, count)?;
        offset = next_hole;
    }

    Ok(())
}

fn convert_reader<R>(reader: &mut R, dst_file: File, dst_type: ImageType) -> Result<()>
where
    R: Read + Seek + SeekHole,
{
    let src_size = reader.seek(SeekFrom::End(0)).map_err(Error::SeekingFile)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(Error::SeekingFile)?;

    // Ensure the destination file is empty before writing to it.
    dst_file.set_len(0).map_err(Error::SettingFileSize)?;

    match dst_type {
        ImageType::Qcow2 => {
            let mut dst_writer = QcowFile::new(dst_file, src_size).map_err(Error::QcowError)?;
            convert_reader_writer(reader, &mut dst_writer, src_size)
        }
        ImageType::Raw => {
            let mut dst_writer = dst_file;
            // Set the length of the destination file to convert it into a sparse file
            // of the desired size.
            dst_writer
                .set_len(src_size)
                .map_err(Error::SettingFileSize)?;
            convert_reader_writer(reader, &mut dst_writer, src_size)
        }
        _ => Err(Error::ConversionNotSupported),
    }
}

/// Copy the contents of a disk image in `src_file` into `dst_file`.
/// The type of `src_file` is automatically detected, and the output file type is
/// determined by `dst_type`.
pub fn convert(src_file: File, dst_file: File, dst_type: ImageType) -> Result<()> {
    let src_type = detect_image_type(&src_file)?;
    match src_type {
        ImageType::Qcow2 => {
            let mut src_reader = QcowFile::from(src_file).map_err(Error::QcowError)?;
            convert_reader(&mut src_reader, dst_file, dst_type)
        }
        ImageType::Raw => {
            // src_file is a raw file.
            let mut src_reader = src_file;
            convert_reader(&mut src_reader, dst_file, dst_type)
        }
        // TODO(schuffelen): Implement Read + Write + SeekHole for CompositeDiskFile
        _ => Err(Error::ConversionNotSupported),
    }
}

/// Detect the type of an image file by checking for a valid header of the supported formats.
pub fn detect_image_type(file: &File) -> Result<ImageType> {
    let mut f = file;
    let disk_size = f.get_len().map_err(Error::SeekingFile)?;
    let orig_seek = f.seek(SeekFrom::Current(0)).map_err(Error::SeekingFile)?;
    f.seek(SeekFrom::Start(0)).map_err(Error::SeekingFile)?;

    // Try to read the disk in a nicely-aligned block size unless the whole file is smaller.
    const MAGIC_BLOCK_SIZE: usize = 4096;
    let mut magic = [0u8; MAGIC_BLOCK_SIZE];
    let magic_read_len = if disk_size > MAGIC_BLOCK_SIZE as u64 {
        MAGIC_BLOCK_SIZE
    } else {
        // This cast is safe since we know disk_size is less than MAGIC_BLOCK_SIZE (4096) and
        // therefore is representable in usize.
        disk_size as usize
    };

    f.read_exact(&mut magic[0..magic_read_len])
        .map_err(Error::ReadingHeader)?;
    f.seek(SeekFrom::Start(orig_seek))
        .map_err(Error::SeekingFile)?;

    #[cfg(feature = "composite-disk")]
    if let Some(cdisk_magic) = magic.get(0..CDISK_MAGIC_LEN) {
        if cdisk_magic == CDISK_MAGIC.as_bytes() {
            return Ok(ImageType::CompositeDisk);
        }
    }

    if let Some(magic4) = magic.get(0..4) {
        if magic4 == QCOW_MAGIC.to_be_bytes() {
            return Ok(ImageType::Qcow2);
        } else if magic4 == SPARSE_HEADER_MAGIC.to_le_bytes() {
            return Ok(ImageType::AndroidSparse);
        }
    }

    Ok(ImageType::Raw)
}

/// Check if the image file type can be used for async disk access.
pub fn async_ok(raw_image: &File) -> Result<bool> {
    let image_type = detect_image_type(raw_image)?;
    Ok(match image_type {
        ImageType::Raw => true,
        ImageType::Qcow2 | ImageType::AndroidSparse | ImageType::CompositeDisk => false,
    })
}

/// Inspect the image file type and create an appropriate disk file to match it.
pub fn create_async_disk_file(raw_image: File) -> Result<Box<dyn ToAsyncDisk>> {
    let image_type = detect_image_type(&raw_image)?;
    Ok(match image_type {
        ImageType::Raw => Box::new(raw_image) as Box<dyn ToAsyncDisk>,
        ImageType::Qcow2 | ImageType::AndroidSparse | ImageType::CompositeDisk => {
            return Err(Error::UnknownType)
        }
    })
}

/// Inspect the image file type and create an appropriate disk file to match it.
pub fn create_disk_file(raw_image: File) -> Result<Box<dyn DiskFile>> {
    let image_type = detect_image_type(&raw_image)?;
    Ok(match image_type {
        ImageType::Raw => Box::new(raw_image) as Box<dyn DiskFile>,
        ImageType::Qcow2 => {
            Box::new(QcowFile::from(raw_image).map_err(Error::QcowError)?) as Box<dyn DiskFile>
        }
        #[cfg(feature = "composite-disk")]
        ImageType::CompositeDisk => {
            // Valid composite disk header present
            Box::new(CompositeDiskFile::from_file(raw_image).map_err(Error::CreateCompositeDisk)?)
                as Box<dyn DiskFile>
        }
        #[cfg(not(feature = "composite-disk"))]
        ImageType::CompositeDisk => return Err(Error::UnknownType),
        ImageType::AndroidSparse => {
            Box::new(AndroidSparse::from_file(raw_image).map_err(Error::CreateAndroidSparseDisk)?)
                as Box<dyn DiskFile>
        }
    })
}

/// An asynchronously accessible disk.
#[async_trait(?Send)]
pub trait AsyncDisk: DiskGetLen + FileSetLen + FileAllocate {
    /// Returns the inner file consuming self.
    fn into_inner(self: Box<Self>) -> Box<dyn ToAsyncDisk>;

    /// Asynchronously fsyncs any completed operations to the disk.
    async fn fsync(&self) -> Result<()>;

    /// Reads from the file at 'file_offset' in to memory `mem` at `mem_offsets`.
    /// `mem_offsets` is similar to an iovec except relative to the start of `mem`.
    async fn read_to_mem<'a>(
        &self,
        file_offset: u64,
        mem: Arc<GuestMemory>,
        mem_offsets: &'a [cros_async::MemRegion],
    ) -> Result<usize>;

    /// Writes to the file at 'file_offset' from memory `mem` at `mem_offsets`.
    async fn write_from_mem<'a>(
        &self,
        file_offset: u64,
        mem: Arc<GuestMemory>,
        mem_offsets: &'a [cros_async::MemRegion],
    ) -> Result<usize>;

    /// Replaces a range of bytes with a hole.
    async fn punch_hole(&self, file_offset: u64, length: u64) -> Result<()>;

    /// Writes up to `length` bytes of zeroes to the stream, returning how many bytes were written.
    async fn write_zeroes_at(&self, file_offset: u64, length: u64) -> Result<()>;
}

use cros_async::IoSourceExt;

/// A disk backed by a single file that implements `AsyncDisk` for access.
pub struct SingleFileDisk {
    inner: Box<dyn IoSourceExt<File>>,
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
    fn into_inner(self: Box<Self>) -> Box<dyn ToAsyncDisk> {
        Box::new(self.inner.into_source())
    }

    async fn fsync(&self) -> Result<()> {
        self.inner.fsync().await.map_err(Error::Fsync)
    }

    async fn read_to_mem<'a>(
        &self,
        file_offset: u64,
        mem: Arc<GuestMemory>,
        mem_offsets: &'a [cros_async::MemRegion],
    ) -> Result<usize> {
        self.inner
            .read_to_mem(file_offset, mem, mem_offsets)
            .await
            .map_err(Error::ReadToMem)
    }

    async fn write_from_mem<'a>(
        &self,
        file_offset: u64,
        mem: Arc<GuestMemory>,
        mem_offsets: &'a [cros_async::MemRegion],
    ) -> Result<usize> {
        self.inner
            .write_from_mem(file_offset, mem, mem_offsets)
            .await
            .map_err(Error::WriteFromMem)
    }

    async fn punch_hole(&self, file_offset: u64, length: u64) -> Result<()> {
        self.inner
            .fallocate(
                file_offset,
                length,
                (libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE) as u32,
            )
            .await
            .map_err(Error::Fallocate)
    }

    async fn write_zeroes_at(&self, file_offset: u64, length: u64) -> Result<()> {
        if self
            .inner
            .fallocate(
                file_offset,
                length,
                (libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE) as u32,
            )
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
                .write_from_vec(file_offset + nwritten as u64, buf)
                .await
                .map(|(n, _)| n as u64)
                .map_err(Error::WriteFromVec)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::{File, OpenOptions};

    use cros_async::{Executor, MemRegion};
    use vm_memory::{GuestAddress, GuestMemory};

    #[test]
    fn read_async() {
        async fn read_zeros_async(ex: &Executor) {
            let guest_mem = Arc::new(GuestMemory::new(&[(GuestAddress(0), 4096)]).unwrap());
            let f = File::open("/dev/zero").unwrap();
            let async_file = SingleFileDisk::new(f, ex).unwrap();
            let result = async_file
                .read_to_mem(
                    0,
                    Arc::clone(&guest_mem),
                    &[MemRegion { offset: 0, len: 48 }],
                )
                .await;
            assert_eq!(48, result.unwrap());
        }

        let ex = Executor::new().unwrap();
        ex.run_until(read_zeros_async(&ex)).unwrap();
    }

    #[test]
    fn write_async() {
        async fn write_zeros_async(ex: &Executor) {
            let guest_mem = Arc::new(GuestMemory::new(&[(GuestAddress(0), 4096)]).unwrap());
            let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
            let async_file = SingleFileDisk::new(f, ex).unwrap();
            let result = async_file
                .write_from_mem(
                    0,
                    Arc::clone(&guest_mem),
                    &[MemRegion { offset: 0, len: 48 }],
                )
                .await;
            assert_eq!(48, result.unwrap());
        }

        let ex = Executor::new().unwrap();
        ex.run_until(write_zeros_async(&ex)).unwrap();
    }

    #[test]
    fn detect_image_type_raw() {
        let mut t = tempfile::tempfile().unwrap();
        // Fill the first block of the file with "random" data.
        let buf = "ABCD".as_bytes().repeat(1024);
        t.write_all(&buf).unwrap();
        let image_type = detect_image_type(&t).expect("failed to detect image type");
        assert_eq!(image_type, ImageType::Raw);
    }

    #[test]
    fn detect_image_type_qcow2() {
        let mut t = tempfile::tempfile().unwrap();
        // Write the qcow2 magic signature. The rest of the header is not filled in, so if
        // detect_image_type is ever updated to validate more of the header, this test would need
        // to be updated.
        let buf: &[u8] = &[0x51, 0x46, 0x49, 0xfb];
        t.write_all(&buf).unwrap();
        let image_type = detect_image_type(&t).expect("failed to detect image type");
        assert_eq!(image_type, ImageType::Qcow2);
    }

    #[test]
    fn detect_image_type_android_sparse() {
        let mut t = tempfile::tempfile().unwrap();
        // Write the Android sparse magic signature. The rest of the header is not filled in, so if
        // detect_image_type is ever updated to validate more of the header, this test would need
        // to be updated.
        let buf: &[u8] = &[0x3a, 0xff, 0x26, 0xed];
        t.write_all(&buf).unwrap();
        let image_type = detect_image_type(&t).expect("failed to detect image type");
        assert_eq!(image_type, ImageType::AndroidSparse);
    }

    #[test]
    #[cfg(feature = "composite-disk")]
    fn detect_image_type_composite() {
        let mut t = tempfile::tempfile().unwrap();
        // Write the composite disk magic signature. The rest of the header is not filled in, so if
        // detect_image_type is ever updated to validate more of the header, this test would need
        // to be updated.
        let buf = "composite_disk\x1d".as_bytes();
        t.write_all(&buf).unwrap();
        let image_type = detect_image_type(&t).expect("failed to detect image type");
        assert_eq!(image_type, ImageType::CompositeDisk);
    }

    #[test]
    fn detect_image_type_small_file() {
        let mut t = tempfile::tempfile().unwrap();
        // Write a file smaller than the four-byte qcow2/sparse magic to ensure the small file logic
        // works correctly and handles it as a raw file.
        let buf: &[u8] = &[0xAA, 0xBB];
        t.write_all(&buf).unwrap();
        let image_type = detect_image_type(&t).expect("failed to detect image type");
        assert_eq!(image_type, ImageType::Raw);
    }
}
