// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

use libc::EINVAL;
use qcow::{QcowFile, QCOW_MAGIC};
use remain::sorted;
use sys_util::{
    AsRawFds, FileReadWriteAtVolatile, FileSetLen, FileSync, PunchHole, SeekHole, WriteZeroes,
};

#[cfg(feature = "composite-disk")]
mod composite;
#[cfg(feature = "composite-disk")]
use composite::{CompositeDiskFile, CDISK_MAGIC, CDISK_MAGIC_LEN};

#[sorted]
#[derive(Debug)]
pub enum Error {
    BlockDeviceNew(sys_util::Error),
    ConversionNotSupported,
    #[cfg(feature = "composite-disk")]
    CreateCompositeDisk(composite::Error),
    QcowError(qcow::Error),
    ReadingData(io::Error),
    ReadingHeader(io::Error),
    SeekingFile(io::Error),
    SettingFileSize(io::Error),
    UnknownType,
    WritingData(io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The prerequisites necessary to support a block device.
#[rustfmt::skip] // rustfmt won't wrap the long list of trait bounds.
pub trait DiskFile:
    FileSetLen
    + FileSync
    + FileReadWriteAtVolatile
    + PunchHole
    + Seek
    + WriteZeroes
    + Send
    + AsRawFds
{
}
impl<
        D: FileSetLen
            + FileSync
            + PunchHole
            + FileReadWriteAtVolatile
            + Seek
            + WriteZeroes
            + Send
            + AsRawFds,
    > DiskFile for D
{
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            BlockDeviceNew(e) => write!(f, "failed to create block device: {}", e),
            ConversionNotSupported => write!(f, "requested file conversion not supported"),
            #[cfg(feature = "composite-disk")]
            CreateCompositeDisk(e) => write!(f, "failure in composite disk: {}", e),
            QcowError(e) => write!(f, "failure in qcow: {}", e),
            ReadingData(e) => write!(f, "failed to read data: {}", e),
            ReadingHeader(e) => write!(f, "failed to read header: {}", e),
            SeekingFile(e) => write!(f, "failed to seek file: {}", e),
            SettingFileSize(e) => write!(f, "failed to set file size: {}", e),
            UnknownType => write!(f, "unknown disk type"),
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

/// Detect the type of an image file by checking for a valid qcow2 header.
pub fn detect_image_type(file: &File) -> Result<ImageType> {
    let mut f = file;
    let orig_seek = f.seek(SeekFrom::Current(0)).map_err(Error::SeekingFile)?;
    f.seek(SeekFrom::Start(0)).map_err(Error::SeekingFile)?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).map_err(Error::ReadingHeader)?;
    let magic = u32::from_be_bytes(magic);
    #[cfg(feature = "composite-disk")]
    {
        f.seek(SeekFrom::Start(0)).map_err(Error::SeekingFile)?;
        let mut cdisk_magic = [0u8; CDISK_MAGIC_LEN];
        f.read_exact(&mut cdisk_magic[..])
            .map_err(Error::ReadingHeader)?;
        if cdisk_magic == CDISK_MAGIC.as_bytes() {
            f.seek(SeekFrom::Start(orig_seek))
                .map_err(Error::SeekingFile)?;
            return Ok(ImageType::CompositeDisk);
        }
    }
    let image_type = if magic == QCOW_MAGIC {
        ImageType::Qcow2
    } else {
        ImageType::Raw
    };
    f.seek(SeekFrom::Start(orig_seek))
        .map_err(Error::SeekingFile)?;
    Ok(image_type)
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
    })
}
