// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Use seekable zstd archive of raw disk image as read only disk

use std::cmp::min;
use std::fs::File;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use async_trait::async_trait;
use base::AsRawDescriptor;
use base::FileAllocate;
use base::FileReadWriteAtVolatile;
use base::FileSetLen;
use base::RawDescriptor;
use base::VolatileSlice;
use cros_async::BackingMemory;
use cros_async::Executor;
use cros_async::IoSource;

use crate::AsyncDisk;
use crate::DiskFile;
use crate::DiskGetLen;
use crate::Error as DiskError;
use crate::Result as DiskResult;
use crate::ToAsyncDisk;

// Zstandard frame magic
pub const ZSTD_FRAME_MAGIC: u32 = 0xFD2FB528;

// Skippable frame magic can be anything between [0x184D2A50, 0x184D2A5F]
pub const ZSTD_SKIPPABLE_MAGIC_LOW: u32 = 0x184D2A50;
pub const ZSTD_SKIPPABLE_MAGIC_HIGH: u32 = 0x184D2A5F;
pub const ZSTD_SEEK_TABLE_MAGIC: u32 = 0x8F92EAB1;

pub const ZSTD_DEFAULT_FRAME_SIZE: usize = 128 << 10; // 128KB

#[derive(Clone, Debug)]
pub struct ZstdSeekTable {
    // Cumulative sum of decompressed sizes of all frames before the indexed frame.
    // The last element is the total decompressed size of the zstd archive.
    cumulative_decompressed_sizes: Vec<u64>,
    // Cumulative sum of compressed sizes of all frames before the indexed frame.
    // The last element is the total compressed size of the zstd archive.
    cumulative_compressed_sizes: Vec<u64>,
}

impl ZstdSeekTable {
    /// Read seek table entries from seek_table_entries
    pub fn from_footer(
        seek_table_entries: &[u8],
        num_frames: u32,
        checksum_flag: bool,
    ) -> anyhow::Result<ZstdSeekTable> {
        let mut cumulative_decompressed_size: u64 = 0;
        let mut cumulative_compressed_size: u64 = 0;
        let mut cumulative_decompressed_sizes = Vec::with_capacity(num_frames as usize + 1);
        let mut cumulative_compressed_sizes = Vec::with_capacity(num_frames as usize + 1);
        let mut offset = 0;
        cumulative_decompressed_sizes.push(0);
        cumulative_compressed_sizes.push(0);
        for _ in 0..num_frames {
            let compressed_size = u32::from_le_bytes(
                seek_table_entries
                    .get(offset..offset + 4)
                    .context("failed to parse seektable entry")?
                    .try_into()?,
            );
            let decompressed_size = u32::from_le_bytes(
                seek_table_entries
                    .get(offset + 4..offset + 8)
                    .context("failed to parse seektable entry")?
                    .try_into()?,
            );
            cumulative_decompressed_size += decompressed_size as u64;
            cumulative_compressed_size += compressed_size as u64;
            cumulative_decompressed_sizes.push(cumulative_decompressed_size);
            cumulative_compressed_sizes.push(cumulative_compressed_size);
            offset += 8 + (checksum_flag as usize * 4);
        }
        cumulative_decompressed_sizes.push(cumulative_decompressed_size);
        cumulative_compressed_sizes.push(cumulative_compressed_size);

        Ok(ZstdSeekTable {
            cumulative_decompressed_sizes,
            cumulative_compressed_sizes,
        })
    }

    /// Returns the index of the frame that contains the given decompressed offset.
    pub fn find_frame_index(&self, decompressed_offset: u64) -> Option<usize> {
        if self.cumulative_decompressed_sizes.is_empty()
            || decompressed_offset >= *self.cumulative_decompressed_sizes.last().unwrap()
        {
            return None;
        }
        self.cumulative_decompressed_sizes
            .partition_point(|&size| size <= decompressed_offset)
            .checked_sub(1)
    }
}

#[derive(Debug)]
pub struct ZstdDisk {
    file: File,
    seek_table: ZstdSeekTable,
}

impl ZstdDisk {
    pub fn from_file(mut file: File) -> anyhow::Result<ZstdDisk> {
        // Verify file is large enough to contain a seek table (17 bytes)
        if file.metadata()?.len() < 17 {
            return Err(anyhow::anyhow!("File too small to contain zstd seek table"));
        }

        // Read last 9 bytes as seek table footer
        let mut seektable_footer = [0u8; 9];
        file.seek(std::io::SeekFrom::End(-9))?;
        file.read_exact(&mut seektable_footer)?;

        // Verify last 4 bytes of footer is seek table magic
        if u32::from_le_bytes(seektable_footer[5..9].try_into()?) != ZSTD_SEEK_TABLE_MAGIC {
            return Err(anyhow::anyhow!("Invalid zstd seek table magic"));
        }

        // Get number of frame from seek table
        let num_frames = u32::from_le_bytes(seektable_footer[0..4].try_into()?);

        // Read flags from seek table descriptor
        let checksum_flag = (seektable_footer[4] >> 7) & 1 != 0;
        if (seektable_footer[4] & 0x7C) != 0 {
            bail!(
                "This zstd seekable decoder cannot parse seek table with non-zero reserved flags"
            );
        }

        let seek_table_entries_size = num_frames * (8 + (checksum_flag as u32 * 4));

        // Seek to the beginning of the seek table
        file.seek(std::io::SeekFrom::End(
            -(9 + seek_table_entries_size as i64),
        ))?;

        // Return new ZstdDisk
        let mut seek_table_entries: Vec<u8> = vec![0u8; seek_table_entries_size as usize];
        file.read_exact(&mut seek_table_entries)?;

        let seek_table =
            ZstdSeekTable::from_footer(&seek_table_entries, num_frames, checksum_flag)?;

        Ok(ZstdDisk { file, seek_table })
    }
}

impl DiskGetLen for ZstdDisk {
    fn get_len(&self) -> std::io::Result<u64> {
        self.seek_table
            .cumulative_decompressed_sizes
            .last()
            .copied()
            .ok_or(io::ErrorKind::InvalidData.into())
    }
}

impl FileSetLen for ZstdDisk {
    fn set_len(&self, _len: u64) -> std::io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsupported operation",
        ))
    }
}

impl AsRawDescriptor for ZstdDisk {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.file.as_raw_descriptor()
    }
}

struct CompressedReadInstruction {
    frame_index: usize,
    read_offset: u64,
    read_size: u64,
}

fn compresed_frame_read_instruction(
    seek_table: &ZstdSeekTable,
    offset: u64,
) -> anyhow::Result<CompressedReadInstruction> {
    let frame_index = seek_table
        .find_frame_index(offset)
        .with_context(|| format!("no frame for offset {}", offset))?;
    let compressed_offset = seek_table.cumulative_compressed_sizes[frame_index];
    let next_compressed_offset = seek_table
        .cumulative_compressed_sizes
        .get(frame_index + 1)
        .context("Offset out of range (next_compressed_offset overflow)")?;
    let compressed_size = next_compressed_offset - compressed_offset;
    Ok(CompressedReadInstruction {
        frame_index,
        read_offset: compressed_offset,
        read_size: compressed_size,
    })
}

impl FileReadWriteAtVolatile for ZstdDisk {
    fn read_at_volatile(&self, slice: VolatileSlice, offset: u64) -> io::Result<usize> {
        let read_instruction = compresed_frame_read_instruction(&self.seek_table, offset)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut compressed_data = vec![0u8; read_instruction.read_size as usize];

        let compressed_frame_slice = VolatileSlice::new(compressed_data.as_mut_slice());

        self.file
            .read_at_volatile(compressed_frame_slice, read_instruction.read_offset)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut decompressor: zstd::bulk::Decompressor<'_> = zstd::bulk::Decompressor::new()?;
        let mut decompressed_data = Vec::with_capacity(ZSTD_DEFAULT_FRAME_SIZE);
        let decoded_size =
            decompressor.decompress_to_buffer(&compressed_data, &mut decompressed_data)?;

        let decompressed_offset_in_frame =
            offset - self.seek_table.cumulative_decompressed_sizes[read_instruction.frame_index];

        if decompressed_offset_in_frame >= decoded_size as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BUG: Frame offset larger than decoded size",
            ));
        }

        let read_len = min(
            slice.size() as u64,
            (decoded_size as u64) - decompressed_offset_in_frame,
        ) as usize;
        let data_to_copy = &decompressed_data[decompressed_offset_in_frame as usize..][..read_len];
        slice
            .sub_slice(0, read_len)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            .copy_from(data_to_copy);
        Ok(data_to_copy.len())
    }

    fn write_at_volatile(&self, _slice: VolatileSlice, _offset: u64) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsupported operation",
        ))
    }
}

pub struct AsyncZstdDisk {
    inner: IoSource<File>,
    seek_table: ZstdSeekTable,
}

impl ToAsyncDisk for ZstdDisk {
    fn to_async_disk(self: Box<Self>, ex: &Executor) -> DiskResult<Box<dyn AsyncDisk>> {
        Ok(Box::new(AsyncZstdDisk {
            inner: ex.async_from(self.file).map_err(DiskError::ToAsync)?,
            seek_table: self.seek_table,
        }))
    }
}

impl DiskGetLen for AsyncZstdDisk {
    fn get_len(&self) -> io::Result<u64> {
        self.seek_table
            .cumulative_decompressed_sizes
            .last()
            .copied()
            .ok_or(io::ErrorKind::InvalidData.into())
    }
}

impl FileSetLen for AsyncZstdDisk {
    fn set_len(&self, _len: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsupported operation",
        ))
    }
}

impl FileAllocate for AsyncZstdDisk {
    fn allocate(&self, _offset: u64, _length: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsupported operation",
        ))
    }
}

#[async_trait(?Send)]
impl AsyncDisk for AsyncZstdDisk {
    async fn flush(&self) -> DiskResult<()> {
        // zstd is read-only, nothing to flush.
        Ok(())
    }

    async fn fsync(&self) -> DiskResult<()> {
        // Do nothing because it's read-only.
        Ok(())
    }

    async fn fdatasync(&self) -> DiskResult<()> {
        // Do nothing because it's read-only.
        Ok(())
    }

    /// Reads data from `file_offset` of decompressed disk image till the end of current
    /// zstd frame and write them into memory `mem` at `mem_offsets`. This function should
    /// function the same as running `preadv()` on decompressed zstd image and reading into
    /// the array of `iovec`s specified with `mem` and `mem_offsets`.
    async fn read_to_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: cros_async::MemRegionIter<'a>,
    ) -> DiskResult<usize> {
        let read_instruction = compresed_frame_read_instruction(&self.seek_table, file_offset)
            .map_err(|e| DiskError::ReadingData(io::Error::new(io::ErrorKind::InvalidData, e)))?;

        let compressed_data = vec![0u8; read_instruction.read_size as usize];

        let (compressed_read_size, compressed_data) = self
            .inner
            .read_to_vec(Some(read_instruction.read_offset), compressed_data)
            .await
            .map_err(|e| DiskError::ReadingData(io::Error::new(ErrorKind::Other, e)))?;

        if compressed_read_size != read_instruction.read_size as usize {
            return Err(DiskError::ReadingData(io::Error::new(
                ErrorKind::UnexpectedEof,
                "Read from compressed data result in wrong length",
            )));
        }

        let mut decompressor: zstd::bulk::Decompressor<'_> =
            zstd::bulk::Decompressor::new().map_err(DiskError::ReadingData)?;
        let mut decompressed_data = Vec::with_capacity(ZSTD_DEFAULT_FRAME_SIZE);
        let decoded_size = decompressor
            .decompress_to_buffer(&compressed_data, &mut decompressed_data)
            .map_err(DiskError::ReadingData)?;

        let decompressed_offset_in_frame = file_offset
            - self.seek_table.cumulative_decompressed_sizes[read_instruction.frame_index];

        if decompressed_offset_in_frame as usize > decoded_size {
            return Err(DiskError::ReadingData(io::Error::new(
                ErrorKind::InvalidData,
                "BUG: Frame offset larger than decoded size",
            )));
        }

        // Copy the decompressed data to the provided memory regions.
        let mut total_copied = 0;
        for mem_region in mem_offsets {
            let src_slice =
                &decompressed_data[decompressed_offset_in_frame as usize + total_copied..];
            let dst_slice = mem
                .get_volatile_slice(mem_region)
                .map_err(DiskError::GuestMemory)?;

            let to_copy = min(src_slice.len(), dst_slice.size());

            if to_copy > 0 {
                dst_slice
                    .sub_slice(0, to_copy)
                    .map_err(|e| DiskError::ReadingData(io::Error::new(ErrorKind::Other, e)))?
                    .copy_from(&src_slice[..to_copy]);

                total_copied += to_copy;

                // if fully copied destination buffers, break the loop.
                if total_copied == dst_slice.size() {
                    break;
                }
            }
        }

        Ok(total_copied)
    }

    async fn write_from_mem<'a>(
        &'a self,
        _file_offset: u64,
        _mem: Arc<dyn BackingMemory + Send + Sync>,
        _mem_offsets: cros_async::MemRegionIter<'a>,
    ) -> DiskResult<usize> {
        Err(DiskError::UnsupportedOperation)
    }

    async fn punch_hole(&self, _file_offset: u64, _length: u64) -> DiskResult<()> {
        Err(DiskError::UnsupportedOperation)
    }

    async fn write_zeroes_at(&self, _file_offset: u64, _length: u64) -> DiskResult<()> {
        Err(DiskError::UnsupportedOperation)
    }
}

impl DiskFile for ZstdDisk {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_frame_index_empty() {
        let seek_table = ZstdSeekTable {
            cumulative_decompressed_sizes: vec![0],
            cumulative_compressed_sizes: vec![0],
        };
        assert_eq!(seek_table.find_frame_index(0), None);
        assert_eq!(seek_table.find_frame_index(5), None);
    }

    #[test]
    fn test_find_frame_index_single_frame() {
        let seek_table = ZstdSeekTable {
            cumulative_decompressed_sizes: vec![0, 100],
            cumulative_compressed_sizes: vec![0, 50],
        };
        assert_eq!(seek_table.find_frame_index(0), Some(0));
        assert_eq!(seek_table.find_frame_index(50), Some(0));
        assert_eq!(seek_table.find_frame_index(99), Some(0));
        assert_eq!(seek_table.find_frame_index(100), None);
    }

    #[test]
    fn test_find_frame_index_multiple_frames() {
        let seek_table = ZstdSeekTable {
            cumulative_decompressed_sizes: vec![0, 100, 300, 500],
            cumulative_compressed_sizes: vec![0, 50, 120, 200],
        };
        assert_eq!(seek_table.find_frame_index(0), Some(0));
        assert_eq!(seek_table.find_frame_index(99), Some(0));
        assert_eq!(seek_table.find_frame_index(100), Some(1));
        assert_eq!(seek_table.find_frame_index(299), Some(1));
        assert_eq!(seek_table.find_frame_index(300), Some(2));
        assert_eq!(seek_table.find_frame_index(499), Some(2));
        assert_eq!(seek_table.find_frame_index(500), None);
        assert_eq!(seek_table.find_frame_index(1000), None);
    }

    #[test]
    fn test_find_frame_index_with_skippable_frames() {
        let seek_table = ZstdSeekTable {
            cumulative_decompressed_sizes: vec![0, 100, 100, 100, 300],
            cumulative_compressed_sizes: vec![0, 50, 60, 70, 150],
        };
        assert_eq!(seek_table.find_frame_index(0), Some(0));
        assert_eq!(seek_table.find_frame_index(99), Some(0));
        // Correctly skips the skippable frames.
        assert_eq!(seek_table.find_frame_index(100), Some(3));
        assert_eq!(seek_table.find_frame_index(299), Some(3));
        assert_eq!(seek_table.find_frame_index(300), None);
    }

    #[test]
    fn test_find_frame_index_with_last_skippable_frame() {
        let seek_table = ZstdSeekTable {
            cumulative_decompressed_sizes: vec![0, 20, 40, 40, 60, 60, 80, 80],
            cumulative_compressed_sizes: vec![0, 10, 20, 30, 40, 50, 60, 70],
        };
        assert_eq!(seek_table.find_frame_index(0), Some(0));
        assert_eq!(seek_table.find_frame_index(20), Some(1));
        assert_eq!(seek_table.find_frame_index(21), Some(1));
        assert_eq!(seek_table.find_frame_index(79), Some(5));
        assert_eq!(seek_table.find_frame_index(80), None);
        assert_eq!(seek_table.find_frame_index(300), None);
    }
}
