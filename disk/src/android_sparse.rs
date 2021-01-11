// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// https://android.googlesource.com/platform/system/core/+/7b444f0/libsparse/sparse_format.h

use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};
use std::mem;

use crate::DiskGetLen;
use base::{
    AsRawDescriptor, FileAllocate, FileReadWriteAtVolatile, FileSetLen, FileSync, PunchHole,
    RawDescriptor, WriteZeroesAt,
};
use data_model::{DataInit, Le16, Le32, VolatileSlice};
use remain::sorted;

#[sorted]
#[derive(Debug)]
pub enum Error {
    InvalidMagicHeader,
    InvalidSpecification(String),
    ReadSpecificationError(io::Error),
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            InvalidMagicHeader => write!(f, "invalid magic header for android sparse format"),
            InvalidSpecification(s) => write!(f, "invalid specification: \"{}\"", s),
            ReadSpecificationError(e) => write!(f, "failed to read specification: \"{}\"", e),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub const SPARSE_HEADER_MAGIC: u32 = 0xed26ff3a;
const MAJOR_VERSION: u16 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct SparseHeader {
    magic: Le32,          /* SPARSE_HEADER_MAGIC */
    major_version: Le16,  /* (0x1) - reject images with higher major versions */
    minor_version: Le16,  /* (0x0) - allow images with higer minor versions */
    file_hdr_sz: Le16,    /* 28 bytes for first revision of the file format */
    chunk_hdr_size: Le16, /* 12 bytes for first revision of the file format */
    blk_sz: Le32,         /* block size in bytes, must be a multiple of 4 (4096) */
    total_blks: Le32,     /* total blocks in the non-sparse output image */
    total_chunks: Le32,   /* total chunks in the sparse input image */
    image_checksum: Le32, /* CRC32 checksum of the original data, counting "don't care" */
                          /* as 0. Standard 802.3 polynomial, use a Public Domain */
                          /* table implementation */
}

unsafe impl DataInit for SparseHeader {}

const CHUNK_TYPE_RAW: u16 = 0xCAC1;
const CHUNK_TYPE_FILL: u16 = 0xCAC2;
const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;
const CHUNK_TYPE_CRC32: u16 = 0xCAC4;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct ChunkHeader {
    chunk_type: Le16, /* 0xCAC1 -> raw; 0xCAC2 -> fill; 0xCAC3 -> don't care */
    reserved1: u16,
    chunk_sz: Le32, /* in blocks in output image */
    total_sz: Le32, /* in bytes of chunk input file including chunk header and data */
}

unsafe impl DataInit for ChunkHeader {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Chunk {
    Raw(u64), // Offset into the file
    Fill(Vec<u8>),
    DontCare,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ChunkWithSize {
    chunk: Chunk,
    expanded_size: u64,
}

/* Following a Raw or Fill or CRC32 chunk is data.
 *  For a Raw chunk, it's the data in chunk_sz * blk_sz.
 *  For a Fill chunk, it's 4 bytes of the fill data.
 *  For a CRC32 chunk, it's 4 bytes of CRC32
 */
#[derive(Debug)]
pub struct AndroidSparse {
    file: File,
    total_size: u64,
    chunks: BTreeMap<u64, ChunkWithSize>,
}

fn parse_chunk<T: Read + Seek>(
    mut input: &mut T,
    chunk_hdr_size: u64,
    blk_sz: u64,
) -> Result<Option<ChunkWithSize>> {
    let current_offset = input
        .seek(SeekFrom::Current(0))
        .map_err(Error::ReadSpecificationError)?;
    let chunk_header =
        ChunkHeader::from_reader(&mut input).map_err(Error::ReadSpecificationError)?;
    let chunk = match chunk_header.chunk_type.to_native() {
        CHUNK_TYPE_RAW => {
            input
                .seek(SeekFrom::Current(
                    chunk_header.total_sz.to_native() as i64 - chunk_hdr_size as i64,
                ))
                .map_err(Error::ReadSpecificationError)?;
            Chunk::Raw(current_offset + chunk_hdr_size as u64)
        }
        CHUNK_TYPE_FILL => {
            if chunk_header.total_sz == chunk_hdr_size as u32 {
                return Err(Error::InvalidSpecification(
                    "Fill chunk did not have any data to fill".to_string(),
                ));
            }
            let fill_size = chunk_header.total_sz.to_native() as u64 - chunk_hdr_size as u64;
            let mut fill_bytes = vec![0u8; fill_size as usize];
            input
                .read_exact(&mut fill_bytes)
                .map_err(Error::ReadSpecificationError)?;
            Chunk::Fill(fill_bytes)
        }
        CHUNK_TYPE_DONT_CARE => Chunk::DontCare,
        CHUNK_TYPE_CRC32 => return Ok(None), // TODO(schuffelen): Validate crc32s in input
        unknown_type => {
            return Err(Error::InvalidSpecification(format!(
                "Chunk had invalid type, was {:x}",
                unknown_type
            )))
        }
    };
    let expanded_size = chunk_header.chunk_sz.to_native() as u64 * blk_sz;
    Ok(Some(ChunkWithSize {
        chunk,
        expanded_size,
    }))
}

impl AndroidSparse {
    pub fn from_file(mut file: File) -> Result<AndroidSparse> {
        file.seek(SeekFrom::Start(0))
            .map_err(Error::ReadSpecificationError)?;
        let sparse_header =
            SparseHeader::from_reader(&mut file).map_err(Error::ReadSpecificationError)?;
        if sparse_header.magic != SPARSE_HEADER_MAGIC {
            return Err(Error::InvalidSpecification(format!(
                "Header did not match magic constant. Expected {:x}, was {:x}",
                SPARSE_HEADER_MAGIC,
                sparse_header.magic.to_native()
            )));
        } else if sparse_header.major_version != MAJOR_VERSION {
            return Err(Error::InvalidSpecification(format!(
                "Header major version did not match. Expected {}, was {}",
                MAJOR_VERSION,
                sparse_header.major_version.to_native(),
            )));
        } else if (sparse_header.chunk_hdr_size.to_native() as usize)
            < mem::size_of::<ChunkHeader>()
        {
            return Err(Error::InvalidSpecification(format!(
                "Chunk header size does not fit chunk header struct, expected >={}, was {}",
                sparse_header.chunk_hdr_size.to_native(),
                mem::size_of::<ChunkHeader>()
            )));
        }
        let header_size = sparse_header.chunk_hdr_size.to_native() as u64;
        let block_size = sparse_header.blk_sz.to_native() as u64;
        let chunks = (0..sparse_header.total_chunks.to_native())
            .filter_map(|_| parse_chunk(&mut file, header_size, block_size).transpose())
            .collect::<Result<Vec<ChunkWithSize>>>()?;
        let total_size =
            sparse_header.total_blks.to_native() as u64 * sparse_header.blk_sz.to_native() as u64;
        AndroidSparse::from_parts(file, total_size, chunks)
    }

    fn from_parts(file: File, size: u64, chunks: Vec<ChunkWithSize>) -> Result<AndroidSparse> {
        let mut chunks_map: BTreeMap<u64, ChunkWithSize> = BTreeMap::new();
        let mut expanded_location: u64 = 0;
        for chunk_with_size in chunks {
            let size = chunk_with_size.expanded_size;
            if chunks_map
                .insert(expanded_location, chunk_with_size)
                .is_some()
            {
                return Err(Error::InvalidSpecification(format!(
                    "Two chunks were at {}",
                    expanded_location
                )));
            }
            expanded_location += size;
        }
        let image = AndroidSparse {
            file,
            total_size: size,
            chunks: chunks_map,
        };
        let calculated_len = image.get_len().map_err(Error::ReadSpecificationError)?;
        if calculated_len != size {
            return Err(Error::InvalidSpecification(format!(
                "Header promised size {}, chunks added up to {}",
                size, calculated_len
            )));
        }
        Ok(image)
    }
}

impl DiskGetLen for AndroidSparse {
    fn get_len(&self) -> io::Result<u64> {
        Ok(self.total_size)
    }
}

impl FileSetLen for AndroidSparse {
    fn set_len(&self, _len: u64) -> io::Result<()> {
        Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "unsupported operation",
        ))
    }
}

impl FileSync for AndroidSparse {
    fn fsync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PunchHole for AndroidSparse {
    fn punch_hole(&mut self, _offset: u64, _length: u64) -> io::Result<()> {
        Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "unsupported operation",
        ))
    }
}

impl WriteZeroesAt for AndroidSparse {
    fn write_zeroes_at(&mut self, _offset: u64, _length: usize) -> io::Result<usize> {
        Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "unsupported operation",
        ))
    }
}

impl AsRawDescriptor for AndroidSparse {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.file.as_raw_descriptor()
    }
}

impl FileAllocate for AndroidSparse {
    fn allocate(&mut self, _offset: u64, _length: u64) -> io::Result<()> {
        Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "unsupported operation",
        ))
    }
}

// Performs reads up to the chunk boundary.
impl FileReadWriteAtVolatile for AndroidSparse {
    fn read_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> io::Result<usize> {
        let found_chunk = self.chunks.range(..=offset).next_back();
        let (
            chunk_start,
            ChunkWithSize {
                chunk,
                expanded_size,
            },
        ) = found_chunk.ok_or_else(|| {
            io::Error::new(
                ErrorKind::UnexpectedEof,
                format!("no chunk for offset {}", offset),
            )
        })?;
        let chunk_offset = offset - chunk_start;
        let chunk_size = *expanded_size;
        let subslice = if chunk_offset + (slice.size() as u64) > chunk_size {
            slice
                .sub_slice(0, (chunk_size - chunk_offset) as usize)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("{:?}", e)))?
        } else {
            slice
        };
        match chunk {
            Chunk::DontCare => {
                subslice.write_bytes(0);
                Ok(subslice.size() as usize)
            }
            Chunk::Raw(file_offset) => self
                .file
                .read_at_volatile(subslice, *file_offset + chunk_offset),
            Chunk::Fill(fill_bytes) => {
                let chunk_offset_mod = chunk_offset % fill_bytes.len() as u64;
                let filled_memory: Vec<u8> = fill_bytes
                    .iter()
                    .cloned()
                    .cycle()
                    .skip(chunk_offset_mod as usize)
                    .take(subslice.size() as usize)
                    .collect();
                subslice.copy_from(&filled_memory);
                Ok(subslice.size() as usize)
            }
        }
    }
    fn write_at_volatile(&mut self, _slice: VolatileSlice, _offset: u64) -> io::Result<usize> {
        Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "unsupported operation",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use tempfile::tempfile;

    const CHUNK_SIZE: usize = mem::size_of::<ChunkHeader>();

    #[test]
    fn parse_raw() {
        let chunk_raw = ChunkHeader {
            chunk_type: CHUNK_TYPE_RAW.into(),
            reserved1: 0,
            chunk_sz: 1.into(),
            total_sz: (CHUNK_SIZE as u32 + 123).into(),
        };
        let header_bytes = chunk_raw.as_slice();
        let mut chunk_bytes: Vec<u8> = Vec::new();
        chunk_bytes.extend_from_slice(header_bytes);
        chunk_bytes.extend_from_slice(&[0u8; 123]);
        let mut chunk_cursor = Cursor::new(chunk_bytes);
        let chunk = parse_chunk(&mut chunk_cursor, CHUNK_SIZE as u64, 123)
            .expect("Failed to parse")
            .expect("Failed to determine chunk type");
        let expected_chunk = ChunkWithSize {
            chunk: Chunk::Raw(CHUNK_SIZE as u64),
            expanded_size: 123,
        };
        assert_eq!(expected_chunk, chunk);
    }

    #[test]
    fn parse_dont_care() {
        let chunk_raw = ChunkHeader {
            chunk_type: CHUNK_TYPE_DONT_CARE.into(),
            reserved1: 0,
            chunk_sz: 100.into(),
            total_sz: (CHUNK_SIZE as u32).into(),
        };
        let header_bytes = chunk_raw.as_slice();
        let mut chunk_cursor = Cursor::new(header_bytes);
        let chunk = parse_chunk(&mut chunk_cursor, CHUNK_SIZE as u64, 123)
            .expect("Failed to parse")
            .expect("Failed to determine chunk type");
        let expected_chunk = ChunkWithSize {
            chunk: Chunk::DontCare,
            expanded_size: 12300,
        };
        assert_eq!(expected_chunk, chunk);
    }

    #[test]
    fn parse_fill() {
        let chunk_raw = ChunkHeader {
            chunk_type: CHUNK_TYPE_FILL.into(),
            reserved1: 0,
            chunk_sz: 100.into(),
            total_sz: (CHUNK_SIZE as u32 + 4).into(),
        };
        let header_bytes = chunk_raw.as_slice();
        let mut chunk_bytes: Vec<u8> = Vec::new();
        chunk_bytes.extend_from_slice(header_bytes);
        chunk_bytes.extend_from_slice(&[123u8; 4]);
        let mut chunk_cursor = Cursor::new(chunk_bytes);
        let chunk = parse_chunk(&mut chunk_cursor, CHUNK_SIZE as u64, 123)
            .expect("Failed to parse")
            .expect("Failed to determine chunk type");
        let expected_chunk = ChunkWithSize {
            chunk: Chunk::Fill(vec![123, 123, 123, 123]),
            expanded_size: 12300,
        };
        assert_eq!(expected_chunk, chunk);
    }

    #[test]
    fn parse_crc32() {
        let chunk_raw = ChunkHeader {
            chunk_type: CHUNK_TYPE_CRC32.into(),
            reserved1: 0,
            chunk_sz: 0.into(),
            total_sz: (CHUNK_SIZE as u32 + 4).into(),
        };
        let header_bytes = chunk_raw.as_slice();
        let mut chunk_bytes: Vec<u8> = Vec::new();
        chunk_bytes.extend_from_slice(header_bytes);
        chunk_bytes.extend_from_slice(&[123u8; 4]);
        let mut chunk_cursor = Cursor::new(chunk_bytes);
        let chunk =
            parse_chunk(&mut chunk_cursor, CHUNK_SIZE as u64, 123).expect("Failed to parse");
        assert_eq!(None, chunk);
    }

    fn test_image(chunks: Vec<ChunkWithSize>) -> AndroidSparse {
        let file = tempfile().expect("failed to create tempfile");
        let size = chunks.iter().map(|x| x.expanded_size).sum();
        AndroidSparse::from_parts(file, size, chunks).expect("Could not create image")
    }

    #[test]
    fn read_dontcare() {
        let chunks = vec![ChunkWithSize {
            chunk: Chunk::DontCare,
            expanded_size: 100,
        }];
        let mut image = test_image(chunks);
        let mut input_memory = [55u8; 100];
        image
            .read_exact_at_volatile(VolatileSlice::new(&mut input_memory[..]), 0)
            .expect("Could not read");
        let expected = [0u8; 100];
        assert_eq!(&expected[..], &input_memory[..]);
    }

    #[test]
    fn read_fill_simple() {
        let chunks = vec![ChunkWithSize {
            chunk: Chunk::Fill(vec![10, 20]),
            expanded_size: 8,
        }];
        let mut image = test_image(chunks);
        let mut input_memory = [55u8; 8];
        image
            .read_exact_at_volatile(VolatileSlice::new(&mut input_memory[..]), 0)
            .expect("Could not read");
        let expected = [10, 20, 10, 20, 10, 20, 10, 20];
        assert_eq!(&expected[..], &input_memory[..]);
    }

    #[test]
    fn read_fill_edges() {
        let chunks = vec![ChunkWithSize {
            chunk: Chunk::Fill(vec![10, 20, 30]),
            expanded_size: 8,
        }];
        let mut image = test_image(chunks);
        let mut input_memory = [55u8; 6];
        image
            .read_exact_at_volatile(VolatileSlice::new(&mut input_memory[..]), 1)
            .expect("Could not read");
        let expected = [20, 30, 10, 20, 30, 10];
        assert_eq!(&expected[..], &input_memory[..]);
    }

    #[test]
    fn read_fill_offset_edges() {
        let chunks = vec![
            ChunkWithSize {
                chunk: Chunk::DontCare,
                expanded_size: 20,
            },
            ChunkWithSize {
                chunk: Chunk::Fill(vec![10, 20, 30]),
                expanded_size: 100,
            },
        ];
        let mut image = test_image(chunks);
        let mut input_memory = [55u8; 7];
        image
            .read_exact_at_volatile(VolatileSlice::new(&mut input_memory[..]), 39)
            .expect("Could not read");
        let expected = [20, 30, 10, 20, 30, 10, 20];
        assert_eq!(&expected[..], &input_memory[..]);
    }

    #[test]
    fn read_raw() {
        let chunks = vec![ChunkWithSize {
            chunk: Chunk::Raw(0),
            expanded_size: 100,
        }];
        let mut image = test_image(chunks);
        write!(image.file, "hello").expect("Failed to write into internal file");
        let mut input_memory = [55u8; 5];
        image
            .read_exact_at_volatile(VolatileSlice::new(&mut input_memory[..]), 0)
            .expect("Could not read");
        let expected = [104, 101, 108, 108, 111];
        assert_eq!(&expected[..], &input_memory[..]);
    }

    #[test]
    fn read_two_fills() {
        let chunks = vec![
            ChunkWithSize {
                chunk: Chunk::Fill(vec![10, 20]),
                expanded_size: 4,
            },
            ChunkWithSize {
                chunk: Chunk::Fill(vec![30, 40]),
                expanded_size: 4,
            },
        ];
        let mut image = test_image(chunks);
        let mut input_memory = [55u8; 8];
        image
            .read_exact_at_volatile(VolatileSlice::new(&mut input_memory[..]), 0)
            .expect("Could not read");
        let expected = [10, 20, 10, 20, 30, 40, 30, 40];
        assert_eq!(&expected[..], &input_memory[..]);
    }
}
