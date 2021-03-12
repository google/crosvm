// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::{max, min};
use std::fmt::{self, Display};
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};
use std::ops::Range;

use crate::{create_disk_file, DiskFile, DiskGetLen, ImageType};
use base::{
    AsRawDescriptors, FileAllocate, FileReadWriteAtVolatile, FileSetLen, FileSync, PunchHole,
    RawDescriptor, WriteZeroesAt,
};
use data_model::VolatileSlice;
use protos::cdisk_spec;
use remain::sorted;

#[sorted]
#[derive(Debug)]
pub enum Error {
    DiskError(Box<crate::Error>),
    InvalidMagicHeader,
    InvalidProto(protobuf::ProtobufError),
    InvalidSpecification(String),
    OpenFile(io::Error, String),
    ReadSpecificationError(io::Error),
    UnknownVersion(u64),
    UnsupportedComponent(ImageType),
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            DiskError(e) => write!(f, "failed to use underlying disk: \"{}\"", e),
            InvalidMagicHeader => write!(f, "invalid magic header for composite disk format"),
            InvalidProto(e) => write!(f, "failed to parse specification proto: \"{}\"", e),
            InvalidSpecification(s) => write!(f, "invalid specification: \"{}\"", s),
            OpenFile(e, p) => write!(f, "failed to open component file \"{}\": \"{}\"", p, e),
            ReadSpecificationError(e) => write!(f, "failed to read specification: \"{}\"", e),
            UnknownVersion(v) => write!(f, "unknown version {} in specification", v),
            UnsupportedComponent(c) => write!(f, "unsupported component disk type \"{:?}\"", c),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
struct ComponentDiskPart {
    file: Box<dyn DiskFile>,
    offset: u64,
    length: u64,
}

impl ComponentDiskPart {
    fn range(&self) -> Range<u64> {
        self.offset..(self.offset + self.length)
    }
}

/// Represents a composite virtual disk made out of multiple component files. This is described on
/// disk by a protocol buffer file that lists out the component file locations and their offsets
/// and lengths on the virtual disk. The spaces covered by the component disks must be contiguous
/// and not overlapping.
#[derive(Debug)]
pub struct CompositeDiskFile {
    component_disks: Vec<ComponentDiskPart>,
}

fn ranges_overlap(a: &Range<u64>, b: &Range<u64>) -> bool {
    // essentially !range_intersection(a, b).is_empty(), but that's experimental
    let intersection = range_intersection(a, b);
    intersection.start < intersection.end
}

fn range_intersection(a: &Range<u64>, b: &Range<u64>) -> Range<u64> {
    Range {
        start: max(a.start, b.start),
        end: min(a.end, b.end),
    }
}

/// A magic string placed at the beginning of a composite disk file to identify it.
pub static CDISK_MAGIC: &str = "composite_disk\x1d";
/// The length of the CDISK_MAGIC string. Created explicitly as a static constant so that it is
/// possible to create a character array of the same length.
pub const CDISK_MAGIC_LEN: usize = 15;

impl CompositeDiskFile {
    fn new(mut disks: Vec<ComponentDiskPart>) -> Result<CompositeDiskFile> {
        disks.sort_by(|d1, d2| d1.offset.cmp(&d2.offset));
        let contiguous_err = disks
            .windows(2)
            .map(|s| {
                if s[0].offset == s[1].offset {
                    let text = format!("Two disks at offset {}", s[0].offset);
                    Err(Error::InvalidSpecification(text))
                } else {
                    Ok(())
                }
            })
            .find(|r| r.is_err());
        if let Some(Err(e)) = contiguous_err {
            return Err(e);
        }
        Ok(CompositeDiskFile {
            component_disks: disks,
        })
    }

    /// Set up a composite disk by reading the specification from a file. The file must consist of
    /// the CDISK_MAGIC string followed by one binary instance of the CompositeDisk protocol
    /// buffer. Returns an error if it could not read the file or if the specification was invalid.
    pub fn from_file(mut file: File) -> Result<CompositeDiskFile> {
        file.seek(SeekFrom::Start(0))
            .map_err(Error::ReadSpecificationError)?;
        let mut magic_space = [0u8; CDISK_MAGIC_LEN];
        file.read_exact(&mut magic_space[..])
            .map_err(Error::ReadSpecificationError)?;
        if magic_space != CDISK_MAGIC.as_bytes() {
            return Err(Error::InvalidMagicHeader);
        }
        let proto: cdisk_spec::CompositeDisk =
            protobuf::parse_from_reader(&mut file).map_err(Error::InvalidProto)?;
        if proto.get_version() != 1 {
            return Err(Error::UnknownVersion(proto.get_version()));
        }
        let mut open_options = OpenOptions::new();
        open_options.read(true);
        let mut disks: Vec<ComponentDiskPart> = proto
            .get_component_disks()
            .iter()
            .map(|disk| {
                open_options.write(
                    disk.get_read_write_capability() == cdisk_spec::ReadWriteCapability::READ_WRITE,
                );
                let file = open_options
                    .open(disk.get_file_path())
                    .map_err(|e| Error::OpenFile(e, disk.get_file_path().to_string()))?;
                Ok(ComponentDiskPart {
                    file: create_disk_file(file).map_err(|e| Error::DiskError(Box::new(e)))?,
                    offset: disk.get_offset(),
                    length: 0, // Assigned later
                })
            })
            .collect::<Result<Vec<ComponentDiskPart>>>()?;
        disks.sort_by(|d1, d2| d1.offset.cmp(&d2.offset));
        for i in 0..(disks.len() - 1) {
            let length = disks[i + 1].offset - disks[i].offset;
            if length == 0 {
                let text = format!("Two disks at offset {}", disks[i].offset);
                return Err(Error::InvalidSpecification(text));
            }
            if let Some(disk) = disks.get_mut(i) {
                disk.length = length;
            } else {
                let text = format!("Unable to set disk length {}", length);
                return Err(Error::InvalidSpecification(text));
            }
        }
        let num_disks = disks.len();
        if let Some(last_disk) = disks.get_mut(num_disks - 1) {
            if proto.get_length() <= last_disk.offset {
                let text = format!(
                    "Full size of disk doesn't match last offset. {} <= {}",
                    proto.get_length(),
                    last_disk.offset
                );
                return Err(Error::InvalidSpecification(text));
            }
            last_disk.length = proto.get_length() - last_disk.offset;
        } else {
            let text = format!(
                "Unable to set last disk length to end at {}",
                proto.get_length()
            );
            return Err(Error::InvalidSpecification(text));
        }

        CompositeDiskFile::new(disks)
    }

    fn length(&self) -> u64 {
        if let Some(disk) = self.component_disks.last() {
            disk.offset + disk.length
        } else {
            0
        }
    }

    fn disk_at_offset(&mut self, offset: u64) -> io::Result<&mut ComponentDiskPart> {
        self.component_disks
            .iter_mut()
            .find(|disk| disk.range().contains(&offset))
            .ok_or(io::Error::new(
                ErrorKind::InvalidData,
                format!("no disk at offset {}", offset),
            ))
    }

    fn disks_in_range<'a>(&'a mut self, range: &Range<u64>) -> Vec<&'a mut ComponentDiskPart> {
        self.component_disks
            .iter_mut()
            .filter(|disk| ranges_overlap(&disk.range(), range))
            .collect()
    }
}

impl DiskGetLen for CompositeDiskFile {
    fn get_len(&self) -> io::Result<u64> {
        Ok(self.length())
    }
}

impl FileSetLen for CompositeDiskFile {
    fn set_len(&self, _len: u64) -> io::Result<()> {
        Err(io::Error::new(ErrorKind::Other, "unsupported operation"))
    }
}

impl FileSync for CompositeDiskFile {
    fn fsync(&mut self) -> io::Result<()> {
        for disk in self.component_disks.iter_mut() {
            disk.file.fsync()?;
        }
        Ok(())
    }
}

// Implements Read and Write targeting volatile storage for composite disks.
//
// Note that reads and writes will return early if crossing component disk boundaries.
// This is allowed by the read and write specifications, which only say read and write
// have to return how many bytes were actually read or written. Use read_exact_volatile
// or write_all_volatile to make sure all bytes are received/transmitted.
//
// If one of the component disks does a partial read or write, that also gets passed
// transparently to the parent.
impl FileReadWriteAtVolatile for CompositeDiskFile {
    fn read_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> io::Result<usize> {
        let cursor_location = offset;
        let disk = self.disk_at_offset(cursor_location)?;
        let subslice = if cursor_location + slice.size() as u64 > disk.offset + disk.length {
            let new_size = disk.offset + disk.length - cursor_location;
            slice
                .sub_slice(0, new_size as usize)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("{:?}", e)))?
        } else {
            slice
        };
        disk.file
            .read_at_volatile(subslice, cursor_location - disk.offset)
    }
    fn write_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> io::Result<usize> {
        let cursor_location = offset;
        let disk = self.disk_at_offset(cursor_location)?;
        let subslice = if cursor_location + slice.size() as u64 > disk.offset + disk.length {
            let new_size = disk.offset + disk.length - cursor_location;
            slice
                .sub_slice(0, new_size as usize)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("{:?}", e)))?
        } else {
            slice
        };
        disk.file
            .write_at_volatile(subslice, cursor_location - disk.offset)
    }
}

impl PunchHole for CompositeDiskFile {
    fn punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()> {
        let range = offset..(offset + length);
        let disks = self.disks_in_range(&range);
        for disk in disks {
            let intersection = range_intersection(&range, &disk.range());
            if intersection.start >= intersection.end {
                continue;
            }
            let result = disk.file.punch_hole(
                intersection.start - disk.offset,
                intersection.end - intersection.start,
            );
            if result.is_err() {
                return result;
            }
        }
        Ok(())
    }
}

impl FileAllocate for CompositeDiskFile {
    fn allocate(&mut self, offset: u64, length: u64) -> io::Result<()> {
        let range = offset..(offset + length);
        let disks = self.disks_in_range(&range);
        for disk in disks {
            let intersection = range_intersection(&range, &disk.range());
            if intersection.start >= intersection.end {
                continue;
            }
            let result = disk.file.allocate(
                intersection.start - disk.offset,
                intersection.end - intersection.start,
            );
            if result.is_err() {
                return result;
            }
        }
        Ok(())
    }
}

impl WriteZeroesAt for CompositeDiskFile {
    fn write_zeroes_at(&mut self, offset: u64, length: usize) -> io::Result<usize> {
        let cursor_location = offset;
        let disk = self.disk_at_offset(cursor_location)?;
        let offset_within_disk = cursor_location - disk.offset;
        let new_length = if cursor_location + length as u64 > disk.offset + disk.length {
            (disk.offset + disk.length - cursor_location) as usize
        } else {
            length
        };
        disk.file.write_zeroes_at(offset_within_disk, new_length)
    }
}

impl AsRawDescriptors for CompositeDiskFile {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        self.component_disks
            .iter()
            .map(|d| d.file.as_raw_descriptors())
            .flatten()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::AsRawDescriptor;
    use data_model::VolatileMemory;
    use tempfile::tempfile;

    #[test]
    fn block_duplicate_offset_disks() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 0,
            length: 100,
        };
        assert!(CompositeDiskFile::new(vec![disk_part1, disk_part2]).is_err());
    }

    #[test]
    fn get_len() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
        };
        let composite = CompositeDiskFile::new(vec![disk_part1, disk_part2]).unwrap();
        let len = composite.get_len().unwrap();
        assert_eq!(len, 200);
    }

    #[test]
    fn single_file_passthrough() {
        let file = tempfile().unwrap();
        let disk_part = ComponentDiskPart {
            file: Box::new(file),
            offset: 0,
            length: 100,
        };
        let mut composite = CompositeDiskFile::new(vec![disk_part]).unwrap();
        let mut input_memory = [55u8; 5];
        let input_volatile_memory = VolatileSlice::new(&mut input_memory[..]);
        composite
            .write_all_at_volatile(input_volatile_memory.get_slice(0, 5).unwrap(), 0)
            .unwrap();
        let mut output_memory = [0u8; 5];
        let output_volatile_memory = VolatileSlice::new(&mut output_memory[..]);
        composite
            .read_exact_at_volatile(output_volatile_memory.get_slice(0, 5).unwrap(), 0)
            .unwrap();
        assert_eq!(input_memory, output_memory);
    }

    #[test]
    fn triple_file_fds() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let file3 = tempfile().unwrap();
        let mut in_fds = vec![
            file1.as_raw_descriptor(),
            file2.as_raw_descriptor(),
            file3.as_raw_descriptor(),
        ];
        in_fds.sort();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
        };
        let disk_part3 = ComponentDiskPart {
            file: Box::new(file3),
            offset: 200,
            length: 100,
        };
        let composite = CompositeDiskFile::new(vec![disk_part1, disk_part2, disk_part3]).unwrap();
        let mut out_fds = composite.as_raw_descriptors();
        out_fds.sort();
        assert_eq!(in_fds, out_fds);
    }

    #[test]
    fn triple_file_passthrough() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let file3 = tempfile().unwrap();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
        };
        let disk_part3 = ComponentDiskPart {
            file: Box::new(file3),
            offset: 200,
            length: 100,
        };
        let mut composite =
            CompositeDiskFile::new(vec![disk_part1, disk_part2, disk_part3]).unwrap();
        let mut input_memory = [55u8; 200];
        let input_volatile_memory = VolatileSlice::new(&mut input_memory[..]);
        composite
            .write_all_at_volatile(input_volatile_memory.get_slice(0, 200).unwrap(), 50)
            .unwrap();
        let mut output_memory = [0u8; 200];
        let output_volatile_memory = VolatileSlice::new(&mut output_memory[..]);
        composite
            .read_exact_at_volatile(output_volatile_memory.get_slice(0, 200).unwrap(), 50)
            .unwrap();
        assert!(input_memory.iter().eq(output_memory.iter()));
    }

    #[test]
    fn triple_file_punch_hole() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let file3 = tempfile().unwrap();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
        };
        let disk_part3 = ComponentDiskPart {
            file: Box::new(file3),
            offset: 200,
            length: 100,
        };
        let mut composite =
            CompositeDiskFile::new(vec![disk_part1, disk_part2, disk_part3]).unwrap();
        let mut input_memory = [55u8; 300];
        let input_volatile_memory = VolatileSlice::new(&mut input_memory[..]);
        composite
            .write_all_at_volatile(input_volatile_memory.get_slice(0, 300).unwrap(), 0)
            .unwrap();
        composite.punch_hole(50, 200).unwrap();
        let mut output_memory = [0u8; 300];
        let output_volatile_memory = VolatileSlice::new(&mut output_memory[..]);
        composite
            .read_exact_at_volatile(output_volatile_memory.get_slice(0, 300).unwrap(), 0)
            .unwrap();

        for i in 50..250 {
            input_memory[i] = 0;
        }
        assert!(input_memory.iter().eq(output_memory.iter()));
    }

    #[test]
    fn triple_file_write_zeroes() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let file3 = tempfile().unwrap();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
        };
        let disk_part3 = ComponentDiskPart {
            file: Box::new(file3),
            offset: 200,
            length: 100,
        };
        let mut composite =
            CompositeDiskFile::new(vec![disk_part1, disk_part2, disk_part3]).unwrap();
        let mut input_memory = [55u8; 300];
        let input_volatile_memory = VolatileSlice::new(&mut input_memory[..]);
        composite
            .write_all_at_volatile(input_volatile_memory.get_slice(0, 300).unwrap(), 0)
            .unwrap();
        let mut zeroes_written = 0;
        while zeroes_written < 200 {
            zeroes_written += composite
                .write_zeroes_at(50 + zeroes_written as u64, 200 - zeroes_written)
                .unwrap();
        }
        let mut output_memory = [0u8; 300];
        let output_volatile_memory = VolatileSlice::new(&mut output_memory[..]);
        composite
            .read_exact_at_volatile(output_volatile_memory.get_slice(0, 300).unwrap(), 0)
            .unwrap();

        for i in 50..250 {
            input_memory[i] = 0;
        }
        for i in 0..300 {
            println!(
                "input[{0}] = {1}, output[{0}] = {2}",
                i, input_memory[i], output_memory[i]
            );
        }
        assert!(input_memory.iter().eq(output_memory.iter()));
    }
}
