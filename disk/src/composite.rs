// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::{max, min};
use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};
use std::ops::Range;
use std::os::unix::io::RawFd;

use crate::{create_disk_file, DiskFile, ImageType};
use data_model::VolatileSlice;
use protos::cdisk_spec;
use remain::sorted;
use sys_util::{AsRawFds, FileReadWriteAtVolatile, FileSetLen, FileSync, PunchHole, WriteZeroes};

#[sorted]
#[derive(Debug)]
pub enum Error {
    DiskError(Box<crate::Error>),
    InvalidMagicHeader,
    InvalidProto(protobuf::ProtobufError),
    InvalidSpecification(String),
    OpenFile(io::Error),
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
            OpenFile(e) => write!(f, "failed to open component file: \"{}\"", e),
            ReadSpecificationError(e) => write!(f, "failed to read specification: \"{}\"", e),
            UnknownVersion(v) => write!(f, "unknown version {} in specification", v),
            UnsupportedComponent(c) => write!(f, "unsupported component disk type \"{:?}\"", c),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

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
pub struct CompositeDiskFile {
    component_disks: Vec<ComponentDiskPart>,
    cursor_location: u64,
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
            cursor_location: 0,
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
                    .map_err(Error::OpenFile)?;
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

    fn disk_at_offset<'a>(&'a mut self, offset: u64) -> io::Result<&'a mut ComponentDiskPart> {
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
        let subslice = if cursor_location + slice.size() > disk.offset + disk.length {
            let new_size = disk.offset + disk.length - cursor_location;
            slice
                .sub_slice(0, new_size)
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
        let subslice = if cursor_location + slice.size() > disk.offset + disk.length {
            let new_size = disk.offset + disk.length - cursor_location;
            slice
                .sub_slice(0, new_size)
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

impl Seek for CompositeDiskFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let cursor_location = match pos {
            SeekFrom::Start(offset) => Ok(offset),
            SeekFrom::End(offset) => u64::try_from(self.length() as i64 + offset),
            SeekFrom::Current(offset) => u64::try_from(self.cursor_location as i64 + offset),
        }
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        self.cursor_location = cursor_location;
        Ok(cursor_location)
    }
}

impl WriteZeroes for CompositeDiskFile {
    fn write_zeroes(&mut self, length: usize) -> io::Result<usize> {
        let cursor_location = self.cursor_location;
        let disk = self.disk_at_offset(cursor_location)?;
        disk.file
            .seek(SeekFrom::Start(cursor_location - disk.offset))?;
        let new_length = if cursor_location + length as u64 > disk.offset + disk.length {
            (disk.offset + disk.length - cursor_location) as usize
        } else {
            length
        };
        let result = disk.file.write_zeroes(new_length);
        if let Ok(size) = result {
            self.cursor_location += size as u64;
        }
        result
    }
}

impl AsRawFds for CompositeDiskFile {
    fn as_raw_fds(&self) -> Vec<RawFd> {
        self.component_disks
            .iter()
            .map(|d| d.file.as_raw_fds())
            .flatten()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_model::VolatileMemory;
    use std::os::unix::io::AsRawFd;
    use sys_util::SharedMemory;

    #[test]
    fn block_duplicate_offset_disks() {
        let file1: File = SharedMemory::new(None).unwrap().into();
        let file2: File = SharedMemory::new(None).unwrap().into();
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
    fn seek_to_end() {
        let file1: File = SharedMemory::new(None).unwrap().into();
        let file2: File = SharedMemory::new(None).unwrap().into();
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
        let mut composite = CompositeDiskFile::new(vec![disk_part1, disk_part2]).unwrap();
        let location = composite.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(location, 200);
    }

    #[test]
    fn single_file_passthrough() {
        let file: File = SharedMemory::new(None).unwrap().into();
        let disk_part = ComponentDiskPart {
            file: Box::new(file),
            offset: 0,
            length: 100,
        };
        let mut composite = CompositeDiskFile::new(vec![disk_part]).unwrap();
        let mut input_memory = [55u8; 5];
        let input_volatile_memory = &mut input_memory[..];
        composite
            .write_all_at_volatile(input_volatile_memory.get_slice(0, 5).unwrap(), 0)
            .unwrap();
        let mut output_memory = [0u8; 5];
        let output_volatile_memory = &mut output_memory[..];
        composite
            .read_exact_at_volatile(output_volatile_memory.get_slice(0, 5).unwrap(), 0)
            .unwrap();
        assert_eq!(input_memory, output_memory);
    }

    #[test]
    fn triple_file_fds() {
        let file1: File = SharedMemory::new(None).unwrap().into();
        let file2: File = SharedMemory::new(None).unwrap().into();
        let file3: File = SharedMemory::new(None).unwrap().into();
        let mut in_fds = vec![file1.as_raw_fd(), file2.as_raw_fd(), file3.as_raw_fd()];
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
        let mut out_fds = composite.as_raw_fds();
        out_fds.sort();
        assert_eq!(in_fds, out_fds);
    }

    #[test]
    fn triple_file_passthrough() {
        let file1: File = SharedMemory::new(None).unwrap().into();
        let file2: File = SharedMemory::new(None).unwrap().into();
        let file3: File = SharedMemory::new(None).unwrap().into();
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
        let input_volatile_memory = &mut input_memory[..];
        composite
            .write_all_at_volatile(input_volatile_memory.get_slice(0, 200).unwrap(), 50)
            .unwrap();
        let mut output_memory = [0u8; 200];
        let output_volatile_memory = &mut output_memory[..];
        composite
            .read_exact_at_volatile(output_volatile_memory.get_slice(0, 200).unwrap(), 50)
            .unwrap();
        assert!(input_memory.into_iter().eq(output_memory.into_iter()));
    }

    #[test]
    fn triple_file_punch_hole() {
        let file1: File = SharedMemory::new(None).unwrap().into();
        let file2: File = SharedMemory::new(None).unwrap().into();
        let file3: File = SharedMemory::new(None).unwrap().into();
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
        let input_volatile_memory = &mut input_memory[..];
        composite
            .write_all_at_volatile(input_volatile_memory.get_slice(0, 300).unwrap(), 0)
            .unwrap();
        composite.punch_hole(50, 200).unwrap();
        let mut output_memory = [0u8; 300];
        let output_volatile_memory = &mut output_memory[..];
        composite
            .read_exact_at_volatile(output_volatile_memory.get_slice(0, 300).unwrap(), 0)
            .unwrap();

        for i in 50..250 {
            input_memory[i] = 0;
        }
        assert!(input_memory.into_iter().eq(output_memory.into_iter()));
    }

    #[test]
    fn triple_file_write_zeroes() {
        let file1: File = SharedMemory::new(None).unwrap().into();
        let file2: File = SharedMemory::new(None).unwrap().into();
        let file3: File = SharedMemory::new(None).unwrap().into();
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
        let input_volatile_memory = &mut input_memory[..];
        composite
            .write_all_at_volatile(input_volatile_memory.get_slice(0, 300).unwrap(), 0)
            .unwrap();
        composite.seek(SeekFrom::Start(50)).unwrap();
        let mut zeroes_written = 0;
        while zeroes_written < 200 {
            zeroes_written += composite.write_zeroes(200 - zeroes_written).unwrap();
        }
        let mut output_memory = [0u8; 300];
        let output_volatile_memory = &mut output_memory[..];
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
        assert!(input_memory.into_iter().eq(output_memory.into_iter()));
    }
}
