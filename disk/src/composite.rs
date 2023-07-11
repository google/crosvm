// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::max;
use std::cmp::min;
use std::collections::HashSet;
use std::convert::TryInto;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use async_trait::async_trait;
use base::open_file;
use base::AsRawDescriptors;
use base::FileAllocate;
use base::FileReadWriteAtVolatile;
use base::FileSetLen;
use base::RawDescriptor;
use crc32fast::Hasher;
use cros_async::BackingMemory;
use cros_async::Executor;
use cros_async::MemRegionIter;
use data_model::VolatileSlice;
use protobuf::Message;
use protos::cdisk_spec;
use protos::cdisk_spec::ComponentDisk;
use protos::cdisk_spec::CompositeDisk;
use protos::cdisk_spec::ReadWriteCapability;
use remain::sorted;
use thiserror::Error;
use uuid::Uuid;

use crate::create_disk_file;
use crate::gpt;
use crate::gpt::write_gpt_header;
use crate::gpt::write_protective_mbr;
use crate::gpt::GptPartitionEntry;
use crate::gpt::GPT_BEGINNING_SIZE;
use crate::gpt::GPT_END_SIZE;
use crate::gpt::GPT_HEADER_SIZE;
use crate::gpt::GPT_NUM_PARTITIONS;
use crate::gpt::GPT_PARTITION_ENTRY_SIZE;
use crate::gpt::SECTOR_SIZE;
use crate::AsyncDisk;
use crate::DiskFile;
use crate::DiskGetLen;
use crate::ImageType;
use crate::ToAsyncDisk;

/// The amount of padding needed between the last partition entry and the first partition, to align
/// the partition appropriately. The two sectors are for the MBR and the GPT header.
const PARTITION_ALIGNMENT_SIZE: usize = GPT_BEGINNING_SIZE as usize
    - 2 * SECTOR_SIZE as usize
    - GPT_NUM_PARTITIONS as usize * GPT_PARTITION_ENTRY_SIZE as usize;
const HEADER_PADDING_LENGTH: usize = SECTOR_SIZE as usize - GPT_HEADER_SIZE as usize;
// Keep all partitions 4k aligned for performance.
const PARTITION_SIZE_SHIFT: u8 = 12;
// Keep the disk size a multiple of 64k for crosvm's virtio_blk driver.
const DISK_SIZE_SHIFT: u8 = 16;

// From https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs.
const LINUX_FILESYSTEM_GUID: Uuid = Uuid::from_u128(0x0FC63DAF_8483_4772_8E79_3D69D8477DE4);
const EFI_SYSTEM_PARTITION_GUID: Uuid = Uuid::from_u128(0xC12A7328_F81F_11D2_BA4B_00A0C93EC93B);

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to use underlying disk: \"{0}\"")]
    DiskError(Box<crate::Error>),
    #[error("duplicate GPT partition label \"{0}\"")]
    DuplicatePartitionLabel(String),
    #[error("failed to write GPT header: \"{0}\"")]
    GptError(gpt::Error),
    #[error("invalid magic header for composite disk format")]
    InvalidMagicHeader,
    #[error("invalid partition path {0:?}")]
    InvalidPath(PathBuf),
    #[error("failed to parse specification proto: \"{0}\"")]
    InvalidProto(protobuf::Error),
    #[error("invalid specification: \"{0}\"")]
    InvalidSpecification(String),
    #[error("no image files for partition {0:?}")]
    NoImageFiles(PartitionInfo),
    #[error("failed to open component file \"{1}\": \"{0}\"")]
    OpenFile(io::Error, String),
    #[error("failed to read specification: \"{0}\"")]
    ReadSpecificationError(io::Error),
    #[error("Read-write partition {0:?} size is not a multiple of {}.", 1 << PARTITION_SIZE_SHIFT)]
    UnalignedReadWrite(PartitionInfo),
    #[error("unknown version {0} in specification")]
    UnknownVersion(u64),
    #[error("unsupported component disk type \"{0:?}\"")]
    UnsupportedComponent(ImageType),
    #[error("failed to write composite disk header: \"{0}\"")]
    WriteHeader(io::Error),
    #[error("failed to write specification proto: \"{0}\"")]
    WriteProto(protobuf::Error),
    #[error("failed to write zero filler: \"{0}\"")]
    WriteZeroFiller(io::Error),
}

impl From<gpt::Error> for Error {
    fn from(e: gpt::Error) -> Self {
        Self::GptError(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
struct ComponentDiskPart {
    file: Box<dyn DiskFile>,
    offset: u64,
    length: u64,
    needs_fsync: bool,
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

// TODO(b/271381851): implement `try_clone`. It allows virtio-blk to run multiple workers.
impl DiskFile for CompositeDiskFile {}

fn ranges_overlap(a: &Range<u64>, b: &Range<u64>) -> bool {
    range_intersection(a, b).is_some()
}

fn range_intersection(a: &Range<u64>, b: &Range<u64>) -> Option<Range<u64>> {
    let r = Range {
        start: max(a.start, b.start),
        end: min(a.end, b.end),
    };
    if r.is_empty() {
        None
    } else {
        Some(r)
    }
}

/// The version of the composite disk format supported by this implementation.
const COMPOSITE_DISK_VERSION: u64 = 2;

/// A magic string placed at the beginning of a composite disk file to identify it.
pub const CDISK_MAGIC: &str = "composite_disk\x1d";

impl CompositeDiskFile {
    fn new(mut disks: Vec<ComponentDiskPart>) -> Result<CompositeDiskFile> {
        disks.sort_by(|d1, d2| d1.offset.cmp(&d2.offset));
        for s in disks.windows(2) {
            if s[0].offset == s[1].offset {
                return Err(Error::InvalidSpecification(format!(
                    "Two disks at offset {}",
                    s[0].offset
                )));
            }
        }
        Ok(CompositeDiskFile {
            component_disks: disks,
        })
    }

    /// Set up a composite disk by reading the specification from a file. The file must consist of
    /// the CDISK_MAGIC string followed by one binary instance of the CompositeDisk protocol
    /// buffer. Returns an error if it could not read the file or if the specification was invalid.
    pub fn from_file(
        mut file: File,
        is_sparse_file: bool,
        max_nesting_depth: u32,
        image_path: &Path,
    ) -> Result<CompositeDiskFile> {
        file.seek(SeekFrom::Start(0))
            .map_err(Error::ReadSpecificationError)?;
        let mut magic_space = [0u8; CDISK_MAGIC.len()];
        file.read_exact(&mut magic_space[..])
            .map_err(Error::ReadSpecificationError)?;
        if magic_space != CDISK_MAGIC.as_bytes() {
            return Err(Error::InvalidMagicHeader);
        }
        let proto: cdisk_spec::CompositeDisk =
            Message::parse_from_reader(&mut file).map_err(Error::InvalidProto)?;
        if proto.version > COMPOSITE_DISK_VERSION {
            return Err(Error::UnknownVersion(proto.version));
        }
        let mut disks: Vec<ComponentDiskPart> = proto
            .component_disks
            .iter()
            .map(|disk| {
                let writable = disk.read_write_capability
                    == cdisk_spec::ReadWriteCapability::READ_WRITE.into();
                let component_path = PathBuf::from(&disk.file_path);
                let path = if component_path.is_relative() || proto.version > 1 {
                    image_path.parent().unwrap().join(component_path)
                } else {
                    component_path
                };
                let comp_file = open_file(
                    &path,
                    OpenOptions::new().read(true).write(writable), // TODO(b/190435784): add support for O_DIRECT.
                )
                .map_err(|e| Error::OpenFile(e.into(), disk.file_path.to_string()))?;

                // Note that a read-only parts of a composite disk should NOT be marked sparse,
                // as the action of marking them sparse is a write. This may seem a little hacky,
                // and it is; however:
                //    (a)  there is not a good way to pass sparseness parameters per composite disk
                //         part (the proto does not have fields for it).
                //    (b)  this override of sorts always matches the correct user intent.
                Ok(ComponentDiskPart {
                    file: create_disk_file(
                        comp_file,
                        is_sparse_file && writable,
                        max_nesting_depth,
                        &path,
                    )
                    .map_err(|e| Error::DiskError(Box::new(e)))?,
                    offset: disk.offset,
                    length: 0, // Assigned later
                    needs_fsync: false,
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
        if let Some(last_disk) = disks.last_mut() {
            if proto.length <= last_disk.offset {
                let text = format!(
                    "Full size of disk doesn't match last offset. {} <= {}",
                    proto.length, last_disk.offset
                );
                return Err(Error::InvalidSpecification(text));
            }
            last_disk.length = proto.length - last_disk.offset;
        } else {
            let text = format!("Unable to set last disk length to end at {}", proto.length);
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
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?
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
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?
        } else {
            slice
        };

        let bytes = disk
            .file
            .write_at_volatile(subslice, cursor_location - disk.offset)?;
        disk.needs_fsync = true;
        Ok(bytes)
    }
}

impl AsRawDescriptors for CompositeDiskFile {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        self.component_disks
            .iter()
            .flat_map(|d| d.file.as_raw_descriptors())
            .collect()
    }
}

struct AsyncComponentDiskPart {
    file: Box<dyn AsyncDisk>,
    offset: u64,
    length: u64,
    needs_fsync: AtomicBool,
}

pub struct AsyncCompositeDiskFile {
    component_disks: Vec<AsyncComponentDiskPart>,
}

impl DiskGetLen for AsyncCompositeDiskFile {
    fn get_len(&self) -> io::Result<u64> {
        Ok(self.length())
    }
}

impl FileSetLen for AsyncCompositeDiskFile {
    fn set_len(&self, _len: u64) -> io::Result<()> {
        Err(io::Error::new(ErrorKind::Other, "unsupported operation"))
    }
}

impl FileAllocate for AsyncCompositeDiskFile {
    fn allocate(&mut self, offset: u64, length: u64) -> io::Result<()> {
        let range = offset..(offset + length);
        let disks = self
            .component_disks
            .iter_mut()
            .filter(|disk| ranges_overlap(&disk.range(), &range));
        for disk in disks {
            if let Some(intersection) = range_intersection(&range, &disk.range()) {
                disk.file.allocate(
                    intersection.start - disk.offset,
                    intersection.end - intersection.start,
                )?;
                disk.needs_fsync.store(true, Ordering::SeqCst);
            }
        }
        Ok(())
    }
}

impl ToAsyncDisk for CompositeDiskFile {
    fn to_async_disk(self: Box<Self>, ex: &Executor) -> crate::Result<Box<dyn AsyncDisk>> {
        Ok(Box::new(AsyncCompositeDiskFile {
            component_disks: self
                .component_disks
                .into_iter()
                .map(|disk| -> crate::Result<_> {
                    Ok(AsyncComponentDiskPart {
                        file: disk.file.to_async_disk(ex)?,
                        offset: disk.offset,
                        length: disk.length,
                        needs_fsync: AtomicBool::new(disk.needs_fsync),
                    })
                })
                .collect::<crate::Result<Vec<_>>>()?,
        }))
    }
}

impl AsyncComponentDiskPart {
    fn range(&self) -> Range<u64> {
        self.offset..(self.offset + self.length)
    }

    fn set_needs_fsync(&self) {
        self.needs_fsync.store(true, Ordering::SeqCst);
    }
}

impl AsyncCompositeDiskFile {
    fn length(&self) -> u64 {
        if let Some(disk) = self.component_disks.last() {
            disk.offset + disk.length
        } else {
            0
        }
    }

    fn disk_at_offset(&self, offset: u64) -> io::Result<&AsyncComponentDiskPart> {
        self.component_disks
            .iter()
            .find(|disk| disk.range().contains(&offset))
            .ok_or(io::Error::new(
                ErrorKind::InvalidData,
                format!("no disk at offset {}", offset),
            ))
    }

    fn disks_in_range<'a>(&'a self, range: &Range<u64>) -> Vec<&'a AsyncComponentDiskPart> {
        self.component_disks
            .iter()
            .filter(|disk| ranges_overlap(&disk.range(), range))
            .collect()
    }
}

#[async_trait(?Send)]
impl AsyncDisk for AsyncCompositeDiskFile {
    fn into_inner(self: Box<Self>) -> Box<dyn DiskFile> {
        Box::new(CompositeDiskFile {
            component_disks: self
                .component_disks
                .into_iter()
                .map(|disk| ComponentDiskPart {
                    file: disk.file.into_inner(),
                    offset: disk.offset,
                    length: disk.length,
                    needs_fsync: disk.needs_fsync.into_inner(),
                })
                .collect(),
        })
    }

    async fn flush(&self) -> crate::Result<()> {
        futures::future::try_join_all(self.component_disks.iter().map(|c| c.file.flush())).await?;
        Ok(())
    }

    async fn fsync(&self) -> crate::Result<()> {
        // TODO: handle the disks concurrently
        for disk in self.component_disks.iter() {
            if disk.needs_fsync.fetch_and(false, Ordering::SeqCst) {
                if let Err(e) = disk.file.fsync().await {
                    disk.set_needs_fsync();
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    async fn fdatasync(&self) -> crate::Result<()> {
        // AsyncCompositeDiskFile does not implement fdatasync for now. Fallback to fsync.
        self.fsync().await
    }

    async fn read_to_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: MemRegionIter<'a>,
    ) -> crate::Result<usize> {
        let disk = self
            .disk_at_offset(file_offset)
            .map_err(crate::Error::ReadingData)?;
        let remaining_disk = disk.offset + disk.length - file_offset;
        disk.file
            .read_to_mem(
                file_offset - disk.offset,
                mem,
                mem_offsets.take_bytes(remaining_disk.try_into().unwrap()),
            )
            .await
    }

    async fn write_from_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: MemRegionIter<'a>,
    ) -> crate::Result<usize> {
        let disk = self
            .disk_at_offset(file_offset)
            .map_err(crate::Error::ReadingData)?;
        let remaining_disk = disk.offset + disk.length - file_offset;
        let n = disk
            .file
            .write_from_mem(
                file_offset - disk.offset,
                mem,
                mem_offsets.take_bytes(remaining_disk.try_into().unwrap()),
            )
            .await?;
        disk.set_needs_fsync();
        Ok(n)
    }

    async fn punch_hole(&self, file_offset: u64, length: u64) -> crate::Result<()> {
        let range = file_offset..(file_offset + length);
        let disks = self.disks_in_range(&range);
        for disk in disks {
            if let Some(intersection) = range_intersection(&range, &disk.range()) {
                disk.file
                    .punch_hole(
                        intersection.start - disk.offset,
                        intersection.end - intersection.start,
                    )
                    .await?;
                disk.set_needs_fsync();
            }
        }
        Ok(())
    }

    async fn write_zeroes_at(&self, file_offset: u64, length: u64) -> crate::Result<()> {
        let range = file_offset..(file_offset + length);
        let disks = self.disks_in_range(&range);
        for disk in disks {
            if let Some(intersection) = range_intersection(&range, &disk.range()) {
                disk.file
                    .write_zeroes_at(
                        intersection.start - disk.offset,
                        intersection.end - intersection.start,
                    )
                    .await?;
                disk.set_needs_fsync();
            }
        }
        Ok(())
    }
}

/// Information about a partition to create.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionInfo {
    pub label: String,
    pub path: PathBuf,
    pub partition_type: ImagePartitionType,
    pub writable: bool,
    pub size: u64,
}

/// Round `val` up to the next multiple of 2**`align_log`.
fn align_to_power_of_2(val: u64, align_log: u8) -> u64 {
    let align = 1 << align_log;
    ((val + (align - 1)) / align) * align
}

impl PartitionInfo {
    fn aligned_size(&self) -> u64 {
        align_to_power_of_2(self.size, PARTITION_SIZE_SHIFT)
    }
}

/// The type of partition.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ImagePartitionType {
    LinuxFilesystem,
    EfiSystemPartition,
}

impl ImagePartitionType {
    fn guid(self) -> Uuid {
        match self {
            Self::LinuxFilesystem => LINUX_FILESYSTEM_GUID,
            Self::EfiSystemPartition => EFI_SYSTEM_PARTITION_GUID,
        }
    }
}

/// Write protective MBR and primary GPT table.
fn write_beginning(
    file: &mut impl Write,
    disk_guid: Uuid,
    partitions: &[u8],
    partition_entries_crc32: u32,
    secondary_table_offset: u64,
    disk_size: u64,
) -> Result<()> {
    // Write the protective MBR to the first sector.
    write_protective_mbr(file, disk_size)?;

    // Write the GPT header, and pad out to the end of the sector.
    write_gpt_header(
        file,
        disk_guid,
        partition_entries_crc32,
        secondary_table_offset,
        false,
    )?;
    file.write_all(&[0; HEADER_PADDING_LENGTH])
        .map_err(Error::WriteHeader)?;

    // Write partition entries, including unused ones.
    file.write_all(partitions).map_err(Error::WriteHeader)?;

    // Write zeroes to align the first partition appropriately.
    file.write_all(&[0; PARTITION_ALIGNMENT_SIZE])
        .map_err(Error::WriteHeader)?;

    Ok(())
}

/// Write secondary GPT table.
fn write_end(
    file: &mut impl Write,
    disk_guid: Uuid,
    partitions: &[u8],
    partition_entries_crc32: u32,
    secondary_table_offset: u64,
    disk_size: u64,
) -> Result<()> {
    // Write partition entries, including unused ones.
    file.write_all(partitions).map_err(Error::WriteHeader)?;

    // Write the GPT header, and pad out to the end of the sector.
    write_gpt_header(
        file,
        disk_guid,
        partition_entries_crc32,
        secondary_table_offset,
        true,
    )?;
    file.write_all(&[0; HEADER_PADDING_LENGTH])
        .map_err(Error::WriteHeader)?;

    // Pad out to the aligned disk size.
    let used_disk_size = secondary_table_offset + GPT_END_SIZE;
    let padding = disk_size - used_disk_size;
    file.write_all(&vec![0; padding as usize])
        .map_err(Error::WriteHeader)?;

    Ok(())
}

/// Create the `GptPartitionEntry` for the given partition.
fn create_gpt_entry(partition: &PartitionInfo, offset: u64) -> GptPartitionEntry {
    let mut partition_name: Vec<u16> = partition.label.encode_utf16().collect();
    partition_name.resize(36, 0);

    GptPartitionEntry {
        partition_type_guid: partition.partition_type.guid(),
        unique_partition_guid: Uuid::new_v4(),
        first_lba: offset / SECTOR_SIZE,
        last_lba: (offset + partition.aligned_size()) / SECTOR_SIZE - 1,
        attributes: 0,
        partition_name: partition_name.try_into().unwrap(),
    }
}

/// Create one or more `ComponentDisk` proto messages for the given partition.
fn create_component_disks(
    partition: &PartitionInfo,
    offset: u64,
    zero_filler_path: &str,
) -> Result<Vec<ComponentDisk>> {
    let aligned_size = partition.aligned_size();

    let mut component_disks = vec![ComponentDisk {
        offset,
        file_path: partition
            .path
            .to_str()
            .ok_or_else(|| Error::InvalidPath(partition.path.to_owned()))?
            .to_string(),
        read_write_capability: if partition.writable {
            ReadWriteCapability::READ_WRITE.into()
        } else {
            ReadWriteCapability::READ_ONLY.into()
        },
        ..ComponentDisk::new()
    }];

    if partition.size != aligned_size {
        if partition.writable {
            return Err(Error::UnalignedReadWrite(partition.to_owned()));
        } else {
            // Fill in the gap by reusing the zero filler file, because we know it is always bigger
            // than the alignment size. Its size is 1 << PARTITION_SIZE_SHIFT (4k).
            component_disks.push(ComponentDisk {
                offset: offset + partition.size,
                file_path: zero_filler_path.to_owned(),
                read_write_capability: ReadWriteCapability::READ_ONLY.into(),
                ..ComponentDisk::new()
            });
        }
    }

    Ok(component_disks)
}

/// Create a new composite disk image containing the given partitions, and write it out to the given
/// files.
pub fn create_composite_disk(
    partitions: &[PartitionInfo],
    zero_filler_path: &Path,
    header_path: &Path,
    header_file: &mut File,
    footer_path: &Path,
    footer_file: &mut File,
    output_composite: &mut File,
) -> Result<()> {
    let zero_filler_path = zero_filler_path
        .to_str()
        .ok_or_else(|| Error::InvalidPath(zero_filler_path.to_owned()))?
        .to_string();
    let header_path = header_path
        .to_str()
        .ok_or_else(|| Error::InvalidPath(header_path.to_owned()))?
        .to_string();
    let footer_path = footer_path
        .to_str()
        .ok_or_else(|| Error::InvalidPath(footer_path.to_owned()))?
        .to_string();

    let mut composite_proto = CompositeDisk::new();
    composite_proto.version = COMPOSITE_DISK_VERSION;
    composite_proto.component_disks.push(ComponentDisk {
        file_path: header_path,
        offset: 0,
        read_write_capability: ReadWriteCapability::READ_ONLY.into(),
        ..ComponentDisk::new()
    });

    // Write partitions to a temporary buffer so that we can calculate the CRC, and construct the
    // ComponentDisk proto messages at the same time.
    let mut partitions_buffer =
        [0u8; GPT_NUM_PARTITIONS as usize * GPT_PARTITION_ENTRY_SIZE as usize];
    let mut writer: &mut [u8] = &mut partitions_buffer;
    let mut next_disk_offset = GPT_BEGINNING_SIZE;
    let mut labels = HashSet::with_capacity(partitions.len());
    for partition in partitions {
        let gpt_entry = create_gpt_entry(partition, next_disk_offset);
        if !labels.insert(gpt_entry.partition_name) {
            return Err(Error::DuplicatePartitionLabel(partition.label.clone()));
        }
        gpt_entry.write_bytes(&mut writer)?;

        for component_disk in
            create_component_disks(partition, next_disk_offset, &zero_filler_path)?
        {
            composite_proto.component_disks.push(component_disk);
        }

        next_disk_offset += partition.aligned_size();
    }
    let secondary_table_offset = next_disk_offset;
    let disk_size = align_to_power_of_2(secondary_table_offset + GPT_END_SIZE, DISK_SIZE_SHIFT);

    composite_proto.component_disks.push(ComponentDisk {
        file_path: footer_path,
        offset: secondary_table_offset,
        read_write_capability: ReadWriteCapability::READ_ONLY.into(),
        ..ComponentDisk::new()
    });

    // Calculate CRC32 of partition entries.
    let mut hasher = Hasher::new();
    hasher.update(&partitions_buffer);
    let partition_entries_crc32 = hasher.finalize();

    let disk_guid = Uuid::new_v4();
    write_beginning(
        header_file,
        disk_guid,
        &partitions_buffer,
        partition_entries_crc32,
        secondary_table_offset,
        disk_size,
    )?;
    write_end(
        footer_file,
        disk_guid,
        &partitions_buffer,
        partition_entries_crc32,
        secondary_table_offset,
        disk_size,
    )?;

    composite_proto.length = disk_size;
    output_composite
        .write_all(CDISK_MAGIC.as_bytes())
        .map_err(Error::WriteHeader)?;
    composite_proto
        .write_to_writer(output_composite)
        .map_err(Error::WriteProto)?;

    Ok(())
}

/// Create a zero filler file which can be used to fill the gaps between partition files.
/// The filler is sized to be big enough to fill the gaps. (1 << PARTITION_SIZE_SHIFT)
pub fn create_zero_filler<P: AsRef<Path>>(zero_filler_path: P) -> Result<()> {
    let f = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(zero_filler_path.as_ref())
        .map_err(Error::WriteZeroFiller)?;
    f.set_len(1 << PARTITION_SIZE_SHIFT)
        .map_err(Error::WriteZeroFiller)
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::matches;

    use base::AsRawDescriptor;
    use tempfile::tempfile;

    use super::*;

    #[test]
    fn block_duplicate_offset_disks() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
            needs_fsync: false,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 0,
            length: 100,
            needs_fsync: false,
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
            needs_fsync: false,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
            needs_fsync: false,
        };
        let composite = CompositeDiskFile::new(vec![disk_part1, disk_part2]).unwrap();
        let len = composite.get_len().unwrap();
        assert_eq!(len, 200);
    }

    #[test]
    fn async_get_len() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
            needs_fsync: false,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
            needs_fsync: false,
        };
        let composite = CompositeDiskFile::new(vec![disk_part1, disk_part2]).unwrap();

        let ex = Executor::new().unwrap();
        let composite = Box::new(composite).to_async_disk(&ex).unwrap();
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
            needs_fsync: false,
        };
        let mut composite = CompositeDiskFile::new(vec![disk_part]).unwrap();
        let mut input_memory = [55u8; 5];
        let input_volatile_memory = VolatileSlice::new(&mut input_memory[..]);
        composite
            .write_all_at_volatile(input_volatile_memory, 0)
            .unwrap();
        let mut output_memory = [0u8; 5];
        let output_volatile_memory = VolatileSlice::new(&mut output_memory[..]);
        composite
            .read_exact_at_volatile(output_volatile_memory, 0)
            .unwrap();
        assert_eq!(input_memory, output_memory);
    }

    #[test]
    fn async_single_file_passthrough() {
        let file = tempfile().unwrap();
        let disk_part = ComponentDiskPart {
            file: Box::new(file),
            offset: 0,
            length: 100,
            needs_fsync: false,
        };
        let composite = CompositeDiskFile::new(vec![disk_part]).unwrap();
        let ex = Executor::new().unwrap();
        ex.run_until(async {
            let composite = Box::new(composite).to_async_disk(&ex).unwrap();
            let expected = [55u8; 5];
            assert_eq!(
                composite.write_double_buffered(0, &expected).await.unwrap(),
                5
            );
            let mut buf = [0u8; 5];
            assert_eq!(
                composite
                    .read_double_buffered(0, &mut buf[..])
                    .await
                    .unwrap(),
                5
            );
            assert_eq!(buf, expected);
        })
        .unwrap();
    }

    #[test]
    fn triple_file_descriptors() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let file3 = tempfile().unwrap();
        let mut in_descriptors = vec![
            file1.as_raw_descriptor(),
            file2.as_raw_descriptor(),
            file3.as_raw_descriptor(),
        ];
        in_descriptors.sort_unstable();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
            needs_fsync: false,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
            needs_fsync: false,
        };
        let disk_part3 = ComponentDiskPart {
            file: Box::new(file3),
            offset: 200,
            length: 100,
            needs_fsync: false,
        };
        let composite = CompositeDiskFile::new(vec![disk_part1, disk_part2, disk_part3]).unwrap();
        let mut out_descriptors = composite.as_raw_descriptors();
        out_descriptors.sort_unstable();
        assert_eq!(in_descriptors, out_descriptors);
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
            needs_fsync: false,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
            needs_fsync: false,
        };
        let disk_part3 = ComponentDiskPart {
            file: Box::new(file3),
            offset: 200,
            length: 100,
            needs_fsync: false,
        };
        let mut composite =
            CompositeDiskFile::new(vec![disk_part1, disk_part2, disk_part3]).unwrap();
        let mut input_memory = [55u8; 200];
        let input_volatile_memory = VolatileSlice::new(&mut input_memory[..]);
        composite
            .write_all_at_volatile(input_volatile_memory, 50)
            .unwrap();
        let mut output_memory = [0u8; 200];
        let output_volatile_memory = VolatileSlice::new(&mut output_memory[..]);
        composite
            .read_exact_at_volatile(output_volatile_memory, 50)
            .unwrap();
        assert!(input_memory.iter().eq(output_memory.iter()));
    }

    #[test]
    fn async_triple_file_passthrough() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let file3 = tempfile().unwrap();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
            needs_fsync: false,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
            needs_fsync: false,
        };
        let disk_part3 = ComponentDiskPart {
            file: Box::new(file3),
            offset: 200,
            length: 100,
            needs_fsync: false,
        };
        let composite = CompositeDiskFile::new(vec![disk_part1, disk_part2, disk_part3]).unwrap();
        let ex = Executor::new().unwrap();
        ex.run_until(async {
            let composite = Box::new(composite).to_async_disk(&ex).unwrap();

            let expected = [55u8; 200];
            assert_eq!(
                composite.write_double_buffered(0, &expected).await.unwrap(),
                100
            );
            assert_eq!(
                composite
                    .write_double_buffered(100, &expected[100..])
                    .await
                    .unwrap(),
                100
            );

            let mut buf = [0u8; 200];
            assert_eq!(
                composite
                    .read_double_buffered(0, &mut buf[..])
                    .await
                    .unwrap(),
                100
            );
            assert_eq!(
                composite
                    .read_double_buffered(100, &mut buf[100..])
                    .await
                    .unwrap(),
                100
            );
            assert_eq!(buf, expected);
        })
        .unwrap();
    }

    #[test]
    fn async_triple_file_punch_hole() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let file3 = tempfile().unwrap();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
            needs_fsync: false,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
            needs_fsync: false,
        };
        let disk_part3 = ComponentDiskPart {
            file: Box::new(file3),
            offset: 200,
            length: 100,
            needs_fsync: false,
        };
        let composite = CompositeDiskFile::new(vec![disk_part1, disk_part2, disk_part3]).unwrap();
        let ex = Executor::new().unwrap();
        ex.run_until(async {
            let composite = Box::new(composite).to_async_disk(&ex).unwrap();

            let input = [55u8; 300];
            assert_eq!(
                composite.write_double_buffered(0, &input).await.unwrap(),
                100
            );
            assert_eq!(
                composite
                    .write_double_buffered(100, &input[100..])
                    .await
                    .unwrap(),
                100
            );
            assert_eq!(
                composite
                    .write_double_buffered(200, &input[200..])
                    .await
                    .unwrap(),
                100
            );

            composite.punch_hole(50, 200).await.unwrap();

            let mut buf = [0u8; 300];
            assert_eq!(
                composite
                    .read_double_buffered(0, &mut buf[..])
                    .await
                    .unwrap(),
                100
            );
            assert_eq!(
                composite
                    .read_double_buffered(100, &mut buf[100..])
                    .await
                    .unwrap(),
                100
            );
            assert_eq!(
                composite
                    .read_double_buffered(200, &mut buf[200..])
                    .await
                    .unwrap(),
                100
            );

            let mut expected = input;
            expected[50..250].iter_mut().for_each(|x| *x = 0);
            assert_eq!(buf, expected);
        })
        .unwrap();
    }

    #[test]
    fn async_triple_file_write_zeroes() {
        let file1 = tempfile().unwrap();
        let file2 = tempfile().unwrap();
        let file3 = tempfile().unwrap();
        let disk_part1 = ComponentDiskPart {
            file: Box::new(file1),
            offset: 0,
            length: 100,
            needs_fsync: false,
        };
        let disk_part2 = ComponentDiskPart {
            file: Box::new(file2),
            offset: 100,
            length: 100,
            needs_fsync: false,
        };
        let disk_part3 = ComponentDiskPart {
            file: Box::new(file3),
            offset: 200,
            length: 100,
            needs_fsync: false,
        };
        let composite = CompositeDiskFile::new(vec![disk_part1, disk_part2, disk_part3]).unwrap();
        let ex = Executor::new().unwrap();
        ex.run_until(async {
            let composite = Box::new(composite).to_async_disk(&ex).unwrap();

            let input = [55u8; 300];
            assert_eq!(
                composite.write_double_buffered(0, &input).await.unwrap(),
                100
            );
            assert_eq!(
                composite
                    .write_double_buffered(100, &input[100..])
                    .await
                    .unwrap(),
                100
            );
            assert_eq!(
                composite
                    .write_double_buffered(200, &input[200..])
                    .await
                    .unwrap(),
                100
            );

            composite.write_zeroes_at(50, 200).await.unwrap();

            let mut buf = [0u8; 300];
            assert_eq!(
                composite
                    .read_double_buffered(0, &mut buf[..])
                    .await
                    .unwrap(),
                100
            );
            assert_eq!(
                composite
                    .read_double_buffered(100, &mut buf[100..])
                    .await
                    .unwrap(),
                100
            );
            assert_eq!(
                composite
                    .read_double_buffered(200, &mut buf[200..])
                    .await
                    .unwrap(),
                100
            );

            let mut expected = input;
            expected[50..250].iter_mut().for_each(|x| *x = 0);
            assert_eq!(buf, expected);
        })
        .unwrap();
    }

    // TODO: fsync on a RO file is legal, this test doesn't work as expected. Consider using a mock
    // DiskFile to detect the fsync calls.
    #[test]
    fn async_fsync_skips_unchanged_parts() {
        let mut rw_file = tempfile().unwrap();
        rw_file.write_all(&[0u8; 100]).unwrap();
        rw_file.seek(SeekFrom::Start(0)).unwrap();
        let mut ro_disk_image = tempfile::NamedTempFile::new().unwrap();
        ro_disk_image.write_all(&[0u8; 100]).unwrap();
        let ro_file = OpenOptions::new()
            .read(true)
            .open(ro_disk_image.path())
            .unwrap();

        let rw_part = ComponentDiskPart {
            file: Box::new(rw_file),
            offset: 0,
            length: 100,
            needs_fsync: false,
        };
        let ro_part = ComponentDiskPart {
            file: Box::new(ro_file),
            offset: 100,
            length: 100,
            needs_fsync: false,
        };
        let composite = CompositeDiskFile::new(vec![rw_part, ro_part]).unwrap();
        let ex = Executor::new().unwrap();
        ex.run_until(async {
            let composite = Box::new(composite).to_async_disk(&ex).unwrap();

            // Write to the RW part so that some fsync operation will occur.
            composite.write_zeroes_at(0, 20).await.unwrap();

            // This is the test's assert. fsyncing should NOT touch a read-only disk part. On Windows,
            // this would be an error.
            composite.fsync().await.expect(
                "Failed to fsync composite disk. \
                     This can happen if the disk writable state is wrong.",
            );
        })
        .unwrap();
    }

    #[test]
    fn beginning_size() {
        let mut buffer = vec![];
        let partitions = [0u8; GPT_NUM_PARTITIONS as usize * GPT_PARTITION_ENTRY_SIZE as usize];
        let disk_size = 1000 * SECTOR_SIZE;
        write_beginning(
            &mut buffer,
            Uuid::from_u128(0x12345678_1234_5678_abcd_12345678abcd),
            &partitions,
            42,
            disk_size - GPT_END_SIZE,
            disk_size,
        )
        .unwrap();

        assert_eq!(buffer.len(), GPT_BEGINNING_SIZE as usize);
    }

    #[test]
    fn end_size() {
        let mut buffer = vec![];
        let partitions = [0u8; GPT_NUM_PARTITIONS as usize * GPT_PARTITION_ENTRY_SIZE as usize];
        let disk_size = 1000 * SECTOR_SIZE;
        write_end(
            &mut buffer,
            Uuid::from_u128(0x12345678_1234_5678_abcd_12345678abcd),
            &partitions,
            42,
            disk_size - GPT_END_SIZE,
            disk_size,
        )
        .unwrap();

        assert_eq!(buffer.len(), GPT_END_SIZE as usize);
    }

    #[test]
    fn end_size_with_padding() {
        let mut buffer = vec![];
        let partitions = [0u8; GPT_NUM_PARTITIONS as usize * GPT_PARTITION_ENTRY_SIZE as usize];
        let disk_size = 1000 * SECTOR_SIZE;
        let padding = 3 * SECTOR_SIZE;
        write_end(
            &mut buffer,
            Uuid::from_u128(0x12345678_1234_5678_abcd_12345678abcd),
            &partitions,
            42,
            disk_size - GPT_END_SIZE - padding,
            disk_size,
        )
        .unwrap();

        assert_eq!(buffer.len(), GPT_END_SIZE as usize + padding as usize);
    }

    /// Creates a composite disk image with no partitions.
    #[test]
    fn create_composite_disk_empty() {
        let mut header_image = tempfile().unwrap();
        let mut footer_image = tempfile().unwrap();
        let mut composite_image = tempfile().unwrap();

        create_composite_disk(
            &[],
            Path::new("/zero_filler.img"),
            Path::new("/header_path.img"),
            &mut header_image,
            Path::new("/footer_path.img"),
            &mut footer_image,
            &mut composite_image,
        )
        .unwrap();
    }

    /// Creates a composite disk image with two partitions.
    #[test]
    fn create_composite_disk_success() {
        let mut header_image = tempfile().unwrap();
        let mut footer_image = tempfile().unwrap();
        let mut composite_image = tempfile().unwrap();

        create_composite_disk(
            &[
                PartitionInfo {
                    label: "partition1".to_string(),
                    path: "/partition1.img".to_string().into(),
                    partition_type: ImagePartitionType::LinuxFilesystem,
                    writable: false,
                    size: 0,
                },
                PartitionInfo {
                    label: "partition2".to_string(),
                    path: "/partition2.img".to_string().into(),
                    partition_type: ImagePartitionType::LinuxFilesystem,
                    writable: true,
                    size: 0,
                },
            ],
            Path::new("/zero_filler.img"),
            Path::new("/header_path.img"),
            &mut header_image,
            Path::new("/footer_path.img"),
            &mut footer_image,
            &mut composite_image,
        )
        .unwrap();
    }

    /// Attempts to create a composite disk image with two partitions with the same label.
    #[test]
    fn create_composite_disk_duplicate_label() {
        let mut header_image = tempfile().unwrap();
        let mut footer_image = tempfile().unwrap();
        let mut composite_image = tempfile().unwrap();

        let result = create_composite_disk(
            &[
                PartitionInfo {
                    label: "label".to_string(),
                    path: "/partition1.img".to_string().into(),
                    partition_type: ImagePartitionType::LinuxFilesystem,
                    writable: false,
                    size: 0,
                },
                PartitionInfo {
                    label: "label".to_string(),
                    path: "/partition2.img".to_string().into(),
                    partition_type: ImagePartitionType::LinuxFilesystem,
                    writable: true,
                    size: 0,
                },
            ],
            Path::new("/zero_filler.img"),
            Path::new("/header_path.img"),
            &mut header_image,
            Path::new("/footer_path.img"),
            &mut footer_image,
            &mut composite_image,
        );
        assert!(matches!(result, Err(Error::DuplicatePartitionLabel(label)) if label == "label"));
    }
}
