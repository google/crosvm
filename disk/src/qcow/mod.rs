// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod qcow_raw_file;
mod refcount;
mod vec_cache;

use std::cmp::max;
use std::cmp::min;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::mem::size_of;
use std::path::Path;
use std::str;

use base::error;
use base::open_file;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::FileAllocate;
use base::FileReadWriteAtVolatile;
use base::FileSetLen;
use base::FileSync;
use base::PunchHole;
use base::RawDescriptor;
use base::WriteZeroesAt;
use cros_async::Executor;
use data_model::VolatileMemory;
use data_model::VolatileSlice;
use libc::EINVAL;
use libc::ENOSPC;
use libc::ENOTSUP;
use remain::sorted;
use thiserror::Error;

use crate::create_disk_file;
use crate::qcow::qcow_raw_file::QcowRawFile;
use crate::qcow::refcount::RefCount;
use crate::qcow::vec_cache::CacheMap;
use crate::qcow::vec_cache::Cacheable;
use crate::qcow::vec_cache::VecCache;
use crate::AsyncDisk;
use crate::AsyncDiskFileWrapper;
use crate::DiskFile;
use crate::DiskGetLen;
use crate::ToAsyncDisk;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("backing file io error: {0}")]
    BackingFileIo(io::Error),
    #[error("backing file open error: {0}")]
    BackingFileOpen(Box<crate::Error>),
    #[error("backing file name is too long: {0} bytes over")]
    BackingFileTooLong(usize),
    #[error("compressed blocks not supported")]
    CompressedBlocksNotSupported,
    #[error("failed to evict cache: {0}")]
    EvictingCache(io::Error),
    #[error("file larger than max of {}: {0}", MAX_QCOW_FILE_SIZE)]
    FileTooBig(u64),
    #[error("failed to get file size: {0}")]
    GettingFileSize(io::Error),
    #[error("failed to get refcount: {0}")]
    GettingRefcount(refcount::Error),
    #[error("failed to parse filename: {0}")]
    InvalidBackingFileName(str::Utf8Error),
    #[error("invalid cluster index")]
    InvalidClusterIndex,
    #[error("invalid cluster size")]
    InvalidClusterSize,
    #[error("invalid index")]
    InvalidIndex,
    #[error("invalid L1 table offset")]
    InvalidL1TableOffset,
    #[error("invalid L1 table size {0}")]
    InvalidL1TableSize(u32),
    #[error("invalid magic")]
    InvalidMagic,
    #[error("invalid offset")]
    InvalidOffset(u64),
    #[error("invalid refcount table offset")]
    InvalidRefcountTableOffset,
    #[error("invalid refcount table size: {0}")]
    InvalidRefcountTableSize(u64),
    #[error("no free clusters")]
    NoFreeClusters,
    #[error("no refcount clusters")]
    NoRefcountClusters,
    #[error("not enough space for refcounts")]
    NotEnoughSpaceForRefcounts,
    #[error("failed to open file: {0}")]
    OpeningFile(io::Error),
    #[error("failed to open file: {0}")]
    ReadingHeader(io::Error),
    #[error("failed to read pointers: {0}")]
    ReadingPointers(io::Error),
    #[error("failed to read ref count block: {0}")]
    ReadingRefCountBlock(refcount::Error),
    #[error("failed to read ref counts: {0}")]
    ReadingRefCounts(io::Error),
    #[error("failed to rebuild ref counts: {0}")]
    RebuildingRefCounts(io::Error),
    #[error("refcount table offset past file end")]
    RefcountTableOffEnd,
    #[error("too many clusters specified for refcount table")]
    RefcountTableTooLarge,
    #[error("failed to seek file: {0}")]
    SeekingFile(io::Error),
    #[error("failed to set refcount refcount: {0}")]
    SettingRefcountRefcount(io::Error),
    #[error("size too small for number of clusters")]
    SizeTooSmallForNumberOfClusters,
    #[error("l1 entry table too large: {0}")]
    TooManyL1Entries(u64),
    #[error("ref count table too large: {0}")]
    TooManyRefcounts(u64),
    #[error("unsupported refcount order")]
    UnsupportedRefcountOrder,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
    #[error("failed to write header: {0}")]
    WritingHeader(io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

// Maximum data size supported.
const MAX_QCOW_FILE_SIZE: u64 = 0x01 << 44; // 16 TB.

// QCOW magic constant that starts the header.
pub const QCOW_MAGIC: u32 = 0x5146_49fb;
// Default to a cluster size of 2^DEFAULT_CLUSTER_BITS
const DEFAULT_CLUSTER_BITS: u32 = 16;
// Limit clusters to reasonable sizes. Choose the same limits as qemu. Making the clusters smaller
// increases the amount of overhead for book keeping.
const MIN_CLUSTER_BITS: u32 = 9;
const MAX_CLUSTER_BITS: u32 = 21;
// The L1 and RefCount table are kept in RAM, only handle files that require less than 35M entries.
// This easily covers 1 TB files. When support for bigger files is needed the assumptions made to
// keep these tables in RAM needs to be thrown out.
const MAX_RAM_POINTER_TABLE_SIZE: u64 = 35_000_000;
// Only support 2 byte refcounts, 2^refcount_order bits.
const DEFAULT_REFCOUNT_ORDER: u32 = 4;

const V3_BARE_HEADER_SIZE: u32 = 104;

// bits 0-8 and 56-63 are reserved.
const L1_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L2_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
// Flags
const COMPRESSED_FLAG: u64 = 1 << 62;
const CLUSTER_USED_FLAG: u64 = 1 << 63;
const COMPATIBLE_FEATURES_LAZY_REFCOUNTS: u64 = 1 << 0;

// The format supports a "header extension area", that crosvm does not use.
const QCOW_EMPTY_HEADER_EXTENSION_SIZE: u32 = 8;

// Defined by the specification
const MAX_BACKING_FILE_SIZE: u32 = 1023;

/// Contains the information from the header of a qcow file.
#[derive(Clone, Debug)]
pub struct QcowHeader {
    pub magic: u32,
    pub version: u32,

    pub backing_file_offset: u64,
    pub backing_file_size: u32,

    pub cluster_bits: u32,
    pub size: u64,
    pub crypt_method: u32,

    pub l1_size: u32,
    pub l1_table_offset: u64,

    pub refcount_table_offset: u64,
    pub refcount_table_clusters: u32,

    pub nb_snapshots: u32,
    pub snapshots_offset: u64,

    // v3 entries
    pub incompatible_features: u64,
    pub compatible_features: u64,
    pub autoclear_features: u64,
    pub refcount_order: u32,
    pub header_size: u32,

    // Post-header entries
    pub backing_file_path: Option<String>,
}

// Reads the next u16 from the file.
fn read_u16_from_file(mut f: &File) -> Result<u16> {
    let mut value = [0u8; 2];
    (&mut f)
        .read_exact(&mut value)
        .map_err(Error::ReadingHeader)?;
    Ok(u16::from_be_bytes(value))
}

// Reads the next u32 from the file.
fn read_u32_from_file(mut f: &File) -> Result<u32> {
    let mut value = [0u8; 4];
    (&mut f)
        .read_exact(&mut value)
        .map_err(Error::ReadingHeader)?;
    Ok(u32::from_be_bytes(value))
}

// Reads the next u64 from the file.
fn read_u64_from_file(mut f: &File) -> Result<u64> {
    let mut value = [0u8; 8];
    (&mut f)
        .read_exact(&mut value)
        .map_err(Error::ReadingHeader)?;
    Ok(u64::from_be_bytes(value))
}

impl QcowHeader {
    /// Creates a QcowHeader from a reference to a file.
    pub fn new(f: &mut File) -> Result<QcowHeader> {
        f.seek(SeekFrom::Start(0)).map_err(Error::ReadingHeader)?;

        let magic = read_u32_from_file(f)?;
        if magic != QCOW_MAGIC {
            return Err(Error::InvalidMagic);
        }

        let mut header = QcowHeader {
            magic,
            version: read_u32_from_file(f)?,
            backing_file_offset: read_u64_from_file(f)?,
            backing_file_size: read_u32_from_file(f)?,
            cluster_bits: read_u32_from_file(f)?,
            size: read_u64_from_file(f)?,
            crypt_method: read_u32_from_file(f)?,
            l1_size: read_u32_from_file(f)?,
            l1_table_offset: read_u64_from_file(f)?,
            refcount_table_offset: read_u64_from_file(f)?,
            refcount_table_clusters: read_u32_from_file(f)?,
            nb_snapshots: read_u32_from_file(f)?,
            snapshots_offset: read_u64_from_file(f)?,
            incompatible_features: read_u64_from_file(f)?,
            compatible_features: read_u64_from_file(f)?,
            autoclear_features: read_u64_from_file(f)?,
            refcount_order: read_u32_from_file(f)?,
            header_size: read_u32_from_file(f)?,
            backing_file_path: None,
        };
        if header.backing_file_size > MAX_BACKING_FILE_SIZE {
            return Err(Error::BackingFileTooLong(header.backing_file_size as usize));
        }
        if header.backing_file_offset != 0 {
            f.seek(SeekFrom::Start(header.backing_file_offset))
                .map_err(Error::ReadingHeader)?;
            let mut backing_file_name_bytes = vec![0u8; header.backing_file_size as usize];
            f.read_exact(&mut backing_file_name_bytes)
                .map_err(Error::ReadingHeader)?;
            header.backing_file_path = Some(
                String::from_utf8(backing_file_name_bytes)
                    .map_err(|err| Error::InvalidBackingFileName(err.utf8_error()))?,
            );
        }
        Ok(header)
    }

    pub fn create_for_size_and_path(size: u64, backing_file: Option<&str>) -> Result<QcowHeader> {
        let cluster_bits: u32 = DEFAULT_CLUSTER_BITS;
        let cluster_size: u32 = 0x01 << cluster_bits;
        let max_length: usize =
            (cluster_size - V3_BARE_HEADER_SIZE - QCOW_EMPTY_HEADER_EXTENSION_SIZE) as usize;
        if let Some(path) = backing_file {
            if path.len() > max_length {
                return Err(Error::BackingFileTooLong(path.len() - max_length));
            }
        }
        // L2 blocks are always one cluster long. They contain cluster_size/sizeof(u64) addresses.
        let l2_size: u32 = cluster_size / size_of::<u64>() as u32;
        let num_clusters: u32 = div_round_up_u64(size, u64::from(cluster_size)) as u32;
        let num_l2_clusters: u32 = div_round_up_u32(num_clusters, l2_size);
        let l1_clusters: u32 = div_round_up_u32(num_l2_clusters, cluster_size);
        let header_clusters = div_round_up_u32(size_of::<QcowHeader>() as u32, cluster_size);
        Ok(QcowHeader {
            magic: QCOW_MAGIC,
            version: 3,
            backing_file_offset: (if backing_file.is_none() {
                0
            } else {
                V3_BARE_HEADER_SIZE + QCOW_EMPTY_HEADER_EXTENSION_SIZE
            }) as u64,
            backing_file_size: backing_file.map_or(0, |x| x.len()) as u32,
            cluster_bits: DEFAULT_CLUSTER_BITS,
            size,
            crypt_method: 0,
            l1_size: num_l2_clusters,
            l1_table_offset: u64::from(cluster_size),
            // The refcount table is after l1 + header.
            refcount_table_offset: u64::from(cluster_size * (l1_clusters + 1)),
            refcount_table_clusters: {
                // Pre-allocate enough clusters for the entire refcount table as it must be
                // continuous in the file. Allocate enough space to refcount all clusters, including
                // the refcount clusters.
                let max_refcount_clusters = max_refcount_clusters(
                    DEFAULT_REFCOUNT_ORDER,
                    cluster_size,
                    num_clusters + l1_clusters + num_l2_clusters + header_clusters,
                ) as u32;
                // The refcount table needs to store the offset of each refcount cluster.
                div_round_up_u32(
                    max_refcount_clusters * size_of::<u64>() as u32,
                    cluster_size,
                )
            },
            nb_snapshots: 0,
            snapshots_offset: 0,
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: DEFAULT_REFCOUNT_ORDER,
            header_size: V3_BARE_HEADER_SIZE,
            backing_file_path: backing_file.map(String::from),
        })
    }

    /// Write the header to `file`.
    pub fn write_to<F: Write + Seek>(&self, file: &mut F) -> Result<()> {
        // Writes the next u32 to the file.
        fn write_u32_to_file<F: Write>(f: &mut F, value: u32) -> Result<()> {
            f.write_all(&value.to_be_bytes())
                .map_err(Error::WritingHeader)
        }

        // Writes the next u64 to the file.
        fn write_u64_to_file<F: Write>(f: &mut F, value: u64) -> Result<()> {
            f.write_all(&value.to_be_bytes())
                .map_err(Error::WritingHeader)
        }

        write_u32_to_file(file, self.magic)?;
        write_u32_to_file(file, self.version)?;
        write_u64_to_file(file, self.backing_file_offset)?;
        write_u32_to_file(file, self.backing_file_size)?;
        write_u32_to_file(file, self.cluster_bits)?;
        write_u64_to_file(file, self.size)?;
        write_u32_to_file(file, self.crypt_method)?;
        write_u32_to_file(file, self.l1_size)?;
        write_u64_to_file(file, self.l1_table_offset)?;
        write_u64_to_file(file, self.refcount_table_offset)?;
        write_u32_to_file(file, self.refcount_table_clusters)?;
        write_u32_to_file(file, self.nb_snapshots)?;
        write_u64_to_file(file, self.snapshots_offset)?;
        write_u64_to_file(file, self.incompatible_features)?;
        write_u64_to_file(file, self.compatible_features)?;
        write_u64_to_file(file, self.autoclear_features)?;
        write_u32_to_file(file, self.refcount_order)?;
        write_u32_to_file(file, self.header_size)?;
        write_u32_to_file(file, 0)?; // header extension type: end of header extension area
        write_u32_to_file(file, 0)?; // length of header extension data: 0
        if let Some(backing_file_path) = self.backing_file_path.as_ref() {
            write!(file, "{}", backing_file_path).map_err(Error::WritingHeader)?;
        }

        // Set the file length by seeking and writing a zero to the last byte. This avoids needing
        // a `File` instead of anything that implements seek as the `file` argument.
        // Zeros out the l1 and refcount table clusters.
        let cluster_size = 0x01u64 << self.cluster_bits;
        let refcount_blocks_size = u64::from(self.refcount_table_clusters) * cluster_size;
        file.seek(SeekFrom::Start(
            self.refcount_table_offset + refcount_blocks_size - 2,
        ))
        .map_err(Error::WritingHeader)?;
        file.write(&[0u8]).map_err(Error::WritingHeader)?;

        Ok(())
    }
}

fn max_refcount_clusters(refcount_order: u32, cluster_size: u32, num_clusters: u32) -> u64 {
    // Use u64 as the product of the u32 inputs can overflow.
    let refcount_bytes = (0x01 << refcount_order as u64) / 8;
    let for_data = div_round_up_u64(num_clusters as u64 * refcount_bytes, cluster_size as u64);
    let for_refcounts = div_round_up_u64(for_data * refcount_bytes, cluster_size as u64);
    for_data + for_refcounts
}

/// Represents a qcow2 file. This is a sparse file format maintained by the qemu project.
/// Full documentation of the format can be found in the qemu repository.
///
/// # Example
///
/// ```
/// # use base::FileReadWriteAtVolatile;
/// # use data_model::VolatileSlice;
/// # use disk::QcowFile;
/// # fn test(file: std::fs::File) -> std::io::Result<()> {
///     let mut q = QcowFile::from(file, disk::MAX_NESTING_DEPTH).expect("Can't open qcow file");
///     let mut buf = [0u8; 12];
///     let mut vslice = VolatileSlice::new(&mut buf);
///     q.read_at_volatile(vslice, 10)?;
/// #   Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct QcowFile {
    raw_file: QcowRawFile,
    header: QcowHeader,
    l1_table: VecCache<u64>,
    l2_entries: u64,
    l2_cache: CacheMap<VecCache<u64>>,
    refcounts: RefCount,
    current_offset: u64,
    unref_clusters: Vec<u64>, // List of freshly unreferenced clusters.
    // List of unreferenced clusters available to be used. unref clusters become available once the
    // removal of references to them have been synced to disk.
    avail_clusters: Vec<u64>,
    backing_file: Option<Box<dyn DiskFile>>,
}

impl QcowFile {
    /// Creates a QcowFile from `file`. File must be a valid qcow2 image.
    pub fn from(mut file: File, max_nesting_depth: u32) -> Result<QcowFile> {
        let header = QcowHeader::new(&mut file)?;

        // Only v3 files are supported.
        if header.version != 3 {
            return Err(Error::UnsupportedVersion(header.version));
        }

        // Make sure that the L1 table fits in RAM.
        if u64::from(header.l1_size) > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::InvalidL1TableSize(header.l1_size));
        }

        let cluster_bits: u32 = header.cluster_bits;
        if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&cluster_bits) {
            return Err(Error::InvalidClusterSize);
        }
        let cluster_size = 0x01u64 << cluster_bits;

        // Limit the total size of the disk.
        if header.size > MAX_QCOW_FILE_SIZE {
            return Err(Error::FileTooBig(header.size));
        }

        let backing_file = if let Some(backing_file_path) = header.backing_file_path.as_ref() {
            let path = backing_file_path.clone();
            let backing_raw_file = open_file(
                Path::new(&path),
                OpenOptions::new().read(true), // TODO(b/190435784): Add support for O_DIRECT.
            )
            .map_err(|e| Error::BackingFileIo(e.into()))?;
            // is_sparse_file is false because qcow is internally sparse and we don't need file
            // system sparseness on top of that.
            let backing_file = create_disk_file(
                backing_raw_file,
                /* is_sparse_file= */ false,
                max_nesting_depth,
                Path::new(&path),
            )
            .map_err(|e| Error::BackingFileOpen(Box::new(e)))?;
            Some(backing_file)
        } else {
            None
        };

        // Only support two byte refcounts.
        let refcount_bits: u64 = 0x01u64
            .checked_shl(header.refcount_order)
            .ok_or(Error::UnsupportedRefcountOrder)?;
        if refcount_bits != 16 {
            return Err(Error::UnsupportedRefcountOrder);
        }
        let refcount_bytes = (refcount_bits + 7) / 8;

        // Need at least one refcount cluster
        if header.refcount_table_clusters == 0 {
            return Err(Error::NoRefcountClusters);
        }
        offset_is_cluster_boundary(header.l1_table_offset, header.cluster_bits)?;
        offset_is_cluster_boundary(header.snapshots_offset, header.cluster_bits)?;
        // refcount table must be a cluster boundary, and within the file's virtual or actual size.
        offset_is_cluster_boundary(header.refcount_table_offset, header.cluster_bits)?;
        let file_size = file.metadata().map_err(Error::GettingFileSize)?.len();
        if header.refcount_table_offset > max(file_size, header.size) {
            return Err(Error::RefcountTableOffEnd);
        }

        // The first cluster should always have a non-zero refcount, so if it is 0,
        // this is an old file with broken refcounts, which requires a rebuild.
        let mut refcount_rebuild_required = true;
        file.seek(SeekFrom::Start(header.refcount_table_offset))
            .map_err(Error::SeekingFile)?;
        let first_refblock_addr = read_u64_from_file(&file)?;
        if first_refblock_addr != 0 {
            file.seek(SeekFrom::Start(first_refblock_addr))
                .map_err(Error::SeekingFile)?;
            let first_cluster_refcount = read_u16_from_file(&file)?;
            if first_cluster_refcount != 0 {
                refcount_rebuild_required = false;
            }
        }

        if (header.compatible_features & COMPATIBLE_FEATURES_LAZY_REFCOUNTS) != 0 {
            refcount_rebuild_required = true;
        }

        let mut raw_file =
            QcowRawFile::from(file, cluster_size).ok_or(Error::InvalidClusterSize)?;
        if refcount_rebuild_required {
            QcowFile::rebuild_refcounts(&mut raw_file, header.clone())?;
        }

        let l2_size = cluster_size / size_of::<u64>() as u64;
        let num_clusters = div_round_up_u64(header.size, cluster_size);
        let num_l2_clusters = div_round_up_u64(num_clusters, l2_size);
        let l1_clusters = div_round_up_u64(num_l2_clusters, cluster_size);
        let header_clusters = div_round_up_u64(size_of::<QcowHeader>() as u64, cluster_size);
        if num_l2_clusters > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::TooManyL1Entries(num_l2_clusters));
        }
        let l1_table = VecCache::from_vec(
            raw_file
                .read_pointer_table(
                    header.l1_table_offset,
                    num_l2_clusters,
                    Some(L1_TABLE_OFFSET_MASK),
                )
                .map_err(Error::ReadingHeader)?,
        );

        let num_clusters = div_round_up_u64(header.size, cluster_size);
        let refcount_clusters = max_refcount_clusters(
            header.refcount_order,
            cluster_size as u32,
            (num_clusters + l1_clusters + num_l2_clusters + header_clusters) as u32,
        );
        // Check that the given header doesn't have a suspiciously sized refcount table.
        if u64::from(header.refcount_table_clusters) > 2 * refcount_clusters {
            return Err(Error::RefcountTableTooLarge);
        }
        if l1_clusters + refcount_clusters > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::TooManyRefcounts(refcount_clusters));
        }
        let refcount_block_entries = cluster_size / refcount_bytes;
        let refcounts = RefCount::new(
            &mut raw_file,
            header.refcount_table_offset,
            refcount_clusters,
            refcount_block_entries,
            cluster_size,
        )
        .map_err(Error::ReadingRefCounts)?;

        let l2_entries = cluster_size / size_of::<u64>() as u64;

        let mut qcow = QcowFile {
            raw_file,
            header,
            l1_table,
            l2_entries,
            l2_cache: CacheMap::new(100),
            refcounts,
            current_offset: 0,
            unref_clusters: Vec::new(),
            avail_clusters: Vec::new(),
            backing_file,
        };

        // Check that the L1 and refcount tables fit in a 64bit address space.
        qcow.header
            .l1_table_offset
            .checked_add(qcow.l1_address_offset(qcow.virtual_size()))
            .ok_or(Error::InvalidL1TableOffset)?;
        qcow.header
            .refcount_table_offset
            .checked_add(u64::from(qcow.header.refcount_table_clusters) * cluster_size)
            .ok_or(Error::InvalidRefcountTableOffset)?;

        qcow.find_avail_clusters()?;

        Ok(qcow)
    }

    /// Creates a new QcowFile at the given path.
    pub fn new(file: File, virtual_size: u64) -> Result<QcowFile> {
        let header = QcowHeader::create_for_size_and_path(virtual_size, None)?;
        QcowFile::new_from_header(file, header, 1)
    }

    /// Creates a new QcowFile at the given path.
    pub fn new_from_backing(
        file: File,
        backing_file_name: &str,
        backing_file_max_nesting_depth: u32,
    ) -> Result<QcowFile> {
        let backing_path = Path::new(backing_file_name);
        let backing_raw_file = open_file(
            backing_path,
            OpenOptions::new().read(true), // TODO(b/190435784): add support for O_DIRECT.
        )
        .map_err(|e| Error::BackingFileIo(e.into()))?;
        // is_sparse_file is false because qcow is internally sparse and we don't need file
        // system sparseness on top of that.
        let backing_file = create_disk_file(
            backing_raw_file,
            /* is_sparse_file= */ false,
            backing_file_max_nesting_depth,
            backing_path,
        )
        .map_err(|e| Error::BackingFileOpen(Box::new(e)))?;
        let size = backing_file.get_len().map_err(Error::BackingFileIo)?;
        let header = QcowHeader::create_for_size_and_path(size, Some(backing_file_name))?;
        let mut result = QcowFile::new_from_header(file, header, backing_file_max_nesting_depth)?;
        result.backing_file = Some(backing_file);
        Ok(result)
    }

    fn new_from_header(
        mut file: File,
        header: QcowHeader,
        max_nesting_depth: u32,
    ) -> Result<QcowFile> {
        file.seek(SeekFrom::Start(0)).map_err(Error::SeekingFile)?;
        header.write_to(&mut file)?;

        let mut qcow = Self::from(file, max_nesting_depth)?;

        // Set the refcount for each refcount table cluster.
        let cluster_size = 0x01u64 << qcow.header.cluster_bits;
        let refcount_table_base = qcow.header.refcount_table_offset as u64;
        let end_cluster_addr =
            refcount_table_base + u64::from(qcow.header.refcount_table_clusters) * cluster_size;

        let mut cluster_addr = 0;
        while cluster_addr < end_cluster_addr {
            let mut unref_clusters = qcow
                .set_cluster_refcount(cluster_addr, 1)
                .map_err(Error::SettingRefcountRefcount)?;
            qcow.unref_clusters.append(&mut unref_clusters);
            cluster_addr += cluster_size;
        }

        Ok(qcow)
    }

    pub fn set_backing_file(&mut self, backing: Option<Box<dyn DiskFile>>) {
        self.backing_file = backing;
    }

    /// Returns the first cluster in the file with a 0 refcount. Used for testing.
    pub fn first_zero_refcount(&mut self) -> Result<Option<u64>> {
        let file_size = self
            .raw_file
            .file_mut()
            .metadata()
            .map_err(Error::GettingFileSize)?
            .len();
        let cluster_size = 0x01u64 << self.header.cluster_bits;

        let mut cluster_addr = 0;
        while cluster_addr < file_size {
            let cluster_refcount = self
                .refcounts
                .get_cluster_refcount(&mut self.raw_file, cluster_addr)
                .map_err(Error::GettingRefcount)?;
            if cluster_refcount == 0 {
                return Ok(Some(cluster_addr));
            }
            cluster_addr += cluster_size;
        }
        Ok(None)
    }

    fn find_avail_clusters(&mut self) -> Result<()> {
        let cluster_size = self.raw_file.cluster_size();

        let file_size = self
            .raw_file
            .file_mut()
            .metadata()
            .map_err(Error::GettingFileSize)?
            .len();

        for i in (0..file_size).step_by(cluster_size as usize) {
            let refcount = self
                .refcounts
                .get_cluster_refcount(&mut self.raw_file, i)
                .map_err(Error::GettingRefcount)?;
            if refcount == 0 {
                self.avail_clusters.push(i);
            }
        }

        Ok(())
    }

    /// Rebuild the reference count tables.
    fn rebuild_refcounts(raw_file: &mut QcowRawFile, header: QcowHeader) -> Result<()> {
        fn add_ref(refcounts: &mut [u16], cluster_size: u64, cluster_address: u64) -> Result<()> {
            let idx = (cluster_address / cluster_size) as usize;
            if idx >= refcounts.len() {
                return Err(Error::InvalidClusterIndex);
            }
            refcounts[idx] += 1;
            Ok(())
        }

        // Add a reference to the first cluster (header plus extensions).
        fn set_header_refcount(refcounts: &mut [u16], cluster_size: u64) -> Result<()> {
            add_ref(refcounts, cluster_size, 0)
        }

        // Add references to the L1 table clusters.
        fn set_l1_refcounts(
            refcounts: &mut [u16],
            header: QcowHeader,
            cluster_size: u64,
        ) -> Result<()> {
            let l1_clusters = div_round_up_u64(header.l1_size as u64, cluster_size);
            let l1_table_offset = header.l1_table_offset;
            for i in 0..l1_clusters {
                add_ref(refcounts, cluster_size, l1_table_offset + i * cluster_size)?;
            }
            Ok(())
        }

        // Traverse the L1 and L2 tables to find all reachable data clusters.
        fn set_data_refcounts(
            refcounts: &mut [u16],
            header: QcowHeader,
            cluster_size: u64,
            raw_file: &mut QcowRawFile,
        ) -> Result<()> {
            let l1_table = raw_file
                .read_pointer_table(
                    header.l1_table_offset,
                    header.l1_size as u64,
                    Some(L1_TABLE_OFFSET_MASK),
                )
                .map_err(Error::ReadingPointers)?;
            for l1_index in 0..header.l1_size as usize {
                let l2_addr_disk = *l1_table.get(l1_index).ok_or(Error::InvalidIndex)?;
                if l2_addr_disk != 0 {
                    // Add a reference to the L2 table cluster itself.
                    add_ref(refcounts, cluster_size, l2_addr_disk)?;

                    // Read the L2 table and find all referenced data clusters.
                    let l2_table = raw_file
                        .read_pointer_table(
                            l2_addr_disk,
                            cluster_size / size_of::<u64>() as u64,
                            Some(L2_TABLE_OFFSET_MASK),
                        )
                        .map_err(Error::ReadingPointers)?;
                    for data_cluster_addr in l2_table {
                        if data_cluster_addr != 0 {
                            add_ref(refcounts, cluster_size, data_cluster_addr)?;
                        }
                    }
                }
            }

            Ok(())
        }

        // Add references to the top-level refcount table clusters.
        fn set_refcount_table_refcounts(
            refcounts: &mut [u16],
            header: QcowHeader,
            cluster_size: u64,
        ) -> Result<()> {
            let refcount_table_offset = header.refcount_table_offset;
            for i in 0..header.refcount_table_clusters as u64 {
                add_ref(
                    refcounts,
                    cluster_size,
                    refcount_table_offset + i * cluster_size,
                )?;
            }
            Ok(())
        }

        // Allocate clusters for refblocks.
        // This needs to be done last so that we have the correct refcounts for all other
        // clusters.
        fn alloc_refblocks(
            refcounts: &mut [u16],
            cluster_size: u64,
            refblock_clusters: u64,
            pointers_per_cluster: u64,
        ) -> Result<Vec<u64>> {
            let refcount_table_entries = div_round_up_u64(refblock_clusters, pointers_per_cluster);
            let mut ref_table = vec![0; refcount_table_entries as usize];
            let mut first_free_cluster: u64 = 0;
            for refblock_addr in &mut ref_table {
                loop {
                    if first_free_cluster >= refcounts.len() as u64 {
                        return Err(Error::NotEnoughSpaceForRefcounts);
                    }
                    if refcounts[first_free_cluster as usize] == 0 {
                        break;
                    }
                    first_free_cluster += 1;
                }

                *refblock_addr = first_free_cluster * cluster_size;
                add_ref(refcounts, cluster_size, *refblock_addr)?;

                first_free_cluster += 1;
            }

            Ok(ref_table)
        }

        // Write the updated reference count blocks and reftable.
        fn write_refblocks(
            refcounts: &[u16],
            mut header: QcowHeader,
            ref_table: &[u64],
            raw_file: &mut QcowRawFile,
            refcount_block_entries: u64,
        ) -> Result<()> {
            // Rewrite the header with lazy refcounts enabled while we are rebuilding the tables.
            header.compatible_features |= COMPATIBLE_FEATURES_LAZY_REFCOUNTS;
            raw_file
                .file_mut()
                .seek(SeekFrom::Start(0))
                .map_err(Error::SeekingFile)?;
            header.write_to(raw_file.file_mut())?;

            for (i, refblock_addr) in ref_table.iter().enumerate() {
                // Write a block of refcounts to the location indicated by refblock_addr.
                let refblock_start = i * (refcount_block_entries as usize);
                let refblock_end = min(
                    refcounts.len(),
                    refblock_start + refcount_block_entries as usize,
                );
                let refblock = &refcounts[refblock_start..refblock_end];
                raw_file
                    .write_refcount_block(*refblock_addr, refblock)
                    .map_err(Error::WritingHeader)?;

                // If this is the last (partial) cluster, pad it out to a full refblock cluster.
                if refblock.len() < refcount_block_entries as usize {
                    let refblock_padding =
                        vec![0u16; refcount_block_entries as usize - refblock.len()];
                    raw_file
                        .write_refcount_block(
                            *refblock_addr + refblock.len() as u64 * 2,
                            &refblock_padding,
                        )
                        .map_err(Error::WritingHeader)?;
                }
            }

            // Rewrite the top-level refcount table.
            raw_file
                .write_pointer_table(header.refcount_table_offset, ref_table, 0)
                .map_err(Error::WritingHeader)?;

            // Rewrite the header again, now with lazy refcounts disabled.
            header.compatible_features &= !COMPATIBLE_FEATURES_LAZY_REFCOUNTS;
            raw_file
                .file_mut()
                .seek(SeekFrom::Start(0))
                .map_err(Error::SeekingFile)?;
            header.write_to(raw_file.file_mut())?;

            Ok(())
        }

        let cluster_size = raw_file.cluster_size();

        let file_size = raw_file
            .file_mut()
            .metadata()
            .map_err(Error::GettingFileSize)?
            .len();

        let refcount_bits = 1u64 << header.refcount_order;
        let refcount_bytes = div_round_up_u64(refcount_bits, 8);
        let refcount_block_entries = cluster_size / refcount_bytes;
        let pointers_per_cluster = cluster_size / size_of::<u64>() as u64;
        let data_clusters = div_round_up_u64(header.size, cluster_size);
        let l2_clusters = div_round_up_u64(data_clusters, pointers_per_cluster);
        let l1_clusters = div_round_up_u64(l2_clusters, cluster_size);
        let header_clusters = div_round_up_u64(size_of::<QcowHeader>() as u64, cluster_size);
        let max_clusters = data_clusters + l2_clusters + l1_clusters + header_clusters;
        let mut max_valid_cluster_index = max_clusters;
        let refblock_clusters = div_round_up_u64(max_valid_cluster_index, refcount_block_entries);
        let reftable_clusters = div_round_up_u64(refblock_clusters, pointers_per_cluster);
        // Account for refblocks and the ref table size needed to address them.
        let refblocks_for_refs = div_round_up_u64(
            refblock_clusters + reftable_clusters,
            refcount_block_entries,
        );
        let reftable_clusters_for_refs =
            div_round_up_u64(refblocks_for_refs, refcount_block_entries);
        max_valid_cluster_index += refblock_clusters + reftable_clusters;
        max_valid_cluster_index += refblocks_for_refs + reftable_clusters_for_refs;

        if max_valid_cluster_index > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::InvalidRefcountTableSize(max_valid_cluster_index));
        }

        let max_valid_cluster_offset = max_valid_cluster_index * cluster_size;
        if max_valid_cluster_offset < file_size - cluster_size {
            return Err(Error::InvalidRefcountTableSize(max_valid_cluster_offset));
        }

        let mut refcounts = vec![0; max_valid_cluster_index as usize];

        // Find all references clusters and rebuild refcounts.
        set_header_refcount(&mut refcounts, cluster_size)?;
        set_l1_refcounts(&mut refcounts, header.clone(), cluster_size)?;
        set_data_refcounts(&mut refcounts, header.clone(), cluster_size, raw_file)?;
        set_refcount_table_refcounts(&mut refcounts, header.clone(), cluster_size)?;

        // Allocate clusters to store the new reference count blocks.
        let ref_table = alloc_refblocks(
            &mut refcounts,
            cluster_size,
            refblock_clusters,
            pointers_per_cluster,
        )?;

        // Write updated reference counts and point the reftable at them.
        write_refblocks(
            &refcounts,
            header,
            &ref_table,
            raw_file,
            refcount_block_entries,
        )
    }

    // Limits the range so that it doesn't exceed the virtual size of the file.
    fn limit_range_file(&self, address: u64, count: usize) -> usize {
        if address.checked_add(count as u64).is_none() || address > self.virtual_size() {
            return 0;
        }
        min(count as u64, self.virtual_size() - address) as usize
    }

    // Limits the range so that it doesn't overflow the end of a cluster.
    fn limit_range_cluster(&self, address: u64, count: usize) -> usize {
        let offset: u64 = self.raw_file.cluster_offset(address);
        let limit = self.raw_file.cluster_size() - offset;
        min(count as u64, limit) as usize
    }

    // Gets the maximum virtual size of this image.
    fn virtual_size(&self) -> u64 {
        self.header.size
    }

    // Gets the offset of `address` in the L1 table.
    fn l1_address_offset(&self, address: u64) -> u64 {
        let l1_index = self.l1_table_index(address);
        l1_index * size_of::<u64>() as u64
    }

    // Gets the offset of `address` in the L1 table.
    fn l1_table_index(&self, address: u64) -> u64 {
        (address / self.raw_file.cluster_size()) / self.l2_entries
    }

    // Gets the offset of `address` in the L2 table.
    fn l2_table_index(&self, address: u64) -> u64 {
        (address / self.raw_file.cluster_size()) % self.l2_entries
    }

    // Gets the offset of the given guest address in the host file. If L1, L2, or data clusters have
    // yet to be allocated, return None.
    fn file_offset_read(&mut self, address: u64) -> std::io::Result<Option<u64>> {
        if address >= self.virtual_size() as u64 {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| std::io::Error::from_raw_os_error(EINVAL))?;

        if l2_addr_disk == 0 {
            // Reading from an unallocated cluster will return zeros.
            return Ok(None);
        }

        let l2_index = self.l2_table_index(address) as usize;

        if !self.l2_cache.contains_key(&l1_index) {
            // Not in the cache.
            let table =
                VecCache::from_vec(Self::read_l2_cluster(&mut self.raw_file, l2_addr_disk)?);

            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache.insert(l1_index, table, |index, evicted| {
                raw_file.write_pointer_table(
                    l1_table[index],
                    evicted.get_values(),
                    CLUSTER_USED_FLAG,
                )
            })?;
        };

        let cluster_addr = self.l2_cache.get(&l1_index).unwrap()[l2_index];
        if cluster_addr == 0 {
            return Ok(None);
        }
        Ok(Some(cluster_addr + self.raw_file.cluster_offset(address)))
    }

    // Gets the offset of the given guest address in the host file. If L1, L2, or data clusters need
    // to be allocated, they will be.
    fn file_offset_write(&mut self, address: u64) -> std::io::Result<u64> {
        if address >= self.virtual_size() as u64 {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| std::io::Error::from_raw_os_error(EINVAL))?;
        let l2_index = self.l2_table_index(address) as usize;

        let mut set_refcounts = Vec::new();

        if !self.l2_cache.contains_key(&l1_index) {
            // Not in the cache.
            let l2_table = if l2_addr_disk == 0 {
                // Allocate a new cluster to store the L2 table and update the L1 table to point
                // to the new table.
                let new_addr: u64 = self.get_new_cluster(None)?;
                // The cluster refcount starts at one meaning it is used but doesn't need COW.
                set_refcounts.push((new_addr, 1));
                self.l1_table[l1_index] = new_addr;
                VecCache::new(self.l2_entries as usize)
            } else {
                VecCache::from_vec(Self::read_l2_cluster(&mut self.raw_file, l2_addr_disk)?)
            };
            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache.insert(l1_index, l2_table, |index, evicted| {
                raw_file.write_pointer_table(
                    l1_table[index],
                    evicted.get_values(),
                    CLUSTER_USED_FLAG,
                )
            })?;
        }

        let cluster_addr = match self.l2_cache.get(&l1_index).unwrap()[l2_index] {
            0 => {
                let initial_data = if let Some(backing) = self.backing_file.as_mut() {
                    let cluster_size = self.raw_file.cluster_size();
                    let cluster_begin = address - (address % cluster_size);
                    let mut cluster_data = vec![0u8; cluster_size as usize];
                    let volatile_slice = VolatileSlice::new(&mut cluster_data);
                    backing.read_exact_at_volatile(volatile_slice, cluster_begin)?;
                    Some(cluster_data)
                } else {
                    None
                };
                // Need to allocate a data cluster
                let cluster_addr = self.append_data_cluster(initial_data)?;
                self.update_cluster_addr(l1_index, l2_index, cluster_addr, &mut set_refcounts)?;
                cluster_addr
            }
            a => a,
        };

        for (addr, count) in set_refcounts {
            let mut newly_unref = self.set_cluster_refcount(addr, count)?;
            self.unref_clusters.append(&mut newly_unref);
        }

        Ok(cluster_addr + self.raw_file.cluster_offset(address))
    }

    // Updates the l1 and l2 tables to point to the new `cluster_addr`.
    fn update_cluster_addr(
        &mut self,
        l1_index: usize,
        l2_index: usize,
        cluster_addr: u64,
        set_refcounts: &mut Vec<(u64, u16)>,
    ) -> io::Result<()> {
        if !self.l2_cache.get(&l1_index).unwrap().dirty() {
            // Free the previously used cluster if one exists. Modified tables are always
            // witten to new clusters so the L1 table can be committed to disk after they
            // are and L1 never points at an invalid table.
            // The index must be valid from when it was insterted.
            let addr = self.l1_table[l1_index];
            if addr != 0 {
                self.unref_clusters.push(addr);
                set_refcounts.push((addr, 0));
            }

            // Allocate a new cluster to store the L2 table and update the L1 table to point
            // to the new table. The cluster will be written when the cache is flushed, no
            // need to copy the data now.
            let new_addr: u64 = self.get_new_cluster(None)?;
            // The cluster refcount starts at one indicating it is used but doesn't need
            // COW.
            set_refcounts.push((new_addr, 1));
            self.l1_table[l1_index] = new_addr;
        }
        // 'unwrap' is OK because it was just added.
        self.l2_cache.get_mut(&l1_index).unwrap()[l2_index] = cluster_addr;
        Ok(())
    }

    // Allocate a new cluster and return its offset within the raw file.
    fn get_new_cluster(&mut self, initial_data: Option<Vec<u8>>) -> std::io::Result<u64> {
        // First use a pre allocated cluster if one is available.
        if let Some(free_cluster) = self.avail_clusters.pop() {
            if let Some(initial_data) = initial_data {
                self.raw_file.write_cluster(free_cluster, initial_data)?;
            } else {
                self.raw_file.zero_cluster(free_cluster)?;
            }
            return Ok(free_cluster);
        }

        let max_valid_cluster_offset = self.refcounts.max_valid_cluster_offset();
        if let Some(new_cluster) = self.raw_file.add_cluster_end(max_valid_cluster_offset)? {
            if let Some(initial_data) = initial_data {
                self.raw_file.write_cluster(new_cluster, initial_data)?;
            }
            Ok(new_cluster)
        } else {
            error!("No free clusters in get_new_cluster()");
            Err(std::io::Error::from_raw_os_error(ENOSPC))
        }
    }

    // Allocate and initialize a new data cluster. Returns the offset of the
    // cluster in to the file on success.
    fn append_data_cluster(&mut self, initial_data: Option<Vec<u8>>) -> std::io::Result<u64> {
        let new_addr: u64 = self.get_new_cluster(initial_data)?;
        // The cluster refcount starts at one indicating it is used but doesn't need COW.
        let mut newly_unref = self.set_cluster_refcount(new_addr, 1)?;
        self.unref_clusters.append(&mut newly_unref);
        Ok(new_addr)
    }

    // Deallocate the storage for the cluster starting at `address`.
    // Any future reads of this cluster will return all zeroes (or the backing file, if in use).
    fn deallocate_cluster(&mut self, address: u64) -> std::io::Result<()> {
        if address >= self.virtual_size() as u64 {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| std::io::Error::from_raw_os_error(EINVAL))?;
        let l2_index = self.l2_table_index(address) as usize;

        if l2_addr_disk == 0 {
            // The whole L2 table for this address is not allocated yet,
            // so the cluster must also be unallocated.
            return Ok(());
        }

        if !self.l2_cache.contains_key(&l1_index) {
            // Not in the cache.
            let table =
                VecCache::from_vec(Self::read_l2_cluster(&mut self.raw_file, l2_addr_disk)?);
            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache.insert(l1_index, table, |index, evicted| {
                raw_file.write_pointer_table(
                    l1_table[index],
                    evicted.get_values(),
                    CLUSTER_USED_FLAG,
                )
            })?;
        }

        let cluster_addr = self.l2_cache.get(&l1_index).unwrap()[l2_index];
        if cluster_addr == 0 {
            // This cluster is already unallocated; nothing to do.
            return Ok(());
        }

        // Decrement the refcount.
        let refcount = self
            .refcounts
            .get_cluster_refcount(&mut self.raw_file, cluster_addr)
            .map_err(|_| std::io::Error::from_raw_os_error(EINVAL))?;
        if refcount == 0 {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let new_refcount = refcount - 1;
        let mut newly_unref = self.set_cluster_refcount(cluster_addr, new_refcount)?;
        self.unref_clusters.append(&mut newly_unref);

        // Rewrite the L2 entry to remove the cluster mapping.
        // unwrap is safe as we just checked/inserted this entry.
        self.l2_cache.get_mut(&l1_index).unwrap()[l2_index] = 0;

        if new_refcount == 0 {
            let cluster_size = self.raw_file.cluster_size();
            // This cluster is no longer in use; deallocate the storage.
            // The underlying FS may not support FALLOC_FL_PUNCH_HOLE,
            // so don't treat an error as fatal.  Future reads will return zeros anyways.
            let _ = self
                .raw_file
                .file_mut()
                .punch_hole(cluster_addr, cluster_size);
            self.unref_clusters.push(cluster_addr);
        }
        Ok(())
    }

    // Fill a range of `length` bytes starting at `address` with zeroes.
    // Any future reads of this range will return all zeroes.
    // If there is no backing file, this will deallocate cluster storage when possible.
    fn zero_bytes(&mut self, address: u64, length: usize) -> std::io::Result<()> {
        let write_count: usize = self.limit_range_file(address, length);

        let mut nwritten: usize = 0;
        while nwritten < write_count {
            let curr_addr = address + nwritten as u64;
            let count = self.limit_range_cluster(curr_addr, write_count - nwritten);

            if self.backing_file.is_none() && count == self.raw_file.cluster_size() as usize {
                // Full cluster and no backing file in use - deallocate the storage.
                self.deallocate_cluster(curr_addr)?;
            } else {
                // Partial cluster - zero out the relevant bytes.
                let offset = if self.backing_file.is_some() {
                    // There is a backing file, so we need to allocate a cluster in order to
                    // zero out the hole-punched bytes such that the backing file contents do not
                    // show through.
                    Some(self.file_offset_write(curr_addr)?)
                } else {
                    // Any space in unallocated clusters can be left alone, since
                    // unallocated clusters already read back as zeroes.
                    self.file_offset_read(curr_addr)?
                };
                if let Some(offset) = offset {
                    // Partial cluster - zero it out.
                    self.raw_file
                        .file_mut()
                        .write_zeroes_all_at(offset, count)?;
                }
            }

            nwritten += count;
        }
        Ok(())
    }

    // Reads an L2 cluster from the disk, returning an error if the file can't be read or if any
    // cluster is compressed.
    fn read_l2_cluster(raw_file: &mut QcowRawFile, cluster_addr: u64) -> std::io::Result<Vec<u64>> {
        let file_values = raw_file.read_pointer_cluster(cluster_addr, None)?;
        if file_values.iter().any(|entry| entry & COMPRESSED_FLAG != 0) {
            return Err(std::io::Error::from_raw_os_error(ENOTSUP));
        }
        Ok(file_values
            .iter()
            .map(|entry| *entry & L2_TABLE_OFFSET_MASK)
            .collect())
    }

    // Set the refcount for a cluster with the given address.
    // Returns a list of any refblocks that can be reused, this happens when a refblock is moved,
    // the old location can be reused.
    fn set_cluster_refcount(&mut self, address: u64, refcount: u16) -> std::io::Result<Vec<u64>> {
        let mut added_clusters = Vec::new();
        let mut unref_clusters = Vec::new();
        let mut refcount_set = false;
        let mut new_cluster = None;

        while !refcount_set {
            match self.refcounts.set_cluster_refcount(
                &mut self.raw_file,
                address,
                refcount,
                new_cluster.take(),
            ) {
                Ok(None) => {
                    refcount_set = true;
                }
                Ok(Some(freed_cluster)) => {
                    unref_clusters.push(freed_cluster);
                    refcount_set = true;
                }
                Err(refcount::Error::EvictingRefCounts(e)) => {
                    return Err(e);
                }
                Err(refcount::Error::InvalidIndex) => {
                    return Err(std::io::Error::from_raw_os_error(EINVAL));
                }
                Err(refcount::Error::NeedCluster(addr)) => {
                    // Read the address and call set_cluster_refcount again.
                    new_cluster = Some((
                        addr,
                        VecCache::from_vec(self.raw_file.read_refcount_block(addr)?),
                    ));
                }
                Err(refcount::Error::NeedNewCluster) => {
                    // Allocate the cluster and call set_cluster_refcount again.
                    let addr = self.get_new_cluster(None)?;
                    added_clusters.push(addr);
                    new_cluster = Some((
                        addr,
                        VecCache::new(self.refcounts.refcounts_per_block() as usize),
                    ));
                }
                Err(refcount::Error::ReadingRefCounts(e)) => {
                    return Err(e);
                }
            }
        }

        for addr in added_clusters {
            self.set_cluster_refcount(addr, 1)?;
        }
        Ok(unref_clusters)
    }

    fn sync_caches(&mut self) -> std::io::Result<()> {
        // Write out all dirty L2 tables.
        for (l1_index, l2_table) in self.l2_cache.iter_mut().filter(|(_k, v)| v.dirty()) {
            // The index must be valid from when we insterted it.
            let addr = self.l1_table[*l1_index];
            if addr != 0 {
                self.raw_file.write_pointer_table(
                    addr,
                    l2_table.get_values(),
                    CLUSTER_USED_FLAG,
                )?;
            } else {
                return Err(std::io::Error::from_raw_os_error(EINVAL));
            }
            l2_table.mark_clean();
        }
        // Write the modified refcount blocks.
        self.refcounts.flush_blocks(&mut self.raw_file)?;
        // Make sure metadata(file len) and all data clusters are written.
        self.raw_file.file_mut().sync_all()?;

        // Push L1 table and refcount table last as all the clusters they point to are now
        // guaranteed to be valid.
        let mut sync_required = false;
        if self.l1_table.dirty() {
            self.raw_file.write_pointer_table(
                self.header.l1_table_offset,
                self.l1_table.get_values(),
                0,
            )?;
            self.l1_table.mark_clean();
            sync_required = true;
        }
        sync_required |= self.refcounts.flush_table(&mut self.raw_file)?;
        if sync_required {
            self.raw_file.file_mut().sync_data()?;
        }
        Ok(())
    }

    // Reads `count` bytes starting at `address`, calling `cb` repeatedly with the data source,
    // number of bytes read so far, offset to read from, and number of bytes to read from the file
    // in that invocation. If None is given to `cb` in place of the backing file, the `cb` should
    // infer zeros would have been read.
    fn read_cb<F>(&mut self, address: u64, count: usize, mut cb: F) -> std::io::Result<usize>
    where
        F: FnMut(Option<&mut dyn DiskFile>, usize, u64, usize) -> std::io::Result<()>,
    {
        let read_count: usize = self.limit_range_file(address, count);

        let mut nread: usize = 0;
        while nread < read_count {
            let curr_addr = address + nread as u64;
            let file_offset = self.file_offset_read(curr_addr)?;
            let count = self.limit_range_cluster(curr_addr, read_count - nread);

            if let Some(offset) = file_offset {
                cb(Some(self.raw_file.file_mut()), nread, offset, count)?;
            } else if let Some(backing) = self.backing_file.as_mut() {
                cb(Some(backing.as_mut()), nread, curr_addr, count)?;
            } else {
                cb(None, nread, 0, count)?;
            }

            nread += count;
        }
        Ok(read_count)
    }

    // Writes `count` bytes starting at `address`, calling `cb` repeatedly with the backing file,
    // number of bytes written so far, raw file offset, and number of bytes to write to the file in
    // that invocation.
    fn write_cb<F>(&mut self, address: u64, count: usize, mut cb: F) -> std::io::Result<usize>
    where
        F: FnMut(&mut File, usize, u64, usize) -> std::io::Result<()>,
    {
        let write_count: usize = self.limit_range_file(address, count);

        let mut nwritten: usize = 0;
        while nwritten < write_count {
            let curr_addr = address + nwritten as u64;
            let offset = self.file_offset_write(curr_addr)?;
            let count = self.limit_range_cluster(curr_addr, write_count - nwritten);

            cb(self.raw_file.file_mut(), nwritten, offset, count)?;

            nwritten += count;
        }
        Ok(write_count)
    }
}

impl Drop for QcowFile {
    fn drop(&mut self) {
        let _ = self.sync_caches();
    }
}

impl AsRawDescriptors for QcowFile {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        let mut descriptors = vec![self.raw_file.file().as_raw_descriptor()];
        if let Some(backing) = &self.backing_file {
            descriptors.append(&mut backing.as_raw_descriptors());
        }
        descriptors
    }
}

impl Read for QcowFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len();
        let slice = VolatileSlice::new(buf);
        let read_count = self.read_cb(
            self.current_offset,
            len,
            |file, already_read, offset, count| {
                let sub_slice = slice.get_slice(already_read, count).unwrap();
                match file {
                    Some(f) => f.read_exact_at_volatile(sub_slice, offset),
                    None => {
                        sub_slice.write_bytes(0);
                        Ok(())
                    }
                }
            },
        )?;
        self.current_offset += read_count as u64;
        Ok(read_count)
    }
}

impl Seek for QcowFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_offset: Option<u64> = match pos {
            SeekFrom::Start(off) => Some(off),
            SeekFrom::End(off) => {
                if off < 0 {
                    0i64.checked_sub(off)
                        .and_then(|increment| self.virtual_size().checked_sub(increment as u64))
                } else {
                    self.virtual_size().checked_add(off as u64)
                }
            }
            SeekFrom::Current(off) => {
                if off < 0 {
                    0i64.checked_sub(off)
                        .and_then(|increment| self.current_offset.checked_sub(increment as u64))
                } else {
                    self.current_offset.checked_add(off as u64)
                }
            }
        };

        if let Some(o) = new_offset {
            if o <= self.virtual_size() {
                self.current_offset = o;
                return Ok(o);
            }
        }
        Err(std::io::Error::from_raw_os_error(EINVAL))
    }
}

impl Write for QcowFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let write_count = self.write_cb(
            self.current_offset,
            buf.len(),
            |file, offset, raw_offset, count| {
                file.seek(SeekFrom::Start(raw_offset))?;
                file.write_all(&buf[offset..(offset + count)])
            },
        )?;
        self.current_offset += write_count as u64;
        Ok(write_count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.fsync()
    }
}

impl FileReadWriteAtVolatile for QcowFile {
    fn read_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> io::Result<usize> {
        self.read_cb(offset, slice.size(), |file, read, offset, count| {
            let sub_slice = slice.get_slice(read, count).unwrap();
            match file {
                Some(f) => f.read_exact_at_volatile(sub_slice, offset),
                None => {
                    sub_slice.write_bytes(0);
                    Ok(())
                }
            }
        })
    }

    fn write_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> io::Result<usize> {
        self.write_cb(offset, slice.size(), |file, offset, raw_offset, count| {
            let sub_slice = slice.get_slice(offset, count).unwrap();
            file.write_all_at_volatile(sub_slice, raw_offset)
        })
    }
}

impl FileSync for QcowFile {
    fn fsync(&mut self) -> std::io::Result<()> {
        self.sync_caches()?;
        self.avail_clusters.append(&mut self.unref_clusters);
        Ok(())
    }
}

impl FileSetLen for QcowFile {
    fn set_len(&self, _len: u64) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "set_len() not supported for QcowFile",
        ))
    }
}

impl DiskGetLen for QcowFile {
    fn get_len(&self) -> io::Result<u64> {
        Ok(self.virtual_size())
    }
}

impl FileAllocate for QcowFile {
    fn allocate(&mut self, offset: u64, len: u64) -> io::Result<()> {
        // Call write_cb with a do-nothing callback, which will have the effect
        // of allocating all clusters in the specified range.
        self.write_cb(
            offset,
            len as usize,
            |_file, _offset, _raw_offset, _count| Ok(()),
        )?;
        Ok(())
    }
}

impl PunchHole for QcowFile {
    fn punch_hole(&mut self, offset: u64, length: u64) -> std::io::Result<()> {
        let mut remaining = length;
        let mut offset = offset;
        while remaining > 0 {
            let chunk_length = min(remaining, std::usize::MAX as u64) as usize;
            self.zero_bytes(offset, chunk_length)?;
            remaining -= chunk_length as u64;
            offset += chunk_length as u64;
        }
        Ok(())
    }
}

impl WriteZeroesAt for QcowFile {
    fn write_zeroes_at(&mut self, offset: u64, length: usize) -> io::Result<usize> {
        self.punch_hole(offset, length as u64)?;
        Ok(length)
    }
}

impl ToAsyncDisk for QcowFile {
    fn to_async_disk(self: Box<Self>, ex: &Executor) -> crate::Result<Box<dyn AsyncDisk>> {
        Ok(Box::new(AsyncDiskFileWrapper::new(*self, ex)))
    }
}

// Returns an Error if the given offset doesn't align to a cluster boundary.
fn offset_is_cluster_boundary(offset: u64, cluster_bits: u32) -> Result<()> {
    if offset & ((0x01 << cluster_bits) - 1) != 0 {
        return Err(Error::InvalidOffset(offset));
    }
    Ok(())
}

// Ceiling of the division of `dividend`/`divisor`.
fn div_round_up_u64(dividend: u64, divisor: u64) -> u64 {
    dividend / divisor + u64::from(dividend % divisor != 0)
}

// Ceiling of the division of `dividend`/`divisor`.
fn div_round_up_u32(dividend: u32, divisor: u32) -> u32 {
    dividend / divisor + u32::from(dividend % divisor != 0)
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;

    use tempfile::tempfile;
    use tempfile::TempDir;

    use super::*;
    use crate::MAX_NESTING_DEPTH;

    fn valid_header() -> Vec<u8> {
        vec![
            0x51u8, 0x46, 0x49, 0xfb, // magic
            0x00, 0x00, 0x00, 0x03, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // backing file offset
            0x00, 0x00, 0x00, 0x00, // backing file size
            0x00, 0x00, 0x00, 0x10, // cluster_bits
            0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, // size
            0x00, 0x00, 0x00, 0x00, // crypt method
            0x00, 0x00, 0x01, 0x00, // L1 size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, // L1 table offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // refcount table offset
            0x00, 0x00, 0x00, 0x03, // refcount table clusters
            0x00, 0x00, 0x00, 0x00, // nb snapshots
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, // snapshots offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // incompatible_features
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // compatible_features
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // autoclear_features
            0x00, 0x00, 0x00, 0x04, // refcount_order
            0x00, 0x00, 0x00, 0x68, // header_length
        ]
    }

    // Test case found by clusterfuzz to allocate excessive memory.
    fn test_huge_header() -> Vec<u8> {
        vec![
            0x51, 0x46, 0x49, 0xfb, // magic
            0x00, 0x00, 0x00, 0x03, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // backing file offset
            0x00, 0x00, 0x00, 0x00, // backing file size
            0x00, 0x00, 0x00, 0x09, // cluster_bits
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // size
            0x00, 0x00, 0x00, 0x00, // crypt method
            0x00, 0x00, 0x01, 0x00, // L1 size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, // L1 table offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // refcount table offset
            0x00, 0x00, 0x00, 0x03, // refcount table clusters
            0x00, 0x00, 0x00, 0x00, // nb snapshots
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, // snapshots offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // incompatible_features
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // compatible_features
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // autoclear_features
            0x00, 0x00, 0x00, 0x04, // refcount_order
            0x00, 0x00, 0x00, 0x68, // header_length
        ]
    }

    fn basic_file(header: &[u8]) -> File {
        let mut disk_file = tempfile().expect("failed to create temp file");
        disk_file.write_all(header).unwrap();
        disk_file.set_len(0x8000_0000).unwrap();
        disk_file.seek(SeekFrom::Start(0)).unwrap();
        disk_file
    }

    fn with_basic_file<F>(header: &[u8], mut testfn: F)
    where
        F: FnMut(File),
    {
        testfn(basic_file(header)); // File closed when the function exits.
    }

    fn with_default_file<F>(file_size: u64, mut testfn: F)
    where
        F: FnMut(QcowFile),
    {
        let file = tempfile().expect("failed to create temp file");
        let qcow_file = QcowFile::new(file, file_size).unwrap();

        testfn(qcow_file); // File closed when the function exits.
    }

    // Test helper function to convert a normal slice to a VolatileSlice and write it.
    fn write_all_at(qcow: &mut QcowFile, data: &[u8], offset: u64) -> std::io::Result<()> {
        let mut mem = data.to_owned();
        let vslice = VolatileSlice::new(&mut mem);
        qcow.write_all_at_volatile(vslice, offset)
    }

    // Test helper function to read to a VolatileSlice and copy it to a normal slice.
    fn read_exact_at(qcow: &mut QcowFile, data: &mut [u8], offset: u64) -> std::io::Result<()> {
        let mut mem = data.to_owned();
        let vslice = VolatileSlice::new(&mut mem);
        qcow.read_exact_at_volatile(vslice, offset)?;
        vslice.copy_to(data);
        Ok(())
    }

    #[test]
    fn default_header() {
        let header = QcowHeader::create_for_size_and_path(0x10_0000, None);
        let mut disk_file = tempfile().expect("failed to create temp file");
        header
            .expect("Failed to create header.")
            .write_to(&mut disk_file)
            .expect("Failed to write header to shm.");
        disk_file.seek(SeekFrom::Start(0)).unwrap();
        QcowFile::from(disk_file, MAX_NESTING_DEPTH)
            .expect("Failed to create Qcow from default Header");
    }

    #[test]
    fn header_read() {
        with_basic_file(&valid_header(), |mut disk_file: File| {
            QcowHeader::new(&mut disk_file).expect("Failed to create Header.");
        });
    }

    #[test]
    fn header_with_backing() {
        let header = QcowHeader::create_for_size_and_path(0x10_0000, Some("/my/path/to/a/file"))
            .expect("Failed to create header.");
        let mut disk_file = tempfile().expect("failed to create temp file");
        header
            .write_to(&mut disk_file)
            .expect("Failed to write header to shm.");
        disk_file.seek(SeekFrom::Start(0)).unwrap();
        let read_header = QcowHeader::new(&mut disk_file).expect("Failed to create header.");
        assert_eq!(
            header.backing_file_path,
            Some(String::from("/my/path/to/a/file"))
        );
        assert_eq!(read_header.backing_file_path, header.backing_file_path);
    }

    #[test]
    fn invalid_magic() {
        let invalid_header = vec![0x51u8, 0x46, 0x4a, 0xfb];
        with_basic_file(&invalid_header, |mut disk_file: File| {
            QcowHeader::new(&mut disk_file).expect_err("Invalid header worked.");
        });
    }

    #[test]
    fn invalid_refcount_order() {
        let mut header = valid_header();
        header[99] = 2;
        with_basic_file(&header, |disk_file: File| {
            QcowFile::from(disk_file, MAX_NESTING_DEPTH)
                .expect_err("Invalid refcount order worked.");
        });
    }

    #[test]
    fn invalid_cluster_bits() {
        let mut header = valid_header();
        header[23] = 3;
        with_basic_file(&header, |disk_file: File| {
            QcowFile::from(disk_file, MAX_NESTING_DEPTH).expect_err("Failed to create file.");
        });
    }

    #[test]
    fn test_header_huge_file() {
        let header = test_huge_header();
        with_basic_file(&header, |disk_file: File| {
            QcowFile::from(disk_file, MAX_NESTING_DEPTH).expect_err("Failed to create file.");
        });
    }

    #[test]
    fn test_header_excessive_file_size_rejected() {
        let mut header = valid_header();
        header[24..32].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1e]);
        with_basic_file(&header, |disk_file: File| {
            QcowFile::from(disk_file, MAX_NESTING_DEPTH).expect_err("Failed to create file.");
        });
    }

    #[test]
    fn test_huge_l1_table() {
        let mut header = valid_header();
        header[36] = 0x12;
        with_basic_file(&header, |disk_file: File| {
            QcowFile::from(disk_file, MAX_NESTING_DEPTH).expect_err("Failed to create file.");
        });
    }

    #[test]
    fn test_header_1_tb_file_min_cluster() {
        let mut header = test_huge_header();
        header[24] = 0;
        header[26] = 1;
        header[31] = 0;
        // 1 TB with the min cluster size makes the arrays too big, it should fail.
        with_basic_file(&header, |disk_file: File| {
            QcowFile::from(disk_file, MAX_NESTING_DEPTH).expect_err("Failed to create file.");
        });
    }

    #[cfg_attr(windows, ignore = "TODO(b/257958782): Enable large test on windows")]
    #[test]
    fn test_header_1_tb_file() {
        let mut header = test_huge_header();
        // reset to 1 TB size.
        header[24] = 0;
        header[26] = 1;
        header[31] = 0;
        // set cluster_bits
        header[23] = 16;
        with_basic_file(&header, |disk_file: File| {
            let mut qcow =
                QcowFile::from(disk_file, MAX_NESTING_DEPTH).expect("Failed to create file.");
            let value = 0x0000_0040_3f00_ffffu64;
            write_all_at(&mut qcow, &value.to_le_bytes(), 0x100_0000_0000 - 8)
                .expect("failed to write data");
        });
    }

    #[test]
    fn test_header_huge_num_refcounts() {
        let mut header = valid_header();
        header[56..60].copy_from_slice(&[0x02, 0x00, 0xe8, 0xff]);
        with_basic_file(&header, |disk_file: File| {
            QcowFile::from(disk_file, MAX_NESTING_DEPTH)
                .expect_err("Created disk with excessive refcount clusters");
        });
    }

    #[test]
    fn test_header_huge_refcount_offset() {
        let mut header = valid_header();
        header[48..56].copy_from_slice(&[0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x02, 0x00]);
        with_basic_file(&header, |disk_file: File| {
            QcowFile::from(disk_file, MAX_NESTING_DEPTH)
                .expect_err("Created disk with excessive refcount offset");
        });
    }

    #[cfg_attr(windows, ignore = "TODO(b/257958782): Enable large test on windows")]
    #[test]
    fn write_read_start() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file, MAX_NESTING_DEPTH).unwrap();
            write_all_at(&mut q, b"test first bytes", 0).expect("Failed to write test string.");
            let mut buf = [0u8; 4];
            read_exact_at(&mut q, &mut buf, 0).expect("Failed to read.");
            assert_eq!(&buf, b"test");
        });
    }

    #[cfg_attr(windows, ignore = "TODO(b/257958782): Enable large test on windows")]
    #[test]
    fn write_read_start_backing() {
        let disk_file = basic_file(&valid_header());
        let mut backing = QcowFile::from(disk_file, MAX_NESTING_DEPTH).unwrap();
        write_all_at(&mut backing, b"test first bytes", 0).expect("Failed to write test string.");
        let mut buf = [0u8; 4];
        let wrapping_disk_file = basic_file(&valid_header());
        let mut wrapping = QcowFile::from(wrapping_disk_file, MAX_NESTING_DEPTH).unwrap();
        wrapping.set_backing_file(Some(Box::new(backing)));
        read_exact_at(&mut wrapping, &mut buf, 0).expect("Failed to read.");
        assert_eq!(&buf, b"test");
    }

    #[cfg_attr(windows, ignore = "TODO(b/257958782): Enable large test on windows")]
    #[test]
    fn write_read_start_backing_overlap() {
        let disk_file = basic_file(&valid_header());
        let mut backing = QcowFile::from(disk_file, MAX_NESTING_DEPTH).unwrap();
        write_all_at(&mut backing, b"test first bytes", 0).expect("Failed to write test string.");
        let wrapping_disk_file = basic_file(&valid_header());
        let mut wrapping = QcowFile::from(wrapping_disk_file, MAX_NESTING_DEPTH).unwrap();
        wrapping.set_backing_file(Some(Box::new(backing)));
        write_all_at(&mut wrapping, b"TEST", 0).expect("Failed to write second test string.");
        let mut buf = [0u8; 10];
        read_exact_at(&mut wrapping, &mut buf, 0).expect("Failed to read.");
        assert_eq!(&buf, b"TEST first");
    }

    #[cfg_attr(windows, ignore = "TODO(b/257958782): Enable large test on windows")]
    #[test]
    fn offset_write_read() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file, MAX_NESTING_DEPTH).unwrap();
            let b = [0x55u8; 0x1000];
            write_all_at(&mut q, &b, 0xfff2000).expect("Failed to write test string.");
            let mut buf = [0u8; 4];
            read_exact_at(&mut q, &mut buf, 0xfff2000).expect("Failed to read.");
            assert_eq!(buf[0], 0x55);
        });
    }

    #[cfg_attr(windows, ignore = "TODO(b/257958782): Enable large test on windows")]
    #[test]
    fn write_zeroes_read() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file, MAX_NESTING_DEPTH).unwrap();
            // Write some test data.
            let b = [0x55u8; 0x1000];
            write_all_at(&mut q, &b, 0xfff2000).expect("Failed to write test string.");
            // Overwrite the test data with zeroes.
            q.write_zeroes_all_at(0xfff2000, 0x200)
                .expect("Failed to write zeroes.");
            // Verify that the correct part of the data was zeroed out.
            let mut buf = [0u8; 0x1000];
            read_exact_at(&mut q, &mut buf, 0xfff2000).expect("Failed to read.");
            assert_eq!(buf[0], 0);
            assert_eq!(buf[0x1FF], 0);
            assert_eq!(buf[0x200], 0x55);
            assert_eq!(buf[0xFFF], 0x55);
        });
    }

    #[cfg_attr(windows, ignore = "TODO(b/257958782): Enable large test on windows")]
    #[test]
    fn write_zeroes_full_cluster() {
        // Choose a size that is larger than a cluster.
        // valid_header uses cluster_bits = 12, which corresponds to a cluster size of 4096.
        const CHUNK_SIZE: usize = 4096 * 2 + 512;
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file, MAX_NESTING_DEPTH).unwrap();
            // Write some test data.
            let b = [0x55u8; CHUNK_SIZE];
            write_all_at(&mut q, &b, 0).expect("Failed to write test string.");
            // Overwrite the full cluster with zeroes.
            q.write_zeroes_all_at(0, CHUNK_SIZE)
                .expect("Failed to write zeroes.");
            // Verify that the data was zeroed out.
            let mut buf = [0u8; CHUNK_SIZE];
            read_exact_at(&mut q, &mut buf, 0).expect("Failed to read.");
            assert_eq!(buf[0], 0);
            assert_eq!(buf[CHUNK_SIZE - 1], 0);
        });
    }

    #[cfg_attr(windows, ignore = "TODO(b/257958782): Enable large test on windows")]
    #[test]
    fn write_zeroes_backing() {
        let disk_file = basic_file(&valid_header());
        let mut backing = QcowFile::from(disk_file, MAX_NESTING_DEPTH).unwrap();
        // Write some test data.
        let b = [0x55u8; 0x1000];
        write_all_at(&mut backing, &b, 0xfff2000).expect("Failed to write test string.");
        let wrapping_disk_file = basic_file(&valid_header());
        let mut wrapping = QcowFile::from(wrapping_disk_file, MAX_NESTING_DEPTH).unwrap();
        wrapping.set_backing_file(Some(Box::new(backing)));
        // Overwrite the test data with zeroes.
        // This should allocate new clusters in the wrapping file so that they can be zeroed.
        wrapping
            .write_zeroes_all_at(0xfff2000, 0x200)
            .expect("Failed to write zeroes.");
        // Verify that the correct part of the data was zeroed out.
        let mut buf = [0u8; 0x1000];
        read_exact_at(&mut wrapping, &mut buf, 0xfff2000).expect("Failed to read.");
        assert_eq!(buf[0], 0);
        assert_eq!(buf[0x1FF], 0);
        assert_eq!(buf[0x200], 0x55);
        assert_eq!(buf[0xFFF], 0x55);
    }
    #[test]
    fn test_header() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let q = QcowFile::from(disk_file, MAX_NESTING_DEPTH).unwrap();
            assert_eq!(q.virtual_size(), 0x20_0000_0000);
        });
    }

    #[test]
    fn read_small_buffer() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file, MAX_NESTING_DEPTH).unwrap();
            let mut b = [5u8; 16];
            read_exact_at(&mut q, &mut b, 1000).expect("Failed to read.");
            assert_eq!(0, b[0]);
            assert_eq!(0, b[15]);
        });
    }

    #[cfg_attr(windows, ignore = "TODO(b/257958782): Enable large test on windows")]
    #[test]
    fn replay_ext4() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file, MAX_NESTING_DEPTH).unwrap();
            const BUF_SIZE: usize = 0x1000;
            let mut b = [0u8; BUF_SIZE];

            struct Transfer {
                pub write: bool,
                pub addr: u64,
            }

            // Write transactions from mkfs.ext4.
            let xfers: Vec<Transfer> = vec![
                Transfer {
                    write: false,
                    addr: 0xfff0000,
                },
                Transfer {
                    write: false,
                    addr: 0xfffe000,
                },
                Transfer {
                    write: false,
                    addr: 0x0,
                },
                Transfer {
                    write: false,
                    addr: 0x1000,
                },
                Transfer {
                    write: false,
                    addr: 0xffff000,
                },
                Transfer {
                    write: false,
                    addr: 0xffdf000,
                },
                Transfer {
                    write: false,
                    addr: 0xfff8000,
                },
                Transfer {
                    write: false,
                    addr: 0xffe0000,
                },
                Transfer {
                    write: false,
                    addr: 0xffce000,
                },
                Transfer {
                    write: false,
                    addr: 0xffb6000,
                },
                Transfer {
                    write: false,
                    addr: 0xffab000,
                },
                Transfer {
                    write: false,
                    addr: 0xffa4000,
                },
                Transfer {
                    write: false,
                    addr: 0xff8e000,
                },
                Transfer {
                    write: false,
                    addr: 0xff86000,
                },
                Transfer {
                    write: false,
                    addr: 0xff84000,
                },
                Transfer {
                    write: false,
                    addr: 0xff89000,
                },
                Transfer {
                    write: false,
                    addr: 0xfe7e000,
                },
                Transfer {
                    write: false,
                    addr: 0x100000,
                },
                Transfer {
                    write: false,
                    addr: 0x3000,
                },
                Transfer {
                    write: false,
                    addr: 0x7000,
                },
                Transfer {
                    write: false,
                    addr: 0xf000,
                },
                Transfer {
                    write: false,
                    addr: 0x2000,
                },
                Transfer {
                    write: false,
                    addr: 0x4000,
                },
                Transfer {
                    write: false,
                    addr: 0x5000,
                },
                Transfer {
                    write: false,
                    addr: 0x6000,
                },
                Transfer {
                    write: false,
                    addr: 0x8000,
                },
                Transfer {
                    write: false,
                    addr: 0x9000,
                },
                Transfer {
                    write: false,
                    addr: 0xa000,
                },
                Transfer {
                    write: false,
                    addr: 0xb000,
                },
                Transfer {
                    write: false,
                    addr: 0xc000,
                },
                Transfer {
                    write: false,
                    addr: 0xd000,
                },
                Transfer {
                    write: false,
                    addr: 0xe000,
                },
                Transfer {
                    write: false,
                    addr: 0x10000,
                },
                Transfer {
                    write: false,
                    addr: 0x11000,
                },
                Transfer {
                    write: false,
                    addr: 0x12000,
                },
                Transfer {
                    write: false,
                    addr: 0x13000,
                },
                Transfer {
                    write: false,
                    addr: 0x14000,
                },
                Transfer {
                    write: false,
                    addr: 0x15000,
                },
                Transfer {
                    write: false,
                    addr: 0x16000,
                },
                Transfer {
                    write: false,
                    addr: 0x17000,
                },
                Transfer {
                    write: false,
                    addr: 0x18000,
                },
                Transfer {
                    write: false,
                    addr: 0x19000,
                },
                Transfer {
                    write: false,
                    addr: 0x1a000,
                },
                Transfer {
                    write: false,
                    addr: 0x1b000,
                },
                Transfer {
                    write: false,
                    addr: 0x1c000,
                },
                Transfer {
                    write: false,
                    addr: 0x1d000,
                },
                Transfer {
                    write: false,
                    addr: 0x1e000,
                },
                Transfer {
                    write: false,
                    addr: 0x1f000,
                },
                Transfer {
                    write: false,
                    addr: 0x21000,
                },
                Transfer {
                    write: false,
                    addr: 0x22000,
                },
                Transfer {
                    write: false,
                    addr: 0x24000,
                },
                Transfer {
                    write: false,
                    addr: 0x40000,
                },
                Transfer {
                    write: false,
                    addr: 0x0,
                },
                Transfer {
                    write: false,
                    addr: 0x3000,
                },
                Transfer {
                    write: false,
                    addr: 0x7000,
                },
                Transfer {
                    write: false,
                    addr: 0x0,
                },
                Transfer {
                    write: false,
                    addr: 0x1000,
                },
                Transfer {
                    write: false,
                    addr: 0x2000,
                },
                Transfer {
                    write: false,
                    addr: 0x3000,
                },
                Transfer {
                    write: false,
                    addr: 0x0,
                },
                Transfer {
                    write: false,
                    addr: 0x449000,
                },
                Transfer {
                    write: false,
                    addr: 0x48000,
                },
                Transfer {
                    write: false,
                    addr: 0x48000,
                },
                Transfer {
                    write: false,
                    addr: 0x448000,
                },
                Transfer {
                    write: false,
                    addr: 0x44a000,
                },
                Transfer {
                    write: false,
                    addr: 0x48000,
                },
                Transfer {
                    write: false,
                    addr: 0x48000,
                },
                Transfer {
                    write: true,
                    addr: 0x0,
                },
                Transfer {
                    write: true,
                    addr: 0x448000,
                },
                Transfer {
                    write: true,
                    addr: 0x449000,
                },
                Transfer {
                    write: true,
                    addr: 0x44a000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff0000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff1000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff2000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff3000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff4000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff5000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff6000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff7000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff8000,
                },
                Transfer {
                    write: true,
                    addr: 0xfff9000,
                },
                Transfer {
                    write: true,
                    addr: 0xfffa000,
                },
                Transfer {
                    write: true,
                    addr: 0xfffb000,
                },
                Transfer {
                    write: true,
                    addr: 0xfffc000,
                },
                Transfer {
                    write: true,
                    addr: 0xfffd000,
                },
                Transfer {
                    write: true,
                    addr: 0xfffe000,
                },
                Transfer {
                    write: true,
                    addr: 0xffff000,
                },
            ];

            for xfer in &xfers {
                if xfer.write {
                    write_all_at(&mut q, &b, xfer.addr).expect("Failed to write.");
                } else {
                    read_exact_at(&mut q, &mut b, xfer.addr).expect("Failed to read.");
                }
            }
        });
    }

    #[cfg_attr(windows, ignore = "TODO(b/257958782): Enable large test on windows")]
    #[test]
    fn combo_write_read() {
        with_default_file(1024 * 1024 * 1024 * 256, |mut qcow_file| {
            const NUM_BLOCKS: usize = 55;
            const BLOCK_SIZE: usize = 0x1_0000;
            const OFFSET: u64 = 0x1_0000_0020;
            let data = [0x55u8; BLOCK_SIZE];
            let mut readback = [0u8; BLOCK_SIZE];
            for i in 0..NUM_BLOCKS {
                let seek_offset = OFFSET + (i as u64) * (BLOCK_SIZE as u64);
                write_all_at(&mut qcow_file, &data, seek_offset)
                    .expect("Failed to write test data.");
                // Read back the data to check it was written correctly.
                read_exact_at(&mut qcow_file, &mut readback, seek_offset).expect("Failed to read.");
                for (orig, read) in data.iter().zip(readback.iter()) {
                    assert_eq!(orig, read);
                }
            }
            // Check that address 0 is still zeros.
            read_exact_at(&mut qcow_file, &mut readback, 0).expect("Failed to read.");
            for read in readback.iter() {
                assert_eq!(*read, 0);
            }
            // Check the data again after the writes have happened.
            for i in 0..NUM_BLOCKS {
                let seek_offset = OFFSET + (i as u64) * (BLOCK_SIZE as u64);
                read_exact_at(&mut qcow_file, &mut readback, seek_offset).expect("Failed to read.");
                for (orig, read) in data.iter().zip(readback.iter()) {
                    assert_eq!(orig, read);
                }
            }

            assert_eq!(qcow_file.first_zero_refcount().unwrap(), None);
        });
    }

    #[test]
    fn rebuild_refcounts() {
        with_basic_file(&valid_header(), |mut disk_file: File| {
            let header = QcowHeader::new(&mut disk_file).expect("Failed to create Header.");
            let cluster_size = 65536;
            let mut raw_file =
                QcowRawFile::from(disk_file, cluster_size).expect("Failed to create QcowRawFile.");
            QcowFile::rebuild_refcounts(&mut raw_file, header)
                .expect("Failed to rebuild recounts.");
        });
    }

    #[cfg_attr(windows, ignore = "TODO(b/257958782): Enable large test on windows")]
    #[test]
    fn nested_qcow() {
        let tmp_dir = TempDir::new().unwrap();

        // A file `backing` is backing a qcow file `qcow.l1`, which in turn is backing another
        // qcow file.
        let backing_file_path = tmp_dir.path().join("backing");
        let _backing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&backing_file_path)
            .unwrap();

        let level1_qcow_file_path = tmp_dir.path().join("qcow.l1");
        let level1_qcow_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&level1_qcow_file_path)
            .unwrap();
        let _level1_qcow_file = QcowFile::new_from_backing(
            level1_qcow_file,
            backing_file_path.to_str().unwrap(),
            1000, /* allow deep nesting */
        )
        .unwrap();

        let level2_qcow_file = tempfile().unwrap();
        let _level2_qcow_file = QcowFile::new_from_backing(
            level2_qcow_file,
            level1_qcow_file_path.to_str().unwrap(),
            1000, /* allow deep nesting */
        )
        .expect("failed to create level2 qcow file");
    }

    #[test]
    fn io_seek() {
        with_default_file(1024 * 1024 * 10, |mut qcow_file| {
            // Cursor should start at 0.
            assert_eq!(qcow_file.seek(SeekFrom::Current(0)).unwrap(), 0);

            // Seek 1 MB from start.
            assert_eq!(
                qcow_file.seek(SeekFrom::Start(1024 * 1024)).unwrap(),
                1024 * 1024
            );

            // Rewind 1 MB + 1 byte (past beginning) - seeking to a negative offset is an error and
            // should not move the cursor.
            qcow_file
                .seek(SeekFrom::Current(-(1024 * 1024 + 1)))
                .expect_err("negative offset seek should fail");
            assert_eq!(qcow_file.seek(SeekFrom::Current(0)).unwrap(), 1024 * 1024);

            // Seek to last byte.
            assert_eq!(
                qcow_file.seek(SeekFrom::End(-1)).unwrap(),
                1024 * 1024 * 10 - 1
            );

            // Seek to EOF.
            assert_eq!(qcow_file.seek(SeekFrom::End(0)).unwrap(), 1024 * 1024 * 10);

            // Seek past EOF is not allowed.
            qcow_file
                .seek(SeekFrom::End(1))
                .expect_err("seek past EOF should fail");
        });
    }

    #[test]
    fn io_write_read() {
        with_default_file(1024 * 1024 * 10, |mut qcow_file| {
            const BLOCK_SIZE: usize = 0x1_0000;
            let data_55 = [0x55u8; BLOCK_SIZE];
            let data_aa = [0xaau8; BLOCK_SIZE];
            let mut readback = [0u8; BLOCK_SIZE];

            qcow_file.write_all(&data_55).unwrap();
            assert_eq!(
                qcow_file.seek(SeekFrom::Current(0)).unwrap(),
                BLOCK_SIZE as u64
            );

            qcow_file.write_all(&data_aa).unwrap();
            assert_eq!(
                qcow_file.seek(SeekFrom::Current(0)).unwrap(),
                BLOCK_SIZE as u64 * 2
            );

            // Read BLOCK_SIZE of just 0xaa.
            assert_eq!(
                qcow_file
                    .seek(SeekFrom::Current(-(BLOCK_SIZE as i64)))
                    .unwrap(),
                BLOCK_SIZE as u64
            );
            qcow_file.read_exact(&mut readback).unwrap();
            assert_eq!(
                qcow_file.seek(SeekFrom::Current(0)).unwrap(),
                BLOCK_SIZE as u64 * 2
            );
            for (orig, read) in data_aa.iter().zip(readback.iter()) {
                assert_eq!(orig, read);
            }

            // Read BLOCK_SIZE of just 0x55.
            qcow_file.rewind().unwrap();
            qcow_file.read_exact(&mut readback).unwrap();
            for (orig, read) in data_55.iter().zip(readback.iter()) {
                assert_eq!(orig, read);
            }

            // Read BLOCK_SIZE crossing between the block of 0x55 and 0xaa.
            qcow_file
                .seek(SeekFrom::Start(BLOCK_SIZE as u64 / 2))
                .unwrap();
            qcow_file.read_exact(&mut readback).unwrap();
            for (orig, read) in data_55[BLOCK_SIZE / 2..]
                .iter()
                .chain(data_aa[..BLOCK_SIZE / 2].iter())
                .zip(readback.iter())
            {
                assert_eq!(orig, read);
            }
        });
    }
}
