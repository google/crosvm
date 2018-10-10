// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate byteorder;
extern crate libc;
extern crate sys_util;

mod qcow_raw_file;
mod refcount;
mod vec_cache;

use qcow_raw_file::QcowRawFile;
use refcount::RefCount;
use vec_cache::{CacheMap, Cacheable, VecCache};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use libc::{EINVAL, ENOTSUP};

use std::cmp::min;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};

use sys_util::{fallocate, FallocateMode, SeekHole, WriteZeroes};

#[derive(Debug)]
pub enum Error {
    BackingFilesNotSupported,
    CompressedBlocksNotSupported,
    GettingFileSize(io::Error),
    GettingRefcount(refcount::Error),
    EvictingCache(io::Error),
    InvalidClusterSize,
    InvalidIndex,
    InvalidL1TableOffset,
    InvalidMagic,
    InvalidOffset(u64),
    InvalidRefcountTableOffset,
    NoRefcountClusters,
    OpeningFile(io::Error),
    ReadingHeader(io::Error),
    ReadingPointers(io::Error),
    ReadingRefCounts(io::Error),
    ReadingRefCountBlock(refcount::Error),
    SeekingFile(io::Error),
    SettingRefcountRefcount(io::Error),
    SizeTooSmallForNumberOfClusters,
    WritingHeader(io::Error),
    UnsupportedRefcountOrder,
    UnsupportedVersion(u32),
}
pub type Result<T> = std::result::Result<T, Error>;

// QCOW magic constant that starts the header.
const QCOW_MAGIC: u32 = 0x5146_49fb;
// Default to a cluster size of 2^DEFAULT_CLUSTER_BITS
const DEFAULT_CLUSTER_BITS: u32 = 16;
const MAX_CLUSTER_BITS: u32 = 30;
// Only support 2 byte refcounts, 2^refcount_order bits.
const DEFAULT_REFCOUNT_ORDER: u32 = 4;

const V3_BARE_HEADER_SIZE: u32 = 104;

// bits 0-8 and 56-63 are reserved.
const L1_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L2_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
// Flags
const COMPRESSED_FLAG: u64 = 1 << 62;
const CLUSTER_USED_FLAG: u64 = 1 << 63;

/// Contains the information from the header of a qcow file.
#[derive(Debug)]
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
}

impl QcowHeader {
    /// Creates a QcowHeader from a reference to a file.
    pub fn new(f: &mut File) -> Result<QcowHeader> {
        f.seek(SeekFrom::Start(0)).map_err(Error::ReadingHeader)?;
        let magic = f.read_u32::<BigEndian>().map_err(Error::ReadingHeader)?;
        if magic != QCOW_MAGIC {
            return Err(Error::InvalidMagic);
        }

        // Reads the next u32 from the file.
        fn read_u32_from_file(f: &mut File) -> Result<u32> {
            f.read_u32::<BigEndian>().map_err(Error::ReadingHeader)
        }

        // Reads the next u64 from the file.
        fn read_u64_from_file(f: &mut File) -> Result<u64> {
            f.read_u64::<BigEndian>().map_err(Error::ReadingHeader)
        }

        Ok(QcowHeader {
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
        })
    }

    /// Create a header for the given `size`.
    pub fn create_for_size(size: u64) -> QcowHeader {
        let cluster_bits: u32 = DEFAULT_CLUSTER_BITS;
        let cluster_size: u32 = 0x01 << cluster_bits;
        // L2 blocks are always one cluster long. They contain cluster_size/sizeof(u64) addresses.
        let l2_size: u32 = cluster_size / size_of::<u64>() as u32;
        let num_clusters: u32 = div_round_up_u64(size, u64::from(cluster_size)) as u32;
        let num_l2_clusters: u32 = div_round_up_u32(num_clusters, l2_size);
        let l1_clusters: u32 = div_round_up_u32(num_l2_clusters, cluster_size);
        QcowHeader {
            magic: QCOW_MAGIC,
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
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
                let max_refcount_clusters =
                    max_refcount_clusters(DEFAULT_REFCOUNT_ORDER, cluster_size, num_clusters)
                        as u32;
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
        }
    }

    /// Write the header to `file`.
    pub fn write_to<F: Write + Seek>(&self, file: &mut F) -> Result<()> {
        // Writes the next u32 to the file.
        fn write_u32_to_file<F: Write>(f: &mut F, value: u32) -> Result<()> {
            f.write_u32::<BigEndian>(value)
                .map_err(Error::WritingHeader)
        }

        // Writes the next u64 to the file.
        fn write_u64_to_file<F: Write>(f: &mut F, value: u64) -> Result<()> {
            f.write_u64::<BigEndian>(value)
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

        // Set the file length by seeking and writing a zero to the last byte. This avoids needing
        // a `File` instead of anything that implements seek as the `file` argument.
        // Zeros out the l1 and refcount table clusters.
        let cluster_size = 0x01u64 << self.cluster_bits;
        let refcount_blocks_size = u64::from(self.refcount_table_clusters) * cluster_size;
        file.seek(SeekFrom::Start(
            self.refcount_table_offset + refcount_blocks_size - 2,
        )).map_err(Error::WritingHeader)?;
        file.write(&[0u8]).map_err(Error::WritingHeader)?;

        Ok(())
    }
}

fn max_refcount_clusters(refcount_order: u32, cluster_size: u32, num_clusters: u32) -> usize {
    let refcount_bytes = (0x01u32 << refcount_order) / 8;
    let for_data = div_round_up_u32(num_clusters * refcount_bytes, cluster_size);
    let for_refcounts = div_round_up_u32(for_data * refcount_bytes, cluster_size);
    for_data as usize + for_refcounts as usize
}

/// Represents a qcow2 file. This is a sparse file format maintained by the qemu project.
/// Full documentation of the format can be found in the qemu repository.
///
/// # Example
///
/// ```
/// # use std::io::{Read, Seek, SeekFrom};
/// # use qcow::{self, QcowFile};
/// # fn test(file: std::fs::File) -> std::io::Result<()> {
///     let mut q = QcowFile::from(file).expect("Can't open qcow file");
///     let mut buf = [0u8; 12];
///     q.seek(SeekFrom::Start(10 as u64))?;
///     q.read(&mut buf[..])?;
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
    //TODO(dgreid) Add support for backing files. - backing_file: Option<Box<QcowFile<T>>>,
}

impl QcowFile {
    /// Creates a QcowFile from `file`. File must be a valid qcow2 image.
    pub fn from(mut file: File) -> Result<QcowFile> {
        let header = QcowHeader::new(&mut file)?;

        // Only v3 files are supported.
        if header.version != 3 {
            return Err(Error::UnsupportedVersion(header.version));
        }

        let cluster_bits: u32 = header.cluster_bits;
        if cluster_bits > MAX_CLUSTER_BITS {
            return Err(Error::InvalidClusterSize);
        }
        let cluster_size = 0x01u64 << cluster_bits;
        if cluster_size < size_of::<u64>() as u64 {
            // Can't fit an offset in a cluster, nothing is going to work.
            return Err(Error::InvalidClusterSize);
        }

        // No current support for backing files.
        if header.backing_file_offset != 0 {
            return Err(Error::BackingFilesNotSupported);
        }

        // Only support two byte refcounts.
        let refcount_bits: u64 = 0x01u64
            .checked_shl(header.refcount_order)
            .ok_or(Error::UnsupportedRefcountOrder)?;
        if refcount_bits != 16 {
            return Err(Error::UnsupportedRefcountOrder);
        }

        // Need at least one refcount cluster
        if header.refcount_table_clusters == 0 {
            return Err(Error::NoRefcountClusters);
        }
        offset_is_cluster_boundary(header.backing_file_offset, header.cluster_bits)?;
        offset_is_cluster_boundary(header.l1_table_offset, header.cluster_bits)?;
        offset_is_cluster_boundary(header.refcount_table_offset, header.cluster_bits)?;
        offset_is_cluster_boundary(header.snapshots_offset, header.cluster_bits)?;

        let mut raw_file =
            QcowRawFile::from(file, cluster_size).ok_or(Error::InvalidClusterSize)?;

        let l2_size = cluster_size / size_of::<u64>() as u64;
        let num_clusters = div_round_up_u64(header.size, u64::from(cluster_size));
        let num_l2_clusters = div_round_up_u64(num_clusters, l2_size);
        let l1_table = VecCache::from_vec(
            raw_file
                .read_pointer_table(
                    header.l1_table_offset,
                    num_l2_clusters,
                    Some(L1_TABLE_OFFSET_MASK),
                ).map_err(Error::ReadingHeader)?,
        );

        let num_clusters = div_round_up_u64(header.size, u64::from(cluster_size)) as u32;
        let refcount_clusters =
            max_refcount_clusters(header.refcount_order, cluster_size as u32, num_clusters) as u64;
        let refcount_block_entries = cluster_size * size_of::<u64>() as u64 / refcount_bits;
        let refcounts = RefCount::new(
            &mut raw_file,
            header.refcount_table_offset,
            refcount_clusters,
            refcount_block_entries,
            cluster_size,
        ).map_err(Error::ReadingRefCounts)?;

        let l2_entries = cluster_size / size_of::<u64>() as u64;

        let qcow = QcowFile {
            raw_file,
            header,
            l1_table,
            l2_entries,
            l2_cache: CacheMap::new(100),
            refcounts,
            current_offset: 0,
            unref_clusters: Vec::new(),
            avail_clusters: Vec::new(),
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

        Ok(qcow)
    }

    /// Creates a new QcowFile at the given path.
    pub fn new(mut file: File, virtual_size: u64) -> Result<QcowFile> {
        let header = QcowHeader::create_for_size(virtual_size);
        file.seek(SeekFrom::Start(0)).map_err(Error::SeekingFile)?;
        header.write_to(&mut file)?;

        let mut qcow = Self::from(file)?;

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

    /// Returns the `QcowHeader` for this file.
    pub fn header(&self) -> &QcowHeader {
        &self.header
    }

    /// Returns the L1 lookup table for this file. This is only useful for debugging.
    pub fn l1_table(&self) -> &[u64] {
        &self.l1_table.get_values()
    }

    /// Returns an L2_table of cluster addresses, only used for debugging.
    pub fn l2_table(&mut self, l1_index: usize) -> Result<Option<&[u64]>> {
        let l2_addr_disk = *self.l1_table.get(l1_index).ok_or(Error::InvalidIndex)?;

        if l2_addr_disk == 0 {
            // Reading from an unallocated cluster will return zeros.
            return Ok(None);
        }

        if !self.l2_cache.contains_key(&l1_index) {
            // Not in the cache.
            let table = VecCache::from_vec(
                Self::read_l2_cluster(&mut self.raw_file, l2_addr_disk)
                    .map_err(Error::ReadingPointers)?,
            );
            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache
                .insert(l1_index, table, |index, evicted| {
                    raw_file.write_pointer_table(
                        l1_table[index],
                        evicted.get_values(),
                        CLUSTER_USED_FLAG,
                    )
                }).map_err(Error::EvictingCache)?;
        }

        // The index must exist as it was just inserted if it didn't already.
        Ok(Some(self.l2_cache.get(&l1_index).unwrap().get_values()))
    }

    /// Returns the refcount table for this file. This is only useful for debugging.
    pub fn ref_table(&self) -> &[u64] {
        &self.refcounts.ref_table()
    }

    /// Returns the `index`th refcount block from the file.
    pub fn refcount_block(&mut self, index: usize) -> Result<Option<&[u16]>> {
        self.refcounts
            .refcount_block(&mut self.raw_file, index)
            .map_err(Error::ReadingRefCountBlock)
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
            match self
                .refcounts
                .get_cluster_refcount(&mut self.raw_file, cluster_addr)
                .map_err(Error::GettingRefcount)?
            {
                0 => return Ok(Some(cluster_addr)),
                _ => (),
            }
            cluster_addr += cluster_size;
        }
        Ok(None)
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
            .ok_or(std::io::Error::from_raw_os_error(EINVAL))?;

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
            .ok_or(std::io::Error::from_raw_os_error(EINVAL))?;
        let l2_index = self.l2_table_index(address) as usize;

        let mut set_refcounts = Vec::new();

        if !self.l2_cache.contains_key(&l1_index) {
            // Not in the cache.
            let l2_table = if l2_addr_disk == 0 {
                // Allocate a new cluster to store the L2 table and update the L1 table to point
                // to the new table.
                let new_addr: u64 =
                    Self::get_new_cluster(&mut self.raw_file, &mut self.avail_clusters)?;
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
                // Need to allocate a data cluster
                let cluster_addr = self.append_data_cluster()?;
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
            let new_addr: u64 =
                Self::get_new_cluster(&mut self.raw_file, &mut self.avail_clusters)?;
            // The cluster refcount starts at one indicating it is used but doesn't need
            // COW.
            set_refcounts.push((new_addr, 1));
            self.l1_table[l1_index] = new_addr;
        }
        // 'unwrap' is OK because it was just added.
        self.l2_cache.get_mut(&l1_index).unwrap()[l2_index] = cluster_addr;
        Ok(())
    }

    // Allocate a new cluster at the end of the current file, return the address.
    fn get_new_cluster(
        raw_file: &mut QcowRawFile,
        avail_clusters: &mut Vec<u64>,
    ) -> std::io::Result<u64> {
        // First use a pre allocated cluster if one is available.
        if let Some(free_cluster) = avail_clusters.pop() {
            let cluster_size = raw_file.cluster_size() as usize;
            raw_file.file_mut().seek(SeekFrom::Start(free_cluster))?;
            raw_file.file_mut().write_zeroes(cluster_size)?;
            return Ok(free_cluster);
        }

        raw_file.add_cluster_end()
    }

    // Allocate and initialize a new data cluster. Returns the offset of the
    // cluster in to the file on success.
    fn append_data_cluster(&mut self) -> std::io::Result<u64> {
        let new_addr: u64 = Self::get_new_cluster(&mut self.raw_file, &mut self.avail_clusters)?;
        // The cluster refcount starts at one indicating it is used but doesn't need COW.
        let mut newly_unref = self.set_cluster_refcount(new_addr, 1)?;
        self.unref_clusters.append(&mut newly_unref);
        Ok(new_addr)
    }

    // Returns true if the cluster containing `address` is already allocated.
    fn cluster_allocated(&mut self, address: u64) -> std::io::Result<bool> {
        if address >= self.virtual_size() as u64 {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or(std::io::Error::from_raw_os_error(EINVAL))?;
        let l2_index = self.l2_table_index(address) as usize;

        if l2_addr_disk == 0 {
            // The whole L2 table for this address is not allocated yet,
            // so the cluster must also be unallocated.
            return Ok(false);
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
        // If cluster_addr != 0, the cluster is allocated.
        Ok(cluster_addr != 0)
    }

    // Find the first guest address greater than or equal to `address` whose allocation state
    // matches `allocated`.
    fn find_allocated_cluster(
        &mut self,
        address: u64,
        allocated: bool,
    ) -> std::io::Result<Option<u64>> {
        let size = self.virtual_size();
        if address >= size {
            return Ok(None);
        }

        // If offset is already within a hole, return it.
        if self.cluster_allocated(address)? == allocated {
            return Ok(Some(address));
        }

        // Skip to the next cluster boundary.
        let cluster_size = self.raw_file.cluster_size();
        let mut cluster_addr = (address / cluster_size + 1) * cluster_size;

        // Search for clusters with the desired allocation state.
        while cluster_addr < size {
            if self.cluster_allocated(cluster_addr)? == allocated {
                return Ok(Some(cluster_addr));
            }
            cluster_addr += cluster_size;
        }

        Ok(None)
    }

    // Deallocate the storage for the cluster starting at `address`.
    // Any future reads of this cluster will return all zeroes.
    fn deallocate_cluster(&mut self, address: u64) -> std::io::Result<()> {
        if address >= self.virtual_size() as u64 {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or(std::io::Error::from_raw_os_error(EINVAL))?;
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
            let _ = fallocate(
                self.raw_file.file_mut(),
                FallocateMode::PunchHole,
                true,
                cluster_addr,
                cluster_size,
            );
            self.unref_clusters.push(cluster_addr);
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
                    let addr = Self::get_new_cluster(&mut self.raw_file, &mut self.avail_clusters)?;
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
                &self.l1_table.get_values(),
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
}

impl Drop for QcowFile {
    fn drop(&mut self) {
        let _ = self.sync_caches();
    }
}

impl AsRawFd for QcowFile {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_file.file().as_raw_fd()
    }
}

impl Read for QcowFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let address: u64 = self.current_offset as u64;
        let read_count: usize = self.limit_range_file(address, buf.len());

        let mut nread: usize = 0;
        while nread < read_count {
            let curr_addr = address + nread as u64;
            let file_offset = self.file_offset_read(curr_addr)?;
            let count = self.limit_range_cluster(curr_addr, read_count - nread);

            if let Some(offset) = file_offset {
                self.raw_file.file_mut().seek(SeekFrom::Start(offset))?;
                self.raw_file
                    .file_mut()
                    .read_exact(&mut buf[nread..(nread + count)])?;
            } else {
                // Previously unwritten region, return zeros
                for b in (&mut buf[nread..(nread + count)]).iter_mut() {
                    *b = 0;
                }
            }

            nread += count;
        }
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
        let address: u64 = self.current_offset as u64;
        let write_count: usize = self.limit_range_file(address, buf.len());

        let mut nwritten: usize = 0;
        while nwritten < write_count {
            let curr_addr = address + nwritten as u64;
            let offset = self.file_offset_write(curr_addr)?;
            let count = self.limit_range_cluster(curr_addr, write_count - nwritten);

            if let Err(e) = self.raw_file.file_mut().seek(SeekFrom::Start(offset)) {
                return Err(e);
            }
            if let Err(e) = self
                .raw_file
                .file_mut()
                .write(&buf[nwritten..(nwritten + count)])
            {
                return Err(e);
            }

            nwritten += count;
        }
        self.current_offset += write_count as u64;
        Ok(write_count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sync_caches()?;
        self.avail_clusters.append(&mut self.unref_clusters);
        Ok(())
    }
}

impl WriteZeroes for QcowFile {
    fn write_zeroes(&mut self, length: usize) -> std::io::Result<usize> {
        let address: u64 = self.current_offset as u64;
        let write_count: usize = self.limit_range_file(address, length);

        let mut nwritten: usize = 0;
        while nwritten < write_count {
            let curr_addr = address + nwritten as u64;
            let count = self.limit_range_cluster(curr_addr, write_count - nwritten);

            if count == self.raw_file.cluster_size() as usize {
                // Full cluster - deallocate the storage.
                self.deallocate_cluster(curr_addr)?;
            } else {
                // Partial cluster - zero out the relevant bytes if it was allocated.
                // Any space in unallocated clusters can be left alone, since
                // unallocated clusters already read back as zeroes.
                if let Some(offset) = self.file_offset_read(curr_addr)? {
                    // Partial cluster - zero it out.
                    self.raw_file.file_mut().seek(SeekFrom::Start(offset))?;
                    self.raw_file.file_mut().write_zeroes(count)?;
                }
            }

            nwritten += count;
        }
        self.current_offset += length as u64;
        Ok(length)
    }
}

impl SeekHole for QcowFile {
    fn seek_hole(&mut self, offset: u64) -> io::Result<Option<u64>> {
        match self.find_allocated_cluster(offset, false) {
            Err(e) => Err(e),
            Ok(None) => {
                if offset < self.virtual_size() {
                    Ok(Some(self.seek(SeekFrom::End(0))?))
                } else {
                    Ok(None)
                }
            }
            Ok(Some(o)) => {
                self.seek(SeekFrom::Start(o))?;
                Ok(Some(o))
            }
        }
    }

    fn seek_data(&mut self, offset: u64) -> io::Result<Option<u64>> {
        match self.find_allocated_cluster(offset, true) {
            Err(e) => Err(e),
            Ok(None) => Ok(None),
            Ok(Some(o)) => {
                self.seek(SeekFrom::Start(o))?;
                Ok(Some(o))
            }
        }
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
    (dividend + divisor - 1) / divisor
}

// Ceiling of the division of `dividend`/`divisor`.
fn div_round_up_u32(dividend: u32, divisor: u32) -> u32 {
    (dividend + divisor - 1) / divisor
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use sys_util::SharedMemory;

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

    fn with_basic_file<F>(header: &[u8], mut testfn: F)
    where
        F: FnMut(File),
    {
        let shm = SharedMemory::new(None).unwrap();
        let mut disk_file: File = shm.into();
        disk_file.write_all(&header).unwrap();
        disk_file.set_len(0x5_0000).unwrap();
        disk_file.seek(SeekFrom::Start(0)).unwrap();

        testfn(disk_file); // File closed when the function exits.
    }

    fn with_default_file<F>(file_size: u64, mut testfn: F)
    where
        F: FnMut(QcowFile),
    {
        let shm = SharedMemory::new(None).unwrap();
        let qcow_file = QcowFile::new(shm.into(), file_size).unwrap();

        testfn(qcow_file); // File closed when the function exits.
    }

    #[test]
    fn default_header() {
        let header = QcowHeader::create_for_size(0x10_0000);
        let shm = SharedMemory::new(None).unwrap();
        let mut disk_file: File = shm.into();
        header
            .write_to(&mut disk_file)
            .expect("Failed to write header to shm.");
        disk_file.seek(SeekFrom::Start(0)).unwrap();
        QcowFile::from(disk_file).expect("Failed to create Qcow from default Header");
    }

    #[test]
    fn header_read() {
        with_basic_file(&valid_header(), |mut disk_file: File| {
            QcowHeader::new(&mut disk_file).expect("Failed to create Header.");
        });
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
            QcowFile::from(disk_file).expect_err("Invalid refcount order worked.");
        });
    }

    #[test]
    fn write_read_start() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file).unwrap();
            q.write(b"test first bytes")
                .expect("Failed to write test string.");
            let mut buf = [0u8; 4];
            q.seek(SeekFrom::Start(0)).expect("Failed to seek.");
            q.read(&mut buf).expect("Failed to read.");
            assert_eq!(&buf, b"test");
        });
    }

    #[test]
    fn offset_write_read() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file).unwrap();
            let b = [0x55u8; 0x1000];
            q.seek(SeekFrom::Start(0xfff2000)).expect("Failed to seek.");
            q.write(&b).expect("Failed to write test string.");
            let mut buf = [0u8; 4];
            q.seek(SeekFrom::Start(0xfff2000)).expect("Failed to seek.");
            q.read(&mut buf).expect("Failed to read.");
            assert_eq!(buf[0], 0x55);
        });
    }

    #[test]
    fn write_zeroes_read() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file).unwrap();
            // Write some test data.
            let b = [0x55u8; 0x1000];
            q.seek(SeekFrom::Start(0xfff2000)).expect("Failed to seek.");
            q.write(&b).expect("Failed to write test string.");
            // Overwrite the test data with zeroes.
            q.seek(SeekFrom::Start(0xfff2000)).expect("Failed to seek.");
            let nwritten = q.write_zeroes(0x200).expect("Failed to write zeroes.");
            assert_eq!(nwritten, 0x200);
            // Verify that the correct part of the data was zeroed out.
            let mut buf = [0u8; 0x1000];
            q.seek(SeekFrom::Start(0xfff2000)).expect("Failed to seek.");
            q.read(&mut buf).expect("Failed to read.");
            assert_eq!(buf[0], 0);
            assert_eq!(buf[0x1FF], 0);
            assert_eq!(buf[0x200], 0x55);
            assert_eq!(buf[0xFFF], 0x55);
        });
    }

    #[test]
    fn write_zeroes_full_cluster() {
        // Choose a size that is larger than a cluster.
        // valid_header uses cluster_bits = 12, which corresponds to a cluster size of 4096.
        const CHUNK_SIZE: usize = 4096 * 2 + 512;
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file).unwrap();
            // Write some test data.
            let b = [0x55u8; CHUNK_SIZE];
            q.seek(SeekFrom::Start(0)).expect("Failed to seek.");
            q.write(&b).expect("Failed to write test string.");
            // Overwrite the full cluster with zeroes.
            q.seek(SeekFrom::Start(0)).expect("Failed to seek.");
            let nwritten = q.write_zeroes(CHUNK_SIZE).expect("Failed to write zeroes.");
            assert_eq!(nwritten, CHUNK_SIZE);
            // Verify that the data was zeroed out.
            let mut buf = [0u8; CHUNK_SIZE];
            q.seek(SeekFrom::Start(0)).expect("Failed to seek.");
            q.read(&mut buf).expect("Failed to read.");
            assert_eq!(buf[0], 0);
            assert_eq!(buf[CHUNK_SIZE - 1], 0);
        });
    }

    #[test]
    fn test_header() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let q = QcowFile::from(disk_file).unwrap();
            assert_eq!(q.virtual_size(), 0x20_0000_0000);
        });
    }

    #[test]
    fn read_small_buffer() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file).unwrap();
            let mut b = [5u8; 16];
            q.seek(SeekFrom::Start(1000)).expect("Failed to seek.");
            q.read(&mut b).expect("Failed to read.");
            assert_eq!(0, b[0]);
            assert_eq!(0, b[15]);
        });
    }

    #[test]
    fn replay_ext4() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let mut q = QcowFile::from(disk_file).unwrap();
            const BUF_SIZE: usize = 0x1000;
            let mut b = [0u8; BUF_SIZE];

            struct Transfer {
                pub write: bool,
                pub addr: u64,
            };

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

            for xfer in xfers.iter() {
                q.seek(SeekFrom::Start(xfer.addr)).expect("Failed to seek.");
                if xfer.write {
                    q.write(&b).expect("Failed to write.");
                } else {
                    let read_count: usize = q.read(&mut b).expect("Failed to read.");
                    assert_eq!(read_count, BUF_SIZE);
                }
            }
        });
    }

    #[test]
    fn combo_write_read() {
        with_default_file(1024 * 1024 * 1024 * 256, |mut qcow_file| {
            const NUM_BLOCKS: usize = 555;
            const BLOCK_SIZE: usize = 0x1_0000;
            const OFFSET: usize = 0x1_0000_0020;
            let data = [0x55u8; BLOCK_SIZE];
            let mut readback = [0u8; BLOCK_SIZE];
            for i in 0..NUM_BLOCKS {
                let seek_offset = OFFSET + i * BLOCK_SIZE;
                qcow_file
                    .seek(SeekFrom::Start(seek_offset as u64))
                    .expect("Failed to seek.");
                let nwritten = qcow_file.write(&data).expect("Failed to write test data.");
                assert_eq!(nwritten, BLOCK_SIZE);
                // Read back the data to check it was written correctly.
                qcow_file
                    .seek(SeekFrom::Start(seek_offset as u64))
                    .expect("Failed to seek.");
                let nread = qcow_file.read(&mut readback).expect("Failed to read.");
                assert_eq!(nread, BLOCK_SIZE);
                for (orig, read) in data.iter().zip(readback.iter()) {
                    assert_eq!(orig, read);
                }
            }
            // Check that address 0 is still zeros.
            qcow_file.seek(SeekFrom::Start(0)).expect("Failed to seek.");
            let nread = qcow_file.read(&mut readback).expect("Failed to read.");
            assert_eq!(nread, BLOCK_SIZE);
            for read in readback.iter() {
                assert_eq!(*read, 0);
            }
            // Check the data again after the writes have happened.
            for i in 0..NUM_BLOCKS {
                let seek_offset = OFFSET + i * BLOCK_SIZE;
                qcow_file
                    .seek(SeekFrom::Start(seek_offset as u64))
                    .expect("Failed to seek.");
                let nread = qcow_file.read(&mut readback).expect("Failed to read.");
                assert_eq!(nread, BLOCK_SIZE);
                for (orig, read) in data.iter().zip(readback.iter()) {
                    assert_eq!(orig, read);
                }
            }

            assert_eq!(qcow_file.first_zero_refcount().unwrap(), None);
        });
    }

    fn seek_cur(file: &mut QcowFile) -> u64 {
        file.seek(SeekFrom::Current(0)).unwrap()
    }

    #[test]
    fn seek_data() {
        with_default_file(0x30000, |mut file| {
            // seek_data at or after the end of the file should return None
            assert_eq!(file.seek_data(0x10000).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);
            assert_eq!(file.seek_data(0x10001).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);

            // Write some data to [0x10000, 0x20000)
            let b = [0x55u8; 0x10000];
            file.seek(SeekFrom::Start(0x10000)).unwrap();
            file.write_all(&b).unwrap();
            assert_eq!(file.seek_data(0).unwrap(), Some(0x10000));
            assert_eq!(seek_cur(&mut file), 0x10000);

            // seek_data within data should return the same offset
            assert_eq!(file.seek_data(0x10000).unwrap(), Some(0x10000));
            assert_eq!(seek_cur(&mut file), 0x10000);
            assert_eq!(file.seek_data(0x10001).unwrap(), Some(0x10001));
            assert_eq!(seek_cur(&mut file), 0x10001);
            assert_eq!(file.seek_data(0x1FFFF).unwrap(), Some(0x1FFFF));
            assert_eq!(seek_cur(&mut file), 0x1FFFF);

            assert_eq!(file.seek_data(0).unwrap(), Some(0x10000));
            assert_eq!(seek_cur(&mut file), 0x10000);
            assert_eq!(file.seek_data(0x1FFFF).unwrap(), Some(0x1FFFF));
            assert_eq!(seek_cur(&mut file), 0x1FFFF);
            assert_eq!(file.seek_data(0x20000).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0x1FFFF);
        });
    }

    #[test]
    fn seek_hole() {
        with_default_file(0x30000, |mut file| {
            // File consisting entirely of a hole
            assert_eq!(file.seek_hole(0).unwrap(), Some(0));
            assert_eq!(seek_cur(&mut file), 0);
            assert_eq!(file.seek_hole(0xFFFF).unwrap(), Some(0xFFFF));
            assert_eq!(seek_cur(&mut file), 0xFFFF);

            // seek_hole at or after the end of the file should return None
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0x30000).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);
            assert_eq!(file.seek_hole(0x30001).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);

            // Write some data to [0x10000, 0x20000)
            let b = [0x55u8; 0x10000];
            file.seek(SeekFrom::Start(0x10000)).unwrap();
            file.write_all(&b).unwrap();

            // seek_hole within a hole should return the same offset
            assert_eq!(file.seek_hole(0).unwrap(), Some(0));
            assert_eq!(seek_cur(&mut file), 0);
            assert_eq!(file.seek_hole(0xFFFF).unwrap(), Some(0xFFFF));
            assert_eq!(seek_cur(&mut file), 0xFFFF);

            // seek_hole within data should return the next hole
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0x10000).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0x10001).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0x1FFFF).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0xFFFF).unwrap(), Some(0xFFFF));
            assert_eq!(seek_cur(&mut file), 0xFFFF);
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0x10000).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0x1FFFF).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0x20000).unwrap(), Some(0x20000));
            assert_eq!(seek_cur(&mut file), 0x20000);
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0x20001).unwrap(), Some(0x20001));
            assert_eq!(seek_cur(&mut file), 0x20001);

            // seek_hole at EOF should return None
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0x30000).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);

            // Write some data to [0x20000, 0x30000)
            file.seek(SeekFrom::Start(0x20000)).unwrap();
            file.write_all(&b).unwrap();

            // seek_hole within [0x20000, 0x30000) should now find the hole at EOF
            assert_eq!(file.seek_hole(0x20000).unwrap(), Some(0x30000));
            assert_eq!(seek_cur(&mut file), 0x30000);
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0x20001).unwrap(), Some(0x30000));
            assert_eq!(seek_cur(&mut file), 0x30000);
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.seek_hole(0x30000).unwrap(), None);
            assert_eq!(seek_cur(&mut file), 0);
        });
    }
}
