// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate byteorder;
extern crate libc;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use libc::{EINVAL, ENOTSUP};

use std::cmp::min;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};

#[derive(Debug)]
pub enum Error {
    BackingFilesNotSupported,
    InvalidClusterSize,
    InvalidL1TableOffset,
    InvalidMagic,
    InvalidOffset(u64),
    InvalidRefcountTableOffset,
    NoRefcountClusters,
    ReadingHeader(io::Error),
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
            magic: magic,
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
        let num_clusters: u32 = div_round_up_u64(size, cluster_size as u64) as u32;
        let num_l2_clusters: u32 = div_round_up_u32(num_clusters, l2_size);
        let l1_clusters: u32 = div_round_up_u32(num_l2_clusters, cluster_size);
        QcowHeader {
            magic: QCOW_MAGIC,
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: DEFAULT_CLUSTER_BITS,
            size: size,
            crypt_method: 0,
            l1_size: num_l2_clusters,
            l1_table_offset: cluster_size as u64,
            refcount_table_offset: (cluster_size * (l1_clusters + 1)) as u64, // After l1 + header.
            refcount_table_clusters: {
                let refcount_bytes = (0x01 << DEFAULT_CLUSTER_BITS) / 8;
                let refcounts_per_cluster = cluster_size / refcount_bytes;
                div_round_up_u32(num_clusters, refcounts_per_cluster)
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
    pub fn write_to<F: Write>(&self, file: &mut F) -> Result<()> {
        // Writes the next u32 to the file.
        fn write_u32_to_file<F: Write>(f: &mut F, value: u32) -> Result<()> {
            f.write_u32::<BigEndian>(value).map_err(Error::WritingHeader)
        }

        // Writes the next u64 to the file.
        fn write_u64_to_file<F: Write>(f: &mut F, value: u64) -> Result<()> {
            f.write_u64::<BigEndian>(value).map_err(Error::WritingHeader)
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
        Ok(())
    }
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
    file: File,
    header: QcowHeader,
    l2_entries: u64,
    cluster_size: u64,
    cluster_mask: u64,
    current_offset: u64,
    refcount_bits: u64,
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

        let qcow = QcowFile {
            file: file,
            header: header,
            l2_entries: cluster_size / size_of::<u64>() as u64,
            cluster_size: cluster_size,
            cluster_mask: cluster_size - 1,
            current_offset: 0,
            refcount_bits: refcount_bits,
        };

        // Check that the L1 and refcount tables fit in a 64bit address space.
        qcow.header.l1_table_offset
            .checked_add(qcow.l1_address_offset(qcow.virtual_size()))
            .ok_or(Error::InvalidL1TableOffset)?;
        qcow.header.refcount_table_offset
            .checked_add(qcow.header.refcount_table_clusters as u64 * qcow.cluster_size)
            .ok_or(Error::InvalidRefcountTableOffset)?;

        Ok(qcow)
    }

    // Limits the range so that it doesn't exceed the virtual size of the file.
    fn limit_range_file(&self, address: u64, count: usize) -> usize {
        if address.checked_add(count as u64).is_none() || address > self.virtual_size() {
            return 0;
        }
        min(count, self.virtual_size() as usize - address as usize)
    }

    // Limits the range so that it doesn't overflow the end of a cluster.
    fn limit_range_cluster(&self, address: u64, count: usize) -> usize {
        let offset: u64 = address & self.cluster_mask;
        let limit = self.cluster_size - offset;
        min(count, limit as usize)
    }

    // Gets the maximum virtual size of this image.
    fn virtual_size(&self) -> u64 {
        self.header.size
    }

    // Gets the offset of `address` in the L1 table.
    fn l1_address_offset(&self, address: u64) -> u64 {
        let l1_index = (address / self.cluster_size) / self.l2_entries;
        l1_index * size_of::<u64>() as u64
    }

    // Gets the offset of `address` in the L2 table.
    fn l2_address_offset(&self, address: u64) -> u64 {
        let l2_index = (address / self.cluster_size) % self.l2_entries;
        l2_index * size_of::<u64>() as u64
    }

    // Returns the offset of address within a cluster.
    fn cluster_offset(&self, address: u64) -> u64 {
        address & self.cluster_mask
    }

    // Returns the file offset for the given `address`. If `address` doesn't
    // have a cluster allocated, the behavior is determined by the `allocate`
    // argument. If `allocate` is true, then allocate the cluster and return the
    // new offset, otherwise return None.  Returns an error if the address is
    // beyond the end or there is an issue accessing the file.
    fn file_offset(&mut self, address: u64, allocate: bool) -> std::io::Result<Option<u64>> {
        if address >= self.virtual_size() as u64 {
            return Err(std::io::Error::from_raw_os_error(EINVAL));
        }

        let l1_entry_offset: u64 = self.header.l1_table_offset + self.l1_address_offset(address);
        if l1_entry_offset >= self.file.metadata()?.len() {
            // L1 table is not allocated in image. No data has ever been written.
            if allocate {
                self.file.set_len(
                    self.header.l1_table_offset +
                        self.l1_address_offset(self.virtual_size()),
                )?;
            } else {
                return Ok(None);
            }
        }
        let l2_addr_disk = read_u64_from_offset(&mut self.file, l1_entry_offset)?;
        if l2_addr_disk & COMPRESSED_FLAG != 0 {
            return Err(std::io::Error::from_raw_os_error(ENOTSUP));
        }
        let l2_addr_from_table: u64 = l2_addr_disk & L1_TABLE_OFFSET_MASK;
        let l2_addr = if l2_addr_from_table == 0 {
            if allocate {
                self.append_data_cluster(l1_entry_offset)?
            } else {
                return Ok(None);
            }
        } else {
            l2_addr_from_table
        };
        let l2_entry_addr: u64 = l2_addr + self.l2_address_offset(address);
        let cluster_addr_disk: u64 = read_u64_from_offset(&mut self.file, l2_entry_addr)?;
        let cluster_addr_from_table: u64 = cluster_addr_disk & L2_TABLE_OFFSET_MASK;
        let cluster_addr = if cluster_addr_from_table == 0 {
            if allocate {
                self.append_data_cluster(l2_entry_addr)?
            } else {
                return Ok(None);
            }
        } else {
            cluster_addr_from_table
        };
        Ok(Some(cluster_addr + self.cluster_offset(address)))
    }

    // Allocate a new cluster at the end of the current file, return the address.
    fn append_new_cluster(&mut self) -> std::io::Result<u64> {
        // Determine where the new end of the file should be and set_len, which
        // translates to truncate(2).
        let file_end: u64 = self.file.seek(SeekFrom::End(0))?;
        let cluster_size: u64 = self.cluster_size;
        let new_cluster_address: u64 = (file_end + cluster_size - 1) & !self.cluster_mask;
        self.file.set_len(new_cluster_address + cluster_size)?;

        Ok(new_cluster_address)
    }

    // Allocate and initialize a new data cluster. Returns the offset of the
    // cluster in to the file on success. Write the address to the offset in
    // `entry_addr` to fill in the L1 or L2 table.
    fn append_data_cluster(&mut self, entry_addr: u64) -> std::io::Result<u64> {
        let new_addr: u64 = self.append_new_cluster()?;
        // Save the new block to the table and mark it as used.
        write_u64_to_offset(&mut self.file, entry_addr, new_addr | CLUSTER_USED_FLAG)?;
        // The cluster refcount starts at one indicating it is used but doesn't need COW.
        self.set_cluster_refcount(new_addr, 1)?;
        Ok(new_addr)
    }

    // Set the refcount for a cluster with the given address.
    fn set_cluster_refcount(&mut self, address: u64, refcount: u16) -> std::io::Result<()> {
        let cluster_size: u64 = self.cluster_size;
        let refcount_block_entries = cluster_size * size_of::<u64>() as u64 / self.refcount_bits;
        let refcount_block_index = (address / cluster_size) % refcount_block_entries;
        let refcount_table_index = (address / cluster_size) / refcount_block_entries;
        let refcount_block_entry_addr =
            self.header.refcount_table_offset + refcount_table_index * size_of::<u64>() as u64;
        let refcount_block_address_from_file =
            read_u64_from_offset(&mut self.file, refcount_block_entry_addr)?;
        let refcount_block_address = if refcount_block_address_from_file == 0 {
            let new_addr = self.append_new_cluster()?;
            write_u64_to_offset(&mut self.file, refcount_block_entry_addr, new_addr)?;
            self.set_cluster_refcount(new_addr, 1)?;
            new_addr
        } else {
            refcount_block_address_from_file
        };
        let refcount_address: u64 = refcount_block_address
                .checked_add(refcount_block_index * 2)
                .ok_or(std::io::Error::from_raw_os_error(EINVAL))?;
        self.file.seek(SeekFrom::Start(refcount_address))?;
        self.file.write_u16::<BigEndian>(refcount)
    }
}

impl AsRawFd for QcowFile {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Read for QcowFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let address: u64 = self.current_offset as u64;
        let read_count: usize = self.limit_range_file(address, buf.len());

        let mut nread: usize = 0;
        while nread < read_count {
            let file_offset = self.file_offset(address + nread as u64, false)?;
            let count = self.limit_range_cluster(address, read_count - nread);

            if let Some(offset) = file_offset {
                self.file.seek(SeekFrom::Start(offset))?;
                self.file.read(&mut buf[nread..(nread + count)])?;
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
                    0i64.checked_sub(off).and_then(|increment| {
                        self.virtual_size().checked_sub(increment as u64)
                    })
                } else {
                    self.virtual_size().checked_add(off as u64)
                }
            }
            SeekFrom::Current(off) => {
                if off < 0 {
                    0i64.checked_sub(off).and_then(|increment| {
                        self.current_offset.checked_sub(increment as u64)
                    })
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
            // file_offset always returns an address when allocate == true.
            let offset = self.file_offset(address + nwritten as u64, true)?.unwrap();
            let count = self.limit_range_cluster(address, write_count - nwritten);

            if let Err(e) = self.file.seek(SeekFrom::Start(offset)) {
                return Err(e);
            }
            if let Err(e) = self.file.write(&buf[nwritten..(nwritten + count)]) {
                return Err(e);
            }

            nwritten += count;
        }
        self.current_offset += write_count as u64;
        Ok(write_count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

// Returns an Error if the given offset doesn't align to a cluster boundary.
fn offset_is_cluster_boundary(offset: u64, cluster_bits: u32) -> Result<()> {
    if offset & ((0x01 << cluster_bits) - 1) != 0 {
        return Err(Error::InvalidOffset(offset));
    }
    Ok(())
}

// Reads a big endian 64 bit number from `offset`.
fn read_u64_from_offset(f: &mut File, offset: u64) -> std::io::Result<u64> {
    f.seek(SeekFrom::Start(offset))?;
    f.read_u64::<BigEndian>()
}

// Writes a big endian 64 bit number to `offset`.
fn write_u64_to_offset(f: &mut File, offset: u64, value: u64) -> std::io::Result<()> {
    f.seek(SeekFrom::Start(offset))?;
    f.write_u64::<BigEndian>(value)
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
extern crate sys_util;

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use super::*;
    use sys_util::SharedMemory;

    fn valid_header() -> Vec<u8> {
        vec![
            0x51u8, 0x46, 0x49, 0xfb, // magic
            0x00, 0x00, 0x00, 0x03, // version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // backing file offset
            0x00, 0x00, 0x00, 0x00, // backing file size
            0x00, 0x00, 0x00, 0x0c, // cluster_bits
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // size
            0x00, 0x00, 0x00, 0x00, // crypt method
            0x00, 0x00, 0x00, 0x00, // L1 size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, // L1 table offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // refcount table offset
            0x00, 0x00, 0x00, 0x01, // refcount table clusters
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
        disk_file.seek(SeekFrom::Start(0)).unwrap();

        testfn(disk_file); // File closed when the function exits.
    }

    #[test]
    fn default_header() {
        let header = QcowHeader::create_for_size(0x10_0000);
        let shm = SharedMemory::new(None).unwrap();
        let mut disk_file: File = shm.into();
        header.write_to(&mut disk_file).expect("Failed to write header to shm.");
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
        let invalid_header = vec![0x51u8, 0x46, 0x49, 0xfb];
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
            q.write(b"test first bytes").expect(
                "Failed to write test string.",
            );
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
    fn test_header() {
        with_basic_file(&valid_header(), |disk_file: File| {
            let q = QcowFile::from(disk_file).unwrap();
            assert_eq!(q.virtual_size(), 0x1000_0000);
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
                Transfer {write: false, addr: 0xfff0000},
                Transfer {write: false, addr: 0xfffe000},
                Transfer {write: false, addr: 0x0},
                Transfer {write: false, addr: 0x1000},
                Transfer {write: false, addr: 0xffff000},
                Transfer {write: false, addr: 0xffdf000},
                Transfer {write: false, addr: 0xfff8000},
                Transfer {write: false, addr: 0xffe0000},
                Transfer {write: false, addr: 0xffce000},
                Transfer {write: false, addr: 0xffb6000},
                Transfer {write: false, addr: 0xffab000},
                Transfer {write: false, addr: 0xffa4000},
                Transfer {write: false, addr: 0xff8e000},
                Transfer {write: false, addr: 0xff86000},
                Transfer {write: false, addr: 0xff84000},
                Transfer {write: false, addr: 0xff89000},
                Transfer {write: false, addr: 0xfe7e000},
                Transfer {write: false, addr: 0x100000},
                Transfer {write: false, addr: 0x3000},
                Transfer {write: false, addr: 0x7000},
                Transfer {write: false, addr: 0xf000},
                Transfer {write: false, addr: 0x2000},
                Transfer {write: false, addr: 0x4000},
                Transfer {write: false, addr: 0x5000},
                Transfer {write: false, addr: 0x6000},
                Transfer {write: false, addr: 0x8000},
                Transfer {write: false, addr: 0x9000},
                Transfer {write: false, addr: 0xa000},
                Transfer {write: false, addr: 0xb000},
                Transfer {write: false, addr: 0xc000},
                Transfer {write: false, addr: 0xd000},
                Transfer {write: false, addr: 0xe000},
                Transfer {write: false, addr: 0x10000},
                Transfer {write: false, addr: 0x11000},
                Transfer {write: false, addr: 0x12000},
                Transfer {write: false, addr: 0x13000},
                Transfer {write: false, addr: 0x14000},
                Transfer {write: false, addr: 0x15000},
                Transfer {write: false, addr: 0x16000},
                Transfer {write: false, addr: 0x17000},
                Transfer {write: false, addr: 0x18000},
                Transfer {write: false, addr: 0x19000},
                Transfer {write: false, addr: 0x1a000},
                Transfer {write: false, addr: 0x1b000},
                Transfer {write: false, addr: 0x1c000},
                Transfer {write: false, addr: 0x1d000},
                Transfer {write: false, addr: 0x1e000},
                Transfer {write: false, addr: 0x1f000},
                Transfer {write: false, addr: 0x21000},
                Transfer {write: false, addr: 0x22000},
                Transfer {write: false, addr: 0x24000},
                Transfer {write: false, addr: 0x40000},
                Transfer {write: false, addr: 0x0},
                Transfer {write: false, addr: 0x3000},
                Transfer {write: false, addr: 0x7000},
                Transfer {write: false, addr: 0x0},
                Transfer {write: false, addr: 0x1000},
                Transfer {write: false, addr: 0x2000},
                Transfer {write: false, addr: 0x3000},
                Transfer {write: false, addr: 0x0},
                Transfer {write: false, addr: 0x449000},
                Transfer {write: false, addr: 0x48000},
                Transfer {write: false, addr: 0x48000},
                Transfer {write: false, addr: 0x448000},
                Transfer {write: false, addr: 0x44a000},
                Transfer {write: false, addr: 0x48000},
                Transfer {write: false, addr: 0x48000},
                Transfer {write: true, addr: 0x0},
                Transfer {write: true, addr: 0x448000},
                Transfer {write: true, addr: 0x449000},
                Transfer {write: true, addr: 0x44a000},
                Transfer {write: true, addr: 0xfff0000},
                Transfer {write: true, addr: 0xfff1000},
                Transfer {write: true, addr: 0xfff2000},
                Transfer {write: true, addr: 0xfff3000},
                Transfer {write: true, addr: 0xfff4000},
                Transfer {write: true, addr: 0xfff5000},
                Transfer {write: true, addr: 0xfff6000},
                Transfer {write: true, addr: 0xfff7000},
                Transfer {write: true, addr: 0xfff8000},
                Transfer {write: true, addr: 0xfff9000},
                Transfer {write: true, addr: 0xfffa000},
                Transfer {write: true, addr: 0xfffb000},
                Transfer {write: true, addr: 0xfffc000},
                Transfer {write: true, addr: 0xfffd000},
                Transfer {write: true, addr: 0xfffe000},
                Transfer {write: true, addr: 0xffff000},
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
}
