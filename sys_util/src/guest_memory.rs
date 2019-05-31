// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Track memory regions that are mapped to the guest VM.

use std::ffi::CStr;
use std::fmt::{self, Display};
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::Arc;

use crate::guest_address::GuestAddress;
use crate::mmap::{self, MemoryMapping};
use crate::shm::{MemfdSeals, SharedMemory};
use crate::{errno, pagesize};
use data_model::volatile_memory::*;
use data_model::DataInit;

#[derive(Debug)]
pub enum Error {
    InvalidGuestAddress(GuestAddress),
    MemoryAccess(GuestAddress, mmap::Error),
    MemoryMappingFailed(mmap::Error),
    MemoryRegionOverlap,
    MemoryNotAligned,
    MemoryCreationFailed(errno::Error),
    MemorySetSizeFailed(errno::Error),
    MemoryAddSealsFailed(errno::Error),
    ShortWrite { expected: usize, completed: usize },
    ShortRead { expected: usize, completed: usize },
}
pub type Result<T> = result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            InvalidGuestAddress(addr) => write!(f, "invalid guest address {}", addr),
            MemoryAccess(addr, e) => {
                write!(f, "invalid guest memory access at addr={}: {}", addr, e)
            }
            MemoryMappingFailed(e) => write!(f, "failed to map guest memory: {}", e),
            MemoryRegionOverlap => write!(f, "memory regions overlap"),
            MemoryNotAligned => write!(f, "memfd regions must be page aligned"),
            MemoryCreationFailed(_) => write!(f, "failed to create memfd region"),
            MemorySetSizeFailed(e) => write!(f, "failed to set memfd region size: {}", e),
            MemoryAddSealsFailed(e) => write!(f, "failed to set seals on memfd region: {}", e),
            ShortWrite {
                expected,
                completed,
            } => write!(
                f,
                "incomplete write of {} instead of {} bytes",
                completed, expected,
            ),
            ShortRead {
                expected,
                completed,
            } => write!(
                f,
                "incomplete read of {} instead of {} bytes",
                completed, expected,
            ),
        }
    }
}

struct MemoryRegion {
    mapping: MemoryMapping,
    guest_base: GuestAddress,
    memfd_offset: usize,
}

fn region_end(region: &MemoryRegion) -> GuestAddress {
    // unchecked_add is safe as the region bounds were checked when it was created.
    region
        .guest_base
        .unchecked_add(region.mapping.size() as u64)
}

/// Tracks a memory region and where it is mapped in the guest, along with a shm
/// fd of the underlying memory regions.
#[derive(Clone)]
pub struct GuestMemory {
    regions: Arc<Vec<MemoryRegion>>,
    memfd: Option<Arc<SharedMemory>>,
}

impl AsRawFd for GuestMemory {
    fn as_raw_fd(&self) -> RawFd {
        match &self.memfd {
            Some(memfd) => memfd.as_raw_fd(),
            None => panic!("GuestMemory is not backed by a memfd"),
        }
    }
}

impl GuestMemory {
    /// Creates backing memfd for GuestMemory regions
    fn create_memfd(ranges: &[(GuestAddress, u64)]) -> Result<SharedMemory> {
        let mut aligned_size = 0;
        let pg_size = pagesize();
        for range in ranges {
            if range.1 % pg_size as u64 != 0 {
                return Err(Error::MemoryNotAligned);
            }

            aligned_size += range.1;
        }

        let mut seals = MemfdSeals::new();

        seals.set_shrink_seal();
        seals.set_grow_seal();
        seals.set_seal_seal();

        let mut memfd =
            SharedMemory::new(Some(CStr::from_bytes_with_nul(b"crosvm_guest\0").unwrap()))
                .map_err(Error::MemoryCreationFailed)?;
        memfd
            .set_size(aligned_size)
            .map_err(Error::MemorySetSizeFailed)?;
        memfd
            .add_seals(seals)
            .map_err(Error::MemoryAddSealsFailed)?;

        Ok(memfd)
    }

    /// Creates a container for guest memory regions.
    /// Valid memory regions are specified as a Vec of (Address, Size) tuples sorted by Address.
    pub fn new(ranges: &[(GuestAddress, u64)]) -> Result<GuestMemory> {
        // Create memfd

        // TODO(prilik) remove optional memfd once parallel CQ lands (crbug.com/942183).
        // Many classic CQ builders run old kernels without memfd support, resulting in test
        // failures. It's less effort to introduce this temporary optional path than to
        // manually mark all affected tests as ignore.
        let memfd = match GuestMemory::create_memfd(ranges) {
            Err(Error::MemoryCreationFailed { .. }) => {
                warn!("GuestMemory is not backed by a memfd");
                None
            }
            Err(e) => return Err(e),
            Ok(memfd) => Some(memfd),
        };

        // Create memory regions
        let mut regions = Vec::<MemoryRegion>::new();
        let mut offset = 0;

        for range in ranges {
            if let Some(last) = regions.last() {
                if last
                    .guest_base
                    .checked_add(last.mapping.size() as u64)
                    .map_or(true, |a| a > range.0)
                {
                    return Err(Error::MemoryRegionOverlap);
                }
            }

            let mapping = match &memfd {
                Some(memfd) => MemoryMapping::from_fd_offset(memfd, range.1 as usize, offset),
                None => MemoryMapping::new(range.1 as usize),
            }
            .map_err(Error::MemoryMappingFailed)?;

            regions.push(MemoryRegion {
                mapping,
                guest_base: range.0,
                memfd_offset: offset,
            });

            offset += range.1 as usize;
        }

        Ok(GuestMemory {
            regions: Arc::new(regions),
            memfd: match memfd {
                Some(memfd) => Some(Arc::new(memfd)),
                None => None,
            },
        })
    }

    /// Returns the end address of memory.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_end_addr() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     assert_eq!(start_addr.checked_add(0x400), Some(gm.end_addr()));
    ///     Ok(())
    /// # }
    /// ```
    pub fn end_addr(&self) -> GuestAddress {
        self.regions
            .iter()
            .max_by_key(|region| region.guest_base)
            .map_or(GuestAddress(0), |region| region_end(region))
    }

    /// Returns the total size of memory in bytes.
    pub fn memory_size(&self) -> u64 {
        self.regions
            .iter()
            .map(|region| region.mapping.size() as u64)
            .sum()
    }

    /// Returns true if the given address is within the memory range available to the guest.
    pub fn address_in_range(&self, addr: GuestAddress) -> bool {
        addr < self.end_addr()
    }

    /// Returns the address plus the offset if it is in range.
    pub fn checked_offset(&self, addr: GuestAddress, offset: u64) -> Option<GuestAddress> {
        addr.checked_add(offset)
            .and_then(|a| if a < self.end_addr() { Some(a) } else { None })
    }

    /// Returns the size of the memory region in bytes.
    pub fn num_regions(&self) -> u64 {
        self.regions.len() as u64
    }

    /// Madvise away the address range in the host that is associated with the given guest range.
    pub fn remove_range(&self, addr: GuestAddress, count: u64) -> Result<()> {
        self.do_in_region(addr, move |mapping, offset| {
            mapping
                .remove_range(offset, count as usize)
                .map_err(|e| Error::MemoryAccess(addr, e))
        })
    }

    /// Perform the specified action on each region's addresses.
    ///
    /// Callback is called with arguments:
    ///  * index: usize
    ///  * guest_addr : GuestAddress
    ///  * size: usize
    ///  * host_addr: usize
    ///  * memfd_offset: usize
    pub fn with_regions<F, E>(&self, mut cb: F) -> result::Result<(), E>
    where
        F: FnMut(usize, GuestAddress, usize, usize, usize) -> result::Result<(), E>,
    {
        for (index, region) in self.regions.iter().enumerate() {
            cb(
                index,
                region.guest_base,
                region.mapping.size(),
                region.mapping.as_ptr() as usize,
                region.memfd_offset,
            )?;
        }
        Ok(())
    }

    /// Writes a slice to guest memory at the specified guest address.
    /// Returns the number of bytes written.  The number of bytes written can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Write a slice at guestaddress 0x200.
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let res = gm.write_at_addr(&[1,2,3,4,5], GuestAddress(0x200)).map_err(|_| ())?;
    ///     assert_eq!(5, res);
    ///     Ok(())
    /// # }
    /// ```
    pub fn write_at_addr(&self, buf: &[u8], guest_addr: GuestAddress) -> Result<usize> {
        self.do_in_region(guest_addr, move |mapping, offset| {
            mapping
                .write_slice(buf, offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Writes the entire contents of a slice to guest memory at the specified
    /// guest address.
    ///
    /// Returns an error if there isn't enough room in the memory region to
    /// complete the entire write. Part of the data may have been written
    /// nevertheless.
    ///
    /// # Examples
    ///
    /// ```
    /// use sys_util::{guest_memory, GuestAddress, GuestMemory};
    ///
    /// fn test_write_all() -> guest_memory::Result<()> {
    ///     let ranges = &[(GuestAddress(0x1000), 0x400)];
    ///     let gm = GuestMemory::new(ranges)?;
    ///     gm.write_all_at_addr(b"zyxwvut", GuestAddress(0x1200))
    /// }
    /// ```
    pub fn write_all_at_addr(&self, buf: &[u8], guest_addr: GuestAddress) -> Result<()> {
        let expected = buf.len();
        let completed = self.write_at_addr(buf, guest_addr)?;
        if expected == completed {
            Ok(())
        } else {
            Err(Error::ShortWrite {
                expected,
                completed,
            })
        }
    }

    /// Reads to a slice from guest memory at the specified guest address.
    /// Returns the number of bytes read.  The number of bytes read can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Read a slice of length 16 at guestaddress 0x200.
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let buf = &mut [0u8; 16];
    ///     let res = gm.read_at_addr(buf, GuestAddress(0x200)).map_err(|_| ())?;
    ///     assert_eq!(16, res);
    ///     Ok(())
    /// # }
    /// ```
    pub fn read_at_addr(&self, buf: &mut [u8], guest_addr: GuestAddress) -> Result<usize> {
        self.do_in_region(guest_addr, move |mapping, offset| {
            mapping
                .read_slice(buf, offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Reads from guest memory at the specified address to fill the entire
    /// buffer.
    ///
    /// Returns an error if there isn't enough room in the memory region to fill
    /// the entire buffer. Part of the buffer may have been filled nevertheless.
    ///
    /// # Examples
    ///
    /// ```
    /// use sys_util::{guest_memory, GuestAddress, GuestMemory, MemoryMapping};
    ///
    /// fn test_read_exact() -> guest_memory::Result<()> {
    ///     let ranges = &[(GuestAddress(0x1000), 0x400)];
    ///     let gm = GuestMemory::new(ranges)?;
    ///     let mut buffer = [0u8; 0x200];
    ///     gm.read_exact_at_addr(&mut buffer, GuestAddress(0x1200))
    /// }
    /// ```
    pub fn read_exact_at_addr(&self, buf: &mut [u8], guest_addr: GuestAddress) -> Result<()> {
        let expected = buf.len();
        let completed = self.read_at_addr(buf, guest_addr)?;
        if expected == completed {
            Ok(())
        } else {
            Err(Error::ShortRead {
                expected,
                completed,
            })
        }
    }

    /// Reads an object from guest memory at the given guest address.
    /// Reading from a volatile area isn't strictly safe as it could change
    /// mid-read.  However, as long as the type T is plain old data and can
    /// handle random initialization, everything will be OK.
    ///
    /// # Examples
    /// * Read a u64 from two areas of guest memory backed by separate mappings.
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_read_u64() -> Result<u64, ()> {
    /// #     let start_addr1 = GuestAddress(0x0);
    /// #     let start_addr2 = GuestAddress(0x400);
    /// #     let mut gm = GuestMemory::new(&vec![(start_addr1, 0x400), (start_addr2, 0x400)])
    /// #         .map_err(|_| ())?;
    ///       let num1: u64 = gm.read_obj_from_addr(GuestAddress(32)).map_err(|_| ())?;
    ///       let num2: u64 = gm.read_obj_from_addr(GuestAddress(0x400+32)).map_err(|_| ())?;
    /// #     Ok(num1 + num2)
    /// # }
    /// ```
    pub fn read_obj_from_addr<T: DataInit>(&self, guest_addr: GuestAddress) -> Result<T> {
        self.do_in_region(guest_addr, |mapping, offset| {
            mapping
                .read_obj(offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Writes an object to the memory region at the specified guest address.
    /// Returns Ok(()) if the object fits, or Err if it extends past the end.
    ///
    /// # Examples
    /// * Write a u64 at guest address 0x1100.
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     gm.write_obj_at_addr(55u64, GuestAddress(0x1100))
    ///         .map_err(|_| ())
    /// # }
    /// ```
    pub fn write_obj_at_addr<T: DataInit>(&self, val: T, guest_addr: GuestAddress) -> Result<()> {
        self.do_in_region(guest_addr, move |mapping, offset| {
            mapping
                .write_obj(val, offset)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Reads data from a file descriptor and writes it to guest memory.
    ///
    /// # Arguments
    /// * `guest_addr` - Begin writing memory at this offset.
    /// * `src` - Read from `src` to memory.
    /// * `count` - Read `count` bytes from `src` to memory.
    ///
    /// # Examples
    ///
    /// * Read bytes from /dev/urandom
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_read_random() -> Result<u32, ()> {
    /// #     let start_addr = GuestAddress(0x1000);
    /// #     let gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///       let mut file = File::open(Path::new("/dev/urandom")).map_err(|_| ())?;
    ///       let addr = GuestAddress(0x1010);
    ///       gm.read_to_memory(addr, &mut file, 128).map_err(|_| ())?;
    ///       let read_addr = addr.checked_add(8).ok_or(())?;
    ///       let rand_val: u32 = gm.read_obj_from_addr(read_addr).map_err(|_| ())?;
    /// #     Ok(rand_val)
    /// # }
    /// ```
    pub fn read_to_memory(
        &self,
        guest_addr: GuestAddress,
        src: &AsRawFd,
        count: usize,
    ) -> Result<()> {
        self.do_in_region(guest_addr, move |mapping, offset| {
            mapping
                .read_to_memory(offset, src, count)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Writes data from memory to a file descriptor.
    ///
    /// # Arguments
    /// * `guest_addr` - Begin reading memory from this offset.
    /// * `dst` - Write from memory to `dst`.
    /// * `count` - Read `count` bytes from memory to `src`.
    ///
    /// # Examples
    ///
    /// * Write 128 bytes to /dev/null
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory, MemoryMapping};
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_write_null() -> Result<(), ()> {
    /// #     let start_addr = GuestAddress(0x1000);
    /// #     let gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///       let mut file = File::open(Path::new("/dev/null")).map_err(|_| ())?;
    ///       let addr = GuestAddress(0x1010);
    ///       gm.write_from_memory(addr, &mut file, 128).map_err(|_| ())?;
    /// #     Ok(())
    /// # }
    /// ```
    pub fn write_from_memory(
        &self,
        guest_addr: GuestAddress,
        dst: &AsRawFd,
        count: usize,
    ) -> Result<()> {
        self.do_in_region(guest_addr, move |mapping, offset| {
            mapping
                .write_from_memory(offset, dst, count)
                .map_err(|e| Error::MemoryAccess(guest_addr, e))
        })
    }

    /// Convert a GuestAddress into a pointer in the address space of this
    /// process. This should only be necessary for giving addresses to the
    /// kernel, as with vhost ioctls. Normal reads/writes to guest memory should
    /// be done through `write_from_memory`, `read_obj_from_addr`, etc.
    ///
    /// # Arguments
    /// * `guest_addr` - Guest address to convert.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sys_util::{GuestAddress, GuestMemory};
    /// # fn test_host_addr() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemory::new(&vec![(start_addr, 0x500)]).map_err(|_| ())?;
    ///     let addr = gm.get_host_address(GuestAddress(0x1200)).unwrap();
    ///     println!("Host address is {:p}", addr);
    ///     Ok(())
    /// # }
    /// ```
    pub fn get_host_address(&self, guest_addr: GuestAddress) -> Result<*const u8> {
        self.do_in_region(guest_addr, |mapping, offset| {
            // This is safe; `do_in_region` already checks that offset is in
            // bounds.
            Ok(unsafe { mapping.as_ptr().add(offset) } as *const u8)
        })
    }

    pub fn do_in_region<F, T>(&self, guest_addr: GuestAddress, cb: F) -> Result<T>
    where
        F: FnOnce(&MemoryMapping, usize) -> Result<T>,
    {
        for region in self.regions.iter() {
            if guest_addr >= region.guest_base && guest_addr < region_end(region) {
                return cb(
                    &region.mapping,
                    guest_addr.offset_from(region.guest_base) as usize,
                );
            }
        }
        Err(Error::InvalidGuestAddress(guest_addr))
    }
}

impl VolatileMemory for GuestMemory {
    fn get_slice(&self, offset: u64, count: u64) -> VolatileMemoryResult<VolatileSlice> {
        for region in self.regions.iter() {
            if offset >= region.guest_base.0 && offset < region_end(region).0 {
                return region
                    .mapping
                    .get_slice(offset - region.guest_base.0, count);
            }
        }
        Err(VolatileMemoryError::OutOfBounds { addr: offset })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_has_memfd;

    #[test]
    fn test_alignment() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);

        assert!(GuestMemory::new(&vec![(start_addr1, 0x100), (start_addr2, 0x400)]).is_err());
        assert!(GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)]).is_ok());
    }

    #[test]
    fn two_regions() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x4000);
        assert!(GuestMemory::new(&vec![(start_addr1, 0x4000), (start_addr2, 0x4000)]).is_ok());
    }

    #[test]
    fn overlap_memory() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        assert!(GuestMemory::new(&vec![(start_addr1, 0x2000), (start_addr2, 0x2000)]).is_err());
    }

    #[test]
    fn test_read_u64() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let gm = GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();

        let val1: u64 = 0xaa55aa55aa55aa55;
        let val2: u64 = 0x55aa55aa55aa55aa;
        gm.write_obj_at_addr(val1, GuestAddress(0x500)).unwrap();
        gm.write_obj_at_addr(val2, GuestAddress(0x1000 + 32))
            .unwrap();
        let num1: u64 = gm.read_obj_from_addr(GuestAddress(0x500)).unwrap();
        let num2: u64 = gm.read_obj_from_addr(GuestAddress(0x1000 + 32)).unwrap();
        assert_eq!(val1, num1);
        assert_eq!(val2, num2);
    }

    #[test]
    fn test_ref_load_u64() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let gm = GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();

        let val1: u64 = 0xaa55aa55aa55aa55;
        let val2: u64 = 0x55aa55aa55aa55aa;
        gm.write_obj_at_addr(val1, GuestAddress(0x500)).unwrap();
        gm.write_obj_at_addr(val2, GuestAddress(0x1000 + 32))
            .unwrap();
        let num1: u64 = gm.get_ref(0x500).unwrap().load();
        let num2: u64 = gm.get_ref(0x1000 + 32).unwrap().load();
        assert_eq!(val1, num1);
        assert_eq!(val2, num2);
    }

    #[test]
    fn test_ref_store_u64() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let gm = GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();

        let val1: u64 = 0xaa55aa55aa55aa55;
        let val2: u64 = 0x55aa55aa55aa55aa;
        gm.get_ref(0x500).unwrap().store(val1);
        gm.get_ref(0x1000 + 32).unwrap().store(val2);
        let num1: u64 = gm.read_obj_from_addr(GuestAddress(0x500)).unwrap();
        let num2: u64 = gm.read_obj_from_addr(GuestAddress(0x1000 + 32)).unwrap();
        assert_eq!(val1, num1);
        assert_eq!(val2, num2);
    }

    #[test]
    fn test_memory_size() {
        let start_region1 = GuestAddress(0x0);
        let size_region1 = 0x1000;
        let start_region2 = GuestAddress(0x10000);
        let size_region2 = 0x2000;
        let gm = GuestMemory::new(&vec![
            (start_region1, size_region1),
            (start_region2, size_region2),
        ])
        .unwrap();

        let mem_size = gm.memory_size();
        assert_eq!(mem_size, size_region1 + size_region2);
    }

    // Get the base address of the mapping for a GuestAddress.
    fn get_mapping(mem: &GuestMemory, addr: GuestAddress) -> Result<*const u8> {
        mem.do_in_region(addr, |mapping, _| Ok(mapping.as_ptr() as *const u8))
    }

    #[test]
    fn guest_to_host() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let mem = GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x4000)]).unwrap();

        // Verify the host addresses match what we expect from the mappings.
        let addr1_base = get_mapping(&mem, start_addr1).unwrap();
        let addr2_base = get_mapping(&mem, start_addr2).unwrap();
        let host_addr1 = mem.get_host_address(start_addr1).unwrap();
        let host_addr2 = mem.get_host_address(start_addr2).unwrap();
        assert_eq!(host_addr1, addr1_base);
        assert_eq!(host_addr2, addr2_base);

        // Check that a bad address returns an error.
        let bad_addr = GuestAddress(0x123456);
        assert!(mem.get_host_address(bad_addr).is_err());
    }

    #[test]
    fn memfd_offset() {
        if !kernel_has_memfd() {
            return;
        }

        let start_region1 = GuestAddress(0x0);
        let size_region1 = 0x1000;
        let start_region2 = GuestAddress(0x10000);
        let size_region2 = 0x2000;
        let gm = GuestMemory::new(&vec![
            (start_region1, size_region1),
            (start_region2, size_region2),
        ])
        .unwrap();

        gm.write_obj_at_addr(0x1337u16, GuestAddress(0x0)).unwrap();
        gm.write_obj_at_addr(0x0420u16, GuestAddress(0x10000))
            .unwrap();

        let _ = gm.with_regions::<_, ()>(|index, _, size, _, memfd_offset| {
            let mmap = MemoryMapping::from_fd_offset(&gm, size, memfd_offset).unwrap();

            if index == 0 {
                assert!(mmap.read_obj::<u16>(0x0).unwrap() == 0x1337u16);
            }

            if index == 1 {
                assert!(mmap.read_obj::<u16>(0x0).unwrap() == 0x0420u16);
            }

            Ok(())
        });
    }
}
