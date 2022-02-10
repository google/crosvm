// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement the driver side of virtio queue handling.
//! The virtqueue struct is expected to be used in userspace VFIO virtio drivers.

use std::mem;
use std::num::Wrapping;
use std::sync::atomic::{fence, Ordering};
#[cfg(not(test))]
use std::{collections::BTreeMap, fs::File};

use anyhow::{anyhow, bail, Context, Result};
use data_model::{DataInit, Le16, Le32, Le64, VolatileSlice};
use virtio_sys::vhost::VRING_DESC_F_WRITE;
use vm_memory::{GuestAddress, GuestMemory};

#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct Desc {
    addr: Le64,
    len: Le32,
    flags: Le16,
    next: Le16,
}
// Safe as there are no implicit offset.
unsafe impl DataInit for Desc {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct UsedElem {
    id: Le32,
    len: Le32,
}
// Safe as there are no implicit offset.
unsafe impl DataInit for UsedElem {}

const BUF_SIZE: u64 = 1024;

pub struct DescTableAddrs {
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
}

struct MemLayout {
    /// Address of the descriptor table.
    /// Since the vvu driver runs in the guest user space, `GuestAddress` here stores the guest
    /// virtual address.
    desc_table: GuestAddress,

    /// Virtual address of the available ring
    avail_ring: GuestAddress,

    /// Virtual address of the used ring
    used_ring: GuestAddress,

    /// Virtual address of the start of buffers.
    buffer_addr: GuestAddress,
}

/// Represents a virtqueue that is allocated in the guest userspace and manipulated from a VFIO
/// driver.
///
/// This struct is similar to `devices::virtio::Queue` which is designed for the virtio devices, but
/// this struct is defined for the virtio drivers.
///
/// # Memory Layout
///
/// `mem` is a continuous memory allocated in the guest userspace and used to have a virtqueue.
/// Its layout is defined in the following table and stored in `mem_layout`.
///
/// |                  | Alignment     | Size                         |
/// |-----------------------------------------------------------------|
/// | Descriptor Table | 16            | 16 ∗ (Queue Size)            |
/// | Available Ring   | 2             | 6 + 2 ∗ (Queue Size)         |
/// | Used Ring        | 4             | 6 + 8 ∗ (Queue Size)         |
/// | Buffers          | (Buffer Size) | (Buffer Size) * (Queue Size) |
/// -------------------------------------------------------------------
///
/// TODO(b/207364742): Once we support `VIRTIO_F_EVENT_IDX`, the additional 2 bytes for the
/// `used_event` field will be added.
/// TODO(b/215153367): Use `crate::virtio::Queue` as an underlying data structure so that we can use
/// `descriptor_utils::{Reader, Writer}` instead of having our own read/write methods.
/// One of the biggest blockers is that `virtio::Queue` is designed for device-side's virtqueue,
/// where readable/writable areas are inverted from our use case.
pub struct UserQueue {
    /// The queue size.
    size: Wrapping<u16>,

    /// The underlying memory.
    mem: GuestMemory,

    /// Virtqueue layout on `mem`.
    mem_layout: MemLayout,

    avail_idx: Wrapping<u16>,

    used_count: Wrapping<u16>,
    free_count: Wrapping<u16>,

    /// Whether buffers are device-writable or readable.
    /// If true, every descriptor has the VIRTQ_DESC_F_WRITE flag.
    /// TODO(b/215153358, b/215153367): Since VIRTQ_DESC_F_WRITE is a per-descriptor flag, this
    /// design is specific to the current vvu specification draft, where a device-writable queue
    /// and a device-readable queue are separated.
    /// Ideally, we should update the vvu spec to use both device-{readable, writable} buffers in
    /// one virtqueue. Also, it's better to use `crate::virtio::DescriptorChain` for descirptors as
    /// a part of b/215153367.
    device_writable: bool,

    /// Mapping from a virtual address to the physical address.
    /// This mapping is initialized by reading `/proc/self/pagemap`.
    /// TODO(b/215310597): This workaround won't work if memory mapping is changed. Currently, we
    /// are assuming that memory mapping is fixed during the vvu negotiation.
    /// Once virtio-iommu supports VFIO usage, we can remove this workaround and we should use
    /// VFIO_IOMMU_MAP_DMA call to get physical addresses.
    #[cfg(not(test))]
    addr_table: BTreeMap<GuestAddress, u64>,
}

impl UserQueue {
    /// Creats a `UserQueue` instance.
    pub fn new(queue_size: u16, device_writable: bool) -> Result<Self> {
        let (mem, size, mem_layout) = Self::init_memory(queue_size)?;
        let mut queue = Self {
            mem,
            size: Wrapping(size),
            mem_layout,
            avail_idx: Wrapping(0),
            used_count: Wrapping(0),
            free_count: Wrapping(size),
            device_writable,
            #[cfg(not(test))]
            addr_table: Default::default(),
        };

        queue.init_descriptor_table()?;

        Ok(queue)
    }

    /// Allocates memory region and returns addresses on the regions for (`desc_table`, `avail_ring`, `used_ring`, `buffer``).
    fn init_memory(max_queue_size: u16) -> Result<(GuestMemory, u16, MemLayout)> {
        // Since vhost-user negotiation finishes within ~20 messages, queue size 32 is enough.
        const MAX_QUEUE_SIZE: u16 = 256;

        let queue_size = std::cmp::min(MAX_QUEUE_SIZE, max_queue_size);
        if queue_size == 0 || !queue_size.is_power_of_two() {
            bail!(
                "queue_size must be a positive power of 2 number but {}",
                queue_size
            );
        }

        fn align(n: u64, m: u64) -> u64 {
            ((n + m - 1) / m) * m
        }

        let desc_table = GuestAddress(0);
        let desc_size = 16u64 * u64::from(queue_size);
        let desc_end = desc_table.0 + desc_size;

        let avail_ring = GuestAddress(align(desc_end, 2));
        let avail_size = 6 + 2 * u64::from(queue_size);
        let avail_end = avail_ring.0 + avail_size;

        let used_ring = GuestAddress(align(avail_end, 4));
        let used_size = 6 + 8 * u64::from(queue_size);
        let used_end = used_ring.0 + used_size;

        let buffer_addr = GuestAddress(align(used_end, BUF_SIZE));
        let buffer_size = BUF_SIZE * u64::from(queue_size);

        let mem_size = align(buffer_addr.0 + buffer_size, base::pagesize() as u64);

        let mem = GuestMemory::new(&[(desc_table, mem_size)])
            .map_err(|e| anyhow!("failed to create GuestMemory for virtqueue: {}", e))?;

        // Call `mlock()` to guarantees that pages will stay in RAM.
        // Note that this can't ensure that physical address mapping is consistent.
        // TODO(b/215310597) We're assume that the kernel won't swap these memory region at least
        // during the vvu negotiation. Although this assumption is risky, it'll be resolved once
        // virtio-iommu for virtio devices is supported.
        mem.with_regions(|_, _, size, ptr, _, _| {
            let ret = unsafe { libc::mlock(ptr as *const libc::c_void, size) };
            if ret == -1 {
                bail!("failed to mlock(): {}", base::Error::last());
            }
            Ok(())
        })?;

        // To ensure the GuestMemory is mapped to physical memory, read the entire buffer first.
        // Otherwise, reading `/proc/self/pagemap` returns invalid values.
        // TODO(b/215310597): Once we use iommu for VFIO, we can probably remove this workaround.
        let mut buf = vec![0; mem_size as usize];
        mem.read_at_addr(&mut buf, desc_table)
            .map_err(|e| anyhow!("failed to read_slice: {}", e))?;

        let mem_layout = MemLayout {
            desc_table,
            avail_ring,
            used_ring,
            buffer_addr,
        };

        Ok((mem, queue_size, mem_layout))
    }

    /// Initialize the descriptor table.
    fn init_descriptor_table(&mut self) -> Result<()> {
        self.init_addr_table()?;

        let flags = if self.device_writable {
            Le16::from(VRING_DESC_F_WRITE as u16)
        } else {
            Le16::from(0)
        };
        let len = Le32::from(BUF_SIZE as u32);
        let next = Le16::from(0);

        // Register pre-allocated buffers to the descriptor area.
        for i in 0..self.size.0 {
            let idx = Wrapping(i);
            let addr = Le64::from(self.to_phys_addr(&self.buffer_guest_addr(idx)?)?);
            let desc = Desc {
                addr,
                len,
                flags,
                next,
            };
            self.write_desc_entry(idx, desc)
                .map_err(|e| anyhow!("failed to write {}-th desc: {}", idx, e))?;

            fence(Ordering::SeqCst);
            self.mem
                .write_obj_at_addr(
                    idx.0,
                    self.mem_layout
                        .avail_ring
                        .unchecked_add(u64::from(4 + 2 * i)),
                )
                .context("failed to write avail ring")?;
        }

        // If all of `self`'s buffers are device-writable, expose them to the device.
        if self.device_writable {
            for _ in 0..self.size.0 {
                // TODO(keiichiw): avail_idx should be incremented in update_avail_index
                self.avail_idx += Wrapping(1);
                self.update_avail_index()?;
            }
        }

        Ok(())
    }

    #[cfg(not(test))]
    /// Reads `/proc/self/pagemap` and stores mapping from virtual addresses for virtqueue
    /// information and buffers to physical addresses.
    fn init_addr_table(&mut self) -> Result<()> {
        let pagemap = File::open("/proc/self/pagemap").context("failed to open pagemap")?;
        self.register_addr(&pagemap, &self.mem_layout.desc_table.clone())?;
        self.register_addr(&pagemap, &self.mem_layout.avail_ring.clone())?;
        self.register_addr(&pagemap, &self.mem_layout.used_ring.clone())?;
        self.register_addr(&pagemap, &self.mem_layout.buffer_addr.clone())?;
        // Register addresses of buffers.
        for i in 0..self.size.0 {
            self.register_addr(&pagemap, &self.buffer_guest_addr(Wrapping(i))?)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn init_addr_table(&mut self) -> Result<()> {
        Ok(())
    }

    /// Registers an address mapping for the given virtual address to `self.addr_table`.
    // TODO(b/215310597): This function reads `/proc/self/pagemap`, which requires root
    // privileges. Instead, we should use VFIO_IOMMU_MAP_DMA call with virtio-iommu to get
    // physical addresses.
    #[cfg(not(test))]
    fn register_addr(&mut self, pagemap_file: &File, addr: &GuestAddress) -> Result<u64> {
        use std::os::unix::fs::FileExt;

        let vaddr = self
            .mem
            .get_slice_at_addr(*addr, 1)
            .context("failed to get slice")?
            .as_ptr() as u64;

        let page_size = base::pagesize() as u64;
        let virt_page_number = vaddr / page_size;
        let offset = std::mem::size_of::<u64>() as u64 * virt_page_number;

        let mut buf = [0u8; 8];
        pagemap_file
            .read_exact_at(&mut buf, offset)
            .context("failed to read pagemap")?;

        let pagemap = u64::from_le_bytes(buf);
        // Bit 55 is soft-dirty.
        if (pagemap & (1u64 << 55)) != 0 {
            bail!("page table entry is soft-dirty")
        }
        // page frame numbers are bits 0-54
        let page = pagemap & 0x7f_ffff_ffff_ffffu64;
        if page == 0 {
            bail!("failed to get page frame number: page={:x}", page);
        }

        let paddr = page * page_size + (vaddr % page_size);
        self.addr_table.insert(*addr, paddr);
        Ok(paddr)
    }

    /// Translate a virtual address to the physical address.
    #[cfg(not(test))]
    fn to_phys_addr(&self, addr: &GuestAddress) -> Result<u64> {
        self.addr_table
            .get(addr)
            .context(anyhow!("addr {} not found", addr))
            .map(|v| *v)
    }

    #[cfg(test)]
    fn to_phys_addr(&self, addr: &GuestAddress) -> Result<u64> {
        Ok(addr.0)
    }

    /// Returns physical addresses of the descriptor table, the avail ring and the used ring.
    pub fn desc_table_addrs(&self) -> Result<DescTableAddrs> {
        let desc = self.to_phys_addr(&self.mem_layout.desc_table)?;
        let avail = self.to_phys_addr(&self.mem_layout.avail_ring)?;
        let used = self.to_phys_addr(&self.mem_layout.used_ring)?;

        Ok(DescTableAddrs { desc, avail, used })
    }

    /// Returns a virtual address of the buffer for the given `index`.
    fn buffer_guest_addr(&self, index: Wrapping<u16>) -> Result<GuestAddress> {
        let offset = u64::from((index % self.size).0) * BUF_SIZE;
        self.mem_layout
            .buffer_addr
            .checked_add(offset)
            .ok_or(anyhow!("overflow txq"))
    }

    /// Writes the given descriptor table entry.
    fn write_desc_entry(&self, index: Wrapping<u16>, desc: Desc) -> Result<()> {
        let addr = GuestAddress(u64::from((index % self.size).0) * mem::size_of::<Desc>() as u64);
        fence(Ordering::SeqCst);
        self.mem
            .write_obj_at_addr(desc, addr)
            .context("failed to write desc")
    }

    /// Puts an index into the avail ring for use by the host.
    fn update_avail_index(&self) -> Result<()> {
        fence(Ordering::SeqCst);
        self.mem
            .write_obj_at_addr(
                self.avail_idx.0,
                self.mem_layout.avail_ring.unchecked_add(2),
            )
            .context("failed to write avail.idx")?;
        Ok(())
    }

    /// Reads the Used ring's index.
    fn read_used_idx(&self) -> Result<Wrapping<u16>> {
        let used_index_addr = self.mem_layout.used_ring.unchecked_add(2);
        fence(Ordering::SeqCst);
        let used_index: u16 = self.mem.read_obj_from_addr(used_index_addr).unwrap();
        Ok(Wrapping(used_index))
    }

    /// Reads the Used ring's element for the given index.
    fn read_used_elem(&self, idx: Wrapping<u16>) -> Result<UsedElem> {
        let offset = 4 + (idx % self.size).0 as usize * mem::size_of::<UsedElem>();
        let addr = self
            .mem_layout
            .used_ring
            .checked_add(offset as u64)
            .context("overflow")?;
        fence(Ordering::SeqCst);
        self.mem
            .read_obj_from_addr(addr)
            .context("failed to read used")
    }

    /// Reads data in the virtqueue.
    /// Returns `Ok(None)` if no data are available.
    ///
    /// TODO: Use `descriptor_utils::Reader`.
    pub fn read_data(&mut self) -> Result<Option<VolatileSlice>> {
        if !self.device_writable {
            bail!("driver cannot read device-readable descriptors");
        }

        let idx = self.read_used_idx()?;
        let cur = self.used_count;
        if cur == idx {
            return Ok(None);
        }

        let elem = self.read_used_elem(cur)?;

        let id = Wrapping(u32::from(elem.id) as u16);
        let len = u32::from(elem.len) as usize;

        let addr = self.buffer_guest_addr(id)?;

        fence(Ordering::SeqCst);
        let s = self
            .mem
            .get_slice_at_addr(addr, len)
            .context("failed to read data")?;

        self.used_count += Wrapping(1);
        self.avail_idx += Wrapping(1);
        self.update_avail_index()?;
        Ok(Some(s))
    }

    /// Writes data into virtqueue's buffer and returns its address.
    ///
    /// TODO: Use `descriptor_utils::Writer`.
    fn write_to_buffer(&self, index: Wrapping<u16>, data: &[u8]) -> Result<GuestAddress> {
        if data.len() as u64 > BUF_SIZE {
            bail!(
                "data size {} is larger than the buffer size {}",
                data.len(),
                BUF_SIZE
            );
        }

        let addr = self.buffer_guest_addr(index)?;
        fence(Ordering::SeqCst);
        let written = self
            .mem
            .write_at_addr(data, addr)
            .context("failed to write data")?;
        if written < data.len() {
            bail!(
                "no enough memory: written {}, but data length is {}",
                written,
                data.len()
            );
        }
        Ok(addr)
    }

    /// Acknowledges buffers that the device used.
    pub fn ack_used(&mut self) -> Result<()> {
        let used_idx = self.read_used_idx()?;
        let num_used = used_idx - self.used_count;

        self.used_count += num_used;
        self.free_count += num_used;

        Ok(())
    }

    /// Writes the given data to the virtqueue.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        if self.device_writable {
            bail!("driver cannot write to device-writable descriptors");
        }

        self.ack_used()?;

        if self.free_count == Wrapping(0) {
            // TODO: wait until the device processes buffers.
            bail!("no avail descriptor is left");
        }

        let addr = self
            .write_to_buffer(self.avail_idx, data)
            .context("failed to write data to virtqueue")?;

        let desc = Desc {
            addr: Le64::from(self.to_phys_addr(&addr)?),
            len: Le32::from(data.len() as u32),
            flags: Le16::from(0),
            next: Le16::from(0),
        };
        self.write_desc_entry(self.avail_idx, desc)?;
        self.free_count -= Wrapping(1);

        self.avail_idx += Wrapping(1);
        self.update_avail_index()?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::io::Read;
    use std::io::Write;

    use crate::virtio::{Queue as DeviceQueue, Reader, Writer};

    fn setup_vq(queue: &mut DeviceQueue, addrs: DescTableAddrs) {
        queue.desc_table = GuestAddress(addrs.desc);
        queue.avail_ring = GuestAddress(addrs.avail);
        queue.used_ring = GuestAddress(addrs.used);
        queue.ready = true;
    }

    fn device_write(mem: &GuestMemory, q: &mut DeviceQueue, data: &[u8]) -> usize {
        let desc_chain = q.pop(mem).unwrap();
        let index = desc_chain.index;

        let mut writer = Writer::new(mem.clone(), desc_chain).unwrap();
        let written = writer.write(data).unwrap();
        q.add_used(mem, index, written as u32);
        written
    }

    fn device_read(mem: &GuestMemory, q: &mut DeviceQueue, len: usize) -> Vec<u8> {
        let desc_chain = q.pop(mem).unwrap();
        let desc_index = desc_chain.index;
        let mut reader = Reader::new(mem.clone(), desc_chain).unwrap();
        let mut buf = vec![0; len];
        reader.read_exact(&mut buf).unwrap();
        q.add_used(mem, desc_index, len as u32);
        buf
    }

    fn driver_read(q: &mut UserQueue) -> Vec<u8> {
        let data = q.read_data().unwrap().unwrap();
        let mut buf = vec![0; data.size()];
        data.copy_to(&mut buf);

        buf
    }

    fn driver_write(q: &mut UserQueue, data: &[u8]) {
        q.write(data).unwrap()
    }

    // Send an array from the driver to the device `count` times.
    fn drv_to_dev(queue_size: u16, count: u32) {
        let mut drv_queue = UserQueue::new(queue_size, false /* device_writable */).unwrap();
        let mut dev_queue = DeviceQueue::new(queue_size);
        setup_vq(&mut dev_queue, drv_queue.desc_table_addrs().unwrap());

        for i in 0..count {
            let input = vec![(i + 1) as u8; 5];
            driver_write(&mut drv_queue, &input);

            let buf = device_read(&drv_queue.mem, &mut dev_queue, input.len());
            assert_eq!(input, buf);
            assert!(dev_queue.peek(&drv_queue.mem).is_none());
        }
    }

    #[test]
    fn test_driver_write() {
        let queue_size = 256;
        let iteration = 20;
        drv_to_dev(queue_size, iteration);
    }

    #[test]
    fn test_driver_write_small_queue() {
        // Test with a small queue.
        let queue_size = 8;
        let iteration = 20;
        drv_to_dev(queue_size, iteration);
    }

    // This test loops (65536 + 20) times. To avoid running it on slow emulated CI environments,
    // specify target architecture.
    // TODO(keiichiw): Change the test to mutate queues' internal state to avoid the actual loop.
    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_driver_write_wrapping() {
        // Test the index can be wrapped around when the iteration count exceeds 16bits.
        let queue_size = 256;

        let iteration = u32::from(u16::MAX) + 20;
        drv_to_dev(queue_size, iteration);
    }

    // Send an array from the device to the driver `count` times.
    fn dev_to_drv(queue_size: u16, count: u32) {
        let mut drv_queue = UserQueue::new(queue_size, true /* device_writable */).unwrap();
        let mut dev_queue = DeviceQueue::new(queue_size);
        setup_vq(&mut dev_queue, drv_queue.desc_table_addrs().unwrap());

        for i in 0..count {
            let input = [i as u8; 5];

            // Device writes data to driver
            let written = device_write(&drv_queue.mem, &mut dev_queue, &input);
            assert_eq!(written, input.len());

            // Driver reads data
            let buf = driver_read(&mut drv_queue);
            assert_eq!(buf, input);
        }
    }

    #[test]
    fn test_driver_read() {
        let queue_size = 256;
        let iteration = 20;
        dev_to_drv(queue_size, iteration);
    }

    #[test]
    fn test_driver_read_small_queue() {
        // Test with a small queue.
        let queue_size = 8;
        let iteration = 20;
        dev_to_drv(queue_size, iteration);
    }

    // This test loops (65536 + 20) times. To avoid running it on slow emulated CI environments,
    // specify target architecture.
    // TODO(keiichiw): Change the test to mutate queues' internal state to avoid the actual loop.
    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_driver_read_wrapping() {
        // Test the index can be wrapped around when the iteration count exceeds 16bits.
        let queue_size = 256;
        let iteration = u32::from(u16::MAX) + 20;
        dev_to_drv(queue_size, iteration);
    }
}
