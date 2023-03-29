// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement the driver side of virtio queue handling.
//! The virtqueue struct is expected to be used in userspace VFIO virtio drivers.

use std::mem;
use std::num::Wrapping;
use std::sync::atomic::fence;
use std::sync::atomic::Ordering;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use data_model::VolatileSlice;
use virtio_sys::virtio_ring::VRING_DESC_F_WRITE;
use vm_memory::GuestAddress as IOVA;
use vm_memory::GuestMemory as QueueMemory;
use zerocopy::FromBytes;

use crate::virtio::Desc;

#[derive(Copy, Clone, Debug, FromBytes)]
#[repr(C)]
struct UsedElem {
    id: Le32,
    len: Le32,
}

const BUF_SIZE: u64 = 1024;

pub struct DescTableAddrs {
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
}

struct MemLayout {
    /// Address of the descriptor table in UserQueue.mem.
    desc_table: IOVA,

    /// Address of the available ring in UserQueue.mem.
    avail_ring: IOVA,

    /// Address of the used ring in UserQueue.mem.
    used_ring: IOVA,

    /// Address of the start of buffers in UserQueue.mem.
    buffer_addr: IOVA,
}

/// Represents a virtqueue that is allocated in the guest userspace and manipulated from a VFIO
/// driver.
///
/// This struct is similar to `devices::virtio::Queue` which is designed for the virtio devices, but
/// this struct is defined for the virtio drivers.
///
/// # Memory Layout
///
/// `mem` is the memory allocated in the guest userspace for the virtqueue, which is mapped into
/// the vvu device via VFIO. The GuestAddresses of `mem` are the IOVAs that should be used when
/// communicating with the vvu device. All accesses to the shared memory from the device backend
/// must be done through the GuestMemory read/write functions.
///
/// The layout `mem` is defined in the following table and stored in `mem_layout`.
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
    mem: QueueMemory,

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
}

/// Interface used by UserQueue to interact with the IOMMU.
pub trait IovaAllocator {
    /// Allocates an IO virtual address region of the requested size.
    fn alloc_iova(&self, size: u64, tag: u8) -> Result<u64>;
    /// Maps the given address at the given IOVA.
    ///
    /// # Safety
    ///
    /// `addr` must reference a region of at least length `size`. Memory passed
    /// to this function may be mutated at any time, so `addr` must not be memory
    /// that is directly managed by rust.
    unsafe fn map_iova(&self, iova: u64, size: u64, addr: *const u8) -> Result<()>;
}

impl UserQueue {
    /// Creats a `UserQueue` instance.
    pub fn new<I>(queue_size: u16, device_writable: bool, tag: u8, iova_alloc: &I) -> Result<Self>
    where
        I: IovaAllocator,
    {
        let (mem, size, mem_layout) = Self::init_memory(queue_size, tag, iova_alloc)?;

        let mut queue = Self {
            mem,
            size: Wrapping(size),
            mem_layout,
            avail_idx: Wrapping(0),
            used_count: Wrapping(0),
            free_count: Wrapping(size),
            device_writable,
        };

        queue.init_descriptor_table()?;

        Ok(queue)
    }

    /// Allocates memory region and returns addresses on the regions for (`desc_table`, `avail_ring`, `used_ring`, `buffer``).
    fn init_memory<I>(
        max_queue_size: u16,
        tag: u8,
        iova_alloc: &I,
    ) -> Result<(QueueMemory, u16, MemLayout)>
    where
        I: IovaAllocator,
    {
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

        let desc_table = IOVA(0);
        let desc_size = 16u64 * u64::from(queue_size);
        let desc_end = desc_table.0 + desc_size;

        let avail_ring = IOVA(align(desc_end, 2));
        let avail_size = 6 + 2 * u64::from(queue_size);
        let avail_end = avail_ring.0 + avail_size;

        let used_ring = IOVA(align(avail_end, 4));
        let used_size = 6 + 8 * u64::from(queue_size);
        let used_end = used_ring.0 + used_size;

        let buffer_addr = IOVA(align(used_end, BUF_SIZE));
        let buffer_size = BUF_SIZE * u64::from(queue_size);

        let mem_size = align(buffer_addr.0 + buffer_size, base::pagesize() as u64);
        let iova_start = iova_alloc
            .alloc_iova(mem_size, tag)
            .context("failed to allocate queue iova")?;

        let mem = QueueMemory::new(&[(IOVA(iova_start), mem_size)])
            .map_err(|e| anyhow!("failed to create QueueMemory for virtqueue: {}", e))?;

        let host_addr = mem
            .get_host_address_range(IOVA(iova_start), mem_size as usize)
            .context("failed to get host address")?;
        // Safe because the region being mapped is managed via the GuestMemory interface.
        unsafe {
            iova_alloc
                .map_iova(iova_start, mem_size, host_addr)
                .context("failed to map queue")?;
        }

        let mem_layout = MemLayout {
            desc_table: desc_table.unchecked_add(iova_start),
            avail_ring: avail_ring.unchecked_add(iova_start),
            used_ring: used_ring.unchecked_add(iova_start),
            buffer_addr: buffer_addr.unchecked_add(iova_start),
        };

        Ok((mem, queue_size, mem_layout))
    }

    /// Initialize the descriptor table.
    fn init_descriptor_table(&mut self) -> Result<()> {
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
            let iova = self.buffer_address(idx)?.offset();
            let desc = Desc {
                addr: iova.into(),
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

    pub fn desc_table_addrs(&self) -> Result<DescTableAddrs> {
        Ok(DescTableAddrs {
            desc: self.mem_layout.desc_table.offset(),
            avail: self.mem_layout.avail_ring.offset(),
            used: self.mem_layout.used_ring.offset(),
        })
    }

    /// Returns the IOVA of the buffer for the given `index`.
    fn buffer_address(&self, index: Wrapping<u16>) -> Result<IOVA> {
        let offset = u64::from((index % self.size).0) * BUF_SIZE;
        self.mem_layout
            .buffer_addr
            .checked_add(offset)
            .ok_or(anyhow!("overflow txq"))
    }

    /// Writes the given descriptor table entry.
    fn write_desc_entry(&self, index: Wrapping<u16>, desc: Desc) -> Result<()> {
        let addr = self
            .mem_layout
            .desc_table
            .unchecked_add(u64::from((index % self.size).0) * mem::size_of::<Desc>() as u64);
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

        let addr = self.buffer_address(id)?;

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
    fn write_to_buffer(&self, index: Wrapping<u16>, data: &[u8]) -> Result<IOVA> {
        if data.len() as u64 > BUF_SIZE {
            bail!(
                "data size {} is larger than the buffer size {}",
                data.len(),
                BUF_SIZE
            );
        }

        let addr = self.buffer_address(index)?;
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
            addr: Le64::from(addr.offset()),
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
    use std::cell::RefCell;
    use std::io::Read;
    use std::io::Write;

    use super::*;
    use crate::virtio::Queue as DeviceQueue;
    use crate::virtio::Reader;
    use crate::virtio::Writer;

    // An allocator that just allocates 0 as an IOVA.
    struct SimpleIovaAllocator(RefCell<bool>);

    impl IovaAllocator for SimpleIovaAllocator {
        fn alloc_iova(&self, _size: u64, _tag: u8) -> Result<u64> {
            if *self.0.borrow() {
                bail!("exhaused");
            }
            *self.0.borrow_mut() = true;
            Ok(0)
        }

        unsafe fn map_iova(&self, _iova: u64, _size: u64, _addr: *const u8) -> Result<()> {
            if !*self.0.borrow() {
                bail!("not allocated");
            }
            Ok(())
        }
    }

    fn setup_vq(queue: &mut DeviceQueue, addrs: DescTableAddrs) {
        queue.set_desc_table(IOVA(addrs.desc));
        queue.set_avail_ring(IOVA(addrs.avail));
        queue.set_used_ring(IOVA(addrs.used));
        queue.set_ready(true);
    }

    fn device_write(mem: &QueueMemory, q: &mut DeviceQueue, data: &[u8]) -> usize {
        let desc_chain = q.pop(mem).unwrap();
        let mut writer = Writer::new(&desc_chain);
        let written = writer.write(data).unwrap();
        q.add_used(mem, desc_chain, written as u32);
        written
    }

    fn device_read(mem: &QueueMemory, q: &mut DeviceQueue, len: usize) -> Vec<u8> {
        let desc_chain = q.pop(mem).unwrap();
        let mut reader = Reader::new(&desc_chain);
        let mut buf = vec![0; len];
        reader.read_exact(&mut buf).unwrap();
        q.add_used(mem, desc_chain, len as u32);
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
        let iova_alloc = SimpleIovaAllocator(RefCell::new(false));
        let mut drv_queue =
            UserQueue::new(queue_size, false /* device_writable */, 0, &iova_alloc).unwrap();
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
        let iova_alloc = SimpleIovaAllocator(RefCell::new(false));
        let mut drv_queue =
            UserQueue::new(queue_size, true /* device_writable */, 0, &iova_alloc).unwrap();
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
