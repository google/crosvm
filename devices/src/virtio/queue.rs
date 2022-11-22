// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::num::Wrapping;
use std::sync::atomic::fence;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::warn;
use base::Protection;
use cros_async::AsyncError;
use cros_async::EventAsync;
use data_model::DataInit;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use smallvec::smallvec;
use smallvec::SmallVec;
use sync::Mutex;
use virtio_sys::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use super::SignalableInterrupt;
use super::VIRTIO_MSI_NO_VECTOR;
use crate::virtio::ipc_memory_mapper::ExportedRegion;
use crate::virtio::ipc_memory_mapper::IpcMemoryMapper;
use crate::virtio::memory_mapper::MemRegion;
use crate::virtio::memory_util::read_obj_from_addr_wrapper;
use crate::virtio::memory_util::write_obj_at_addr_wrapper;

const VIRTQ_DESC_F_NEXT: u16 = 0x1;
const VIRTQ_DESC_F_WRITE: u16 = 0x2;
#[allow(dead_code)]
const VIRTQ_DESC_F_INDIRECT: u16 = 0x4;

const VIRTQ_USED_F_NO_NOTIFY: u16 = 0x1;
#[allow(dead_code)]
const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 0x1;

/// An iterator over a single descriptor chain.  Not to be confused with AvailIter,
/// which iterates over the descriptor chain heads in a queue.
pub struct DescIter {
    next: Option<DescriptorChain>,
}

impl DescIter {
    /// Returns an iterator that only yields the readable descriptors in the chain.
    pub fn readable(self) -> impl Iterator<Item = DescriptorChain> {
        self.take_while(DescriptorChain::is_read_only)
    }

    /// Returns an iterator that only yields the writable descriptors in the chain.
    pub fn writable(self) -> impl Iterator<Item = DescriptorChain> {
        self.skip_while(DescriptorChain::is_read_only)
    }
}

impl Iterator for DescIter {
    type Item = DescriptorChain;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current) = self.next.take() {
            self.next = current.next_descriptor();
            Some(current)
        } else {
            None
        }
    }
}

/// A virtio descriptor chain.
#[derive(Clone)]
pub struct DescriptorChain {
    mem: GuestMemory,
    desc_table: GuestAddress,
    queue_size: u16,
    ttl: u16, // used to prevent infinite chain cycles

    /// Index into the descriptor table
    pub index: u16,

    /// Guest physical address of device specific data, or IO virtual address
    /// if iommu is used
    pub addr: GuestAddress,

    /// Length of device specific data
    pub len: u32,

    /// Includes next, write, and indirect bits
    pub flags: u16,

    /// Index into the descriptor table of the next descriptor if flags has
    /// the next bit set
    pub next: u16,

    /// The memory regions associated with the current descriptor.
    regions: SmallVec<[MemRegion; 1]>,

    /// Translates `addr` to guest physical address
    iommu: Option<Arc<Mutex<IpcMemoryMapper>>>,

    /// The exported descriptor table of this chain's queue. Present
    /// iff iommu is present.
    exported_desc_table: Option<ExportedRegion>,

    /// The exported iommu region of the current descriptor. Present iff
    /// iommu is present.
    exported_region: Option<ExportedRegion>,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Desc {
    pub addr: Le64,
    pub len: Le32,
    pub flags: Le16,
    pub next: Le16,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for Desc {}

impl DescriptorChain {
    pub(crate) fn checked_new(
        mem: &GuestMemory,
        desc_table: GuestAddress,
        queue_size: u16,
        index: u16,
        required_flags: u16,
        iommu: Option<Arc<Mutex<IpcMemoryMapper>>>,
        exported_desc_table: Option<ExportedRegion>,
    ) -> Result<DescriptorChain> {
        if index >= queue_size {
            bail!("index ({}) >= queue_size ({})", index, queue_size);
        }

        let desc_head = desc_table
            .checked_add((index as u64) * 16)
            .context("integer overflow")?;
        let desc: Desc = read_obj_from_addr_wrapper(mem, &exported_desc_table, desc_head)
            .with_context(|| format!("failed to read desc {:x}", desc_head.offset()))?;

        let addr = GuestAddress(desc.addr.into());
        let len = desc.len.to_native();
        let (regions, exported_region) = if let Some(iommu) = &iommu {
            if exported_desc_table.is_none() {
                bail!("missing exported descriptor table");
            }

            let exported_region =
                ExportedRegion::new(mem, iommu.clone(), addr.offset(), len.into())
                    .context("failed to get mem regions")?;

            let regions = exported_region.get_mem_regions();
            let required_prot = if required_flags & VIRTQ_DESC_F_WRITE == 0 {
                Protection::read()
            } else {
                Protection::write()
            };
            for r in &regions {
                if !r.prot.allows(&required_prot) {
                    bail!("missing RW permissions for descriptor");
                }
            }

            (regions, Some(exported_region))
        } else {
            (
                smallvec![MemRegion {
                    gpa: addr,
                    len: len.into(),
                    prot: Protection::read_write(),
                }],
                None,
            )
        };

        let chain = DescriptorChain {
            mem: mem.clone(),
            desc_table,
            queue_size,
            ttl: queue_size,
            index,
            addr,
            len,
            flags: desc.flags.into(),
            next: desc.next.into(),
            iommu,
            regions,
            exported_region,
            exported_desc_table,
        };

        if chain.is_valid() && chain.flags & required_flags == required_flags {
            Ok(chain)
        } else {
            bail!("chain is invalid")
        }
    }

    pub fn into_mem_regions(self) -> (SmallVec<[MemRegion; 1]>, Option<ExportedRegion>) {
        (self.regions, self.exported_region)
    }

    fn is_valid(&self) -> bool {
        if self.len > 0 {
            // Each region in `self.regions` must be a contiguous range in `self.mem`.
            if !self
                .regions
                .iter()
                .all(|r| self.mem.is_valid_range(r.gpa, r.len as u64))
            {
                return false;
            }
        }

        !self.has_next() || self.next < self.queue_size
    }

    /// Gets if this descriptor chain has another descriptor chain linked after it.
    pub fn has_next(&self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0 && self.ttl > 1
    }

    /// If the driver designated this as a write only descriptor.
    ///
    /// If this is false, this descriptor is read only.
    /// Write only means the the emulated device can write and the driver can read.
    pub fn is_write_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }

    /// If the driver designated this as a read only descriptor.
    ///
    /// If this is false, this descriptor is write only.
    /// Read only means the emulated device can read and the driver can write.
    pub fn is_read_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE == 0
    }

    /// Gets the next descriptor in this descriptor chain, if there is one.
    ///
    /// Note that this is distinct from the next descriptor chain returned by `AvailIter`, which is
    /// the head of the next _available_ descriptor chain.
    pub fn next_descriptor(&self) -> Option<DescriptorChain> {
        if self.has_next() {
            // Once we see a write-only descriptor, all subsequent descriptors must be write-only.
            let required_flags = self.flags & VIRTQ_DESC_F_WRITE;
            let iommu = self.iommu.as_ref().map(Arc::clone);
            match DescriptorChain::checked_new(
                &self.mem,
                self.desc_table,
                self.queue_size,
                self.next,
                required_flags,
                iommu,
                self.exported_desc_table.clone(),
            ) {
                Ok(mut c) => {
                    c.ttl = self.ttl - 1;
                    Some(c)
                }
                Err(e) => {
                    error!("{:#}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    /// Produces an iterator over all the descriptors in this chain.
    pub fn into_iter(self) -> DescIter {
        DescIter { next: Some(self) }
    }
}

/// Consuming iterator over all available descriptor chain heads in the queue.
pub struct AvailIter<'a, 'b> {
    mem: &'a GuestMemory,
    queue: &'b mut Queue,
}

impl<'a, 'b> Iterator for AvailIter<'a, 'b> {
    type Item = DescriptorChain;

    fn next(&mut self) -> Option<Self::Item> {
        self.queue.pop(self.mem)
    }
}

#[derive(Clone)]
/// A virtio queue's parameters.
///
/// WARNING: it is NOT safe to clone and then use n>1 Queue(s) to interact with the same virtqueue.
/// That will prevent descriptor index tracking from being accurate, which can cause incorrect
/// interrupt masking.
/// TODO(b/201119859) drop Clone from this struct.
pub struct Queue {
    /// The maximal size in elements offered by the device
    pub max_size: u16,

    /// The queue size in elements the driver selected
    size: u16,

    /// Inidcates if the queue is finished with configuration
    ready: bool,

    /// Indicates that a ready queue's configuration has been validated successfully.
    validated: bool,

    /// MSI-X vector for the queue. Don't care for INTx
    vector: u16,

    /// Guest physical address of the descriptor table
    desc_table: GuestAddress,

    /// Guest physical address of the available ring
    avail_ring: GuestAddress,

    /// Guest physical address of the used ring
    used_ring: GuestAddress,

    pub next_avail: Wrapping<u16>,
    pub next_used: Wrapping<u16>,

    // Device feature bits accepted by the driver
    features: u64,
    last_used: Wrapping<u16>,

    // Count of notification disables. Users of the queue can disable guest notification while
    // processing requests. This is the count of how many are in flight(could be several contexts
    // handling requests in parallel). When this count is zero, notifications are re-enabled.
    notification_disable_count: usize,

    iommu: Option<Arc<Mutex<IpcMemoryMapper>>>,

    // When |iommu| is present, |desc_table| and the rings are IOVAs rather than real
    // GPAs. These are the exported regions used to access the underlying GPAs. They
    // are initialized by |export_memory| and released by |release_exported_memory|.
    exported_desc_table: Option<ExportedRegion>,
    exported_avail_ring: Option<ExportedRegion>,
    exported_used_ring: Option<ExportedRegion>,
}

macro_rules! accessors {
    ($var:ident, $t:ty, $setter:ident) => {
        pub fn $var(&self) -> $t {
            self.$var
        }

        pub fn $setter(&mut self, val: $t) {
            if self.ready {
                warn!("ignoring write to {} on ready queue", stringify!($var));
                return;
            }
            self.$var = val;
        }
    };
}

impl Queue {
    /// Constructs an empty virtio queue with the given `max_size`.
    pub fn new(max_size: u16) -> Queue {
        Queue {
            max_size,
            size: max_size,
            ready: false,
            validated: false,
            vector: VIRTIO_MSI_NO_VECTOR,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
            features: 0,
            last_used: Wrapping(0),
            notification_disable_count: 0,
            iommu: None,
            exported_desc_table: None,
            exported_avail_ring: None,
            exported_used_ring: None,
        }
    }

    accessors!(vector, u16, set_vector);
    accessors!(size, u16, set_size);
    accessors!(ready, bool, set_ready);
    accessors!(desc_table, GuestAddress, set_desc_table);
    accessors!(avail_ring, GuestAddress, set_avail_ring);
    accessors!(used_ring, GuestAddress, set_used_ring);

    /// Return the actual size of the queue, as the driver may not set up a
    /// queue as big as the device allows.
    pub fn actual_size(&self) -> u16 {
        min(self.size, self.max_size)
    }

    /// Reset queue to a clean state
    pub fn reset(&mut self) {
        self.ready = false;
        self.validated = false;
        self.size = self.max_size;
        self.vector = VIRTIO_MSI_NO_VECTOR;
        self.desc_table = GuestAddress(0);
        self.avail_ring = GuestAddress(0);
        self.used_ring = GuestAddress(0);
        self.next_avail = Wrapping(0);
        self.next_used = Wrapping(0);
        self.features = 0;
        self.last_used = Wrapping(0);
        self.exported_desc_table = None;
        self.exported_avail_ring = None;
        self.exported_used_ring = None;
    }

    /// Reset queue's counters.
    /// This method doesn't change the queue's metadata so it's reusable without initializing it
    /// again.
    pub fn reset_counters(&mut self) {
        self.next_avail = Wrapping(0);
        self.next_used = Wrapping(0);
        self.last_used = Wrapping(0);
    }

    pub fn is_valid(&mut self, mem: &GuestMemory) -> bool {
        if !self.ready {
            error!("attempt to use virtio queue that is not marked ready");
            return false;
        }

        if !self.validated {
            self.validate(mem);
        }
        self.validated
    }

    fn ring_sizes(&self) -> Vec<(GuestAddress, usize)> {
        let queue_size = self.actual_size() as usize;
        vec![
            (self.desc_table, 16 * queue_size),
            (self.avail_ring, 6 + 2 * queue_size),
            (self.used_ring, 6 + 8 * queue_size),
        ]
    }

    /// If this queue is for a device that sits behind a virtio-iommu device, exports
    /// this queue's memory. After the queue becomes ready, this must be called before
    /// using the queue, to convert the IOVA-based configuration to GuestAddresses.
    pub fn export_memory(&mut self, mem: &GuestMemory) -> Result<()> {
        if !self.ready {
            bail!("not ready");
        }
        if self.exported_desc_table.is_some() {
            bail!("already exported");
        }

        let iommu = self.iommu.as_ref().context("no iommu to export with")?;

        let ring_sizes = self.ring_sizes();
        let rings = ring_sizes.iter().zip(vec![
            &mut self.exported_desc_table,
            &mut self.exported_avail_ring,
            &mut self.exported_used_ring,
        ]);

        for ((addr, size), region) in rings {
            *region = Some(
                ExportedRegion::new(mem, iommu.clone(), addr.offset(), *size as u64)
                    .context("failed to export region")?,
            );
        }
        Ok(())
    }

    /// Releases memory exported by a previous call to [`Queue::export_memory()`].
    pub fn release_exported_memory(&mut self) {
        self.exported_desc_table = None;
        self.exported_avail_ring = None;
        self.exported_used_ring = None;
    }

    fn validate(&mut self, mem: &GuestMemory) {
        if self.size > self.max_size || self.size == 0 || (self.size & (self.size - 1)) != 0 {
            error!("virtio queue with invalid size: {}", self.size);
            return;
        }

        if self.iommu.is_none() {
            let ring_sizes = self.ring_sizes();
            let rings =
                ring_sizes
                    .iter()
                    .zip(vec!["descriptor table", "available ring", "used ring"]);
            for ((addr, size), name) in rings {
                if !addr
                    .checked_add(*size as u64)
                    .map_or(false, |v| mem.address_in_range(v))
                {
                    error!(
                        "virtio queue {} goes out of bounds: start:0x{:08x} size:0x{:08x}",
                        name,
                        addr.offset(),
                        size,
                    );
                    return;
                }
            }
        }
        self.validated = true;
    }

    // Get the index of the first available descriptor chain in the available ring
    // (the next one that the driver will fill).
    //
    // All available ring entries between `self.next_avail` and `get_avail_index()` are available
    // to be processed by the device.
    fn get_avail_index(&self, mem: &GuestMemory) -> Wrapping<u16> {
        fence(Ordering::SeqCst);

        let avail_index_addr = self.avail_ring.unchecked_add(2);
        let avail_index: u16 =
            read_obj_from_addr_wrapper(mem, &self.exported_avail_ring, avail_index_addr).unwrap();

        Wrapping(avail_index)
    }

    // Set the `avail_event` field in the used ring.
    //
    // This allows the device to inform the driver that driver-to-device notification
    // (kicking the ring) is not necessary until the driver reaches the `avail_index` descriptor.
    //
    // This value is only used if the `VIRTIO_F_EVENT_IDX` feature has been negotiated.
    fn set_avail_event(&mut self, mem: &GuestMemory, avail_index: Wrapping<u16>) {
        fence(Ordering::SeqCst);

        let avail_event_addr = self
            .used_ring
            .unchecked_add(4 + 8 * u64::from(self.actual_size()));
        write_obj_at_addr_wrapper(
            mem,
            &self.exported_used_ring,
            avail_index.0,
            avail_event_addr,
        )
        .unwrap();
    }

    // Query the value of a single-bit flag in the available ring.
    //
    // Returns `true` if `flag` is currently set (by the driver) in the available ring flags.
    fn get_avail_flag(&self, mem: &GuestMemory, flag: u16) -> bool {
        fence(Ordering::SeqCst);

        let avail_flags: u16 =
            read_obj_from_addr_wrapper(mem, &self.exported_avail_ring, self.avail_ring).unwrap();

        avail_flags & flag == flag
    }

    // Get the `used_event` field in the available ring.
    //
    // The returned value is the index of the next descriptor chain entry for which the driver
    // needs to be notified upon use.  Entries before this index may be used without notifying
    // the driver.
    //
    // This value is only valid if the `VIRTIO_F_EVENT_IDX` feature has been negotiated.
    fn get_used_event(&self, mem: &GuestMemory) -> Wrapping<u16> {
        fence(Ordering::SeqCst);

        let used_event_addr = self
            .avail_ring
            .unchecked_add(4 + 2 * u64::from(self.actual_size()));
        let used_event: u16 =
            read_obj_from_addr_wrapper(mem, &self.exported_avail_ring, used_event_addr).unwrap();

        Wrapping(used_event)
    }

    // Set the `idx` field in the used ring.
    //
    // This indicates to the driver that all entries up to (but not including) `used_index` have
    // been used by the device and may be processed by the driver.
    fn set_used_index(&mut self, mem: &GuestMemory, used_index: Wrapping<u16>) {
        fence(Ordering::SeqCst);

        let used_index_addr = self.used_ring.unchecked_add(2);
        write_obj_at_addr_wrapper(mem, &self.exported_used_ring, used_index.0, used_index_addr)
            .unwrap();
    }

    // Set a single-bit flag in the used ring.
    //
    // Changes the bit specified by the mask in `flag` to `value`.
    fn set_used_flag(&mut self, mem: &GuestMemory, flag: u16, value: bool) {
        fence(Ordering::SeqCst);

        let mut used_flags: u16 =
            read_obj_from_addr_wrapper(mem, &self.exported_used_ring, self.used_ring).unwrap();
        if value {
            used_flags |= flag;
        } else {
            used_flags &= !flag;
        }
        write_obj_at_addr_wrapper(mem, &self.exported_used_ring, used_flags, self.used_ring)
            .unwrap();
    }

    /// Get the first available descriptor chain without removing it from the queue.
    /// Call `pop_peeked` to remove the returned descriptor chain from the queue.
    pub fn peek(&mut self, mem: &GuestMemory) -> Option<DescriptorChain> {
        if !self.is_valid(mem) {
            return None;
        }

        let queue_size = self.actual_size();
        let avail_index = self.get_avail_index(mem);
        let avail_len = avail_index - self.next_avail;

        if avail_len.0 > queue_size || self.next_avail == avail_index {
            return None;
        }

        // This fence ensures that subsequent reads from the descriptor do not
        // get reordered and happen only after fetching the available_index and
        // checking that there is a slot available.
        fence(Ordering::SeqCst);

        let desc_idx_addr_offset = 4 + (u64::from(self.next_avail.0 % queue_size) * 2);
        let desc_idx_addr = self.avail_ring.checked_add(desc_idx_addr_offset)?;

        // This index is checked below in checked_new.
        let descriptor_index: u16 =
            read_obj_from_addr_wrapper(mem, &self.exported_avail_ring, desc_idx_addr).unwrap();

        let iommu = self.iommu.as_ref().map(Arc::clone);
        DescriptorChain::checked_new(
            mem,
            self.desc_table,
            queue_size,
            descriptor_index,
            0,
            iommu,
            self.exported_desc_table.clone(),
        )
        .map_err(|e| {
            error!("{:#}", e);
            e
        })
        .ok()
    }

    /// Remove the first available descriptor chain from the queue.
    /// This function should only be called immediately following `peek`.
    pub fn pop_peeked(&mut self, mem: &GuestMemory) {
        self.next_avail += Wrapping(1);
        if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) != 0 {
            self.set_avail_event(mem, self.next_avail);
        }
    }

    /// If a new DescriptorHead is available, returns one and removes it from the queue.
    pub fn pop(&mut self, mem: &GuestMemory) -> Option<DescriptorChain> {
        let descriptor_chain = self.peek(mem);
        if descriptor_chain.is_some() {
            self.pop_peeked(mem);
        }
        descriptor_chain
    }

    /// A consuming iterator over all available descriptor chain heads offered by the driver.
    pub fn iter<'a, 'b>(&'b mut self, mem: &'a GuestMemory) -> AvailIter<'a, 'b> {
        AvailIter { mem, queue: self }
    }

    /// Asynchronously read the next descriptor chain from the queue.
    /// Returns a `DescriptorChain` when it is `await`ed.
    pub async fn next_async(
        &mut self,
        mem: &GuestMemory,
        eventfd: &mut EventAsync,
    ) -> std::result::Result<DescriptorChain, AsyncError> {
        loop {
            // Check if there are more descriptors available.
            if let Some(chain) = self.pop(mem) {
                return Ok(chain);
            }
            eventfd.next_val().await?;
        }
    }

    /// Puts an available descriptor head into the used ring for use by the guest.
    pub fn add_used(&mut self, mem: &GuestMemory, desc_index: u16, len: u32) {
        if desc_index >= self.actual_size() {
            error!(
                "attempted to add out of bounds descriptor to used ring: {}",
                desc_index
            );
            return;
        }

        let used_ring = self.used_ring;
        let next_used = (self.next_used.0 % self.actual_size()) as usize;
        let used_elem = used_ring.unchecked_add((4 + next_used * 8) as u64);

        // These writes can't fail as we are guaranteed to be within the descriptor ring.
        write_obj_at_addr_wrapper(mem, &self.exported_used_ring, desc_index as u32, used_elem)
            .unwrap();
        write_obj_at_addr_wrapper(
            mem,
            &self.exported_used_ring,
            len as u32,
            used_elem.unchecked_add(4),
        )
        .unwrap();

        self.next_used += Wrapping(1);
        self.set_used_index(mem, self.next_used);
    }

    /// Enable / Disable guest notify device that requests are available on
    /// the descriptor chain.
    pub fn set_notify(&mut self, mem: &GuestMemory, enable: bool) {
        if enable {
            self.notification_disable_count -= 1;
        } else {
            self.notification_disable_count += 1;
        }

        // We should only set VIRTQ_USED_F_NO_NOTIFY when the VIRTIO_RING_F_EVENT_IDX feature has
        // not been negotiated.
        if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) == 0 {
            self.set_used_flag(
                mem,
                VIRTQ_USED_F_NO_NOTIFY,
                self.notification_disable_count > 0,
            );
        }
    }

    /// Returns if the queue should have an interrupt sent based on its state.
    ///
    /// This function implements `VIRTIO_RING_F_EVENT_IDX`, otherwise known as
    /// interrupt suppression. The virtio spec provides the driver with a field,
    /// `used_event`, which says that once we write that descriptor (or several
    /// in the case of a flurry of `add_used` calls), we should send a
    /// notification. Because the values involved wrap around `u16::MAX`, and to
    /// avoid checking the condition on every `add_used` call, the math is a
    /// little complicated.
    ///
    /// The critical inequality is:
    /// ```text
    ///      (next_used - 1) - used_event < next_used - last_used
    /// ```
    ///
    /// For illustration purposes, we label it as `A < B`, where
    /// `A = (next_used -1) - used_event`, and `B = next_used - last_used`.
    ///
    /// `A` and `B` represent two distances, measured in a wrapping ring of size
    /// `u16::MAX`. In the "send intr" case, the inequality is true. In the
    /// "don't send intr" case, the inequality is false. We must be very careful
    /// in assigning a direction to the ring, so that when we
    /// graph the subtraction operations, we are measuring the right distance
    /// (similar to how DC circuits are analyzed).
    ///
    /// The two distances are as follows:
    ///  * `A` is the distance between the driver's requested notification
    ///    point, and the current position in the ring.
    ///
    ///  * `B` is the distance between the last time we notified the guest,
    ///    and the current position in the ring.
    ///
    /// If we graph these distances for the situation where we want to notify
    /// the guest, and when we don't want to notify the guest, we see that
    /// `A < B` becomes true the moment `next_used - 1` passes `used_event`. See
    /// the graphs at the bottom of this comment block for a more visual
    /// explanation.
    ///
    /// Once an interrupt is sent, we have a final useful property: last_used
    /// moves up next_used, which causes the inequality to be false. Thus, we
    /// won't send notifications again until `used_event` is moved forward by
    /// the driver.
    ///
    /// Finally, let's talk about a couple of ways to write this inequality
    /// that don't work, and critically, explain *why*.
    ///
    /// First, a naive reading of the virtio spec might lead us to ask: why not
    /// just use the following inequality:
    /// ```text
    ///      next_used - 1 >= used_event
    /// ```
    ///
    /// because that's much simpler, right? The trouble is that the ring wraps,
    /// so it could be that a smaller index is actually ahead of a larger one.
    /// That's why we have to use distances in the ring instead.
    ///
    /// Second, one might look at the correct inequality:
    /// ```text
    ///      (next_used - 1) - used_event < next_used - last_used
    /// ```
    ///
    /// And try to simplify it to:
    /// ```text
    ///      last_used - 1 < used_event
    /// ```
    ///
    /// Functionally, this won't work because next_used isn't present at all
    /// anymore. (Notifications will never be sent.) But why is that? The algebra
    /// here *appears* to work out, but all semantic meaning is lost. There are
    /// two explanations for why this happens:
    /// * The intuitive one: the terms in the inequality are not actually
    ///   separable; in other words, (next_used - last_used) is an inseparable
    ///   term, so subtracting next_used from both sides of the original
    ///   inequality and zeroing them out is semantically invalid. But why aren't
    ///   they separable? See below.
    /// * The theoretical one: canceling like terms relies a vector space law:
    ///   a + x = b + x => a = b (cancellation law). For congruences / equality
    ///   under modulo, this law is satisfied, but for inequalities under mod, it
    ///   is not; therefore, we cannot cancel like terms.
    ///
    /// ```text
    /// ┌──────────────────────────────────┐
    /// │                                  │
    /// │                                  │
    /// │                                  │
    /// │           ┌────────────  next_used - 1
    /// │           │A                   x
    /// │           │       ┌────────────x────────────┐
    /// │           │       │            x            │
    /// │           │       │                         │
    /// │           │       │               │         │
    /// │           │       │               │         │
    /// │     used_event  xxxx        + ◄───┘       xxxxx last_used
    /// │                   │                         │      │
    /// │                   │        Send intr        │      │
    /// │                   │                         │      │
    /// │                   └─────────────────────────┘      │
    /// │                                                    │
    /// │ B                                                  │
    /// └────────────────────────────────────────────────────┘
    ///
    ///             ┌───────────────────────────────────────────────────┐
    ///             │                                                 A │
    ///             │       ┌────────────────────────┐                  │
    ///             │       │                        │                  │
    ///             │       │                        │                  │
    ///             │       │              │         │                  │
    ///             │       │              │         │                  │
    ///       used_event  xxxx             │       xxxxx last_used      │
    ///                     │        + ◄───┘         │       │          │
    ///                     │                        │       │          │
    ///                     │     Don't send intr    │       │          │
    ///                     │                        │       │          │
    ///                     └───────────x────────────┘       │          │
    ///                                 x                    │          │
    ///                              next_used - 1           │          │
    ///                              │  │                  B │          │
    ///                              │  └────────────────────┘          │
    ///                              │                                  │
    ///                              └──────────────────────────────────┘
    /// ```
    fn queue_wants_interrupt(&self, mem: &GuestMemory) -> bool {
        if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) != 0 {
            let used_event = self.get_used_event(mem);
            self.next_used - used_event - Wrapping(1) < self.next_used - self.last_used
        } else {
            !self.get_avail_flag(mem, VIRTQ_AVAIL_F_NO_INTERRUPT)
        }
    }

    /// inject interrupt into guest on this queue
    /// return true: interrupt is injected into guest for this queue
    ///        false: interrupt isn't injected
    pub fn trigger_interrupt<I: SignalableInterrupt>(
        &mut self,
        mem: &GuestMemory,
        interrupt: &I,
    ) -> bool {
        if self.queue_wants_interrupt(mem) {
            self.last_used = self.next_used;
            interrupt.signal_used_queue(self.vector);
            true
        } else {
            false
        }
    }

    /// Acknowledges that this set of features should be enabled on this queue.
    pub fn ack_features(&mut self, features: u64) {
        self.features |= features;
    }

    pub fn set_iommu(&mut self, iommu: Arc<Mutex<IpcMemoryMapper>>) {
        self.iommu = Some(iommu);
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use memoffset::offset_of;

    use super::super::Interrupt;
    use super::*;
    use crate::IrqLevelEvent;

    const GUEST_MEMORY_SIZE: u64 = 0x10000;
    const DESC_OFFSET: u64 = 0;
    const AVAIL_OFFSET: u64 = 0x200;
    const USED_OFFSET: u64 = 0x400;
    const QUEUE_SIZE: usize = 0x10;
    const BUFFER_OFFSET: u64 = 0x8000;
    const BUFFER_LEN: u32 = 0x400;

    #[derive(Copy, Clone, Debug)]
    #[repr(C)]
    struct Avail {
        flags: Le16,
        idx: Le16,
        ring: [Le16; QUEUE_SIZE],
        used_event: Le16,
    }
    // Safe as this only runs in test
    unsafe impl DataInit for Avail {}
    impl Default for Avail {
        fn default() -> Self {
            Avail {
                flags: Le16::from(0u16),
                idx: Le16::from(0u16),
                ring: [Le16::from(0u16); QUEUE_SIZE],
                used_event: Le16::from(0u16),
            }
        }
    }

    #[derive(Copy, Clone, Debug)]
    #[repr(C)]
    struct UsedElem {
        id: Le32,
        len: Le32,
    }
    // Safe as this only runs in test
    unsafe impl DataInit for UsedElem {}
    impl Default for UsedElem {
        fn default() -> Self {
            UsedElem {
                id: Le32::from(0u32),
                len: Le32::from(0u32),
            }
        }
    }

    #[derive(Copy, Clone, Debug)]
    #[repr(C)]
    struct Used {
        flags: Le16,
        idx: Le16,
        used_elem_ring: [UsedElem; QUEUE_SIZE],
        avail_event: Le16,
    }
    // Safe as this only runs in test
    unsafe impl DataInit for Used {}
    impl Default for Used {
        fn default() -> Self {
            Used {
                flags: Le16::from(0u16),
                idx: Le16::from(0u16),
                used_elem_ring: [UsedElem::default(); QUEUE_SIZE],
                avail_event: Le16::from(0u16),
            }
        }
    }

    fn setup_vq(queue: &mut Queue, mem: &GuestMemory) {
        let desc = Desc {
            addr: Le64::from(BUFFER_OFFSET),
            len: Le32::from(BUFFER_LEN),
            flags: Le16::from(0u16),
            next: Le16::from(1u16),
        };
        let _ = mem.write_obj_at_addr(desc, GuestAddress(DESC_OFFSET));

        let avail = Avail::default();
        let _ = mem.write_obj_at_addr(avail, GuestAddress(AVAIL_OFFSET));

        let used = Used::default();
        let _ = mem.write_obj_at_addr(used, GuestAddress(USED_OFFSET));

        queue.desc_table = GuestAddress(DESC_OFFSET);
        queue.avail_ring = GuestAddress(AVAIL_OFFSET);
        queue.used_ring = GuestAddress(USED_OFFSET);
        queue.ack_features((1u64) << VIRTIO_RING_F_EVENT_IDX);
    }

    #[test]
    fn queue_event_id_guest_fast() {
        let mut queue = Queue::new(QUEUE_SIZE.try_into().unwrap());
        let memory_start_addr = GuestAddress(0x0);
        let mem = GuestMemory::new(&[(memory_start_addr, GUEST_MEMORY_SIZE)]).unwrap();
        setup_vq(&mut queue, &mem);

        let interrupt = Interrupt::new(IrqLevelEvent::new().unwrap(), None, 10);

        // Offset of used_event within Avail structure
        let used_event_offset = offset_of!(Avail, used_event) as u64;
        let used_event_address = GuestAddress(AVAIL_OFFSET + used_event_offset);

        // Assume driver submit 0x100 req to device,
        // device has handled them, so increase self.next_used to 0x100
        let mut device_generate: Wrapping<u16> = Wrapping(0x100);
        for _ in 0..device_generate.0 {
            queue.add_used(&mem, 0x0, BUFFER_LEN);
        }

        // At this moment driver hasn't handled any interrupts yet, so it
        // should inject interrupt.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);

        // Driver handle all the interrupts and update avail.used_event to 0x100
        let mut driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver have handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // Assume driver submit another u16::MAX - 0x100 req to device,
        // Device has handled all of them, so increase self.next_used to u16::MAX
        for _ in device_generate.0..u16::max_value() {
            queue.add_used(&mem, 0x0, BUFFER_LEN);
        }
        device_generate = Wrapping(u16::max_value());

        // At this moment driver just handled 0x100 interrupts, so it
        // should inject interrupt.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);

        // driver handle all the interrupts and update avail.used_event to u16::MAX
        driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver have handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // Assume driver submit another 1 request,
        // device has handled it, so wrap self.next_used to 0
        queue.add_used(&mem, 0x0, BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver has handled all the previous interrupts, so it
        // should inject interrupt again.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);

        // driver handle that interrupts and update avail.used_event to 0
        driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver have handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);
    }

    #[test]
    fn queue_event_id_guest_slow() {
        let mut queue = Queue::new(QUEUE_SIZE.try_into().unwrap());
        let memory_start_addr = GuestAddress(0x0);
        let mem = GuestMemory::new(&[(memory_start_addr, GUEST_MEMORY_SIZE)]).unwrap();
        setup_vq(&mut queue, &mem);

        let interrupt = Interrupt::new(IrqLevelEvent::new().unwrap(), None, 10);

        // Offset of used_event within Avail structure
        let used_event_offset = offset_of!(Avail, used_event) as u64;
        let used_event_address = GuestAddress(AVAIL_OFFSET + used_event_offset);

        // Assume driver submit 0x100 req to device,
        // device have handled 0x100 req, so increase self.next_used to 0x100
        let mut device_generate: Wrapping<u16> = Wrapping(0x100);
        for _ in 0..device_generate.0 {
            queue.add_used(&mem, 0x0, BUFFER_LEN);
        }

        // At this moment driver hasn't handled any interrupts yet, so it
        // should inject interrupt.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);

        // Driver handle part of the interrupts and update avail.used_event to 0x80
        let mut driver_handled = Wrapping(0x80);
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver hasn't finished last interrupt yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // Assume driver submit another 1 request,
        // device has handled it, so increment self.next_used.
        queue.add_used(&mem, 0x0, BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver hasn't finished last interrupt yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // Assume driver submit another u16::MAX - 0x101 req to device,
        // Device has handled all of them, so increase self.next_used to u16::MAX
        for _ in device_generate.0..u16::max_value() {
            queue.add_used(&mem, 0x0, BUFFER_LEN);
        }
        device_generate = Wrapping(u16::max_value());

        // At this moment driver hasn't finished last interrupt yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // driver handle most of the interrupts and update avail.used_event to u16::MAX - 1,
        driver_handled = device_generate - Wrapping(1);
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // Assume driver submit another 1 request,
        // device has handled it, so wrap self.next_used to 0
        queue.add_used(&mem, 0x0, BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver has already finished the last interrupt(0x100),
        // and device service other request, so new interrupt is needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);

        // Assume driver submit another 1 request,
        // device has handled it, so increment self.next_used to 1
        queue.add_used(&mem, 0x0, BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver hasn't finished last interrupt((Wrapping(0)) yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // driver handle all the remain interrupts and wrap avail.used_event to 0x1.
        driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver has handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // Assume driver submit another 1 request,
        // device has handled it, so increase self.next_used.
        queue.add_used(&mem, 0x0, BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver has finished all the previous interrupts, so it
        // should inject interrupt again.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);
    }
}
