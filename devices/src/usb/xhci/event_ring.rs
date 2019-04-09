// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::DataInit;
use std;
use std::fmt::{self, Display};
use std::mem::size_of;
use std::sync::atomic::{fence, Ordering};
use sys_util::{GuestAddress, GuestMemory, GuestMemoryError};

use super::xhci_abi::*;

#[derive(Debug)]
pub enum Error {
    Uninitialized,
    EventRingFull,
    BadEnqueuePointer(GuestAddress),
    BadSegTableIndex(u16),
    BadSegTableAddress(GuestAddress),
    MemoryRead(GuestMemoryError),
    MemoryWrite(GuestMemoryError),
}

type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            Uninitialized => write!(f, "event ring is uninitialized"),
            EventRingFull => write!(f, "event ring is full"),
            BadEnqueuePointer(addr) => write!(f, "event ring has a bad enqueue pointer: {}", addr),
            BadSegTableIndex(i) => write!(f, "event ring has a bad seg table index: {}", i),
            BadSegTableAddress(addr) => write!(f, "event ring has a bad seg table addr: {}", addr),
            MemoryRead(e) => write!(f, "event ring cannot read from guest memory: {}", e),
            MemoryWrite(e) => write!(f, "event ring cannot write to guest memory: {}", e),
        }
    }
}

/// Event rings are segmented circular buffers used to pass event TRBs from the xHCI device back to
/// the guest.  Each event ring is associated with a single interrupter.  See section 4.9.4 of the
/// xHCI specification for more details.
/// This implementation is only for primary interrupter. Please review xhci spec before using it
/// for secondary.
pub struct EventRing {
    mem: GuestMemory,
    segment_table_size: u16,
    segment_table_base_address: GuestAddress,
    current_segment_index: u16,
    trb_count: u16,
    enqueue_pointer: GuestAddress,
    dequeue_pointer: GuestAddress,
    producer_cycle_state: bool,
}

impl EventRing {
    /// Create an empty, uninitialized event ring.
    pub fn new(mem: GuestMemory) -> Self {
        EventRing {
            mem,
            segment_table_size: 0,
            segment_table_base_address: GuestAddress(0),
            current_segment_index: 0,
            enqueue_pointer: GuestAddress(0),
            dequeue_pointer: GuestAddress(0),
            trb_count: 0,
            // As specified in xHCI spec 4.9.4, cycle state should be initialized to 1.
            producer_cycle_state: true,
        }
    }

    /// This function implements left side of xHCI spec, Figure 4-12.
    pub fn add_event(&mut self, mut trb: Trb) -> Result<()> {
        self.check_inited()?;
        if self.is_full()? {
            return Err(Error::EventRingFull);
        }
        // Event is write twice to avoid race condition.
        // Guest kernel use cycle bit to check ownership, thus we should write cycle last.
        trb.set_cycle(!self.producer_cycle_state);
        self.mem
            .write_obj_at_addr(trb, self.enqueue_pointer)
            .map_err(Error::MemoryWrite)?;

        // Updating the cycle state bit should always happen after updating other parts.
        fence(Ordering::SeqCst);

        trb.set_cycle(self.producer_cycle_state);

        // Offset of cycle state byte.
        const CYCLE_STATE_OFFSET: usize = 12usize;
        let data = trb.as_slice();
        // Trb contains 4 dwords, the last one contains cycle bit.
        let cycle_bit_dword = &data[CYCLE_STATE_OFFSET..];
        let address = self.enqueue_pointer;
        let address = address
            .checked_add(CYCLE_STATE_OFFSET as u64)
            .ok_or(Error::BadEnqueuePointer(self.enqueue_pointer))?;
        self.mem
            .write_all_at_addr(cycle_bit_dword, address)
            .map_err(Error::MemoryWrite)?;

        usb_debug!(
            "event write to pointer {:#x}, trb_count {}, {}",
            self.enqueue_pointer.0,
            self.trb_count,
            trb
        );
        self.enqueue_pointer = match self.enqueue_pointer.checked_add(size_of::<Trb>() as u64) {
            Some(addr) => addr,
            None => return Err(Error::BadEnqueuePointer(self.enqueue_pointer)),
        };
        self.trb_count -= 1;
        if self.trb_count == 0 {
            self.current_segment_index += 1;
            if self.current_segment_index == self.segment_table_size {
                self.producer_cycle_state ^= true;
                self.current_segment_index = 0;
            }
            self.load_current_seg_table_entry()?;
        }
        Ok(())
    }

    /// Set segment table size.
    pub fn set_seg_table_size(&mut self, size: u16) -> Result<()> {
        usb_debug!("event ring seg table size is set to {}", size);
        self.segment_table_size = size;
        self.try_reconfigure_event_ring()
    }

    /// Set segment table base addr.
    pub fn set_seg_table_base_addr(&mut self, addr: GuestAddress) -> Result<()> {
        usb_debug!("event ring seg table base addr is set to {:#x}", addr.0);
        self.segment_table_base_address = addr;
        self.try_reconfigure_event_ring()
    }

    /// Set dequeue pointer.
    pub fn set_dequeue_pointer(&mut self, addr: GuestAddress) {
        usb_debug!("event ring dequeue pointer set to {:#x}", addr.0);
        self.dequeue_pointer = addr;
    }

    /// Get the enqueue pointer.
    pub fn get_enqueue_pointer(&self) -> GuestAddress {
        self.enqueue_pointer
    }

    /// Check if event ring is empty.
    pub fn is_empty(&self) -> bool {
        self.enqueue_pointer == self.dequeue_pointer
    }

    /// Event ring is considered full when there is only space for one last TRB. In this case, xHC
    /// should write an error Trb and do a bunch of handlings. See spec, figure 4-12 for more
    /// details.
    /// For now, we just check event ring full and fail (as it's unlikely to happen).
    pub fn is_full(&self) -> Result<bool> {
        if self.trb_count == 1 {
            // erst == event ring segment table
            let next_erst_idx = (self.current_segment_index + 1) % self.segment_table_size;
            let erst_entry = self.read_seg_table_entry(next_erst_idx)?;
            Ok(self.dequeue_pointer.0 == erst_entry.get_ring_segment_base_address())
        } else {
            Ok(self.dequeue_pointer.0 == self.enqueue_pointer.0 + size_of::<Trb>() as u64)
        }
    }

    /// Try to init event ring. Will fail if seg table size/address are invalid.
    fn try_reconfigure_event_ring(&mut self) -> Result<()> {
        if self.segment_table_size == 0 || self.segment_table_base_address.0 == 0 {
            return Ok(());
        }
        self.load_current_seg_table_entry()
    }

    // Check if this event ring is inited.
    fn check_inited(&self) -> Result<()> {
        if self.segment_table_size == 0
            || self.segment_table_base_address == GuestAddress(0)
            || self.enqueue_pointer == GuestAddress(0)
        {
            return Err(Error::Uninitialized);
        }
        Ok(())
    }

    // Load entry of current seg table.
    fn load_current_seg_table_entry(&mut self) -> Result<()> {
        let entry = self.read_seg_table_entry(self.current_segment_index)?;
        self.enqueue_pointer = GuestAddress(entry.get_ring_segment_base_address());
        self.trb_count = entry.get_ring_segment_size();
        Ok(())
    }

    // Get seg table entry at index.
    fn read_seg_table_entry(&self, index: u16) -> Result<EventRingSegmentTableEntry> {
        let seg_table_addr = self.get_seg_table_addr(index)?;
        // TODO(jkwang) We can refactor GuestMemory to allow in-place memory operation.
        self.mem
            .read_obj_from_addr(seg_table_addr)
            .map_err(Error::MemoryRead)
    }

    // Get seg table addr at index.
    fn get_seg_table_addr(&self, index: u16) -> Result<GuestAddress> {
        if index > self.segment_table_size {
            return Err(Error::BadSegTableIndex(index));
        }
        self.segment_table_base_address
            .checked_add(((size_of::<EventRingSegmentTableEntry>() as u16) * index) as u64)
            .ok_or(Error::BadSegTableAddress(self.segment_table_base_address))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn test_uninited() {
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut er = EventRing::new(gm.clone());
        let trb = Trb::new();
        match er.add_event(trb).err().unwrap() {
            Error::Uninitialized => {}
            _ => panic!("unexpected error"),
        }
        assert_eq!(er.is_empty(), true);
        assert_eq!(er.is_full().unwrap(), false);
    }

    #[test]
    fn test_event_ring() {
        let trb_size = size_of::<Trb>() as u64;
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut er = EventRing::new(gm.clone());
        let mut st_entries = [EventRingSegmentTableEntry::new(); 3];
        st_entries[0].set_ring_segment_base_address(0x100);
        st_entries[0].set_ring_segment_size(3);
        st_entries[1].set_ring_segment_base_address(0x200);
        st_entries[1].set_ring_segment_size(3);
        st_entries[2].set_ring_segment_base_address(0x300);
        st_entries[2].set_ring_segment_size(3);
        gm.write_obj_at_addr(st_entries[0], GuestAddress(0x8))
            .unwrap();
        gm.write_obj_at_addr(
            st_entries[1],
            GuestAddress(0x8 + size_of::<EventRingSegmentTableEntry>() as u64),
        )
        .unwrap();
        gm.write_obj_at_addr(
            st_entries[2],
            GuestAddress(0x8 + 2 * size_of::<EventRingSegmentTableEntry>() as u64),
        )
        .unwrap();
        // Init event ring. Must init after segment tables writting.
        er.set_seg_table_size(3).unwrap();
        er.set_seg_table_base_addr(GuestAddress(0x8)).unwrap();
        er.set_dequeue_pointer(GuestAddress(0x100));

        let mut trb = Trb::new();

        // Fill first table.
        trb.set_control(1);
        assert_eq!(er.is_empty(), true);
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm.read_obj_from_addr(GuestAddress(0x100)).unwrap();
        assert_eq!(t.get_control(), 1);
        assert_eq!(t.get_cycle(), true);

        trb.set_control(2);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x100 + trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 2);
        assert_eq!(t.get_cycle(), true);

        trb.set_control(3);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x100 + 2 * trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 3);
        assert_eq!(t.get_cycle(), true);

        // Fill second table.
        trb.set_control(4);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm.read_obj_from_addr(GuestAddress(0x200)).unwrap();
        assert_eq!(t.get_control(), 4);
        assert_eq!(t.get_cycle(), true);

        trb.set_control(5);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x200 + trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 5);
        assert_eq!(t.get_cycle(), true);

        trb.set_control(6);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x200 + 2 * trb_size as u64))
            .unwrap();
        assert_eq!(t.get_control(), 6);
        assert_eq!(t.get_cycle(), true);

        // Fill third table.
        trb.set_control(7);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm.read_obj_from_addr(GuestAddress(0x300)).unwrap();
        assert_eq!(t.get_control(), 7);
        assert_eq!(t.get_cycle(), true);

        trb.set_control(8);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        // There is only one last trb. Considered full.
        assert_eq!(er.is_full().unwrap(), true);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x300 + trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 8);
        assert_eq!(t.get_cycle(), true);

        // Add the last trb will result in error.
        match er.add_event(trb.clone()) {
            Err(Error::EventRingFull) => {}
            _ => panic!("er should be full"),
        };

        // Dequeue one trb.
        er.set_dequeue_pointer(GuestAddress(0x100 + trb_size));
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);

        // Fill the last trb of the third table.
        trb.set_control(9);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        // There is only one last trb. Considered full.
        assert_eq!(er.is_full().unwrap(), true);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x300 + trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 8);
        assert_eq!(t.get_cycle(), true);

        // Add the last trb will result in error.
        match er.add_event(trb.clone()) {
            Err(Error::EventRingFull) => {}
            _ => panic!("er should be full"),
        };

        // Dequeue until empty.
        er.set_dequeue_pointer(GuestAddress(0x100));
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), true);

        // Fill first table again.
        trb.set_control(10);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm.read_obj_from_addr(GuestAddress(0x100)).unwrap();
        assert_eq!(t.get_control(), 10);
        // cycle bit should be reversed.
        assert_eq!(t.get_cycle(), false);

        trb.set_control(11);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x100 + trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 11);
        assert_eq!(t.get_cycle(), false);

        trb.set_control(12);
        assert_eq!(er.add_event(trb.clone()).unwrap(), ());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x100 + 2 * trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 12);
        assert_eq!(t.get_cycle(), false);
    }
}
