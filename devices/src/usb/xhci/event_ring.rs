// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::size_of;
use std::sync::atomic::fence;
use std::sync::atomic::Ordering;

use remain::sorted;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;
use zerocopy::IntoBytes;

use super::xhci_abi::EventRingSegmentTableEntry;
use super::xhci_abi::Trb;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("event ring has a bad enqueue pointer: {0}")]
    BadEnqueuePointer(GuestAddress),
    #[error("event ring has a bad seg table addr: {0}")]
    BadSegTableAddress(GuestAddress),
    #[error("event ring has a bad seg table index: {0}")]
    BadSegTableIndex(u16),
    #[error("event ring is full")]
    EventRingFull,
    #[error("event ring cannot read from guest memory: {0}")]
    MemoryRead(GuestMemoryError),
    #[error("event ring cannot write to guest memory: {0}")]
    MemoryWrite(GuestMemoryError),
    #[error("event ring is uninitialized")]
    Uninitialized,
}

type Result<T> = std::result::Result<T, Error>;

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
        let data = trb.as_bytes();
        // Trb contains 4 dwords, the last one contains cycle bit.
        let cycle_bit_dword = &data[CYCLE_STATE_OFFSET..];
        let address = self.enqueue_pointer;
        let address = address
            .checked_add(CYCLE_STATE_OFFSET as u64)
            .ok_or(Error::BadEnqueuePointer(self.enqueue_pointer))?;
        self.mem
            .write_all_at_addr(cycle_bit_dword, address)
            .map_err(Error::MemoryWrite)?;

        xhci_trace!(
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
        xhci_trace!("set_seg_table_size({:#x})", size);
        self.segment_table_size = size;
        self.try_reconfigure_event_ring()
    }

    /// Set segment table base addr.
    pub fn set_seg_table_base_addr(&mut self, addr: GuestAddress) -> Result<()> {
        xhci_trace!("set_seg_table_base_addr({:#x})", addr.0);
        self.segment_table_base_address = addr;
        self.try_reconfigure_event_ring()
    }

    /// Set dequeue pointer.
    pub fn set_dequeue_pointer(&mut self, addr: GuestAddress) {
        xhci_trace!("set_dequeue_pointer({:#x})", addr.0);
        self.dequeue_pointer = addr;
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
            let next_erst_idx =
                Self::next_seg_table_index(self.current_segment_index, self.segment_table_size)?;
            let erst_entry = self.read_seg_table_entry(next_erst_idx)?;
            Ok(self.dequeue_pointer.0 == erst_entry.get_ring_segment_base_address())
        } else {
            Self::is_non_boundary_full(self.enqueue_pointer, self.dequeue_pointer)
        }
    }

    fn next_seg_table_index(current_segment_index: u16, segment_table_size: u16) -> Result<u16> {
        if segment_table_size == 0 {
            return Err(Error::Uninitialized);
        }
        Ok(((current_segment_index as u32 + 1) % (segment_table_size as u32)) as u16)
    }

    fn is_non_boundary_full(
        enqueue_pointer: GuestAddress,
        dequeue_pointer: GuestAddress,
    ) -> Result<bool> {
        let next_enq = enqueue_pointer
            .checked_add(size_of::<Trb>() as u64)
            .ok_or(Error::BadEnqueuePointer(enqueue_pointer))?;
        Ok(dequeue_pointer == next_enq)
    }

    /// Try to init event ring. Will fail if seg table size/address are invalid.
    fn try_reconfigure_event_ring(&mut self) -> Result<()> {
        if self.segment_table_size == 0 || self.segment_table_base_address.0 == 0 {
            return Ok(());
        }
        if self.current_segment_index >= self.segment_table_size {
            self.current_segment_index = 0;
        }
        self.load_current_seg_table_entry()
    }

    // Check if this event ring is inited.
    fn check_inited(&self) -> Result<()> {
        Self::check_inited_params(
            self.segment_table_size,
            self.segment_table_base_address,
            self.enqueue_pointer,
            self.trb_count,
        )
    }

    fn check_inited_params(
        segment_table_size: u16,
        segment_table_base_address: GuestAddress,
        enqueue_pointer: GuestAddress,
        trb_count: u16,
    ) -> Result<()> {
        if segment_table_size == 0
            || segment_table_base_address == GuestAddress(0)
            || enqueue_pointer == GuestAddress(0)
            || trb_count == 0
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
        Self::calc_seg_table_addr(
            self.segment_table_base_address,
            self.segment_table_size,
            index,
        )
    }

    fn calc_seg_table_addr(
        base_address: GuestAddress,
        segment_table_size: u16,
        index: u16,
    ) -> Result<GuestAddress> {
        if index >= segment_table_size {
            return Err(Error::BadSegTableIndex(index));
        }
        base_address
            .checked_add((size_of::<EventRingSegmentTableEntry>() as u64) * (index as u64))
            .ok_or(Error::BadSegTableAddress(base_address))
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use base::pagesize;

    use super::*;

    #[test]
    fn test_uninited() {
        let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
        let mut er = EventRing::new(gm);
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
        let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
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
        assert!(er.add_event(trb).is_ok());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm.read_obj_from_addr(GuestAddress(0x100)).unwrap();
        assert_eq!(t.get_control(), 1);
        assert_eq!(t.get_cycle(), true);

        trb.set_control(2);
        assert!(er.add_event(trb).is_ok());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x100 + trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 2);
        assert_eq!(t.get_cycle(), true);

        trb.set_control(3);
        assert!(er.add_event(trb).is_ok());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x100 + 2 * trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 3);
        assert_eq!(t.get_cycle(), true);

        // Fill second table.
        trb.set_control(4);
        assert!(er.add_event(trb).is_ok());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm.read_obj_from_addr(GuestAddress(0x200)).unwrap();
        assert_eq!(t.get_control(), 4);
        assert_eq!(t.get_cycle(), true);

        trb.set_control(5);
        assert!(er.add_event(trb).is_ok());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x200 + trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 5);
        assert_eq!(t.get_cycle(), true);

        trb.set_control(6);
        assert!(er.add_event(trb).is_ok());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x200 + 2 * trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 6);
        assert_eq!(t.get_cycle(), true);

        // Fill third table.
        trb.set_control(7);
        assert!(er.add_event(trb).is_ok());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm.read_obj_from_addr(GuestAddress(0x300)).unwrap();
        assert_eq!(t.get_control(), 7);
        assert_eq!(t.get_cycle(), true);

        trb.set_control(8);
        assert!(er.add_event(trb).is_ok());
        // There is only one last trb. Considered full.
        assert_eq!(er.is_full().unwrap(), true);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x300 + trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 8);
        assert_eq!(t.get_cycle(), true);

        // Add the last trb will result in error.
        match er.add_event(trb) {
            Err(Error::EventRingFull) => {}
            _ => panic!("er should be full"),
        };

        // Dequeue one trb.
        er.set_dequeue_pointer(GuestAddress(0x100 + trb_size));
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);

        // Fill the last trb of the third table.
        trb.set_control(9);
        assert!(er.add_event(trb).is_ok());
        // There is only one last trb. Considered full.
        assert_eq!(er.is_full().unwrap(), true);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x300 + trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 8);
        assert_eq!(t.get_cycle(), true);

        // Add the last trb will result in error.
        match er.add_event(trb) {
            Err(Error::EventRingFull) => {}
            _ => panic!("er should be full"),
        };

        // Dequeue until empty.
        er.set_dequeue_pointer(GuestAddress(0x100));
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), true);

        // Fill first table again.
        trb.set_control(10);
        assert!(er.add_event(trb).is_ok());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm.read_obj_from_addr(GuestAddress(0x100)).unwrap();
        assert_eq!(t.get_control(), 10);
        // cycle bit should be reversed.
        assert_eq!(t.get_cycle(), false);

        trb.set_control(11);
        assert!(er.add_event(trb).is_ok());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x100 + trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 11);
        assert_eq!(t.get_cycle(), false);

        trb.set_control(12);
        assert!(er.add_event(trb).is_ok());
        assert_eq!(er.is_full().unwrap(), false);
        assert_eq!(er.is_empty(), false);
        let t: Trb = gm
            .read_obj_from_addr(GuestAddress(0x100 + 2 * trb_size))
            .unwrap();
        assert_eq!(t.get_control(), 12);
        assert_eq!(t.get_cycle(), false);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn proof_event_ring_seg_table_and_state() {
        let seg_table_size: u16 = kani::any();
        let base_addr: u64 = kani::any();
        let cur_idx: u16 = kani::any();
        let trb_count: u16 = kani::any();
        let enq_addr: u64 = kani::any();
        let deq_addr: u64 = kani::any();
        let lookup_idx: u16 = kani::any();

        // 1. Verify calc_seg_table_addr bounds check and 64-bit multiplication without u16
        //    overflow.
        let addr_res =
            EventRing::calc_seg_table_addr(GuestAddress(base_addr), seg_table_size, lookup_idx);
        if lookup_idx >= seg_table_size {
            assert!(matches!(addr_res, Err(Error::BadSegTableIndex(_))));
        } else {
            let expected_offset =
                (size_of::<EventRingSegmentTableEntry>() as u64) * (lookup_idx as u64);
            match base_addr.checked_add(expected_offset) {
                Some(expected_addr) => {
                    assert!(matches!(addr_res, Ok(addr) if addr.0 == expected_addr));
                }
                None => {
                    assert!(matches!(addr_res, Err(Error::BadSegTableAddress(_))));
                }
            }
        }

        // 2. Verify check_inited_params rejects uninitialized state including trb_count == 0.
        let inited = EventRing::check_inited_params(
            seg_table_size,
            GuestAddress(base_addr),
            GuestAddress(enq_addr),
            trb_count,
        );
        if seg_table_size == 0 || base_addr == 0 || enq_addr == 0 || trb_count == 0 {
            assert!(matches!(inited, Err(Error::Uninitialized)));
        } else {
            assert!(inited.is_ok());
        }

        // 3. Verify next_seg_table_index and is_non_boundary_full never panic or overflow.
        let next_idx_res = EventRing::next_seg_table_index(cur_idx, seg_table_size);
        if seg_table_size == 0 {
            assert!(matches!(next_idx_res, Err(Error::Uninitialized)));
        } else {
            let Ok(next_idx) = next_idx_res else {
                unreachable!();
            };
            assert!(next_idx < seg_table_size);
            if cur_idx < seg_table_size {
                let expected = if cur_idx + 1 == seg_table_size {
                    0
                } else {
                    cur_idx + 1
                };
                assert!(next_idx == expected);
            }
        }

        let full_res =
            EventRing::is_non_boundary_full(GuestAddress(enq_addr), GuestAddress(deq_addr));
        match enq_addr.checked_add(size_of::<Trb>() as u64) {
            Some(next_enq) => {
                assert!(matches!(full_res, Ok(full) if full == (deq_addr == next_enq)));
            }
            None => {
                assert!(matches!(full_res, Err(Error::BadEnqueuePointer(_))));
            }
        }
    }
}
