// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::fmt::Display;
use std::mem::size_of;

use base::debug;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;

use super::xhci_abi::AddressedTrb;
use super::xhci_abi::Error as TrbError;
use super::xhci_abi::LinkTrb;
use super::xhci_abi::TransferDescriptor;
use super::xhci_abi::Trb;
use super::xhci_abi::TrbCast;
use super::xhci_abi::TrbType;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("bad dequeue pointer: {0}")]
    BadDequeuePointer(GuestAddress),
    #[error("cannot cast trb: {0}")]
    CastTrb(TrbError),
    #[error("cannot read guest memory: {0}")]
    ReadGuestMemory(GuestMemoryError),
    #[error("cannot get trb chain bit: {0}")]
    TrbChain(TrbError),
}

type Result<T> = std::result::Result<T, Error>;

/// Ring Buffer is segmented circular buffer in guest memory containing work items
/// called transfer descriptors, each of which consists of one or more TRBs.
/// Ring buffer logic is shared between transfer ring and command ring.
/// Transfer Ring management is defined in xHCI spec 4.9.2.
pub struct RingBuffer {
    name: String,
    mem: GuestMemory,
    dequeue_pointer: GuestAddress,
    // Used to check if the ring is empty. Toggled when looping back to the begining
    // of the buffer.
    consumer_cycle_state: bool,
}

impl Display for RingBuffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RingBuffer `{}`", self.name)
    }
}

// Public interfaces for Ring buffer.
impl RingBuffer {
    /// Create a new RingBuffer.
    pub fn new(name: String, mem: GuestMemory) -> Self {
        RingBuffer {
            name,
            mem,
            dequeue_pointer: GuestAddress(0),
            consumer_cycle_state: false,
        }
    }

    /// Dequeue next transfer descriptor from the transfer ring.
    pub fn dequeue_transfer_descriptor(&mut self) -> Result<Option<TransferDescriptor>> {
        let mut td: TransferDescriptor = TransferDescriptor::new();
        while let Some(addressed_trb) = self.get_current_trb()? {
            if let Ok(TrbType::Link) = addressed_trb.trb.get_trb_type() {
                let link_trb = addressed_trb
                    .trb
                    .cast::<LinkTrb>()
                    .map_err(Error::CastTrb)?;
                self.dequeue_pointer = GuestAddress(link_trb.get_ring_segment_pointer());
                self.consumer_cycle_state =
                    self.consumer_cycle_state != link_trb.get_toggle_cycle();
                continue;
            }

            self.dequeue_pointer = match self.dequeue_pointer.checked_add(size_of::<Trb>() as u64) {
                Some(addr) => addr,
                None => {
                    return Err(Error::BadDequeuePointer(self.dequeue_pointer));
                }
            };

            xhci_trace!(
                "{}: adding trb to td {}",
                self.name.as_str(),
                addressed_trb.trb
            );
            td.push(addressed_trb);
            if !addressed_trb.trb.get_chain_bit().map_err(Error::TrbChain)? {
                debug!("xhci: trb chain is false returning");
                break;
            }
        }
        // A valid transfer descriptor contains at least one addressed trb and the last trb has
        // chain bit != 0.
        match td.last() {
            Some(t) => {
                if t.trb.get_chain_bit().map_err(Error::TrbChain)? {
                    return Ok(None);
                }
            }
            None => return Ok(None),
        }
        Ok(Some(td))
    }

    /// Get dequeue pointer of the ring buffer.
    pub fn get_dequeue_pointer(&self) -> GuestAddress {
        self.dequeue_pointer
    }

    /// Set dequeue pointer of the ring buffer.
    pub fn set_dequeue_pointer(&mut self, addr: GuestAddress) {
        xhci_trace!("{}: set dequeue pointer {:x}", self.name.as_str(), addr.0);

        self.dequeue_pointer = addr;
    }

    /// Get consumer cycle state of the ring buffer.
    pub fn get_consumer_cycle_state(&self) -> bool {
        self.consumer_cycle_state
    }

    /// Set consumer cycle state of the ring buffer.
    pub fn set_consumer_cycle_state(&mut self, state: bool) {
        xhci_trace!("{}: set consumer cycle state {}", self.name.as_str(), state);
        self.consumer_cycle_state = state;
    }

    // Read trb pointed by dequeue pointer. Does not proceed dequeue pointer.
    fn get_current_trb(&self) -> Result<Option<AddressedTrb>> {
        let trb: Trb = self
            .mem
            .read_obj_from_addr(self.dequeue_pointer)
            .map_err(Error::ReadGuestMemory)?;
        xhci_trace!("{}: trb read from memory {:?}", self.name.as_str(), trb);
        // If cycle bit of trb does not equal consumer cycle state, the ring is empty.
        // This trb is invalid.
        if trb.get_cycle() != self.consumer_cycle_state {
            debug!(
                "xhci: cycle bit does not match, self cycle {}",
                self.consumer_cycle_state
            );
            Ok(None)
        } else {
            Ok(Some(AddressedTrb {
                trb,
                gpa: self.dequeue_pointer.0,
            }))
        }
    }
}

#[cfg(test)]
mod test {
    use base::pagesize;

    use super::*;
    use crate::usb::xhci::xhci_abi::*;

    #[test]
    fn ring_test_dequeue() {
        let trb_size = size_of::<Trb>() as u64;
        let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
        let mut transfer_ring = RingBuffer::new(String::new(), gm.clone());

        // Structure of ring buffer:
        //  0x100  --> 0x200  --> 0x300
        //  trb 1  |   trb 3  |   trb 5
        //  trb 2  |   trb 4  |   trb 6
        //  l trb  -   l trb  -   l trb to 0x100
        let mut trb = NormalTrb::new();
        trb.set_trb_type(TrbType::Normal);
        trb.set_data_buffer(1);
        trb.set_chain(true);
        gm.write_obj_at_addr(trb, GuestAddress(0x100)).unwrap();

        trb.set_data_buffer(2);
        gm.write_obj_at_addr(trb, GuestAddress(0x100 + trb_size))
            .unwrap();

        let mut ltrb = LinkTrb::new();
        ltrb.set_trb_type(TrbType::Link);
        ltrb.set_ring_segment_pointer(0x200);
        gm.write_obj_at_addr(ltrb, GuestAddress(0x100 + 2 * trb_size))
            .unwrap();

        trb.set_data_buffer(3);
        gm.write_obj_at_addr(trb, GuestAddress(0x200)).unwrap();

        // Chain bit is false.
        trb.set_data_buffer(4);
        trb.set_chain(false);
        gm.write_obj_at_addr(trb, GuestAddress(0x200 + 1 * trb_size))
            .unwrap();

        ltrb.set_ring_segment_pointer(0x300);
        gm.write_obj_at_addr(ltrb, GuestAddress(0x200 + 2 * trb_size))
            .unwrap();

        trb.set_data_buffer(5);
        trb.set_chain(true);
        gm.write_obj_at_addr(trb, GuestAddress(0x300)).unwrap();

        // Chain bit is false.
        trb.set_data_buffer(6);
        trb.set_chain(false);
        gm.write_obj_at_addr(trb, GuestAddress(0x300 + 1 * trb_size))
            .unwrap();

        ltrb.set_ring_segment_pointer(0x100);
        gm.write_obj_at_addr(ltrb, GuestAddress(0x300 + 2 * trb_size))
            .unwrap();

        transfer_ring.set_dequeue_pointer(GuestAddress(0x100));
        transfer_ring.set_consumer_cycle_state(false);

        // Read first transfer descriptor.
        let descriptor = transfer_ring
            .dequeue_transfer_descriptor()
            .unwrap()
            .unwrap();
        assert_eq!(descriptor.len(), 4);
        assert_eq!(descriptor[0].trb.get_parameter(), 1);
        assert_eq!(descriptor[1].trb.get_parameter(), 2);
        assert_eq!(descriptor[2].trb.get_parameter(), 3);
        assert_eq!(descriptor[3].trb.get_parameter(), 4);

        // Read second transfer descriptor.
        let descriptor = transfer_ring
            .dequeue_transfer_descriptor()
            .unwrap()
            .unwrap();
        assert_eq!(descriptor.len(), 2);
        assert_eq!(descriptor[0].trb.get_parameter(), 5);
        assert_eq!(descriptor[1].trb.get_parameter(), 6);
    }

    #[test]
    fn transfer_ring_test_dequeue_failure() {
        let trb_size = size_of::<Trb>() as u64;
        let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
        let mut transfer_ring = RingBuffer::new(String::new(), gm.clone());

        let mut trb = NormalTrb::new();
        trb.set_trb_type(TrbType::Normal);
        trb.set_data_buffer(1);
        trb.set_chain(true);
        gm.write_obj_at_addr(trb, GuestAddress(0x100)).unwrap();

        trb.set_data_buffer(2);
        gm.write_obj_at_addr(trb, GuestAddress(0x100 + trb_size))
            .unwrap();

        let mut ltrb = LinkTrb::new();
        ltrb.set_trb_type(TrbType::Link);
        ltrb.set_ring_segment_pointer(0x200);
        ltrb.set_toggle_cycle(true);
        gm.write_obj_at_addr(ltrb, GuestAddress(0x100 + 2 * trb_size))
            .unwrap();

        trb.set_data_buffer(3);
        gm.write_obj_at_addr(trb, GuestAddress(0x200)).unwrap();

        transfer_ring.set_dequeue_pointer(GuestAddress(0x100));
        transfer_ring.set_consumer_cycle_state(false);

        // Read first transfer descriptor.
        let descriptor = transfer_ring.dequeue_transfer_descriptor().unwrap();
        assert_eq!(descriptor.is_none(), true);
    }

    #[test]
    fn ring_test_toggle_cycle() {
        let trb_size = size_of::<Trb>() as u64;
        let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
        let mut transfer_ring = RingBuffer::new(String::new(), gm.clone());

        let mut trb = NormalTrb::new();
        trb.set_trb_type(TrbType::Normal);
        trb.set_data_buffer(1);
        trb.set_chain(false);
        trb.set_cycle(false);
        gm.write_obj_at_addr(trb, GuestAddress(0x100)).unwrap();

        let mut ltrb = LinkTrb::new();
        ltrb.set_trb_type(TrbType::Link);
        ltrb.set_ring_segment_pointer(0x100);
        ltrb.set_toggle_cycle(true);
        ltrb.set_cycle(false);
        gm.write_obj_at_addr(ltrb, GuestAddress(0x100 + trb_size))
            .unwrap();

        // Initial state: consumer cycle = false
        transfer_ring.set_dequeue_pointer(GuestAddress(0x100));
        transfer_ring.set_consumer_cycle_state(false);

        // Read first transfer descriptor.
        let descriptor = transfer_ring
            .dequeue_transfer_descriptor()
            .unwrap()
            .unwrap();
        assert_eq!(descriptor.len(), 1);
        assert_eq!(descriptor[0].trb.get_parameter(), 1);

        // Cycle bit should be unchanged since we haven't advanced past the Link TRB yet.
        assert_eq!(transfer_ring.consumer_cycle_state, false);

        // Overwrite the first TRB with a new one (data = 2)
        // with the new producer cycle bit state (true).
        let mut trb = NormalTrb::new();
        trb.set_trb_type(TrbType::Normal);
        trb.set_data_buffer(2);
        trb.set_cycle(true); // Link TRB toggled the cycle.
        gm.write_obj_at_addr(trb, GuestAddress(0x100)).unwrap();

        // Read new transfer descriptor.
        let descriptor = transfer_ring
            .dequeue_transfer_descriptor()
            .unwrap()
            .unwrap();
        assert_eq!(descriptor.len(), 1);
        assert_eq!(descriptor[0].trb.get_parameter(), 2);

        assert_eq!(transfer_ring.consumer_cycle_state, true);

        // Update the Link TRB with the new cycle bit.
        let mut ltrb = LinkTrb::new();
        ltrb.set_trb_type(TrbType::Link);
        ltrb.set_ring_segment_pointer(0x100);
        ltrb.set_toggle_cycle(true);
        ltrb.set_cycle(true); // Producer cycle state is now 1.
        gm.write_obj_at_addr(ltrb, GuestAddress(0x100 + trb_size))
            .unwrap();

        // Overwrite the first TRB again with a new one (data = 3)
        // with the new producer cycle bit state (false).
        let mut trb = NormalTrb::new();
        trb.set_trb_type(TrbType::Normal);
        trb.set_data_buffer(3);
        trb.set_cycle(false); // Link TRB toggled the cycle.
        gm.write_obj_at_addr(trb, GuestAddress(0x100)).unwrap();

        // Read new transfer descriptor.
        let descriptor = transfer_ring
            .dequeue_transfer_descriptor()
            .unwrap()
            .unwrap();
        assert_eq!(descriptor.len(), 1);
        assert_eq!(descriptor[0].trb.get_parameter(), 3);

        assert_eq!(transfer_ring.consumer_cycle_state, false);
    }
}
