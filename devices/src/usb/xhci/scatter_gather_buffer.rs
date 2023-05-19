// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use bit_field::Error as BitFieldError;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;

use super::xhci_abi::AddressedTrb;
use super::xhci_abi::Error as TrbError;
use super::xhci_abi::NormalTrb;
use super::xhci_abi::TransferDescriptor;
use super::xhci_abi::TrbCast;
use super::xhci_abi::TrbType;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("should not build buffer from trb type: {0:?}")]
    BadTrbType(TrbType),
    #[error("cannot cast trb: {0}")]
    CastTrb(TrbError),
    #[error("immediate data longer than allowed: {0}")]
    ImmediateDataTooLong(usize),
    #[error("cannot read guest memory: {0}")]
    ReadGuestMemory(GuestMemoryError),
    #[error("unknown trb type: {0}")]
    UnknownTrbType(BitFieldError),
    #[error("cannot write guest memory: {0}")]
    WriteGuestMemory(GuestMemoryError),
}

type Result<T> = std::result::Result<T, Error>;

/// See xHCI spec 3.2.8 for scatter/gather transfer. It's used in bulk/interrupt transfers. See
/// 3.2.10 for details.
pub struct ScatterGatherBuffer {
    mem: GuestMemory,
    td: TransferDescriptor,
}

impl ScatterGatherBuffer {
    /// Create a new buffer from transfer descriptor.
    pub fn new(mem: GuestMemory, td: TransferDescriptor) -> Result<ScatterGatherBuffer> {
        for atrb in &td {
            let trb_type = atrb.trb.get_trb_type().map_err(Error::UnknownTrbType)?;
            if trb_type != TrbType::Normal
                && trb_type != TrbType::DataStage
                && trb_type != TrbType::Isoch
            {
                return Err(Error::BadTrbType(trb_type));
            }
        }
        Ok(ScatterGatherBuffer { mem, td })
    }

    /// Total len of this buffer.
    pub fn len(&self) -> Result<usize> {
        let mut total_len = 0usize;
        for atrb in &self.td {
            total_len += atrb
                .trb
                .cast::<NormalTrb>()
                .map_err(Error::CastTrb)?
                .get_trb_transfer_length() as usize;
        }
        Ok(total_len)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Get the guest address and length of the TRB's data buffer.
    /// This is usually a separate buffer pointed to by the TRB,
    /// but it can also be within the TRB itself in the case of immediate data.
    fn get_trb_data(&self, atrb: &AddressedTrb) -> Result<(GuestAddress, usize)> {
        let normal_trb = atrb.trb.cast::<NormalTrb>().map_err(Error::CastTrb)?;
        let len = normal_trb.get_trb_transfer_length() as usize;
        let addr = if normal_trb.get_immediate_data() == 1 {
            // If the Immediate Data flag is set, the first <= 8 bytes of the TRB hold the data.
            if len > 8 {
                return Err(Error::ImmediateDataTooLong(len));
            }
            atrb.gpa
        } else {
            normal_trb.get_data_buffer()
        };
        Ok((GuestAddress(addr), len))
    }

    /// Read content to buffer, return number of bytes read.
    pub fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut total_size = 0usize;
        let mut offset = 0;
        for atrb in &self.td {
            let (guest_address, len) = self.get_trb_data(atrb)?;
            let buffer_len = {
                if offset == buffer.len() {
                    return Ok(total_size);
                }
                if buffer.len() > offset + len {
                    len
                } else {
                    buffer.len() - offset
                }
            };
            let buffer_end = offset + buffer_len;
            let cur_buffer = &mut buffer[offset..buffer_end];
            offset = buffer_end;
            total_size += self
                .mem
                .read_at_addr(cur_buffer, guest_address)
                .map_err(Error::ReadGuestMemory)?;
        }
        Ok(total_size)
    }

    /// Write content from buffer, return number of bytes written.
    pub fn write(&self, buffer: &[u8]) -> Result<usize> {
        let mut total_size = 0usize;
        let mut offset = 0;
        for atrb in &self.td {
            let (guest_address, len) = self.get_trb_data(atrb)?;
            let buffer_len = {
                if offset == buffer.len() {
                    return Ok(total_size);
                }
                if buffer.len() > offset + len {
                    len
                } else {
                    buffer.len() - offset
                }
            };
            let buffer_end = offset + buffer_len;
            let cur_buffer = &buffer[offset..buffer_end];
            offset = buffer_end;
            total_size += self
                .mem
                .write_at_addr(cur_buffer, guest_address)
                .map_err(Error::WriteGuestMemory)?;
        }
        Ok(total_size)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::usb::xhci::xhci_abi::AddressedTrb;
    use crate::usb::xhci::xhci_abi::Trb;

    #[test]
    fn scatter_gather_buffer_test() {
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut td = TransferDescriptor::new();

        // In this td, we are going to have scatter buffer at 0x100, length 4, 0x200 length 2 and
        // 0x300 length 1.

        let mut trb = Trb::new();
        let ntrb = trb.cast_mut::<NormalTrb>().unwrap();
        ntrb.set_trb_type(TrbType::Normal);
        ntrb.set_data_buffer(0x100);
        ntrb.set_trb_transfer_length(4);
        td.push(AddressedTrb { trb, gpa: 0 });

        let mut trb = Trb::new();
        let ntrb = trb.cast_mut::<NormalTrb>().unwrap();
        ntrb.set_trb_type(TrbType::Normal);
        ntrb.set_data_buffer(0x200);
        ntrb.set_trb_transfer_length(2);
        td.push(AddressedTrb { trb, gpa: 0 });

        let mut trb = Trb::new();
        let ntrb = trb.cast_mut::<NormalTrb>().unwrap();
        ntrb.set_trb_type(TrbType::Normal);
        ntrb.set_data_buffer(0x300);
        ntrb.set_trb_transfer_length(1);
        td.push(AddressedTrb { trb, gpa: 0 });

        let buffer = ScatterGatherBuffer::new(gm.clone(), td).unwrap();

        assert_eq!(buffer.len().unwrap(), 7);
        let data_to_write: [u8; 7] = [7, 6, 5, 4, 3, 2, 1];
        buffer.write(&data_to_write).unwrap();

        let mut d = [0; 4];
        gm.read_exact_at_addr(&mut d, GuestAddress(0x100)).unwrap();
        assert_eq!(d, [7, 6, 5, 4]);
        gm.read_exact_at_addr(&mut d, GuestAddress(0x200)).unwrap();
        assert_eq!(d, [3, 2, 0, 0]);
        gm.read_exact_at_addr(&mut d, GuestAddress(0x300)).unwrap();
        assert_eq!(d, [1, 0, 0, 0]);

        let mut data_read = [0; 7];
        buffer.read(&mut data_read).unwrap();
        assert_eq!(data_to_write, data_read);
    }

    #[test]
    fn immediate_data_test() {
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut td = TransferDescriptor::new();

        let expected_immediate_data: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE];

        let mut trb = Trb::new();
        let ntrb = trb.cast_mut::<NormalTrb>().unwrap();
        ntrb.set_trb_type(TrbType::Normal);
        ntrb.set_data_buffer(u64::from_le_bytes(expected_immediate_data));
        ntrb.set_trb_transfer_length(8);
        ntrb.set_immediate_data(1);
        td.push(AddressedTrb { trb, gpa: 0xC00 });

        gm.write_obj_at_addr(trb, GuestAddress(0xc00)).unwrap();

        let buffer = ScatterGatherBuffer::new(gm, td).unwrap();

        let mut data_read = [0; 8];
        buffer.read(&mut data_read).unwrap();
        assert_eq!(data_read, expected_immediate_data);
    }
}
