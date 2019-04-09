// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::xhci_abi::{Error as TrbError, NormalTrb, TransferDescriptor, TrbCast, TrbType};
use bit_field::Error as BitFieldError;
use std::fmt::{self, Display};
use sys_util::{GuestAddress, GuestMemory, GuestMemoryError};

#[derive(Debug)]
pub enum Error {
    ReadGuestMemory(GuestMemoryError),
    WriteGuestMemory(GuestMemoryError),
    UnknownTrbType(BitFieldError),
    CastTrb(TrbError),
    BadTrbType(TrbType),
}

type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            ReadGuestMemory(e) => write!(f, "cannot read guest memory: {}", e),
            WriteGuestMemory(e) => write!(f, "cannot write guest memory: {}", e),
            UnknownTrbType(e) => write!(f, "unknown trb type: {}", e),
            CastTrb(e) => write!(f, "cannot cast trb: {}", e),
            BadTrbType(t) => write!(f, "should not build buffer from trb type: {:?}", t),
        }
    }
}

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

    /// Read content to buffer, return number of bytes read.
    pub fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut total_size = 0usize;
        let mut offset = 0;
        for atrb in &self.td {
            let normal_trb = atrb.trb.cast::<NormalTrb>().map_err(Error::CastTrb)?;
            let len = normal_trb.get_trb_transfer_length() as usize;
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
                .read_at_addr(cur_buffer, GuestAddress(normal_trb.get_data_buffer()))
                .map_err(Error::ReadGuestMemory)?;
        }
        Ok(total_size)
    }

    /// Write content from buffer, return number of bytes written.
    pub fn write(&self, buffer: &[u8]) -> Result<usize> {
        let mut total_size = 0usize;
        let mut offset = 0;
        for atrb in &self.td {
            let normal_trb = atrb.trb.cast::<NormalTrb>().map_err(Error::CastTrb)?;
            let len = normal_trb.get_trb_transfer_length() as usize;
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
                .write_at_addr(cur_buffer, GuestAddress(normal_trb.get_data_buffer()))
                .map_err(Error::WriteGuestMemory)?;
        }
        Ok(total_size)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::usb::xhci::xhci_abi::{AddressedTrb, Trb};

    #[test]
    fn scatter_gather_buffer_test() {
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
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
        assert_eq!(d, [7, 6, 5, 4]);;
        gm.read_exact_at_addr(&mut d, GuestAddress(0x200)).unwrap();
        assert_eq!(d, [3, 2, 0, 0]);;
        gm.read_exact_at_addr(&mut d, GuestAddress(0x300)).unwrap();
        assert_eq!(d, [1, 0, 0, 0]);;

        let mut data_read = [0; 7];
        buffer.read(&mut data_read).unwrap();
        assert_eq!(data_to_write, data_read);
    }
}
