// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::io::Write;

use base::warn;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::virtio::scsi::constants::INQUIRY;
use crate::virtio::scsi::constants::TYPE_DISK;
use crate::virtio::scsi::device::ExecuteError;
use crate::virtio::scsi::device::Request;
use crate::virtio::scsi::device::RequestStatus;
use crate::virtio::Writer;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Inquiry(Inquiry),
}

impl Command {
    pub fn new(cdb: &[u8]) -> Result<Self, ExecuteError> {
        let op = cdb[0];
        match op {
            INQUIRY => {
                let cmd = Inquiry::read_from(cdb).ok_or(ExecuteError::ReadCommand)?;
                Ok(Self::Inquiry(cmd))
            }
            _ => {
                todo!("SCSI command {:#x?} is not implemented", op);
            }
        }
    }

    pub fn execute(&self, writer: &mut Writer, req: &mut Request) {
        match self {
            Self::Inquiry(inquiry) => inquiry.emulate(writer, req),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct Inquiry {
    opcode: u8,
    vpd_field: u8,
    page_code: u8,
    alloc_len_bytes: [u8; 2],
    control: u8,
}

impl Inquiry {
    fn vital_product_data_enabled(&self) -> bool {
        self.vpd_field & 0x1 != 0
    }

    fn alloc_len(&self) -> usize {
        u16::from_be_bytes(self.alloc_len_bytes) as usize
    }

    fn page_code(&self) -> u8 {
        self.page_code
    }

    fn emulate(&self, writer: &mut Writer, req: &mut Request) {
        if self.vital_product_data_enabled() {
            return self.emulate_vital_product_data_page(writer, req);
        }
        // PAGE CODE should be 0 when vpd bit is 0.
        if self.page_code() != 0 {
            req.status = RequestStatus::CheckCondition {
                err: ExecuteError::InvalidField,
                fixed: true,
            };
            return;
        }
        let alloc_len = self.alloc_len();
        let mut outbuf = vec![0u8; cmp::max(writer.available_bytes(), alloc_len)];
        // Peripheral
        outbuf[0] = TYPE_DISK;
        // Removable bit. We currently do not support removable SCSI devices.
        outbuf[1] = 0x0;
        // Version 0x5 indicates that the device complies to SPC-3.
        outbuf[2] = 0x5;
        // Hierarchical Support | Response Data Format
        // Support hierarchical addressing mode to assign LUNs to logical units.
        // Response Data Format should be 2.
        outbuf[3] = 0x10 | 0x2;
        // Additional Length
        outbuf[4] = {
            let buflen = outbuf.len().try_into().unwrap_or(u8::MAX);
            // We will write at least 36 bytes and this is the 5th byte.
            cmp::max(buflen, 36) - 5
        };
        // Cmdque: support full task management mode
        outbuf[7] = 0x2;
        // Vendor
        Self::fill_left_aligned_ascii(&mut outbuf[8..16], "CROSVM");
        // Product ID
        Self::fill_left_aligned_ascii(&mut outbuf[16..32], "CROSVM HARDDISK");
        // Product revision level
        Self::fill_left_aligned_ascii(&mut outbuf[32..36], "0.1");

        let _ = writer
            .write_all(&outbuf[..alloc_len])
            .map_err(|e| warn!("failed to write bytes: {e}"));
    }

    fn emulate_vital_product_data_page(&self, writer: &mut Writer, req: &mut Request) {
        let alloc_len = self.alloc_len();
        let mut outbuf = vec![0u8; cmp::max(4096, alloc_len)];
        // Peripheral
        outbuf[0] = TYPE_DISK;
        let page_code = self.page_code();
        outbuf[1] = page_code;
        match page_code {
            // Supported VPD Pages
            0x00 => {
                // outbuf[2] byte is reserved.
                // We only support mandatory page codes for now.
                // 0x00: Supported VPD Pages (this command)
                // 0x83: Device Identification
                const SUPPORTED_VPD_PAGE_CODES: [u8; 2] = [0x00, 0x83];
                let page_code_len: u8 = SUPPORTED_VPD_PAGE_CODES
                    .len()
                    .try_into()
                    .expect("The number of vpd page codes cannot exceed u8::MAX");
                // Page legth
                outbuf[3] = page_code_len;
                outbuf[4..4 + page_code_len as usize].copy_from_slice(&SUPPORTED_VPD_PAGE_CODES);
            }
            // Device Identification
            0x83 => {
                const DEVICE_ID: &[u8] = b"CROSVM SCSI DEVICE";
                let device_id_len: u8 = DEVICE_ID
                    .len()
                    .try_into()
                    .expect("device id should be shorter");
                // Page length: An identification descriptor will be 4 bytes followed by an id.
                outbuf[2..4].copy_from_slice(&(4 + device_id_len as u16).to_be_bytes());
                // ASCII
                outbuf[4] = 0x2;
                // ASSOCIATION | IDENTIFICATION_TYPE_FIELD
                // ASSOCIATION: device_id is associated with the addressed logical unit.
                // IDENTIFICATION_TYPE_FIELD: vendor specific
                // outbuf[5] = 0x0 | 0x0;
                // outbuf[6] byte is reserved.
                outbuf[7] = device_id_len;
                outbuf[8..8 + device_id_len as usize].copy_from_slice(DEVICE_ID);
            }
            _ => {
                warn!("unsupported vpd page code: {:#x?}", page_code);
                req.status = RequestStatus::CheckCondition {
                    err: ExecuteError::InvalidField,
                    fixed: true,
                };
                return;
            }
        };
        let _ = writer
            .write_all(&outbuf[..alloc_len])
            .map_err(|e| warn!("failed to write bytes: {e}"));
    }

    fn fill_left_aligned_ascii(buf: &mut [u8], s: &str) {
        debug_assert!(s.len() < buf.len());
        buf[..s.len()].copy_from_slice(s.as_bytes());
        buf[s.len()..].fill(b' ');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_inquiry() {
        let cdb = [0x12, 0x01, 0x00, 0x00, 0x40, 0x00];
        let command = Command::new(&cdb).unwrap();
        let inquiry = match command {
            Command::Inquiry(inq) => inq,
            _ => panic!("unexpected command type: {:?}", command),
        };
        assert!(inquiry.vital_product_data_enabled());
        assert_eq!(inquiry.alloc_len(), 0x0040);
        assert_eq!(inquiry.page_code(), 0x00);
    }
}
