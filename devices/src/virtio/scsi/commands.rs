// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::io::Write;

use base::warn;
use disk::AsyncDisk;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::virtio::scsi::constants::INQUIRY;
use crate::virtio::scsi::constants::MODE_SELECT_6;
use crate::virtio::scsi::constants::MODE_SENSE_6;
use crate::virtio::scsi::constants::READ_10;
use crate::virtio::scsi::constants::READ_6;
use crate::virtio::scsi::constants::READ_CAPACITY_10;
use crate::virtio::scsi::constants::REPORT_LUNS;
use crate::virtio::scsi::constants::SYNCHRONIZE_CACHE_10;
use crate::virtio::scsi::constants::TEST_UNIT_READY;
use crate::virtio::scsi::constants::TYPE_DISK;
use crate::virtio::scsi::constants::WRITE_10;
use crate::virtio::scsi::device::ExecuteError;
use crate::virtio::scsi::device::LogicalUnit;
use crate::virtio::Reader;
use crate::virtio::Writer;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    TestUnitReady(TestUnitReady),
    Read6(Read6),
    Inquiry(Inquiry),
    ModeSelect6(ModeSelect6),
    ModeSense6(ModeSense6),
    ReadCapacity10(ReadCapacity10),
    Read10(Read10),
    Write10(Write10),
    SynchronizeCache10(SynchronizeCache10),
    ReportLuns(ReportLuns),
}

impl Command {
    pub fn new(cdb: &[u8]) -> Result<Self, ExecuteError> {
        let op = cdb[0];
        match op {
            TEST_UNIT_READY => Ok(Self::TestUnitReady(Self::parse_command(cdb)?)),
            READ_6 => Ok(Self::Read6(Self::parse_command(cdb)?)),
            INQUIRY => Ok(Self::Inquiry(Self::parse_command(cdb)?)),
            MODE_SELECT_6 => Ok(Self::ModeSelect6(Self::parse_command(cdb)?)),
            MODE_SENSE_6 => Ok(Self::ModeSense6(Self::parse_command(cdb)?)),
            READ_CAPACITY_10 => Ok(Self::ReadCapacity10(Self::parse_command(cdb)?)),
            READ_10 => Ok(Self::Read10(Self::parse_command(cdb)?)),
            WRITE_10 => Ok(Self::Write10(Self::parse_command(cdb)?)),
            SYNCHRONIZE_CACHE_10 => Ok(Self::SynchronizeCache10(Self::parse_command(cdb)?)),
            REPORT_LUNS => Ok(Self::ReportLuns(Self::parse_command(cdb)?)),
            _ => {
                warn!("SCSI command {:#x?} is not implemented", op);
                Err(ExecuteError::Unsupported(op))
            }
        }
    }

    fn parse_command<T: FromBytes>(cdb: &[u8]) -> Result<T, ExecuteError> {
        let size = std::mem::size_of::<T>();
        T::read_from(&cdb[..size]).ok_or(ExecuteError::ReadCommand)
    }

    pub async fn execute(
        &self,
        reader: &mut Reader,
        writer: &mut Writer,
        dev: LogicalUnit,
        disk_image: &dyn AsyncDisk,
    ) -> Result<(), ExecuteError> {
        match self {
            Self::TestUnitReady(_) => Ok(()), // noop as the device is ready.
            Self::Read6(read6) => read6.emulate(writer, dev, disk_image).await,
            Self::Inquiry(inquiry) => inquiry.emulate(writer),
            Self::ModeSelect6(mode_select_6) => mode_select_6.emulate(),
            Self::ModeSense6(mode_sense_6) => mode_sense_6.emulate(writer, dev),
            Self::ReadCapacity10(read_capacity_10) => read_capacity_10.emulate(writer, dev),
            Self::Read10(read_10) => read_10.emulate(writer, dev, disk_image).await,
            Self::Write10(write_10) => write_10.emulate(reader, dev, disk_image).await,
            Self::SynchronizeCache10(synchronize_cache_10) => {
                synchronize_cache_10.emulate(disk_image).await
            }
            Self::ReportLuns(report_luns) => report_luns.emulate(writer),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct TestUnitReady {
    opcode: u8,
    reserved: [u8; 4],
    control: u8,
}

fn check_lba_range(max_lba: u64, sector_num: u64, sector_len: usize) -> bool {
    // Checking `sector_num + sector_len - 1 <= max_lba`, but we are being careful about overflows
    // and underflows.
    match sector_num.checked_add(sector_len as u64) {
        Some(v) => v <= max_lba + 1,
        None => false,
    }
}

async fn read_from_disk(
    disk_image: &dyn AsyncDisk,
    writer: &mut Writer,
    dev: LogicalUnit,
    xfer_blocks: usize,
    lba: u64,
) -> Result<(), ExecuteError> {
    let max_lba = dev.max_lba;
    if !check_lba_range(max_lba, lba, xfer_blocks) {
        return Err(ExecuteError::LbaOutOfRange {
            length: xfer_blocks,
            sector: lba,
            max_lba,
        });
    }
    let block_size = dev.block_size;
    let count = xfer_blocks * block_size as usize;
    let offset = lba * block_size as u64;
    let before = writer.bytes_written();
    writer
        .write_all_from_at_fut(disk_image, count, offset)
        .await
        .map_err(|desc_error| {
            let resid = count - (writer.bytes_written() - before);
            ExecuteError::ReadIo { resid, desc_error }
        })
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct Read6 {
    opcode: u8,
    lba_bytes: [u8; 3],
    xfer_len_byte: u8,
    control: u8,
}

impl Read6 {
    fn lba(&self) -> u32 {
        u32::from_be_bytes([
            0,
            // The top three bits are reserved.
            self.lba_bytes[0] & 0x1f,
            self.lba_bytes[1],
            self.lba_bytes[2],
        ])
    }

    fn xfer_len(&self) -> usize {
        // The transfer length set to 0 means 256 blocks should be read.
        if self.xfer_len_byte == 0 {
            256
        } else {
            self.xfer_len_byte as usize
        }
    }

    async fn emulate(
        &self,
        writer: &mut Writer,
        dev: LogicalUnit,
        disk_image: &dyn AsyncDisk,
    ) -> Result<(), ExecuteError> {
        read_from_disk(disk_image, writer, dev, self.xfer_len(), self.lba() as u64).await
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
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

    fn emulate(&self, writer: &mut Writer) -> Result<(), ExecuteError> {
        if self.vital_product_data_enabled() {
            return self.emulate_vital_product_data_page(writer);
        }
        // PAGE CODE should be 0 when vpd bit is 0.
        if self.page_code() != 0 {
            return Err(ExecuteError::InvalidField);
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

        writer
            .write_all(&outbuf[..alloc_len])
            .map_err(ExecuteError::Write)
    }

    fn emulate_vital_product_data_page(&self, writer: &mut Writer) -> Result<(), ExecuteError> {
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
                return Err(ExecuteError::InvalidField);
            }
        };
        writer
            .write_all(&outbuf[..alloc_len])
            .map_err(ExecuteError::Write)
    }

    fn fill_left_aligned_ascii(buf: &mut [u8], s: &str) {
        debug_assert!(s.len() < buf.len());
        buf[..s.len()].copy_from_slice(s.as_bytes());
        buf[s.len()..].fill(b' ');
    }
}

// According to the spec, devices that implement MODE SENSE(6) shall also implement MODE SELECT(6)
// as well.
#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct ModeSelect6 {
    opcode: u8,
    pf_sp_field: u8,
    _reserved: [u8; 2],
    param_list_len: u8,
    control: u8,
}

impl ModeSelect6 {
    fn emulate(&self) -> Result<(), ExecuteError> {
        // TODO(b/303338922): Implement this command properly.
        Err(ExecuteError::InvalidField)
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct ModeSense6 {
    opcode: u8,
    dbd_field: u8,
    page_control_and_page_code: u8,
    subpage_code: u8,
    alloc_len: u8,
    control: u8,
}

impl ModeSense6 {
    fn alloc_len(&self) -> usize {
        self.alloc_len as usize
    }

    fn disable_block_desc(&self) -> bool {
        self.dbd_field & 0x8 != 0
    }

    fn page_code(&self) -> u8 {
        // The top two bits represents page control field, and the rest is page code.
        self.page_control_and_page_code & 0x3f
    }

    fn page_control(&self) -> u8 {
        self.page_control_and_page_code >> 6
    }

    fn subpage_code(&self) -> u8 {
        self.subpage_code
    }

    fn emulate(&self, writer: &mut Writer, dev: LogicalUnit) -> Result<(), ExecuteError> {
        let alloc_len = self.alloc_len();
        let mut outbuf = vec![0u8; cmp::max(4096, alloc_len)];
        // outbuf[0]: Represents data length. Will be filled later.
        // outbuf[1]: Medium type should be 0.

        // Device specific parameter
        // We do not support the disabled page out (DPO) and forced unit access (FUA) bit.
        outbuf[2] = if dev.read_only { 0x80 } else { 0x00 };
        let mut idx = if !self.disable_block_desc() && dev.max_lba > 0 {
            // Block descriptor length.
            outbuf[3] = 8;
            // outbuf[4]: Density code is 0.
            let sectors = dev.max_lba / dev.block_size as u64;
            // Fill in the number of sectors if not bigger than 0xffffff, leave it with 0
            // otherwise.
            if sectors <= 0xffffff {
                outbuf[5..8].copy_from_slice(&(sectors as u32).to_be_bytes()[1..]);
            }
            // outbuf[8]: reserved.
            outbuf[9..12].copy_from_slice(&dev.block_size.to_be_bytes()[1..]);
            12
        } else {
            4
        };

        let page_control = self.page_control();
        // We do not support saved values.
        if page_control == 0b11 {
            return Err(ExecuteError::SavingParamNotSupported);
        }

        let page_code = self.page_code();
        let subpage_code = self.subpage_code();
        // The pair of the page code and the subpage code specifies which mode pages and subpages
        // to return. Refer to the Table 99 in the SPC-3 spec for more details:
        // <https://www.t10.org/cgi-bin/ac.pl?t=f&f=spc3r23.pdf>
        match (page_code, subpage_code) {
            // Return all mode pages with subpage 0.
            (0x3f, 0x00) => {
                Self::add_all_page_codes(subpage_code, page_control, &mut outbuf, &mut idx)
            }
            // Return all mode pages with subpages 0x00-0xfe.
            (0x3f, 0xff) => {
                for subpage_code in 0..0xff {
                    Self::add_all_page_codes(subpage_code, page_control, &mut outbuf, &mut idx)
                }
            }
            // subpage_code other than 0x00 or 0xff are reserved.
            (0x3f, _) => return Err(ExecuteError::InvalidField),
            // Return a specific mode page with subpages 0x00-0xfe.
            (_, 0xff) => {
                for subpage_code in 0..0xff {
                    match Self::fill_page(
                        page_code,
                        subpage_code,
                        page_control,
                        &mut outbuf[idx as usize..],
                    ) {
                        Some(n) => idx += n,
                        None => return Err(ExecuteError::InvalidField),
                    };
                }
            }
            (_, _) => {
                match Self::fill_page(
                    page_code,
                    subpage_code,
                    page_control,
                    &mut outbuf[idx as usize..],
                ) {
                    Some(n) => idx += n,
                    None => return Err(ExecuteError::InvalidField),
                };
            }
        };
        outbuf[0] = idx - 1;
        writer
            .write_all(&outbuf[..alloc_len])
            .map_err(ExecuteError::Write)
    }

    // Fill in mode pages with a specific subpage_code.
    fn add_all_page_codes(subpage_code: u8, page_control: u8, outbuf: &mut [u8], idx: &mut u8) {
        for page_code in 1..0x3f {
            if let Some(n) = Self::fill_page(
                page_code,
                subpage_code,
                page_control,
                &mut outbuf[*idx as usize..],
            ) {
                *idx += n;
            }
        }
        // Add mode page 0 after all other mode pages were returned.
        if let Some(n) =
            Self::fill_page(0, subpage_code, page_control, &mut outbuf[*idx as usize..])
        {
            *idx += n;
        }
    }

    // Fill in the information of the page code and return the number of bytes written to the
    // buffer.
    fn fill_page(
        page_code: u8,
        subpage_code: u8,
        page_control: u8,
        outbuf: &mut [u8],
    ) -> Option<u8> {
        // outbuf[0]: page code
        // outbuf[1]: page length
        match (page_code, subpage_code) {
            // Vendor specific.
            (0x00, 0x00) => None,
            // Read-Write error recovery mode page
            (0x01, 0x00) => {
                let len = 10;
                outbuf[0] = page_code;
                outbuf[1] = len;
                if page_control != 0b01 {
                    // Automatic write reallocation enabled.
                    outbuf[3] = 0x80;
                }
                Some(len + 2)
            }
            // Caching.
            (0x08, 0x00) => {
                let len = 0x12;
                outbuf[0] = page_code;
                outbuf[1] = len;
                // Writeback cache enabled.
                outbuf[2] = 0x04;
                Some(len + 2)
            }
            _ => None,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct ReadCapacity10 {
    opcode: u8,
    _obsolete: u8,
    lba_bytes: [u8; 4],
    _reserved: [u8; 2],
    pmi_field: u8,
    control: u8,
}

impl ReadCapacity10 {
    fn lba(&self) -> u32 {
        u32::from_be_bytes(self.lba_bytes)
    }

    fn pmi(&self) -> bool {
        self.pmi_field & 0x1 != 0
    }

    fn emulate(&self, writer: &mut Writer, dev: LogicalUnit) -> Result<(), ExecuteError> {
        if !self.pmi() && self.lba() != 0 {
            return Err(ExecuteError::InvalidField);
        }
        let block_size = dev.block_size;
        // Returned value is the block address of the last sector.
        // If the block address exceeds u32::MAX, we return u32::MAX.
        let block_address: u32 = (dev.max_lba / dev.block_size as u64)
            .saturating_sub(1)
            .try_into()
            .unwrap_or(u32::MAX);
        let mut outbuf = [0u8; 8];
        outbuf[..4].copy_from_slice(&block_address.to_be_bytes());
        outbuf[4..8].copy_from_slice(&block_size.to_be_bytes());
        writer.write_all(&outbuf).map_err(ExecuteError::Write)
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct Read10 {
    opcode: u8,
    rdprotect: u8,
    lba_bytes: [u8; 4],
    group_number: u8,
    xfer_len_bytes: [u8; 2],
    control: u8,
}

impl Read10 {
    fn xfer_len(&self) -> usize {
        u16::from_be_bytes(self.xfer_len_bytes) as usize
    }

    fn lba(&self) -> u64 {
        u32::from_be_bytes(self.lba_bytes) as u64
    }

    async fn emulate(
        &self,
        writer: &mut Writer,
        dev: LogicalUnit,
        disk_image: &dyn AsyncDisk,
    ) -> Result<(), ExecuteError> {
        read_from_disk(disk_image, writer, dev, self.xfer_len(), self.lba()).await
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct Write10 {
    opcode: u8,
    wrprotect: u8,
    lba_bytes: [u8; 4],
    group_number: u8,
    xfer_len_bytes: [u8; 2],
    control: u8,
}

impl Write10 {
    fn lba(&self) -> u64 {
        u32::from_be_bytes(self.lba_bytes) as u64
    }

    fn xfer_len(&self) -> usize {
        u16::from_be_bytes(self.xfer_len_bytes) as usize
    }

    async fn emulate(
        &self,
        reader: &mut Reader,
        dev: LogicalUnit,
        disk_image: &dyn AsyncDisk,
    ) -> Result<(), ExecuteError> {
        write_to_disk(disk_image, reader, dev, self.xfer_len(), self.lba()).await
    }
}

async fn write_to_disk(
    disk_image: &dyn AsyncDisk,
    reader: &mut Reader,
    dev: LogicalUnit,
    xfer_blocks: usize,
    lba: u64,
) -> Result<(), ExecuteError> {
    if dev.read_only {
        return Err(ExecuteError::ReadOnly);
    }
    let block_size = dev.block_size;
    let count = xfer_blocks * block_size as usize;
    let offset = lba * block_size as u64;
    let before = reader.bytes_read();
    reader
        .read_exact_to_at_fut(disk_image, count, offset)
        .await
        .map_err(|desc_error| {
            let resid = count - (reader.bytes_read() - before);
            ExecuteError::WriteIo { resid, desc_error }
        })
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct SynchronizeCache10 {
    opcode: u8,
    immed_byte: u8,
    lba_bytes: [u8; 4],
    group_number: u8,
    block_num_bytes: [u8; 2],
    control: u8,
}

impl SynchronizeCache10 {
    async fn emulate(&self, disk_image: &dyn AsyncDisk) -> Result<(), ExecuteError> {
        disk_image.fdatasync().await.map_err(|e| {
            warn!("failed to sync: {e}");
            ExecuteError::SynchronizationError
        })
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct ReportLuns {
    opcode: u8,
    _reserved: u8,
    select_report: u8,
    _reserved2: [u8; 3],
    alloc_len_bytes: [u8; 4],
    _reserved3: u8,
    control: u8,
}

impl ReportLuns {
    fn alloc_len(&self) -> usize {
        u32::from_be_bytes(self.alloc_len_bytes) as usize
    }

    fn emulate(&self, writer: &mut Writer) -> Result<(), ExecuteError> {
        // We need at least 16 bytes.
        if self.alloc_len() < 16 {
            return Err(ExecuteError::InvalidField);
        }
        // Each LUN takes 8 bytes and we only support LUN0 (b/300586438).
        let lun_list_len = 8u32;
        writer
            .write_all(&lun_list_len.to_be_bytes())
            .map_err(ExecuteError::Write)?;
        let reserved = [0; 4];
        writer.write_all(&reserved).map_err(ExecuteError::Write)?;
        let lun0 = 0u64;
        writer
            .write_all(&lun0.to_be_bytes())
            .map_err(ExecuteError::Write)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_test_unit_ready() {
        let cdb = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let command = Command::new(&cdb).unwrap();
        assert_eq!(
            command,
            Command::TestUnitReady(TestUnitReady {
                opcode: TEST_UNIT_READY,
                reserved: [0; 4],
                control: 0
            })
        );
    }

    #[test]
    fn parse_read6() {
        let cdb = [0x08, 0xab, 0xcd, 0xef, 0x00, 0x00];
        let command = Command::new(&cdb).unwrap();
        let read6 = match command {
            Command::Read6(r) => r,
            _ => panic!("unexpected command type: {:?}", command),
        };
        assert_eq!(read6.xfer_len(), 256);
        assert_eq!(read6.lba(), 0x0bcdef);
    }

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

    #[test]
    fn parse_mode_sense_6() {
        let cdb = [0x1a, 0x00, 0xa8, 0x00, 0x04, 0x00];
        let command = Command::new(&cdb).unwrap();
        let mode_sense_6 = match command {
            Command::ModeSense6(m) => m,
            _ => panic!("unexpected command type: {:?}", command),
        };
        assert_eq!(mode_sense_6.alloc_len(), 0x04);
        assert_eq!(mode_sense_6.page_code(), 0x28);
        assert_eq!(mode_sense_6.page_control(), 0x02);
    }

    #[test]
    fn parse_read_capacity_10() {
        let cdb = [0x25, 0x00, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x9, 0x0];
        let command = Command::new(&cdb).unwrap();
        let cap = match command {
            Command::ReadCapacity10(c) => c,
            _ => panic!("unexpected command type: {:?}", command),
        };
        assert_eq!(cap.lba(), 0xabcdef01);
        assert!(cap.pmi());
    }

    #[test]
    fn parse_read10() {
        let cdb = [0x28, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00];
        let command = Command::new(&cdb).unwrap();
        let read10 = match command {
            Command::Read10(r) => r,
            _ => panic!("unexpected command type: {:?}", command),
        };
        assert_eq!(read10.xfer_len(), 0x0008);
        assert_eq!(read10.lba(), 0x003c0000);
    }

    #[test]
    fn parse_write10() {
        let cdb = [0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00];
        let command = Command::new(&cdb).unwrap();
        let write10 = match command {
            Command::Write10(w) => w,
            _ => panic!("unexpected command type: {:?}", command),
        };
        assert_eq!(write10.xfer_len(), 0x0008);
        assert_eq!(write10.lba(), 0x00000000);
    }

    #[test]
    fn parse_synchronize_cache_10() {
        let cdb = [0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let command = Command::new(&cdb).unwrap();
        assert_eq!(
            command,
            Command::SynchronizeCache10(SynchronizeCache10 {
                opcode: SYNCHRONIZE_CACHE_10,
                immed_byte: 0,
                lba_bytes: [0x00, 0x00, 0x00, 0x00],
                group_number: 0x00,
                block_num_bytes: [0x00, 0x00],
                control: 0x00,
            })
        );
    }

    #[test]
    fn parse_report_luns() {
        let cdb = [
            0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x00, 0x00,
        ];
        let command = Command::new(&cdb).unwrap();
        let report_luns = match command {
            Command::ReportLuns(r) => r,
            _ => panic!("unexpected command type: {:?}", command),
        };
        assert_eq!(report_luns.alloc_len(), 0xabcdef12);
    }
}
