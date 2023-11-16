// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::io::Write;

use base::warn;
use data_model::Be16;
use data_model::Be32;
use data_model::Be64;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::virtio::scsi::constants::INQUIRY;
use crate::virtio::scsi::constants::MAINTENANCE_IN;
use crate::virtio::scsi::constants::MODE_SELECT_6;
use crate::virtio::scsi::constants::MODE_SENSE_6;
use crate::virtio::scsi::constants::READ_10;
use crate::virtio::scsi::constants::READ_6;
use crate::virtio::scsi::constants::READ_CAPACITY_10;
use crate::virtio::scsi::constants::READ_CAPACITY_16;
use crate::virtio::scsi::constants::REPORT_LUNS;
use crate::virtio::scsi::constants::REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS;
use crate::virtio::scsi::constants::SERVICE_ACTION_IN_16;
use crate::virtio::scsi::constants::SYNCHRONIZE_CACHE_10;
use crate::virtio::scsi::constants::TEST_UNIT_READY;
use crate::virtio::scsi::constants::TYPE_DISK;
use crate::virtio::scsi::constants::UNMAP;
use crate::virtio::scsi::constants::WRITE_10;
use crate::virtio::scsi::constants::WRITE_SAME_10;
use crate::virtio::scsi::constants::WRITE_SAME_16;
use crate::virtio::scsi::device::AsyncLogicalUnit;
use crate::virtio::scsi::device::ExecuteError;
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
    ReadCapacity16(ReadCapacity16),
    Read10(Read10),
    Write10(Write10),
    SynchronizeCache10(SynchronizeCache10),
    WriteSame10(WriteSame10),
    Unmap(Unmap),
    WriteSame16(WriteSame16),
    ReportLuns(ReportLuns),
    ReportSupportedTMFs(ReportSupportedTMFs),
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
            WRITE_SAME_10 => Ok(Self::WriteSame10(Self::parse_command(cdb)?)),
            UNMAP => Ok(Self::Unmap(Self::parse_command(cdb)?)),
            WRITE_SAME_16 => Ok(Self::WriteSame16(Self::parse_command(cdb)?)),
            SERVICE_ACTION_IN_16 => Self::parse_service_action_in_16(cdb),
            REPORT_LUNS => Ok(Self::ReportLuns(Self::parse_command(cdb)?)),
            MAINTENANCE_IN => Self::parse_maintenance_in(cdb),
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

    fn parse_maintenance_in(cdb: &[u8]) -> Result<Self, ExecuteError> {
        const MAINTENANCE_IN_SIZE: usize = 12;
        // Top three bits are reserved.
        let service_action = cdb[1] & 0x1f;
        match service_action {
            REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS => {
                let r = ReportSupportedTMFs::read_from(&cdb[..MAINTENANCE_IN_SIZE])
                    .ok_or(ExecuteError::ReadCommand)?;
                Ok(Self::ReportSupportedTMFs(r))
            }
            _ => {
                warn!(
                    "service action {:#x?} for MAINTENANCE_IN is not implemented",
                    service_action
                );
                Err(ExecuteError::Unsupported(cdb[0]))
            }
        }
    }

    fn parse_service_action_in_16(cdb: &[u8]) -> Result<Self, ExecuteError> {
        const SERVICE_ACTION_IN_16_SIZE: usize = 16;
        // Top three bits are reserved.
        let service_action = cdb[1] & 0x1f;
        match service_action {
            READ_CAPACITY_16 => {
                let r = ReadCapacity16::read_from(&cdb[..SERVICE_ACTION_IN_16_SIZE])
                    .ok_or(ExecuteError::ReadCommand)?;
                Ok(Self::ReadCapacity16(r))
            }
            _ => {
                warn!(
                    "service action {:#x?} for SERVICE_ACTION_IN_16 is not implemented",
                    service_action
                );
                Err(ExecuteError::Unsupported(cdb[0]))
            }
        }
    }

    pub async fn execute(
        &self,
        reader: &mut Reader,
        writer: &mut Writer,
        dev: &AsyncLogicalUnit,
    ) -> Result<(), ExecuteError> {
        match self {
            Self::TestUnitReady(_) => Ok(()), // noop as the device is ready.
            Self::Read6(read6) => read6.emulate(writer, dev).await,
            Self::Inquiry(inquiry) => inquiry.emulate(writer, dev),
            Self::ModeSelect6(mode_select_6) => mode_select_6.emulate(),
            Self::ModeSense6(mode_sense_6) => mode_sense_6.emulate(writer, dev),
            Self::ReadCapacity10(read_capacity_10) => read_capacity_10.emulate(writer, dev),
            Self::ReadCapacity16(read_capacity_16) => read_capacity_16.emulate(writer, dev),
            Self::Read10(read_10) => read_10.emulate(writer, dev).await,
            Self::Write10(write_10) => write_10.emulate(reader, dev).await,
            Self::SynchronizeCache10(synchronize_cache_10) => {
                synchronize_cache_10.emulate(dev).await
            }
            Self::WriteSame10(write_same_10) => write_same_10.emulate(reader, dev).await,
            Self::Unmap(unmap) => unmap.emulate(reader, dev).await,
            Self::WriteSame16(write_same_16) => write_same_16.emulate(reader, dev).await,
            Self::ReportLuns(report_luns) => report_luns.emulate(writer),
            Self::ReportSupportedTMFs(report_supported_tmfs) => {
                report_supported_tmfs.emulate(writer)
            }
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

fn check_lba_range(max_lba: u64, sector_num: u64, sector_len: usize) -> Result<(), ExecuteError> {
    // Checking `sector_num + sector_len - 1 <= max_lba`, but we are being careful about overflows
    // and underflows.
    match sector_num.checked_add(sector_len as u64) {
        Some(v) if v <= max_lba + 1 => Ok(()),
        _ => Err(ExecuteError::LbaOutOfRange {
            length: sector_len,
            sector: sector_num,
            max_lba,
        }),
    }
}

async fn read_from_disk(
    writer: &mut Writer,
    dev: &AsyncLogicalUnit,
    xfer_blocks: usize,
    lba: u64,
) -> Result<(), ExecuteError> {
    check_lba_range(dev.max_lba, lba, xfer_blocks)?;
    let block_size = dev.block_size;
    let count = xfer_blocks * block_size as usize;
    let offset = lba * block_size as u64;
    let before = writer.bytes_written();
    writer
        .write_all_from_at_fut(&*dev.disk_image, count, offset)
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
        dev: &AsyncLogicalUnit,
    ) -> Result<(), ExecuteError> {
        let xfer_len = self.xfer_len();
        let lba = self.lba() as u64;
        let _trace = cros_tracing::trace_event!(VirtioScsi, "READ(6)", xfer_len, lba);
        read_from_disk(writer, dev, xfer_len, lba).await
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

    fn emulate(&self, writer: &mut Writer, dev: &AsyncLogicalUnit) -> Result<(), ExecuteError> {
        let _trace = cros_tracing::trace_event!(VirtioScsi, "INQUIRY");
        if self.vital_product_data_enabled() {
            return self.emulate_vital_product_data_page(writer, dev);
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

    fn emulate_vital_product_data_page(
        &self,
        writer: &mut Writer,
        dev: &AsyncLogicalUnit,
    ) -> Result<(), ExecuteError> {
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
                // 0x00: Supported VPD Pages (this command)
                // 0x83: Device Identification
                // 0xb0: Block Limits
                // 0xb2: Logical Block Provisioning
                const SUPPORTED_VPD_PAGE_CODES: [u8; 4] = [0x00, 0x83, 0xb0, 0xb2];
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
            // Block Limits
            0xb0 => {
                // Page length
                outbuf[3] = 0x3c;
                // We do not support a value of zero in the NUMBER OF LOGICAL BLOCKS field in the
                // WRITE SAME command CDBs.
                outbuf[4] = 1;
                // skip outbuf[5]: crosvm does not support the COMPARE AND WRITE command.
                // Maximum transfer length
                outbuf[8..12]
                    .copy_from_slice(&dev.max_lba.try_into().unwrap_or(u32::MAX).to_be_bytes());
                // Maximum unmap LBA count
                outbuf[20..24].fill(0xff);
                // Maximum unmap block descriptor count
                outbuf[24..28].fill(0xff);
                // Optimal unmap granularity
                outbuf[28..32].copy_from_slice(&128u32.to_be_bytes());
                // Maximum WRITE SAME length
                outbuf[36..44].copy_from_slice(&dev.max_lba.to_be_bytes());
            }
            // Logical Block Provisioning
            0xb2 => {
                // Page length
                outbuf[3] = 4;
                // skip outbuf[4]: crosvm does not support logical block provisioning threshold sets.
                const UNMAP: u8 = 1 << 7;
                const WRITE_SAME_16: u8 = 1 << 6;
                const WRITE_SAME_10: u8 = 1 << 5;
                outbuf[5] = UNMAP | WRITE_SAME_10 | WRITE_SAME_16;
                // The logical unit is thin-provisioned.
                outbuf[6] = 0x02;
                // skip outbuf[7]: The logical block data represented by unmapped LBAs is vendor
                // specific
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
        let _trace = cros_tracing::trace_event!(VirtioScsi, "MODE_SELECT(6)");
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

    fn emulate(&self, writer: &mut Writer, dev: &AsyncLogicalUnit) -> Result<(), ExecuteError> {
        let _trace = cros_tracing::trace_event!(VirtioScsi, "MODE_SENSE(6)");
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
            let sectors = dev.max_lba;
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
    _obsolete1: u8,
    _obsolete2: [u8; 4],
    _reserved: [u8; 2],
    _obsolete3: u8,
    control: u8,
}

impl ReadCapacity10 {
    fn emulate(&self, writer: &mut Writer, dev: &AsyncLogicalUnit) -> Result<(), ExecuteError> {
        // Returned value is the block address of the last sector.
        // If the block address exceeds u32::MAX, we return u32::MAX.
        let block_address: u32 = dev.max_lba.saturating_sub(1).try_into().unwrap_or(u32::MAX);
        let mut outbuf = [0u8; 8];
        outbuf[..4].copy_from_slice(&block_address.to_be_bytes());
        outbuf[4..8].copy_from_slice(&dev.block_size.to_be_bytes());
        writer.write_all(&outbuf).map_err(ExecuteError::Write)
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct ReadCapacity16 {
    opcode: u8,
    service_action_field: u8,
    _obsolete: [u8; 8],
    alloc_len_bytes: [u8; 4],
    _reserved: u8,
    control: u8,
}

impl ReadCapacity16 {
    fn emulate(&self, writer: &mut Writer, dev: &AsyncLogicalUnit) -> Result<(), ExecuteError> {
        let _trace = cros_tracing::trace_event!(VirtioScsi, "READ_CAPACITY(16)");
        let mut outbuf = [0u8; 32];
        // Last logical block address
        outbuf[..8].copy_from_slice(&dev.max_lba.saturating_sub(1).to_be_bytes());
        // Block size
        outbuf[8..12].copy_from_slice(&dev.block_size.to_be_bytes());
        // crosvm implements logical block provisioning management.
        outbuf[14] = 1 << 7;
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
        dev: &AsyncLogicalUnit,
    ) -> Result<(), ExecuteError> {
        let xfer_len = self.xfer_len();
        let lba = self.lba();
        let _trace = cros_tracing::trace_event!(VirtioScsi, "READ(10)", lba, xfer_len);
        read_from_disk(writer, dev, xfer_len, lba).await
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
        dev: &AsyncLogicalUnit,
    ) -> Result<(), ExecuteError> {
        let xfer_len = self.xfer_len();
        let lba = self.lba();
        let _trace = cros_tracing::trace_event!(VirtioScsi, "WRITE(10)", lba, xfer_len);
        write_to_disk(reader, dev, xfer_len, lba).await
    }
}

async fn write_to_disk(
    reader: &mut Reader,
    dev: &AsyncLogicalUnit,
    xfer_blocks: usize,
    lba: u64,
) -> Result<(), ExecuteError> {
    if dev.read_only {
        return Err(ExecuteError::ReadOnly);
    }
    check_lba_range(dev.max_lba, lba, xfer_blocks)?;
    let block_size = dev.block_size;
    let count = xfer_blocks * block_size as usize;
    let offset = lba * block_size as u64;
    let before = reader.bytes_read();
    reader
        .read_exact_to_at_fut(&*dev.disk_image, count, offset)
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
    async fn emulate(&self, dev: &AsyncLogicalUnit) -> Result<(), ExecuteError> {
        let _trace = cros_tracing::trace_event!(VirtioScsi, "SYNCHRONIZE_CACHE(10)");
        dev.disk_image.fdatasync().await.map_err(|e| {
            warn!("failed to sync: {e}");
            ExecuteError::SynchronizationError
        })
    }
}

async fn unmap(dev: &AsyncLogicalUnit, lba: u64, nblocks: u64) -> Result<(), ExecuteError> {
    check_lba_range(dev.max_lba, lba, nblocks as usize)?;
    let offset = lba * dev.block_size as u64;
    let length = nblocks * dev.block_size as u64;
    // Ignore the errors here since the device is not strictly required to unmap the LBAs.
    let _ = dev.disk_image.punch_hole(offset, length).await;
    Ok(())
}

async fn write_same(
    dev: &AsyncLogicalUnit,
    lba: u64,
    nblocks: u64,
    reader: &mut Reader,
) -> Result<(), ExecuteError> {
    check_lba_range(dev.max_lba, lba, nblocks as usize)?;
    // The WRITE SAME command expects the device to transfer a single logical block from the
    // Data-Out buffer.
    reader.split_at(dev.block_size as usize);
    if reader.get_remaining().iter().all(|s| s.is_all_zero()) {
        // Ignore the errors here since the device is not strictly required to unmap the LBAs.
        let _ = dev.disk_image.write_zeroes_at(lba, nblocks).await;
        Ok(())
    } else {
        // TODO(b/309376528): If the specified data is not zero, raise error for now.
        Err(ExecuteError::InvalidField)
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct WriteSame10 {
    opcode: u8,
    wrprotect_anchor_unmap: u8,
    lba_bytes: [u8; 4],
    group_number_field: u8,
    nblocks_bytes: [u8; 2],
    control: u8,
}

impl WriteSame10 {
    fn lba(&self) -> u32 {
        u32::from_be_bytes(self.lba_bytes)
    }

    fn nblocks(&self) -> u16 {
        u16::from_be_bytes(self.nblocks_bytes)
    }

    fn unmap(&self) -> bool {
        self.wrprotect_anchor_unmap & 0x8 != 0
    }

    fn anchor(&self) -> bool {
        self.wrprotect_anchor_unmap & 0x10 != 0
    }

    async fn emulate(
        &self,
        reader: &mut Reader,
        dev: &AsyncLogicalUnit,
    ) -> Result<(), ExecuteError> {
        let lba = self.lba() as u64;
        let nblocks = self.nblocks() as u64;
        let _trace = cros_tracing::trace_event!(VirtioScsi, "WRITE_SAME(10)", lba, nblocks);
        if nblocks == 0 {
            // crosvm does not allow the number of blocks to be zero.
            return Err(ExecuteError::InvalidField);
        }
        if self.anchor() {
            // crosvm currently do not support anchor operations.
            return Err(ExecuteError::InvalidField);
        }
        if self.unmap() {
            unmap(dev, lba, nblocks).await
        } else {
            write_same(dev, lba, nblocks, reader).await
        }
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct Unmap {
    opcode: u8,
    anchor_field: u8,
    _reserved: [u8; 4],
    group_number_field: u8,
    param_list_len_bytes: [u8; 2],
    control: u8,
}

impl Unmap {
    fn anchor(&self) -> bool {
        self.anchor_field & 0x01 != 0
    }

    fn param_list_len(&self) -> u16 {
        u16::from_be_bytes(self.param_list_len_bytes)
    }

    async fn emulate(
        &self,
        reader: &mut Reader,
        dev: &AsyncLogicalUnit,
    ) -> Result<(), ExecuteError> {
        let _trace = cros_tracing::trace_event!(VirtioScsi, "UNMAP");
        // Reject anchor == 1
        if self.anchor() {
            return Err(ExecuteError::InvalidField);
        }
        if dev.read_only {
            return Err(ExecuteError::ReadOnly);
        }
        let param_list_len = self.param_list_len();
        if 0 < param_list_len && param_list_len < 8 {
            return Err(ExecuteError::InvalidParamLen);
        }
        // unmap data len
        reader.consume(2);
        let unmap_block_descriptors = {
            let block_data_len = reader
                .read_obj::<Be16>()
                .map_err(ExecuteError::Read)?
                .to_native();
            // If the data length is not a multiple of 16, the last unmap block should be ignored.
            block_data_len / 16
        };
        // reserved
        reader.consume(4);
        for _ in 0..unmap_block_descriptors {
            let lba = reader
                .read_obj::<Be64>()
                .map_err(ExecuteError::Read)?
                .to_native();
            let nblocks = reader
                .read_obj::<Be32>()
                .map_err(ExecuteError::Read)?
                .to_native() as u64;
            // reserved
            reader.consume(4);
            unmap(dev, lba, nblocks).await?;
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct WriteSame16 {
    opcode: u8,
    wrprotect_anchor_unmap: u8,
    lba_bytes: [u8; 8],
    nblocks_bytes: [u8; 4],
    group_number_field: u8,
    control: u8,
}

impl WriteSame16 {
    fn lba(&self) -> u64 {
        u64::from_be_bytes(self.lba_bytes)
    }

    fn nblocks(&self) -> u32 {
        u32::from_be_bytes(self.nblocks_bytes)
    }

    fn unmap(&self) -> bool {
        self.wrprotect_anchor_unmap & 0x8 != 0
    }

    fn anchor(&self) -> bool {
        self.wrprotect_anchor_unmap & 0x10 != 0
    }

    async fn emulate(
        &self,
        reader: &mut Reader,
        dev: &AsyncLogicalUnit,
    ) -> Result<(), ExecuteError> {
        let lba = self.lba();
        let nblocks = self.nblocks() as u64;
        let _trace = cros_tracing::trace_event!(VirtioScsi, "WRITE_SAME(16)", lba, nblocks);
        if nblocks == 0 {
            // crosvm does not allow the number of blocks to be zero.
            return Err(ExecuteError::InvalidField);
        }
        if self.anchor() {
            // crosvm currently do not support anchor operations.
            return Err(ExecuteError::InvalidField);
        }
        if self.unmap() {
            unmap(dev, lba, nblocks).await
        } else {
            write_same(dev, lba, nblocks, reader).await
        }
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
        let _trace = cros_tracing::trace_event!(VirtioScsi, "REPORT_LUNS");
        // We need at least 16 bytes.
        if self.alloc_len() < 16 {
            return Err(ExecuteError::InvalidField);
        }
        // Each LUN takes 8 bytes and we only support LUN0.
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

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes, PartialEq, Eq)]
#[repr(C, packed)]
pub struct ReportSupportedTMFs {
    opcode: u8,
    service_action_field: u8,
    _reserved1: [u8; 4],
    alloc_len_bytes: [u8; 4],
    _reserved2: u8,
    control: u8,
}

impl ReportSupportedTMFs {
    fn alloc_len(&self) -> u32 {
        u32::from_be_bytes(self.alloc_len_bytes)
    }

    fn emulate(&self, writer: &mut Writer) -> Result<(), ExecuteError> {
        let _trace = cros_tracing::trace_event!(VirtioScsi, "REPORT_SUPPORTED_TMFs");
        // The allocation length should be at least four.
        if self.alloc_len() < 4 {
            return Err(ExecuteError::InvalidField);
        }
        // We support LOGICAL UNIT RESET and TARGET RESET.
        const LOGICAL_UNIT_RESET: u8 = 1 << 3;
        const TARGET_RESET: u8 = 1 << 1;
        writer
            .write_obj(LOGICAL_UNIT_RESET | TARGET_RESET)
            .map_err(ExecuteError::Write)?;
        // Push reserved bytes.
        let reserved = [0u8; 3];
        writer.write_all(&reserved).map_err(ExecuteError::Write)?;
        Ok(())
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
        match command {
            Command::ReadCapacity10(_) => (),
            _ => panic!("unexpected command type: {:?}", command),
        };
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

    #[test]
    fn parse_report_supported_tmfs() {
        let cdb = [
            0xa3, 0x0d, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x00, 0x00,
        ];
        let command = Command::new(&cdb).unwrap();
        let report_supported_tmfs = match command {
            Command::ReportSupportedTMFs(r) => r,
            _ => panic!("unexpected command type: {:?}", command),
        };
        assert_eq!(report_supported_tmfs.alloc_len(), 0xabcdef12);
    }
}
