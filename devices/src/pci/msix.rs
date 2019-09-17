// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::pci::{PciCapability, PciCapabilityID};
use std::convert::TryInto;
use sys_util::error;

use data_model::DataInit;

const MAX_MSIX_VECTORS_PER_DEVICE: u16 = 2048;
const MSIX_TABLE_ENTRIES_MODULO: u64 = 16;
const MSIX_PBA_ENTRIES_MODULO: u64 = 8;
const BITS_PER_PBA_ENTRY: usize = 64;
const FUNCTION_MASK_BIT: u16 = 0x4000;
const MSIX_ENABLE_BIT: u16 = 0x8000;

#[derive(Clone)]
struct MsixTableEntry {
    msg_addr_lo: u32,
    msg_addr_hi: u32,
    msg_data: u32,
    vector_ctl: u32,
}

impl MsixTableEntry {
    #[allow(dead_code)]
    fn masked(&self) -> bool {
        self.vector_ctl & 0x1 == 0x1
    }
}

impl Default for MsixTableEntry {
    fn default() -> Self {
        MsixTableEntry {
            msg_addr_lo: 0,
            msg_addr_hi: 0,
            msg_data: 0,
            vector_ctl: 0,
        }
    }
}

/// Wrapper over MSI-X Capability Structure and MSI-X Tables
pub struct MsixConfig {
    table_entries: Vec<MsixTableEntry>,
    pba_entries: Vec<u64>,
    masked: bool,
    enabled: bool,
    _msix_num: u16,
}

impl MsixConfig {
    pub fn new(msix_vectors: u16) -> Self {
        assert!(msix_vectors <= MAX_MSIX_VECTORS_PER_DEVICE);

        let mut table_entries: Vec<MsixTableEntry> = Vec::new();
        table_entries.resize_with(msix_vectors as usize, Default::default);
        let mut pba_entries: Vec<u64> = Vec::new();
        let num_pba_entries: usize = ((msix_vectors as usize) / BITS_PER_PBA_ENTRY) + 1;
        pba_entries.resize_with(num_pba_entries, Default::default);

        MsixConfig {
            table_entries,
            pba_entries,
            masked: false,
            enabled: false,
            _msix_num: msix_vectors,
        }
    }

    /// Check whether the Function Mask bit in Message Control word in set or not.
    /// if 1, all of the vectors associated with the function are masked,
    /// regardless of their per-vector Mask bit states.
    /// If 0, each vector’s Mask bit determines whether the vector is masked or not.
    pub fn masked(&self) -> bool {
        self.masked
    }

    /// Check whether the MSI-X Enable bit in Message Control word in set or not.
    /// if 1, the function is permitted to use MSI-X to request service.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Read the MSI-X Capability Structure.
    /// The top 2 bits in Message Control word are emulated and all other
    /// bits are read only.
    pub fn read_msix_capability(&self, data: u32) -> u32 {
        let mut msg_ctl = (data >> 16) as u16;
        msg_ctl &= !(MSIX_ENABLE_BIT | FUNCTION_MASK_BIT);

        if self.enabled {
            msg_ctl |= MSIX_ENABLE_BIT;
        }
        if self.masked {
            msg_ctl |= FUNCTION_MASK_BIT;
        }
        (msg_ctl as u32) << 16 | (data & u16::max_value() as u32)
    }

    /// Write to the MSI-X Capability Structure.
    /// Only the top 2 bits in Message Control Word are writable.
    pub fn write_msix_capability(&mut self, offset: u64, data: &[u8]) {
        if offset == 2 && data.len() == 2 {
            let reg = u16::from_le_bytes([data[0], data[1]]);

            self.masked = (reg & FUNCTION_MASK_BIT) == FUNCTION_MASK_BIT;
            self.enabled = (reg & MSIX_ENABLE_BIT) == MSIX_ENABLE_BIT;
        } else {
            error!(
                "invalid write to MSI-X Capability Structure offset {:x}",
                offset
            );
        }
    }

    /// Read MSI-X table
    ///  # Arguments
    ///  * 'offset' - the offset within the MSI-X Table
    ///  * 'data' - used to store the read results
    ///
    /// For all accesses to MSI-X Table and MSI-X PBA fields, software must use aligned full
    /// DWORD or aligned full QWORD transactions; otherwise, the result is undefined.
    ///
    ///             DWORD3            DWORD2      DWORD1            DWORD0
    ///   entry 0:  Vector Control    Msg Data    Msg Upper Addr    Msg Addr
    ///   entry 1:  Vector Control    Msg Data    Msg Upper Addr    Msg Addr
    ///   entry 2:  Vector Control    Msg Data    Msg Upper Addr    Msg Addr
    ///   ...
    pub fn read_msix_table(&self, offset: u64, data: &mut [u8]) {
        let index: usize = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_TABLE_ENTRIES_MODULO;

        match data.len() {
            4 => {
                let value = match modulo_offset {
                    0x0 => self.table_entries[index].msg_addr_lo,
                    0x4 => self.table_entries[index].msg_addr_hi,
                    0x8 => self.table_entries[index].msg_data,
                    0xc => self.table_entries[index].vector_ctl,
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                data.copy_from_slice(&value.to_le_bytes());
            }
            8 => {
                let value = match modulo_offset {
                    0x0 => {
                        (u64::from(self.table_entries[index].msg_addr_hi) << 32)
                            | u64::from(self.table_entries[index].msg_addr_lo)
                    }
                    0x8 => {
                        (u64::from(self.table_entries[index].vector_ctl) << 32)
                            | u64::from(self.table_entries[index].msg_data)
                    }
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                data.copy_from_slice(&value.to_le_bytes());
            }
            _ => error!("invalid data length"),
        };
    }

    /// Write to MSI-X table
    ///
    /// Message Address: the contents of this field specifies the address
    ///     for the memory write transaction; different MSI-X vectors have
    ///     different Message Address values
    /// Message Data: the contents of this field specifies the data driven
    ///     on AD[31::00] during the memory write transaction’s data phase.
    /// Vector Control: only bit 0 (Mask Bit) is not reserved: when this bit
    ///     is set, the function is prohibited from sending a message using
    ///     this MSI-X Table entry.
    pub fn write_msix_table(&mut self, offset: u64, data: &[u8]) {
        let index: usize = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_TABLE_ENTRIES_MODULO;

        match data.len() {
            4 => {
                let value = u32::from_le_bytes(data.try_into().unwrap());
                match modulo_offset {
                    0x0 => self.table_entries[index].msg_addr_lo = value,
                    0x4 => self.table_entries[index].msg_addr_hi = value,
                    0x8 => self.table_entries[index].msg_data = value,
                    0xc => self.table_entries[index].vector_ctl = value,
                    _ => error!("invalid offset"),
                };
            }
            8 => {
                let value = u64::from_le_bytes(data.try_into().unwrap());
                match modulo_offset {
                    0x0 => {
                        self.table_entries[index].msg_addr_lo = (value & 0xffff_ffffu64) as u32;
                        self.table_entries[index].msg_addr_hi = (value >> 32) as u32;
                    }
                    0x8 => {
                        self.table_entries[index].msg_data = (value & 0xffff_ffffu64) as u32;
                        self.table_entries[index].vector_ctl = (value >> 32) as u32;
                    }
                    _ => error!("invalid offset"),
                };
            }
            _ => error!("invalid data length"),
        };
    }

    /// Read PBA Entries
    ///  # Arguments
    ///  * 'offset' - the offset within the PBA entries
    ///  * 'data' - used to store the read results
    ///
    /// Pending Bits[63::00]: For each Pending Bit that is set, the function
    /// has a pending message for the associated MSI-X Table entry.
    pub fn read_pba_entries(&self, offset: u64, data: &mut [u8]) {
        let index: usize = (offset / MSIX_PBA_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_PBA_ENTRIES_MODULO;

        match data.len() {
            4 => {
                let value: u32 = match modulo_offset {
                    0x0 => (self.pba_entries[index] & 0xffff_ffffu64) as u32,
                    0x4 => (self.pba_entries[index] >> 32) as u32,
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                data.copy_from_slice(&value.to_le_bytes());
            }
            8 => {
                let value: u64 = match modulo_offset {
                    0x0 => self.pba_entries[index],
                    _ => {
                        error!("invalid offset");
                        0
                    }
                };

                data.copy_from_slice(&value.to_le_bytes());
            }
            _ => error!("invalid data length"),
        }
    }

    /// Write to PBA Entries
    ///
    /// Software should never write, and should only read Pending Bits.
    /// If software writes to Pending Bits, the result is undefined.
    pub fn write_pba_entries(&mut self, _offset: u64, _data: &[u8]) {
        error!("Pending Bit Array is read only");
    }

    #[allow(dead_code)]
    fn set_pba_bit(&mut self, vector: u16, set: bool) {
        assert!(vector < MAX_MSIX_VECTORS_PER_DEVICE);

        let index: usize = (vector as usize) / BITS_PER_PBA_ENTRY;
        let shift: usize = (vector as usize) % BITS_PER_PBA_ENTRY;
        let mut mask: u64 = (1 << shift) as u64;

        if set {
            self.pba_entries[index] |= mask;
        } else {
            mask = !mask;
            self.pba_entries[index] &= mask;
        }
    }

    #[allow(dead_code)]
    fn get_pba_bit(&self, vector: u16) -> u8 {
        assert!(vector < MAX_MSIX_VECTORS_PER_DEVICE);

        let index: usize = (vector as usize) / BITS_PER_PBA_ENTRY;
        let shift: usize = (vector as usize) % BITS_PER_PBA_ENTRY;

        ((self.pba_entries[index] >> shift) & 0x0000_0001u64) as u8
    }
}

// It is safe to implement DataInit; all members are simple numbers and any value is valid.
unsafe impl DataInit for MsixCap {}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
/// MSI-X Capability Structure
pub struct MsixCap {
    // To make add_capability() happy
    _cap_vndr: u8,
    _cap_next: u8,
    // Message Control Register
    //   10-0:  MSI-X Table size
    //   13-11: Reserved
    //   14:    Mask. Mask all MSI-X when set.
    //   15:    Enable. Enable all MSI-X when set.
    msg_ctl: u16,
    // Table. Contains the offset and the BAR indicator (BIR)
    //   2-0:  Table BAR indicator (BIR). Can be 0 to 5.
    //   31-3: Table offset in the BAR pointed by the BIR.
    table: u32,
    // Pending Bit Array. Contains the offset and the BAR indicator (BIR)
    //   2-0:  PBA BAR indicator (BIR). Can be 0 to 5.
    //   31-3: PBA offset in the BAR pointed by the BIR.
    pba: u32,
}

impl PciCapability for MsixCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::MSIX
    }
}

impl MsixCap {
    pub fn new(
        table_pci_bar: u8,
        table_size: u16,
        table_off: u32,
        pba_pci_bar: u8,
        pba_off: u32,
    ) -> Self {
        assert!(table_size < MAX_MSIX_VECTORS_PER_DEVICE);

        // Set the table size and enable MSI-X.
        let msg_ctl: u16 = MSIX_ENABLE_BIT + table_size - 1;

        MsixCap {
            _cap_vndr: 0,
            _cap_next: 0,
            msg_ctl,
            table: (table_off & 0xffff_fff8u32) | u32::from(table_pci_bar & 0x7u8),
            pba: (pba_off & 0xffff_fff8u32) | u32::from(pba_pci_bar & 0x7u8),
        }
    }
}
