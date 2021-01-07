// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::pci::{PciCapability, PciCapabilityID};
use base::{error, AsRawDescriptor, Error as SysError, Event, RawDescriptor, Tube, TubeError};

use std::convert::TryInto;
use std::fmt::{self, Display};
use vm_control::{VmIrqRequest, VmIrqResponse};

use data_model::DataInit;

const MAX_MSIX_VECTORS_PER_DEVICE: u16 = 2048;
pub const MSIX_TABLE_ENTRIES_MODULO: u64 = 16;
pub const MSIX_PBA_ENTRIES_MODULO: u64 = 8;
pub const BITS_PER_PBA_ENTRY: usize = 64;
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

struct IrqfdGsi {
    irqfd: Event,
    gsi: u32,
}

/// Wrapper over MSI-X Capability Structure and MSI-X Tables
pub struct MsixConfig {
    table_entries: Vec<MsixTableEntry>,
    pba_entries: Vec<u64>,
    irq_vec: Vec<IrqfdGsi>,
    masked: bool,
    enabled: bool,
    msi_device_socket: Tube,
    msix_num: u16,
}

enum MsixError {
    AddMsiRoute(SysError),
    AddMsiRouteRecv(TubeError),
    AddMsiRouteSend(TubeError),
    AllocateOneMsi(SysError),
    AllocateOneMsiRecv(TubeError),
    AllocateOneMsiSend(TubeError),
}

impl Display for MsixError {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::MsixError::*;

        #[sorted]
        match self {
            AddMsiRoute(e) => write!(f, "AddMsiRoute failed: {}", e),
            AddMsiRouteRecv(e) => write!(f, "failed to receive AddMsiRoute response: {}", e),
            AddMsiRouteSend(e) => write!(f, "failed to send AddMsiRoute request: {}", e),
            AllocateOneMsi(e) => write!(f, "AllocateOneMsi failed: {}", e),
            AllocateOneMsiRecv(e) => write!(f, "failed to receive AllocateOneMsi response: {}", e),
            AllocateOneMsiSend(e) => write!(f, "failed to send AllocateOneMsi request: {}", e),
        }
    }
}

type MsixResult<T> = std::result::Result<T, MsixError>;

pub enum MsixStatus {
    Changed,
    EntryChanged(usize),
    NothingToDo,
}

impl MsixConfig {
    pub fn new(msix_vectors: u16, vm_socket: Tube) -> Self {
        assert!(msix_vectors <= MAX_MSIX_VECTORS_PER_DEVICE);

        let mut table_entries: Vec<MsixTableEntry> = Vec::new();
        table_entries.resize_with(msix_vectors as usize, Default::default);
        let mut pba_entries: Vec<u64> = Vec::new();
        let num_pba_entries: usize = ((msix_vectors as usize) / BITS_PER_PBA_ENTRY) + 1;
        pba_entries.resize_with(num_pba_entries, Default::default);

        MsixConfig {
            table_entries,
            pba_entries,
            irq_vec: Vec::new(),
            masked: false,
            enabled: false,
            msi_device_socket: vm_socket,
            msix_num: msix_vectors,
        }
    }

    /// Get the number of MSI-X vectors in this configuration.
    pub fn num_vectors(&self) -> u16 {
        self.msix_num
    }

    /// Check whether the Function Mask bit in Message Control word in set or not.
    /// if 1, all of the vectors associated with the function are masked,
    /// regardless of their per-vector Mask bit states.
    /// If 0, each vector's Mask bit determines whether the vector is masked or not.
    pub fn masked(&self) -> bool {
        self.masked
    }

    /// Check whether the Function Mask bit in MSIX table Message Control
    /// word in set or not.
    /// If true, the vector is masked.
    /// If false, the vector is unmasked.
    pub fn table_masked(&self, index: usize) -> bool {
        if index >= self.table_entries.len() {
            true
        } else {
            self.table_entries[index].masked()
        }
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
    pub fn write_msix_capability(&mut self, offset: u64, data: &[u8]) -> MsixStatus {
        if offset == 2 && data.len() == 2 {
            let reg = u16::from_le_bytes([data[0], data[1]]);
            let old_masked = self.masked;
            let old_enabled = self.enabled;

            self.masked = (reg & FUNCTION_MASK_BIT) == FUNCTION_MASK_BIT;
            self.enabled = (reg & MSIX_ENABLE_BIT) == MSIX_ENABLE_BIT;

            if !old_enabled && self.enabled {
                if let Err(e) = self.msix_enable() {
                    error!("failed to enable MSI-X: {}", e);
                    self.enabled = false;
                }
            }

            // If the Function Mask bit was set, and has just been cleared, it's
            // important to go through the entire PBA to check if there was any
            // pending MSI-X message to inject, given that the vector is not
            // masked.
            if old_masked && !self.masked {
                for (index, entry) in self.table_entries.clone().iter().enumerate() {
                    if !entry.masked() && self.get_pba_bit(index as u16) == 1 {
                        self.inject_msix_and_clear_pba(index);
                    }
                }
                return MsixStatus::Changed;
            } else if !old_masked && self.masked {
                return MsixStatus::Changed;
            }
        } else {
            error!(
                "invalid write to MSI-X Capability Structure offset {:x}",
                offset
            );
        }
        MsixStatus::NothingToDo
    }

    fn add_msi_route(&self, index: u16, gsi: u32) -> MsixResult<()> {
        let mut data: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
        self.read_msix_table((index * 16).into(), data.as_mut());
        let msi_address: u64 = u64::from_le_bytes(data);
        let mut data: [u8; 4] = [0, 0, 0, 0];
        self.read_msix_table((index * 16 + 8).into(), data.as_mut());
        let msi_data: u32 = u32::from_le_bytes(data);

        if msi_address == 0 {
            return Ok(());
        }

        self.msi_device_socket
            .send(&VmIrqRequest::AddMsiRoute {
                gsi,
                msi_address,
                msi_data,
            })
            .map_err(MsixError::AddMsiRouteSend)?;
        if let VmIrqResponse::Err(e) = self
            .msi_device_socket
            .recv()
            .map_err(MsixError::AddMsiRouteRecv)?
        {
            return Err(MsixError::AddMsiRoute(e));
        }
        Ok(())
    }

    fn msix_enable(&mut self) -> MsixResult<()> {
        self.irq_vec.clear();
        for i in 0..self.msix_num {
            let irqfd = Event::new().unwrap();
            let request = VmIrqRequest::AllocateOneMsi { irqfd };
            self.msi_device_socket
                .send(&request)
                .map_err(MsixError::AllocateOneMsiSend)?;
            let irq_num: u32;
            match self
                .msi_device_socket
                .recv()
                .map_err(MsixError::AllocateOneMsiRecv)?
            {
                VmIrqResponse::AllocateOneMsi { gsi } => irq_num = gsi,
                VmIrqResponse::Err(e) => return Err(MsixError::AllocateOneMsi(e)),
                _ => unreachable!(),
            }
            self.irq_vec.push(IrqfdGsi {
                irqfd: match request {
                    VmIrqRequest::AllocateOneMsi { irqfd } => irqfd,
                    _ => unreachable!(),
                },
                gsi: irq_num,
            });

            self.add_msi_route(i, irq_num)?;
        }
        Ok(())
    }

    /// Read MSI-X table
    ///  # Arguments
    ///  * 'offset' - the offset within the MSI-X Table
    ///  * 'data' - used to store the read results
    ///
    /// For all accesses to MSI-X Table and MSI-X PBA fields, software must use aligned full
    /// DWORD or aligned full QWORD transactions; otherwise, the result is undefined.
    ///
    ///   location: DWORD3            DWORD2      DWORD1            DWORD0
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
    ///     on AD[31::00] during the memory write transaction's data phase.
    /// Vector Control: only bit 0 (Mask Bit) is not reserved: when this bit
    ///     is set, the function is prohibited from sending a message using
    ///     this MSI-X Table entry.
    pub fn write_msix_table(&mut self, offset: u64, data: &[u8]) -> MsixStatus {
        let index: usize = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_TABLE_ENTRIES_MODULO;

        // Store the value of the entry before modification
        let old_entry = self.table_entries[index].clone();

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

        let new_entry = self.table_entries[index].clone();
        if self.enabled()
            && (old_entry.msg_addr_lo != new_entry.msg_addr_lo
                || old_entry.msg_addr_hi != new_entry.msg_addr_hi
                || old_entry.msg_data != new_entry.msg_data)
        {
            let irq_num = self.irq_vec[index].gsi;
            if let Err(e) = self.add_msi_route(index as u16, irq_num) {
                error!("add_msi_route failed: {}", e);
            }
        }

        // After the MSI-X table entry has been updated, it is necessary to
        // check if the vector control masking bit has changed. In case the
        // bit has been flipped from 1 to 0, we need to inject a MSI message
        // if the corresponding pending bit from the PBA is set. Once the MSI
        // has been injected, the pending bit in the PBA needs to be cleared.
        // All of this is valid only if MSI-X has not been masked for the whole
        // device.

        // Check if bit has been flipped
        if !self.masked() {
            if old_entry.masked() && !self.table_entries[index].masked() {
                if self.get_pba_bit(index as u16) == 1 {
                    self.inject_msix_and_clear_pba(index);
                }
                return MsixStatus::EntryChanged(index);
            } else if !old_entry.masked() && self.table_entries[index].masked() {
                return MsixStatus::EntryChanged(index);
            }
        }
        MsixStatus::NothingToDo
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

    fn get_pba_bit(&self, vector: u16) -> u8 {
        assert!(vector < MAX_MSIX_VECTORS_PER_DEVICE);

        let index: usize = (vector as usize) / BITS_PER_PBA_ENTRY;
        let shift: usize = (vector as usize) % BITS_PER_PBA_ENTRY;

        ((self.pba_entries[index] >> shift) & 0x0000_0001u64) as u8
    }

    fn inject_msix_and_clear_pba(&mut self, vector: usize) {
        if let Some(irq) = self.irq_vec.get(vector) {
            irq.irqfd.write(1).unwrap();
        }

        // Clear the bit from PBA
        self.set_pba_bit(vector as u16, false);
    }

    /// Inject virtual interrupt to the guest
    ///
    ///  # Arguments
    ///  * 'vector' - the index to the MSI-X Table entry
    ///
    /// PCI Spec 3.0 6.8.3.5: while a vector is masked, the function is
    /// prohibited from sending the associated message, and the function
    /// must set the associated Pending bit whenever the function would
    /// otherwise send the message. When software unmasks a vector whose
    /// associated Pending bit is set, the function must schedule sending
    /// the associated message, and clear the Pending bit as soon as the
    /// message has been sent.
    ///
    /// If the vector is unmasked, writing to irqfd which wakes up KVM to
    /// inject virtual interrupt to the guest.
    pub fn trigger(&mut self, vector: u16) {
        if self.table_entries[vector as usize].masked() || self.masked() {
            self.set_pba_bit(vector, true);
        } else if let Some(irq) = self.irq_vec.get(vector as usize) {
            irq.irqfd.write(1).unwrap();
        }
    }

    /// Return the raw fd of the MSI device socket
    pub fn get_msi_socket(&self) -> RawDescriptor {
        self.msi_device_socket.as_raw_descriptor()
    }

    /// Return irqfd of MSI-X Table entry
    ///
    ///  # Arguments
    ///  * 'vector' - the index to the MSI-X table entry
    pub fn get_irqfd(&self, vector: usize) -> Option<&Event> {
        match self.irq_vec.get(vector) {
            Some(irq) => Some(&irq.irqfd),
            None => None,
        }
    }
}

impl AsRawDescriptor for MsixConfig {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.msi_device_socket.as_raw_descriptor()
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
