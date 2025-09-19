// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryInto;

use anyhow::Context;
use base::error;
use base::info;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::Event;
use base::RawDescriptor;
use base::Tube;
use base::TubeError;
use bit_field::*;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
use thiserror::Error;
use vm_control::VmIrqRequest;
use vm_control::VmIrqResponse;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::pci::pci_configuration::PciCapConfig;
use crate::pci::pci_configuration::PciCapConfigWriteResult;
use crate::pci::PciCapability;
use crate::pci::PciCapabilityID;

const MAX_MSIX_VECTORS_PER_DEVICE: u16 = 2048;
pub const MSIX_TABLE_ENTRIES_MODULO: u64 = 16;
pub const MSIX_PBA_ENTRIES_MODULO: u64 = 8;
pub const BITS_PER_PBA_ENTRY: usize = 64;
const FUNCTION_MASK_BIT: u16 = 0x4000;
const MSIX_ENABLE_BIT: u16 = 0x8000;
const MSIX_TABLE_ENTRY_MASK_BIT: u32 = 0x1;

#[derive(Serialize, Deserialize, Clone, Default)]
struct MsixTableEntry {
    msg_addr_lo: u32,
    msg_addr_hi: u32,
    msg_data: u32,
    vector_ctl: u32,
}

impl MsixTableEntry {
    fn masked(&self) -> bool {
        self.vector_ctl & MSIX_TABLE_ENTRY_MASK_BIT == MSIX_TABLE_ENTRY_MASK_BIT
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
    irq_vec: Vec<Option<IrqfdGsi>>,
    masked: bool,
    enabled: bool,
    msi_device_socket: Tube,
    msix_num: u16,
    pci_id: u32,
    pci_address: Option<resources::PciAddress>,
    device_name: String,
}

#[derive(Serialize, Deserialize)]
struct MsixConfigSnapshot {
    table_entries: Vec<MsixTableEntry>,
    pba_entries: Vec<u64>,
    /// Just like MsixConfig::irq_vec, but only the GSI.
    irq_gsi_vec: Vec<Option<u32>>,
    masked: bool,
    enabled: bool,
    msix_num: u16,
    pci_id: u32,
    pci_address: Option<resources::PciAddress>,
    device_name: String,
}

#[sorted]
#[derive(Error, Debug)]
pub enum MsixError {
    #[error("AddMsiRoute failed: {0}")]
    AddMsiRoute(SysError),
    #[error("failed to receive AddMsiRoute response: {0}")]
    AddMsiRouteRecv(TubeError),
    #[error("failed to send AddMsiRoute request: {0}")]
    AddMsiRouteSend(TubeError),
    #[error("AllocateOneMsi failed: {0}")]
    AllocateOneMsi(SysError),
    #[error("failed to receive AllocateOneMsi response: {0}")]
    AllocateOneMsiRecv(TubeError),
    #[error("failed to send AllocateOneMsi request: {0}")]
    AllocateOneMsiSend(TubeError),
    #[error("failed to deserialize snapshot: {0}")]
    DeserializationFailed(anyhow::Error),
    #[error("invalid vector length in snapshot: {0}")]
    InvalidVectorLength(std::num::TryFromIntError),
    #[error("ReleaseOneIrq failed: {0}")]
    ReleaseOneIrq(base::Error),
    #[error("failed to receive ReleaseOneIrq response: {0}")]
    ReleaseOneIrqRecv(TubeError),
    #[error("failed to send ReleaseOneIrq request: {0}")]
    ReleaseOneIrqSend(TubeError),
}

type MsixResult<T> = std::result::Result<T, MsixError>;

#[derive(Copy, Clone)]
pub enum MsixStatus {
    Changed,
    EntryChanged(usize),
    NothingToDo,
}

impl PciCapConfigWriteResult for MsixStatus {}

impl MsixConfig {
    pub fn new(msix_vectors: u16, vm_socket: Tube, pci_id: u32, device_name: String) -> Self {
        assert!(msix_vectors <= MAX_MSIX_VECTORS_PER_DEVICE);

        let mut table_entries: Vec<MsixTableEntry> = Vec::new();
        table_entries.resize_with(msix_vectors as usize, Default::default);
        table_entries
            .iter_mut()
            .for_each(|entry| entry.vector_ctl |= MSIX_TABLE_ENTRY_MASK_BIT);
        let mut pba_entries: Vec<u64> = Vec::new();
        let num_pba_entries: usize = (msix_vectors as usize).div_ceil(BITS_PER_PBA_ENTRY);
        pba_entries.resize_with(num_pba_entries, Default::default);

        let mut irq_vec = Vec::new();
        irq_vec.resize_with(msix_vectors.into(), || None::<IrqfdGsi>);

        MsixConfig {
            table_entries,
            pba_entries,
            irq_vec,
            masked: false,
            enabled: false,
            msi_device_socket: vm_socket,
            msix_num: msix_vectors,
            pci_id,
            pci_address: None,
            device_name,
        }
    }

    /// PCI address of the associated device.
    pub fn set_pci_address(&mut self, pci_address: resources::PciAddress) {
        self.pci_address = Some(pci_address);
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
        (msg_ctl as u32) << 16 | (data & u16::MAX as u32)
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
                if let Err(e) = self.msix_enable_all() {
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

    /// Create a snapshot of the current MsixConfig struct for use in
    /// snapshotting.
    pub fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        AnySnapshot::to_any(MsixConfigSnapshot {
            table_entries: self.table_entries.clone(),
            pba_entries: self.pba_entries.clone(),
            masked: self.masked,
            enabled: self.enabled,
            msix_num: self.msix_num,
            pci_id: self.pci_id,
            pci_address: self.pci_address,
            device_name: self.device_name.clone(),
            irq_gsi_vec: self
                .irq_vec
                .iter()
                .map(|irq_opt| irq_opt.as_ref().map(|irq| irq.gsi))
                .collect(),
        })
        .context("failed to serialize MsixConfigSnapshot")
    }

    /// Restore a MsixConfig struct based on a snapshot. In short, this will
    /// restore all data exposed via MMIO, and recreate all MSI-X vectors (they
    /// will be re-wired to the irq chip).
    pub fn restore(&mut self, snapshot: AnySnapshot) -> MsixResult<()> {
        let snapshot: MsixConfigSnapshot =
            AnySnapshot::from_any(snapshot).map_err(MsixError::DeserializationFailed)?;

        self.table_entries = snapshot.table_entries;
        self.pba_entries = snapshot.pba_entries;
        self.masked = snapshot.masked;
        self.enabled = snapshot.enabled;
        self.msix_num = snapshot.msix_num;
        self.pci_id = snapshot.pci_id;
        self.pci_address = snapshot.pci_address;
        self.device_name = snapshot.device_name;

        self.msix_release_all()?;
        self.irq_vec
            .resize_with(snapshot.irq_gsi_vec.len(), || None::<IrqfdGsi>);
        for (vector, gsi) in snapshot.irq_gsi_vec.iter().enumerate() {
            if let Some(gsi_num) = gsi {
                self.msix_restore_one(vector, *gsi_num)?;
            } else {
                info!(
                    "skipping restore of vector {} for device {}",
                    vector, self.device_name
                );
            }
        }
        Ok(())
    }

    /// Restore the specified MSI-X vector.
    ///
    /// Note: we skip the checks from [MsixConfig::msix_enable_one] because for
    /// an interrupt to be present in [MsixConfigSnapshot::irq_gsi_vec], it must
    /// have passed those checks.
    fn msix_restore_one(&mut self, index: usize, gsi: u32) -> MsixResult<()> {
        let irqfd = Event::new().map_err(MsixError::AllocateOneMsi)?;
        let request = VmIrqRequest::AllocateOneMsiAtGsi {
            irqfd,
            gsi,
            device_id: self.pci_id,
            queue_id: index,
            device_name: self.device_name.clone(),
        };
        self.msi_device_socket
            .send(&request)
            .map_err(MsixError::AllocateOneMsiSend)?;
        if let VmIrqResponse::Err(e) = self
            .msi_device_socket
            .recv()
            .map_err(MsixError::AllocateOneMsiRecv)?
        {
            return Err(MsixError::AllocateOneMsi(e));
        };

        self.irq_vec[index] = Some(IrqfdGsi {
            irqfd: match request {
                VmIrqRequest::AllocateOneMsiAtGsi { irqfd, .. } => irqfd,
                _ => unreachable!(),
            },
            gsi,
        });
        self.add_msi_route(index as u16, gsi)?;
        Ok(())
    }

    /// On warm restore, there could already be MSIs registered. We need to
    /// release them in case the routing has changed (e.g. different
    /// data <-> GSI).
    fn msix_release_all(&mut self) -> MsixResult<()> {
        for irqfd_gsi in self.irq_vec.drain(..).flatten() {
            let request = VmIrqRequest::ReleaseOneIrq {
                gsi: irqfd_gsi.gsi,
                irqfd: irqfd_gsi.irqfd,
            };

            self.msi_device_socket
                .send(&request)
                .map_err(MsixError::ReleaseOneIrqSend)?;
            if let VmIrqResponse::Err(e) = self
                .msi_device_socket
                .recv()
                .map_err(MsixError::ReleaseOneIrqRecv)?
            {
                return Err(MsixError::ReleaseOneIrq(e));
            }
        }
        Ok(())
    }

    fn add_msi_route(&mut self, index: u16, gsi: u32) -> MsixResult<()> {
        let mut data: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
        self.read_msix_table((index * 16).into(), data.as_mut());
        let msi_address: u64 = u64::from_le_bytes(data);
        let mut data: [u8; 4] = [0, 0, 0, 0];
        self.read_msix_table((index * 16 + 8).into(), data.as_mut());
        let msi_data: u32 = u32::from_le_bytes(data);

        if msi_address == 0 {
            return Ok(());
        }

        // Only used on aarch64, but make sure it is initialized correctly on all archs for better
        // test coverage.
        #[allow(unused_variables)]
        let pci_address = self
            .pci_address
            .expect("MsixConfig: must call set_pci_address before config writes");

        self.msi_device_socket
            .send(&VmIrqRequest::AddMsiRoute {
                gsi,
                msi_address,
                msi_data,
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                pci_address,
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

    // Enable MSI-X
    fn msix_enable_all(&mut self) -> MsixResult<()> {
        for index in 0..self.irq_vec.len() {
            self.msix_enable_one(index)?;
        }
        Ok(())
    }

    // Use a new MSI-X vector
    // Create a new eventfd and bind them to a new msi
    fn msix_enable_one(&mut self, index: usize) -> MsixResult<()> {
        if self.irq_vec[index].is_some()
            || !self.enabled()
            || self.masked()
            || self.table_masked(index)
        {
            return Ok(());
        }
        let irqfd = Event::new().map_err(MsixError::AllocateOneMsi)?;
        let request = VmIrqRequest::AllocateOneMsi {
            irqfd,
            device_id: self.pci_id,
            queue_id: index,
            device_name: self.device_name.clone(),
        };
        self.msi_device_socket
            .send(&request)
            .map_err(MsixError::AllocateOneMsiSend)?;
        let irq_num: u32 = match self
            .msi_device_socket
            .recv()
            .map_err(MsixError::AllocateOneMsiRecv)?
        {
            VmIrqResponse::AllocateOneMsi { gsi } => gsi,
            VmIrqResponse::Err(e) => return Err(MsixError::AllocateOneMsi(e)),
            _ => unreachable!(),
        };
        self.irq_vec[index] = Some(IrqfdGsi {
            irqfd: match request {
                VmIrqRequest::AllocateOneMsi { irqfd, .. } => irqfd,
                _ => unreachable!(),
            },
            gsi: irq_num,
        });

        self.add_msi_route(index as u16, irq_num)?;
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

        if index >= self.table_entries.len() {
            error!("invalid MSI-X table index {}", index);
            return;
        }

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
    ///     on AD\[31::00\] during the memory write transaction's data phase.
    /// Vector Control: only bit 0 (Mask Bit) is not reserved: when this bit
    ///     is set, the function is prohibited from sending a message using
    ///     this MSI-X Table entry.
    pub fn write_msix_table(&mut self, offset: u64, data: &[u8]) -> MsixStatus {
        let index: usize = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_TABLE_ENTRIES_MODULO;

        if index >= self.table_entries.len() {
            error!("invalid MSI-X table index {}", index);
            return MsixStatus::NothingToDo;
        }

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

        // This MSI-X vector is enabled for the first time.
        if self.enabled()
            && !self.masked()
            && self.irq_vec[index].is_none()
            && old_entry.masked()
            && !new_entry.masked()
        {
            if let Err(e) = self.msix_enable_one(index) {
                error!("failed to enable MSI-X vector {}: {}", index, e);
                self.table_entries[index].vector_ctl |= MSIX_TABLE_ENTRY_MASK_BIT;
            }
            return MsixStatus::EntryChanged(index);
        }

        if self.enabled()
            && (old_entry.msg_addr_lo != new_entry.msg_addr_lo
                || old_entry.msg_addr_hi != new_entry.msg_addr_hi
                || old_entry.msg_data != new_entry.msg_data)
        {
            if let Some(irqfd_gsi) = &self.irq_vec[index] {
                let irq_num = irqfd_gsi.gsi;
                if let Err(e) = self.add_msi_route(index as u16, irq_num) {
                    error!("add_msi_route failed: {}", e);
                }
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
    /// Pending Bits\[63::00\]: For each Pending Bit that is set, the function
    /// has a pending message for the associated MSI-X Table entry.
    pub fn read_pba_entries(&self, offset: u64, data: &mut [u8]) {
        let index: usize = (offset / MSIX_PBA_ENTRIES_MODULO) as usize;
        let modulo_offset = offset % MSIX_PBA_ENTRIES_MODULO;

        if index >= self.pba_entries.len() {
            error!("invalid PBA index {}", index);
            return;
        }

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
        if let Some(irq) = &self.irq_vec[vector] {
            irq.irqfd.signal().unwrap();
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
        } else if let Some(irq) = self.irq_vec.get(vector as usize).unwrap_or(&None) {
            irq.irqfd.signal().unwrap();
        }
    }

    /// Return the raw descriptor of the MSI device socket
    pub fn get_msi_socket(&self) -> RawDescriptor {
        self.msi_device_socket.as_raw_descriptor()
    }

    /// Return irqfd of MSI-X Table entry
    ///
    ///  # Arguments
    ///  * 'vector' - the index to the MSI-X table entry
    pub fn get_irqfd(&self, vector: usize) -> Option<&Event> {
        match self.irq_vec.get(vector).unwrap_or(&None) {
            Some(irq) => Some(&irq.irqfd),
            None => None,
        }
    }

    pub fn destroy(&mut self) {
        while let Some(irq) = self.irq_vec.pop() {
            if let Some(irq) = irq {
                let request = VmIrqRequest::ReleaseOneIrq {
                    gsi: irq.gsi,
                    irqfd: irq.irqfd,
                };
                if self.msi_device_socket.send(&request).is_err() {
                    continue;
                }
                let _ = self.msi_device_socket.recv::<VmIrqResponse>();
            }
        }
    }
}

const MSIX_CONFIG_READ_MASK: [u32; 3] = [0xc000_0000, 0, 0];

impl PciCapConfig for MsixConfig {
    fn read_mask(&self) -> &'static [u32] {
        &MSIX_CONFIG_READ_MASK
    }

    fn read_reg(&self, reg_idx: usize) -> u32 {
        if reg_idx == 0 {
            self.read_msix_capability(0)
        } else {
            0
        }
    }

    fn write_reg(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> Option<Box<dyn PciCapConfigWriteResult>> {
        let status = if reg_idx == 0 {
            self.write_msix_capability(offset, data)
        } else {
            MsixStatus::NothingToDo
        };
        Some(Box::new(status))
    }
}

impl AsRawDescriptor for MsixConfig {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.msi_device_socket.as_raw_descriptor()
    }
}

/// Message Control Register
//   10-0:  MSI-X Table size
//   13-11: Reserved
//   14:    Mask. Mask all MSI-X when set.
//   15:    Enable. Enable all MSI-X when set.
// See <https://wiki.osdev.org/PCI#Enabling_MSI-X> for the details.
#[bitfield]
#[derive(Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct MsixCtrl {
    table_size: B10,
    reserved: B4,
    mask: B1,
    enable: B1,
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
/// MSI-X Capability Structure
pub struct MsixCap {
    // To make add_capability() happy
    _cap_vndr: u8,
    _cap_next: u8,
    // Message Control Register
    msg_ctl: MsixCtrl,
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
        self.as_bytes()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::Msix
    }

    fn writable_bits(&self) -> Vec<u32> {
        // Only msg_ctl[15:14] is writable
        vec![0x3000_0000, 0, 0]
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
        let mut msg_ctl = MsixCtrl::new();
        msg_ctl.set_enable(1);
        // Table Size is N - 1 encoded.
        msg_ctl.set_table_size(table_size - 1);

        MsixCap {
            _cap_vndr: 0,
            _cap_next: 0,
            msg_ctl,
            table: (table_off & 0xffff_fff8u32) | u32::from(table_pci_bar & 0x7u8),
            pba: (pba_off & 0xffff_fff8u32) | u32::from(pba_pci_bar & 0x7u8),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::thread;

    use super::*;

    #[track_caller]
    fn recv_allocate_msi(t: &Tube) -> u32 {
        match t.recv::<VmIrqRequest>().unwrap() {
            VmIrqRequest::AllocateOneMsiAtGsi { gsi, .. } => gsi,
            msg => panic!("unexpected irqchip message: {:?}", msg),
        }
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    struct MsiRouteDetails {
        gsi: u32,
        msi_address: u64,
        msi_data: u32,
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        pci_address: resources::PciAddress,
    }

    const TEST_PCI_ADDRESS: resources::PciAddress = resources::PciAddress {
        bus: 1,
        dev: 2,
        func: 3,
    };

    #[track_caller]
    fn recv_add_msi_route(t: &Tube) -> MsiRouteDetails {
        match t.recv::<VmIrqRequest>().unwrap() {
            VmIrqRequest::AddMsiRoute {
                gsi,
                msi_address,
                msi_data,
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                pci_address,
            } => MsiRouteDetails {
                gsi,
                msi_address,
                msi_data,
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                pci_address,
            },
            msg => panic!("unexpected irqchip message: {:?}", msg),
        }
    }

    #[track_caller]
    fn recv_release_one_irq(t: &Tube) -> u32 {
        match t.recv::<VmIrqRequest>().unwrap() {
            VmIrqRequest::ReleaseOneIrq { gsi, irqfd: _ } => gsi,
            msg => panic!("unexpected irqchip message: {:?}", msg),
        }
    }

    #[track_caller]
    fn send_ok(t: &Tube) {
        t.send(&VmIrqResponse::Ok).unwrap();
    }

    /// Tests a cold restore where there are no existing vectors at the time
    /// restore is called.
    #[test]
    fn verify_msix_restore_cold_smoke() {
        let (irqchip_tube, msix_config_tube) = Tube::pair().unwrap();
        let (_unused, unused_config_tube) = Tube::pair().unwrap();

        let mut cfg = MsixConfig::new(2, unused_config_tube, 0, "test_device".to_owned());
        cfg.set_pci_address(TEST_PCI_ADDRESS);

        // Set up two MSI-X vectors (0 and 1).
        // Data is 0xdVEC_NUM. Address is 0xaVEC_NUM.
        cfg.table_entries[0].msg_data = 0xd0;
        cfg.table_entries[0].msg_addr_lo = 0xa0;
        cfg.table_entries[0].msg_addr_hi = 0;
        cfg.table_entries[1].msg_data = 0xd1;
        cfg.table_entries[1].msg_addr_lo = 0xa1;
        cfg.table_entries[1].msg_addr_hi = 0;

        // Pretend that these vectors were hooked up to GSIs 10 & 20,
        // respectively.
        cfg.irq_vec = vec![
            Some(IrqfdGsi {
                gsi: 10,
                irqfd: Event::new().unwrap(),
            }),
            Some(IrqfdGsi {
                gsi: 20,
                irqfd: Event::new().unwrap(),
            }),
        ];

        // Take a snapshot of MsixConfig.
        let snapshot = cfg.snapshot().unwrap();

        // Create a fake irqchip to respond to our requests
        let irqchip_fake = thread::spawn(move || {
            assert_eq!(recv_allocate_msi(&irqchip_tube), 10);
            send_ok(&irqchip_tube);
            assert_eq!(
                recv_add_msi_route(&irqchip_tube),
                MsiRouteDetails {
                    gsi: 10,
                    msi_address: 0xa0,
                    msi_data: 0xd0,
                    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                    pci_address: TEST_PCI_ADDRESS,
                }
            );
            send_ok(&irqchip_tube);

            assert_eq!(recv_allocate_msi(&irqchip_tube), 20);
            send_ok(&irqchip_tube);
            assert_eq!(
                recv_add_msi_route(&irqchip_tube),
                MsiRouteDetails {
                    gsi: 20,
                    msi_address: 0xa1,
                    msi_data: 0xd1,
                    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                    pci_address: TEST_PCI_ADDRESS,
                }
            );
            send_ok(&irqchip_tube);
            irqchip_tube
        });

        let mut restored_cfg = MsixConfig::new(10, msix_config_tube, 10, "some_device".to_owned());
        restored_cfg.restore(snapshot).unwrap();
        irqchip_fake.join().unwrap();

        assert_eq!(restored_cfg.pci_id, 0);
        assert_eq!(restored_cfg.device_name, "test_device");
    }

    /// Tests a warm restore where there are existing vectors at the time
    /// restore is called. These vectors need to be released first.
    #[test]
    fn verify_msix_restore_warm_smoke() {
        let (irqchip_tube, msix_config_tube) = Tube::pair().unwrap();

        let mut cfg = MsixConfig::new(2, msix_config_tube, 0, "test_device".to_owned());
        cfg.set_pci_address(TEST_PCI_ADDRESS);

        // Set up two MSI-X vectors (0 and 1).
        // Data is 0xdVEC_NUM. Address is 0xaVEC_NUM.
        cfg.table_entries[0].msg_data = 0xd0;
        cfg.table_entries[0].msg_addr_lo = 0xa0;
        cfg.table_entries[0].msg_addr_hi = 0;
        cfg.table_entries[1].msg_data = 0xd1;
        cfg.table_entries[1].msg_addr_lo = 0xa1;
        cfg.table_entries[1].msg_addr_hi = 0;

        // Pretend that these vectors were hooked up to GSIs 10 & 20,
        // respectively.
        cfg.irq_vec = vec![
            Some(IrqfdGsi {
                gsi: 10,
                irqfd: Event::new().unwrap(),
            }),
            Some(IrqfdGsi {
                gsi: 20,
                irqfd: Event::new().unwrap(),
            }),
        ];

        // Take a snapshot of MsixConfig.
        let snapshot = cfg.snapshot().unwrap();

        // Create a fake irqchip to respond to our requests
        let irqchip_fake = thread::spawn(move || {
            // First, we free the existing vectors / GSIs.
            assert_eq!(recv_release_one_irq(&irqchip_tube), 10);
            send_ok(&irqchip_tube);
            assert_eq!(recv_release_one_irq(&irqchip_tube), 20);
            send_ok(&irqchip_tube);

            // Now we re-allocate them.
            assert_eq!(recv_allocate_msi(&irqchip_tube), 10);
            send_ok(&irqchip_tube);
            assert_eq!(
                recv_add_msi_route(&irqchip_tube),
                MsiRouteDetails {
                    gsi: 10,
                    msi_address: 0xa0,
                    msi_data: 0xd0,
                    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                    pci_address: TEST_PCI_ADDRESS,
                }
            );
            send_ok(&irqchip_tube);

            assert_eq!(recv_allocate_msi(&irqchip_tube), 20);
            send_ok(&irqchip_tube);
            assert_eq!(
                recv_add_msi_route(&irqchip_tube),
                MsiRouteDetails {
                    gsi: 20,
                    msi_address: 0xa1,
                    msi_data: 0xd1,
                    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                    pci_address: TEST_PCI_ADDRESS,
                }
            );
            send_ok(&irqchip_tube);
            irqchip_tube
        });

        cfg.restore(snapshot).unwrap();
        irqchip_fake.join().unwrap();

        assert_eq!(cfg.pci_id, 0);
        assert_eq!(cfg.device_name, "test_device");
    }
}
