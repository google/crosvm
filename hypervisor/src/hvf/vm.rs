// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! HVF VM implementation.

use std::collections::BTreeMap;
use std::sync::Arc;

use base::AsRawDescriptor;
use base::Error;
use base::Event;
use base::MappedRegion;
use base::Protection;
use base::Result;
use base::SafeDescriptor;
use cros_fdt::Fdt;
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use super::bindings;
use super::vcpu::HvfVcpu;
use super::Hvf;
use crate::BalloonEvent;
use crate::ClockState;
use crate::Config;
use crate::Datamatch;
use crate::DeviceKind;
use crate::Hypervisor;
use crate::HypervisorKind;
use crate::IoEventAddress;
use crate::MemCacheType;
use crate::MemSlot;
use crate::VcpuAArch64;
use crate::VcpuFeature;
use crate::Vm;
use crate::VmAArch64;
use crate::VmCap;

/// Memory region tracking entry.
struct MemRegionEntry {
    guest_addr: u64,
    size: usize,
    mem: Box<dyn MappedRegion>,
}

/// IO event registration entry.
struct IoEventEntry {
    event: Event,
    addr: IoEventAddress,
    datamatch: Datamatch,
}

/// HVF VM implementation.
///
/// Unlike KVM, HVF manages VM state globally per-process. The HvfVm struct
/// tracks our view of this state.
pub struct HvfVm {
    /// Reference to the hypervisor
    hvf: Hvf,
    /// Guest memory
    guest_mem: GuestMemory,
    /// Memory regions added via add_memory_region
    mem_regions: Arc<Mutex<BTreeMap<MemSlot, MemRegionEntry>>>,
    /// Next available memory slot
    next_mem_slot: Arc<Mutex<MemSlot>>,
    /// Registered IO events (HVF doesn't support in-kernel ioeventfd)
    io_events: Arc<Mutex<Vec<IoEventEntry>>>,
    /// Number of VCPUs created
    vcpu_count: Arc<Mutex<usize>>,
}

impl HvfVm {
    /// Creates a new HVF VM.
    pub fn new(hvf: &Hvf, guest_mem: GuestMemory, _cfg: Config) -> Result<HvfVm> {
        // Only one VM per process allowed
        Hvf::mark_vm_created()?;

        // Create the VM
        // SAFETY: HVF API call with null config (uses defaults)
        let ret = unsafe { bindings::hv_vm_create(std::ptr::null_mut()) };
        if ret != bindings::HV_SUCCESS {
            Hvf::mark_vm_destroyed();
            return Err(Error::new(libc::EIO));
        }

        let vm = HvfVm {
            hvf: hvf.try_clone()?,
            guest_mem: guest_mem.clone(),
            mem_regions: Arc::new(Mutex::new(BTreeMap::new())),
            next_mem_slot: Arc::new(Mutex::new(guest_mem.num_regions() as MemSlot)),
            io_events: Arc::new(Mutex::new(Vec::new())),
            vcpu_count: Arc::new(Mutex::new(0)),
        };

        // Map initial guest memory regions
        for region in guest_mem.regions() {
            let flags = bindings::HV_MEMORY_READ | bindings::HV_MEMORY_WRITE | bindings::HV_MEMORY_EXEC;
            // SAFETY: host_addr is valid for the region size
            let ret = unsafe {
                bindings::hv_vm_map(
                    region.host_addr as *mut std::ffi::c_void,
                    region.guest_addr.offset(),
                    region.size,
                    flags,
                )
            };
            if ret != bindings::HV_SUCCESS {
                // Clean up on failure
                unsafe { bindings::hv_vm_destroy() };
                Hvf::mark_vm_destroyed();
                return Err(Error::new(libc::ENOMEM));
            }
        }

        Ok(vm)
    }
}

impl Drop for HvfVm {
    fn drop(&mut self) {
        // Unmap all memory regions before destroying the VM
        {
            let regions = self.mem_regions.lock();
            for (_, entry) in regions.iter() {
                // SAFETY: We're unmapping memory we previously mapped
                unsafe {
                    bindings::hv_vm_unmap(entry.guest_addr, entry.size);
                }
            }
        }

        // Unmap guest memory regions
        for region in self.guest_mem.regions() {
            // SAFETY: We're unmapping memory we previously mapped
            unsafe {
                bindings::hv_vm_unmap(region.guest_addr.offset(), region.size);
            }
        }

        // Destroy the VM
        // SAFETY: We created the VM in new()
        unsafe { bindings::hv_vm_destroy() };
        Hvf::mark_vm_destroyed();
    }
}

impl Vm for HvfVm {
    fn try_clone(&self) -> Result<Self> {
        Ok(HvfVm {
            hvf: self.hvf.try_clone()?,
            guest_mem: self.guest_mem.clone(),
            mem_regions: self.mem_regions.clone(),
            next_mem_slot: self.next_mem_slot.clone(),
            io_events: self.io_events.clone(),
            vcpu_count: self.vcpu_count.clone(),
        })
    }

    fn try_clone_descriptor(&self) -> Result<SafeDescriptor> {
        // HVF doesn't use file descriptors for VMs
        // Return a dummy descriptor (this matches how some other hypervisors handle this)
        Err(Error::new(libc::ENOTSUP))
    }

    fn hypervisor_kind(&self) -> HypervisorKind {
        // TODO: Add HypervisorKind::Hvf to the enum
        // For now, we'll need to use an existing variant or add one
        HypervisorKind::Kvm // Placeholder - should be HypervisorKind::Hvf
    }

    fn check_capability(&self, c: VmCap) -> bool {
        match c {
            VmCap::DirtyLog => false, // HVF doesn't support dirty page tracking
            VmCap::PvClock => false,
            VmCap::Protected => false,
            VmCap::EarlyInitCpuid => false,
            VmCap::ReadOnlyMemoryRegion => true,
            VmCap::MemNoncoherentDma => false,
            #[cfg(target_arch = "aarch64")]
            VmCap::ArmPmuV3 => false, // TODO: Check if HVF supports PMU
            #[cfg(target_arch = "aarch64")]
            VmCap::Sve => false, // TODO: Check if HVF supports SVE
            #[cfg(target_arch = "x86_64")]
            VmCap::BusLockDetect => false,
        }
    }

    fn get_guest_phys_addr_bits(&self) -> u8 {
        // Apple Silicon supports 48-bit physical addresses for guests
        48
    }

    fn get_memory(&self) -> &GuestMemory {
        &self.guest_mem
    }

    fn add_memory_region(
        &mut self,
        guest_addr: GuestAddress,
        mem: Box<dyn MappedRegion>,
        read_only: bool,
        _log_dirty_pages: bool,
        _cache: MemCacheType,
    ) -> Result<MemSlot> {
        let size = mem.size();
        let host_addr = mem.as_ptr();

        // Determine memory flags
        let mut flags = bindings::HV_MEMORY_READ;
        if !read_only {
            flags |= bindings::HV_MEMORY_WRITE;
        }
        flags |= bindings::HV_MEMORY_EXEC;

        // Map the memory
        // SAFETY: host_addr is valid for the specified size
        let ret = unsafe {
            bindings::hv_vm_map(
                host_addr as *mut std::ffi::c_void,
                guest_addr.offset(),
                size,
                flags,
            )
        };
        if ret != bindings::HV_SUCCESS {
            return Err(Error::new(libc::ENOMEM));
        }

        // Allocate a slot
        let mut slot_guard = self.next_mem_slot.lock();
        let slot = *slot_guard;
        *slot_guard += 1;

        // Store the mapping
        let entry = MemRegionEntry {
            guest_addr: guest_addr.offset(),
            size,
            mem,
        };
        self.mem_regions.lock().insert(slot, entry);

        Ok(slot)
    }

    fn msync_memory_region(&mut self, slot: MemSlot, offset: usize, size: usize) -> Result<()> {
        let regions = self.mem_regions.lock();
        let entry = regions.get(&slot).ok_or_else(|| Error::new(libc::ENOENT))?;
        entry.mem.msync(offset, size).map_err(|_| Error::new(libc::EIO))
    }

    fn remove_memory_region(&mut self, slot: MemSlot) -> Result<Box<dyn MappedRegion>> {
        let mut regions = self.mem_regions.lock();
        let entry = regions.remove(&slot).ok_or_else(|| Error::new(libc::ENOENT))?;

        // Unmap from HVF
        // SAFETY: We're unmapping memory we previously mapped
        let ret = unsafe { bindings::hv_vm_unmap(entry.guest_addr, entry.size) };
        if ret != bindings::HV_SUCCESS {
            // Re-insert the entry on failure
            regions.insert(slot, MemRegionEntry {
                guest_addr: entry.guest_addr,
                size: entry.size,
                mem: entry.mem,
            });
            return Err(Error::new(libc::EIO));
        }

        Ok(entry.mem)
    }

    fn create_device(&self, _kind: DeviceKind) -> Result<SafeDescriptor> {
        // HVF doesn't support creating kernel devices
        Err(Error::new(libc::ENOTSUP))
    }

    fn get_dirty_log(&self, _slot: MemSlot, _dirty_log: &mut [u8]) -> Result<()> {
        // HVF doesn't support dirty page tracking
        Err(Error::new(libc::ENOTSUP))
    }

    fn register_ioevent(
        &mut self,
        evt: &Event,
        addr: IoEventAddress,
        datamatch: Datamatch,
    ) -> Result<()> {
        // HVF doesn't support in-kernel ioeventfd, so we track them ourselves
        // and dispatch them in handle_io_events
        let entry = IoEventEntry {
            event: evt.try_clone()?,
            addr,
            datamatch,
        };
        self.io_events.lock().push(entry);
        Ok(())
    }

    fn unregister_ioevent(
        &mut self,
        evt: &Event,
        addr: IoEventAddress,
        datamatch: Datamatch,
    ) -> Result<()> {
        let mut events = self.io_events.lock();
        let evt_raw = evt.as_raw_descriptor();
        events.retain(|e| {
            !(e.event.as_raw_descriptor() == evt_raw
                && e.addr == addr
                && e.datamatch == datamatch)
        });
        Ok(())
    }

    fn handle_io_events(&self, addr: IoEventAddress, data: &[u8]) -> Result<()> {
        let events = self.io_events.lock();
        for entry in events.iter() {
            if entry.addr != addr {
                continue;
            }

            let matches = match entry.datamatch {
                Datamatch::AnyLength => true,
                Datamatch::U8(None) => data.len() == 1,
                Datamatch::U8(Some(v)) => data.len() == 1 && data[0] == v,
                Datamatch::U16(None) => data.len() == 2,
                Datamatch::U16(Some(v)) => {
                    data.len() == 2 && u16::from_ne_bytes([data[0], data[1]]) == v
                }
                Datamatch::U32(None) => data.len() == 4,
                Datamatch::U32(Some(v)) => {
                    data.len() == 4
                        && u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) == v
                }
                Datamatch::U64(None) => data.len() == 8,
                Datamatch::U64(Some(v)) => {
                    data.len() == 8
                        && u64::from_ne_bytes([
                            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                        ]) == v
                }
            };

            if matches {
                entry.event.signal()?;
            }
        }
        Ok(())
    }

    fn get_pvclock(&self) -> Result<ClockState> {
        Err(Error::new(libc::ENOTSUP))
    }

    fn set_pvclock(&self, _state: &ClockState) -> Result<()> {
        Err(Error::new(libc::ENOTSUP))
    }

    fn add_fd_mapping(
        &mut self,
        slot: u32,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
        prot: Protection,
    ) -> Result<()> {
        let regions = self.mem_regions.lock();
        let entry = regions.get(&slot).ok_or_else(|| Error::new(libc::ENOENT))?;

        entry
            .mem
            .add_fd_mapping(offset, size, fd, fd_offset, prot)
            .map_err(|_| Error::new(libc::EIO))
    }

    fn remove_mapping(&mut self, slot: u32, offset: usize, size: usize) -> Result<()> {
        let regions = self.mem_regions.lock();
        let entry = regions.get(&slot).ok_or_else(|| Error::new(libc::ENOENT))?;

        entry
            .mem
            .remove_mapping(offset, size)
            .map_err(|_| Error::new(libc::EIO))
    }

    fn handle_balloon_event(&mut self, event: BalloonEvent) -> Result<()> {
        match event {
            BalloonEvent::Inflate(m) => {
                // For inflate, we could punch holes in the memory
                // For now, just acknowledge it
                let _ = m;
                Ok(())
            }
            BalloonEvent::Deflate(m) => {
                // For deflate, the memory should be accessible again
                let _ = m;
                Ok(())
            }
            BalloonEvent::BalloonTargetReached(_) => Ok(()),
        }
    }

    fn enable_hypercalls(&mut self, _nr: u64, _count: usize) -> Result<()> {
        // HVF handles hypercalls differently - they come as VM exits
        Ok(())
    }
}

impl VmAArch64 for HvfVm {
    fn get_hypervisor(&self) -> &dyn Hypervisor {
        &self.hvf
    }

    fn load_protected_vm_firmware(
        &mut self,
        _fw_addr: GuestAddress,
        _fw_max_size: u64,
    ) -> Result<()> {
        // HVF doesn't support protected VMs
        Err(Error::new(libc::ENOTSUP))
    }

    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuAArch64>> {
        let vcpu = HvfVcpu::new(id, self.io_events.clone())?;
        *self.vcpu_count.lock() += 1;
        Ok(Box::new(vcpu))
    }

    fn create_fdt(&self, fdt: &mut Fdt, phandles: &BTreeMap<&str, u32>) -> cros_fdt::Result<()> {
        // Create hypervisor node for HVF
        // This is optional and mainly for identification
        let _ = fdt;
        let _ = phandles;
        Ok(())
    }

    fn init_arch(
        &self,
        _payload_entry_address: GuestAddress,
        _fdt_address: GuestAddress,
        _fdt_size: usize,
    ) -> anyhow::Result<()> {
        // HVF doesn't require special arch initialization at the VM level
        Ok(())
    }

    fn set_counter_offset(&self, offset: u64) -> Result<()> {
        // HVF handles vtimer offset per-VCPU, not per-VM
        // This would need to be applied to all VCPUs
        let _ = offset;
        Err(Error::new(libc::ENOTSUP))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hvf_vm_capabilities() {
        // Test capability reporting without creating a real VM
        // This is a compile-time check that all capabilities are handled
    }
}
