// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

use cros_fdt::FdtWriter;
use libc::ENOENT;
use libc::ENOTSUP;
use vm_memory::GuestAddress;
use vm_memory::MemoryRegionPurpose;

use base::error;
use base::Error;
use base::Result;

use crate::Hypervisor;
use crate::PsciVersion;
use crate::VcpuAArch64;
use crate::VcpuRegAArch64;
use crate::VmAArch64;
use crate::PSCI_0_2;

use super::GunyahVcpu;
use super::GunyahVm;

const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;

const IRQ_TYPE_EDGE_RISING: u32 = 0x00000001;
const IRQ_TYPE_LEVEL_HIGH: u32 = 0x00000004;

fn fdt_create_shm_device(
    fdt: &mut FdtWriter,
    index: u32,
    guest_addr: GuestAddress,
) -> cros_fdt::Result<()> {
    let shm_name = format!("shm-{:x}", index);
    let shm_node = fdt.begin_node(&shm_name)?;
    fdt.property_string("vdevice-type", "shm")?;
    fdt.property_null("peer-default")?;
    fdt.property_u64("dma_base", 0)?;
    let mem_node = fdt.begin_node("memory")?;
    fdt.property_u32("label", index)?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u64("base", guest_addr.offset())?;
    fdt.end_node(mem_node)?;
    fdt.end_node(shm_node)
}

impl VmAArch64 for GunyahVm {
    fn get_hypervisor(&self) -> &dyn Hypervisor {
        &self.gh
    }

    fn load_protected_vm_firmware(
        &mut self,
        fw_addr: GuestAddress,
        fw_max_size: u64,
    ) -> Result<()> {
        self.set_protected_vm_firmware_ipa(fw_addr, fw_max_size)
    }

    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuAArch64>> {
        Ok(Box::new(GunyahVm::create_vcpu(self, id)?))
    }

    fn create_fdt(
        &self,
        fdt: &mut FdtWriter,
        phandles: &BTreeMap<&str, u32>,
    ) -> cros_fdt::Result<()> {
        let top_node = fdt.begin_node("gunyah-vm-config")?;

        fdt.property_string("image-name", "crosvm-vm")?;
        fdt.property_string("os-type", "linux")?;

        let memory_node = fdt.begin_node("memory")?;
        fdt.property_u32("#address-cells", 2)?;
        fdt.property_u32("#size-cells", 2)?;

        let mut base_set = false;
        let mut firmware_set = false;
        for region in self.guest_mem.regions() {
            match region.options.purpose {
                MemoryRegionPurpose::GuestMemoryRegion => {
                    // Assume first GuestMemoryRegion contains the payload
                    if !base_set {
                        base_set = true;
                        fdt.property_u64("base-address", region.guest_addr.offset())?;
                    }
                }
                MemoryRegionPurpose::ProtectedFirmwareRegion => {
                    if firmware_set {
                        // Should only have one protected firmware memory region.
                        error!("Multiple ProtectedFirmwareRegions unexpected.");
                        unreachable!()
                    }
                    firmware_set = true;
                    fdt.property_u64("firmware-address", region.guest_addr.offset())?;
                }
                _ => {}
            }
        }

        fdt.end_node(memory_node)?;

        let interrupts_node = fdt.begin_node("interrupts")?;
        fdt.property_u32("config", *phandles.get("intc").unwrap())?;
        fdt.end_node(interrupts_node)?;

        let vcpus_node = fdt.begin_node("vcpus")?;
        fdt.property_string("affinity", "proxy")?;
        fdt.end_node(vcpus_node)?;

        let vdev_node = fdt.begin_node("vdevices")?;
        fdt.property_string("generate", "/hypervisor")?;
        for irq in self.routes.lock().iter() {
            let bell_name = format!("bell-{:x}", irq.irq);
            let bell_node = fdt.begin_node(&bell_name)?;
            fdt.property_string("vdevice-type", "doorbell")?;
            let path_name = format!("/hypervisor/bell-{:x}", irq.irq);
            fdt.property_string("generate", &path_name)?;
            fdt.property_u32("label", irq.irq)?;
            fdt.property_null("peer-default")?;
            fdt.property_null("source-can-clear")?;

            let interrupt_type = if irq.level {
                IRQ_TYPE_LEVEL_HIGH
            } else {
                IRQ_TYPE_EDGE_RISING
            };
            let interrupts = [GIC_FDT_IRQ_TYPE_SPI, irq.irq, interrupt_type];
            fdt.property_array_u32("interrupts", &interrupts)?;
            fdt.end_node(bell_node)?;
        }

        let mut base_set = false;
        for region in self.guest_mem.regions() {
            let create_shm_node = match region.options.purpose {
                MemoryRegionPurpose::GuestMemoryRegion => {
                    // Assume first GuestMemoryRegion contains the payload
                    // This memory region is described by the "base-address" property
                    // and doesn't get re-described as a separate shm node.
                    let ret = base_set;
                    base_set = true;
                    ret
                }
                // Described by the "firmware-address" property
                MemoryRegionPurpose::ProtectedFirmwareRegion => false,
                MemoryRegionPurpose::StaticSwiotlbRegion => true,
            };

            if create_shm_node {
                fdt_create_shm_device(fdt, region.index.try_into().unwrap(), region.guest_addr)?;
            }
        }

        fdt.end_node(vdev_node)?;

        fdt.end_node(top_node)?;

        Ok(())
    }

    fn init_arch(
        &self,
        payload_entry_address: GuestAddress,
        fdt_address: GuestAddress,
        fdt_size: usize,
    ) -> Result<()> {
        // Gunyah initializes the PC to be the payload entry (except for protected VMs)
        // and assumes that the image is loaded at the beginning of the "primary"
        // memory parcel (region). This parcel contains both DTB and kernel Image, so
        // make sure that DTB and payload are in the same memory region and that
        // payload is at the start of that region.

        let (dtb_mapping, _, dtb_obj_offset) = self
            .guest_mem
            .find_region(fdt_address)
            .map_err(|_| Error::new(ENOENT))?;
        let (payload_mapping, payload_offset, payload_obj_offset) = self
            .guest_mem
            .find_region(payload_entry_address)
            .map_err(|_| Error::new(ENOENT))?;

        if !std::ptr::eq(dtb_mapping, payload_mapping) || dtb_obj_offset != payload_obj_offset {
            panic!("DTB and payload are not part of same memory region.");
        }

        if payload_offset != 0 {
            panic!("Payload offset must be zero");
        }

        self.set_dtb_config(fdt_address, fdt_size)?;

        self.start()?;

        Ok(())
    }
}

impl VcpuAArch64 for GunyahVcpu {
    fn init(&self, _features: &[crate::VcpuFeature]) -> Result<()> {
        Ok(())
    }

    fn init_pmu(&self, _irq: u64) -> Result<()> {
        Err(Error::new(ENOTSUP))
    }

    fn has_pvtime_support(&self) -> bool {
        false
    }

    fn init_pvtime(&self, _pvtime_ipa: u64) -> Result<()> {
        Err(Error::new(ENOTSUP))
    }

    fn set_one_reg(&self, _reg_id: VcpuRegAArch64, _data: u64) -> Result<()> {
        unimplemented!()
    }

    fn get_one_reg(&self, _reg_id: VcpuRegAArch64) -> Result<u64> {
        Err(Error::new(ENOTSUP))
    }

    fn get_psci_version(&self) -> Result<PsciVersion> {
        Ok(PSCI_0_2)
    }

    #[cfg(feature = "gdb")]
    fn set_guest_debug(&self, _addrs: &[GuestAddress], _enable_singlestep: bool) -> Result<()> {
        Err(Error::new(ENOTSUP))
    }

    #[cfg(feature = "gdb")]
    fn set_gdb_registers(
        &self,
        _regs: &<gdbstub_arch::aarch64::AArch64 as gdbstub::arch::Arch>::Registers,
    ) -> Result<()> {
        Err(Error::new(ENOTSUP))
    }

    #[cfg(feature = "gdb")]
    fn get_gdb_registers(
        &self,
        _regs: &mut <gdbstub_arch::aarch64::AArch64 as gdbstub::arch::Arch>::Registers,
    ) -> Result<()> {
        Err(Error::new(ENOTSUP))
    }

    #[cfg(feature = "gdb")]
    fn get_max_hw_bps(&self) -> Result<usize> {
        Err(Error::new(ENOTSUP))
    }

    #[cfg(feature = "gdb")]
    fn set_gdb_register(
        &self,
        _reg: <gdbstub_arch::aarch64::AArch64 as gdbstub::arch::Arch>::RegId,
        _data: &[u8],
    ) -> Result<()> {
        Err(Error::new(ENOTSUP))
    }

    #[cfg(feature = "gdb")]
    fn get_gdb_register(
        &self,
        _reg: <gdbstub_arch::aarch64::AArch64 as gdbstub::arch::Arch>::RegId,
        _data: &mut [u8],
    ) -> Result<usize> {
        Err(Error::new(ENOTSUP))
    }
}
