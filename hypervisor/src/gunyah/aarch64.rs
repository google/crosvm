// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

use base::error;
use base::Error;
use base::Result;
use cros_fdt::Fdt;
use cros_fdt::FdtNode;
use libc::ENOENT;
use libc::ENOTSUP;
use vm_memory::GuestAddress;
use vm_memory::MemoryRegionPurpose;

use super::GunyahVcpu;
use super::GunyahVm;
use crate::Hypervisor;
use crate::PsciVersion;
use crate::VcpuAArch64;
use crate::VcpuRegAArch64;
use crate::VmAArch64;
use crate::PSCI_0_2;

const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;

const IRQ_TYPE_EDGE_RISING: u32 = 0x00000001;
const IRQ_TYPE_LEVEL_HIGH: u32 = 0x00000004;

fn fdt_create_shm_device(
    parent: &mut FdtNode,
    index: u32,
    guest_addr: GuestAddress,
) -> cros_fdt::Result<()> {
    let shm_name = format!("shm-{:x}", index);
    let shm_node = parent.subnode_mut(&shm_name)?;
    shm_node.set_prop("vdevice-type", "shm")?;
    shm_node.set_prop("peer-default", ())?;
    shm_node.set_prop("dma_base", 0u64)?;
    let mem_node = shm_node.subnode_mut("memory")?;
    mem_node.set_prop("label", index)?;
    mem_node.set_prop("#address-cells", 2u32)?;
    mem_node.set_prop("base", guest_addr.offset())
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

    fn create_fdt(&self, fdt: &mut Fdt, phandles: &BTreeMap<&str, u32>) -> cros_fdt::Result<()> {
        let top_node = fdt.root_mut().subnode_mut("gunyah-vm-config")?;

        top_node.set_prop("image-name", "crosvm-vm")?;
        top_node.set_prop("os-type", "linux")?;

        let memory_node = top_node.subnode_mut("memory")?;
        memory_node.set_prop("#address-cells", 2u32)?;
        memory_node.set_prop("#size-cells", 2u32)?;

        let mut base_set = false;
        let mut firmware_set = false;
        for region in self.guest_mem.regions() {
            match region.options.purpose {
                MemoryRegionPurpose::GuestMemoryRegion => {
                    // Assume first GuestMemoryRegion contains the payload
                    if !base_set {
                        base_set = true;
                        memory_node.set_prop("base-address", region.guest_addr.offset())?;
                    }
                }
                MemoryRegionPurpose::ProtectedFirmwareRegion => {
                    if firmware_set {
                        // Should only have one protected firmware memory region.
                        error!("Multiple ProtectedFirmwareRegions unexpected.");
                        unreachable!()
                    }
                    firmware_set = true;
                    memory_node.set_prop("firmware-address", region.guest_addr.offset())?;
                }
                _ => {}
            }
        }

        let interrupts_node = top_node.subnode_mut("interrupts")?;
        interrupts_node.set_prop("config", *phandles.get("intc").unwrap())?;

        let vcpus_node = top_node.subnode_mut("vcpus")?;
        vcpus_node.set_prop("affinity", "proxy")?;

        let vdev_node = top_node.subnode_mut("vdevices")?;
        vdev_node.set_prop("generate", "/hypervisor")?;

        for irq in self.routes.lock().iter() {
            let bell_name = format!("bell-{:x}", irq.irq);
            let bell_node = vdev_node.subnode_mut(&bell_name)?;
            bell_node.set_prop("vdevice-type", "doorbell")?;
            let path_name = format!("/hypervisor/bell-{:x}", irq.irq);
            bell_node.set_prop("generate", path_name)?;
            bell_node.set_prop("label", irq.irq)?;
            bell_node.set_prop("peer-default", ())?;
            bell_node.set_prop("source-can-clear", ())?;

            let interrupt_type = if irq.level {
                IRQ_TYPE_LEVEL_HIGH
            } else {
                IRQ_TYPE_EDGE_RISING
            };
            let interrupts = [GIC_FDT_IRQ_TYPE_SPI, irq.irq, interrupt_type];
            bell_node.set_prop("interrupts", &interrupts)?;
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
                fdt_create_shm_device(
                    vdev_node,
                    region.index.try_into().unwrap(),
                    region.guest_addr,
                )?;
            }
        }

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

    fn set_vector_reg(&self, _reg_num: u8, _data: u128) -> Result<()> {
        unimplemented!()
    }

    fn get_vector_reg(&self, _reg_num: u8) -> Result<u128> {
        unimplemented!()
    }

    fn get_psci_version(&self) -> Result<PsciVersion> {
        Ok(PSCI_0_2)
    }

    #[cfg(feature = "gdb")]
    fn set_guest_debug(&self, _addrs: &[GuestAddress], _enable_singlestep: bool) -> Result<()> {
        Err(Error::new(ENOTSUP))
    }

    #[cfg(feature = "gdb")]
    fn get_max_hw_bps(&self) -> Result<usize> {
        Err(Error::new(ENOTSUP))
    }
}
