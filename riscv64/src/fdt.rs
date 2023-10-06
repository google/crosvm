// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use arch::apply_device_tree_overlays;
use arch::DtbOverlay;
#[cfg(any(target_os = "android", target_os = "linux"))]
use arch::PlatformBusResources;
use cros_fdt::Error;
use cros_fdt::Fdt;
use cros_fdt::Result;
use devices::irqchip::aia_aplic_addr;
use devices::irqchip::aia_imsic_size;
use devices::irqchip::AIA_APLIC_SIZE;
use devices::irqchip::AIA_IMSIC_BASE;
use devices::PciAddress;
use devices::PciInterruptPin;
use rand::rngs::OsRng;
use rand::RngCore;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

// This is the start of DRAM in the physical address space.
use crate::RISCV64_PHYS_MEM_START;

// CPUs are assigned phandles starting with this number.
const PHANDLE_CPU0: u32 = 0x100;

const PHANDLE_AIA_APLIC: u32 = 2;
const PHANDLE_AIA_IMSIC: u32 = 3;
const PHANDLE_CPU_INTC_BASE: u32 = 4;

fn create_memory_node(fdt: &mut Fdt, guest_mem: &GuestMemory) -> Result<()> {
    let mut mem_reg_prop = Vec::new();
    let mut previous_memory_region_end = None;
    let mut regions = guest_mem.guest_memory_regions();
    regions.sort();
    for region in regions {
        // Merge with the previous region if possible.
        if let Some(previous_end) = previous_memory_region_end {
            if region.0 == previous_end {
                *mem_reg_prop.last_mut().unwrap() += region.1 as u64;
                previous_memory_region_end =
                    Some(previous_end.checked_add(region.1 as u64).unwrap());
                continue;
            }
            assert!(region.0 > previous_end, "Memory regions overlap");
        }

        mem_reg_prop.push(region.0.offset());
        mem_reg_prop.push(region.1 as u64);
        previous_memory_region_end = Some(region.0.checked_add(region.1 as u64).unwrap());
    }

    let memory_node = fdt.root_mut().subnode_mut("memory")?;
    memory_node.set_prop("device_type", "memory")?;
    memory_node.set_prop("reg", mem_reg_prop)?;
    Ok(())
}

fn create_cpu_nodes(fdt: &mut Fdt, num_cpus: u32, timebase_frequency: u32) -> Result<()> {
    let cpus_node = fdt.root_mut().subnode_mut("cpus")?;
    cpus_node.set_prop("#address-cells", 0x1u32)?;
    cpus_node.set_prop("#size-cells", 0x0u32)?;
    cpus_node.set_prop("timebase-frequency", timebase_frequency)?;

    for cpu_id in 0..num_cpus {
        let cpu_name = format!("cpu@{:x}", cpu_id);
        let cpu_node = cpus_node.subnode_mut(&cpu_name)?;
        cpu_node.set_prop("device_type", "cpu")?;
        cpu_node.set_prop("compatible", "riscv")?;
        cpu_node.set_prop("mmu-type", "sv48")?;
        cpu_node.set_prop("riscv,isa", "rv64iafdcsu_smaia_ssaia")?;
        cpu_node.set_prop("status", "okay")?;
        cpu_node.set_prop("reg", cpu_id)?;
        cpu_node.set_prop("phandle", PHANDLE_CPU0 + cpu_id)?;

        // Add interrupt controller node
        let intc_node = cpu_node.subnode_mut("interrupt-controller")?;
        intc_node.set_prop("compatible", "riscv,cpu-intc")?;
        intc_node.set_prop("#interrupt-cells", 1u32)?;
        intc_node.set_prop("interrupt-controller", ())?;
        intc_node.set_prop("phandle", PHANDLE_CPU_INTC_BASE + cpu_id)?;
    }
    Ok(())
}

fn create_chosen_node(
    fdt: &mut Fdt,
    cmdline: &str,
    initrd: Option<(GuestAddress, usize)>,
) -> Result<()> {
    let chosen_node = fdt.root_mut().subnode_mut("chosen")?;
    chosen_node.set_prop("linux,pci-probe-only", 1u32)?;
    chosen_node.set_prop("bootargs", cmdline)?;

    let mut kaslr_seed_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut kaslr_seed_bytes);
    let kaslr_seed = u64::from_le_bytes(kaslr_seed_bytes);
    chosen_node.set_prop("kaslr-seed", kaslr_seed)?;

    let mut rng_seed_bytes = [0u8; 256];
    OsRng.fill_bytes(&mut rng_seed_bytes);
    chosen_node.set_prop("rng-seed", &rng_seed_bytes)?;

    if let Some((initrd_addr, initrd_size)) = initrd {
        let initrd_start = initrd_addr.offset();
        let initrd_end = initrd_start + initrd_size as u64;
        chosen_node.set_prop("linux,initrd-start", initrd_start)?;
        chosen_node.set_prop("linux,initrd-end", initrd_end)?;
    }

    Ok(())
}

// num_ids: number of imsic ids from the aia subsystem
// num_sources: number of aplic sources from the aia subsystem
fn create_aia_node(
    fdt: &mut Fdt,
    num_cpus: usize,
    num_ids: usize,
    num_sources: usize,
) -> Result<()> {
    let name = format!("imsics@{:#08x}", AIA_IMSIC_BASE);
    let imsic_node = fdt.root_mut().subnode_mut(&name)?;
    imsic_node.set_prop("compatible", "riscv,imsics")?;

    let regs = [
        0u32,
        AIA_IMSIC_BASE as u32,
        0,
        aia_imsic_size(num_cpus) as u32,
    ];
    imsic_node.set_prop("reg", &regs)?;
    imsic_node.set_prop("#interrupt-cells", 0u32)?;
    imsic_node.set_prop("interrupt-controller", ())?;
    imsic_node.set_prop("msi-controller", ())?;
    imsic_node.set_prop("riscv,num-ids", num_ids as u32)?;
    imsic_node.set_prop("phandle", PHANDLE_AIA_IMSIC)?;

    const S_MODE_EXT_IRQ: u32 = 9;
    let mut cpu_intc_regs: Vec<u32> = Vec::with_capacity(num_cpus * 2);
    for hart in 0..num_cpus {
        cpu_intc_regs.push(PHANDLE_CPU_INTC_BASE + hart as u32);
        cpu_intc_regs.push(S_MODE_EXT_IRQ);
    }
    imsic_node.set_prop("interrupts-extended", cpu_intc_regs)?;

    /* Skip APLIC node if we have no interrupt sources */
    if num_sources > 0 {
        let name = format!("aplic@{:#08x}", aia_aplic_addr(num_cpus));
        let aplic_node = fdt.root_mut().subnode_mut(&name)?;
        aplic_node.set_prop("compatible", "riscv,aplic")?;

        let regs = [0u32, aia_aplic_addr(num_cpus) as u32, 0, AIA_APLIC_SIZE];
        aplic_node.set_prop("reg", &regs)?;
        aplic_node.set_prop("#interrupt-cells", 2u32)?;
        aplic_node.set_prop("interrupt-controller", ())?;
        aplic_node.set_prop("riscv,num-sources", num_sources as u32)?;
        aplic_node.set_prop("phandle", PHANDLE_AIA_APLIC)?;
        aplic_node.set_prop("msi-parent", PHANDLE_AIA_IMSIC)?;
    }

    Ok(())
}

/// PCI host controller address range.
///
/// This represents a single entry in the "ranges" property for a PCI host controller.
///
/// See [PCI Bus Binding to Open Firmware](https://www.openfirmware.info/data/docs/bus.pci.pdf)
/// and https://www.kernel.org/doc/Documentation/devicetree/bindings/pci/host-generic-pci.txt
/// for more information.
#[derive(Copy, Clone)]
pub struct PciRange {
    pub space: PciAddressSpace,
    pub bus_address: u64,
    pub cpu_physical_address: u64,
    pub size: u64,
    pub prefetchable: bool,
}

/// PCI address space.
#[derive(Copy, Clone)]
#[allow(dead_code)]
pub enum PciAddressSpace {
    /// PCI configuration space
    Configuration = 0b00,
    /// I/O space
    Io = 0b01,
    /// 32-bit memory space
    Memory = 0b10,
    /// 64-bit memory space
    Memory64 = 0b11,
}

/// Location of memory-mapped PCI configuration space.
#[derive(Copy, Clone)]
pub struct PciConfigRegion {
    /// Physical address of the base of the memory-mapped PCI configuration region.
    pub base: u64,
    /// Size of the PCI configuration region in bytes.
    pub size: u64,
}

fn create_pci_nodes(
    fdt: &mut Fdt,
    pci_irqs: Vec<(PciAddress, u32, PciInterruptPin)>,
    cfg: PciConfigRegion,
    ranges: &[PciRange],
) -> Result<()> {
    // Add devicetree nodes describing a PCI generic host controller.
    // See Documentation/devicetree/bindings/pci/host-generic-pci.txt in the kernel
    // and "PCI Bus Binding to IEEE Std 1275-1994".
    let ranges: Vec<u32> = ranges
        .iter()
        .flat_map(|r| {
            let ss = r.space as u32;
            let p = r.prefetchable as u32;
            [
                // BUS_ADDRESS(3) encoded as defined in OF PCI Bus Binding
                (ss << 24) | (p << 30),
                (r.bus_address >> 32) as u32,
                r.bus_address as u32,
                // CPU_PHYSICAL(2)
                (r.cpu_physical_address >> 32) as u32,
                r.cpu_physical_address as u32,
                // SIZE(2)
                (r.size >> 32) as u32,
                r.size as u32,
            ]
        })
        .collect();

    let bus_range = [0u32, 0u32]; // Only bus 0
    let reg = [cfg.base, cfg.size];

    const IRQ_TYPE_LEVEL_HIGH: u32 = 0x00000004;
    let mut interrupts: Vec<u32> = Vec::new();
    let mut masks: Vec<u32> = Vec::new();

    for (address, irq_num, irq_pin) in pci_irqs.iter() {
        // PCI_DEVICE(3)
        interrupts.push(address.to_config_address(0, 8));
        interrupts.push(0);
        interrupts.push(0);

        // INT#(1)
        interrupts.push(irq_pin.to_mask() + 1);

        // INTERRUPT INFO
        interrupts.push(PHANDLE_AIA_APLIC);
        interrupts.push(*irq_num);
        interrupts.push(IRQ_TYPE_LEVEL_HIGH);

        // PCI_DEVICE(3)
        masks.push(0xf800); // bits 11..15 (device)
        masks.push(0);
        masks.push(0);

        // INT#(1)
        masks.push(0x7); // allow INTA#-INTD# (1 | 2 | 3 | 4)
    }

    let pci_node = fdt.root_mut().subnode_mut("pci")?;
    pci_node.set_prop("compatible", "pci-host-cam-generic")?;
    pci_node.set_prop("device_type", "pci")?;
    pci_node.set_prop("ranges", ranges)?;
    pci_node.set_prop("bus-range", &bus_range)?;
    pci_node.set_prop("#address-cells", 3u32)?;
    pci_node.set_prop("#size-cells", 2u32)?;
    pci_node.set_prop("reg", &reg)?;
    pci_node.set_prop("#interrupt-cells", 1u32)?;
    pci_node.set_prop("interrupt-map", interrupts)?;
    pci_node.set_prop("interrupt-map-mask", masks)?;
    pci_node.set_prop("msi-parent", PHANDLE_AIA_IMSIC)?;
    pci_node.set_prop("dma-coherent", ())?;
    Ok(())
}

/// Creates a flattened device tree containing all of the parameters for the
/// kernel and loads it into the guest memory at the specified offset.
///
/// # Arguments
///
/// * `fdt_max_size` - The amount of space reserved for the device tree
/// * `guest_mem` - The guest memory object
/// * `pci_irqs` - List of PCI device address to PCI interrupt number and pin mappings
/// * `pci_cfg` - Location of the memory-mapped PCI configuration space.
/// * `pci_ranges` - Memory ranges accessible via the PCI host controller.
/// * `num_cpus` - Number of virtual CPUs the guest will have
/// * `fdt_load_offset` - The offset into physical memory for the device tree
/// * `cmdline` - The kernel commandline
/// * `initrd` - An optional tuple of initrd guest physical address and size
/// * `timebase_frequency` - The time base frequency for the VM.
pub fn create_fdt(
    fdt_max_size: usize,
    guest_mem: &GuestMemory,
    pci_irqs: Vec<(PciAddress, u32, PciInterruptPin)>,
    pci_cfg: PciConfigRegion,
    pci_ranges: &[PciRange],
    #[cfg(any(target_os = "android", target_os = "linux"))] platform_dev_resources: Vec<
        PlatformBusResources,
    >,
    num_cpus: u32,
    fdt_load_offset: u64,
    aia_num_ids: usize,
    aia_num_sources: usize,
    cmdline: &str,
    initrd: Option<(GuestAddress, usize)>,
    timebase_frequency: u32,
    device_tree_overlays: Vec<DtbOverlay>,
) -> Result<()> {
    let mut fdt = Fdt::new(&[]);

    // The whole thing is put into one giant node with some top level properties
    let root_node = fdt.root_mut();
    root_node.set_prop("compatible", "linux,dummy-virt")?;
    root_node.set_prop("#address-cells", 0x2u32)?;
    root_node.set_prop("#size-cells", 0x2u32)?;
    create_chosen_node(&mut fdt, cmdline, initrd)?;
    create_memory_node(&mut fdt, guest_mem)?;
    create_cpu_nodes(&mut fdt, num_cpus, timebase_frequency)?;
    create_aia_node(&mut fdt, num_cpus as usize, aia_num_ids, aia_num_sources)?;
    create_pci_nodes(&mut fdt, pci_irqs, pci_cfg, pci_ranges)?;

    // Done writing base FDT, now apply DT overlays
    apply_device_tree_overlays(
        &mut fdt,
        device_tree_overlays,
        #[cfg(any(target_os = "android", target_os = "linux"))]
        platform_dev_resources,
    )?;

    let fdt_final = fdt.finish()?;
    if fdt_final.len() > fdt_max_size {
        return Err(Error::TotalSizeTooLarge);
    }

    let fdt_address = GuestAddress(RISCV64_PHYS_MEM_START + fdt_load_offset);
    let written = guest_mem
        .write_at_addr(fdt_final.as_slice(), fdt_address)
        .map_err(|_| Error::FdtGuestMemoryWriteError)?;
    if written < fdt_final.len() {
        return Err(Error::FdtGuestMemoryWriteError);
    }

    Ok(())
}
