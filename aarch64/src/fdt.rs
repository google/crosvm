// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use arch::apply_device_tree_overlays;
use arch::fdt::create_memory_node;
use arch::fdt::create_reserved_memory_node;
use arch::fdt::reserved_memory_regions_from_guest_mem;
use arch::fdt::ReservedMemoryRegion;
use arch::serial::SerialDeviceInfo;
use arch::CpuSet;
use arch::DtbOverlay;
#[cfg(any(target_os = "android", target_os = "linux"))]
use arch::PlatformBusResources;
use base::open_file_or_duplicate;
use cros_fdt::Error;
use cros_fdt::Fdt;
use cros_fdt::Result;
// This is a Battery related constant
use devices::bat::GOLDFISHBAT_MMIO_LEN;
use devices::pl030::PL030_AMBA_ID;
use devices::IommuDevType;
use devices::PciAddress;
use devices::PciInterruptPin;
use hypervisor::PsciVersion;
use hypervisor::PSCI_0_2;
use hypervisor::PSCI_1_0;
use rand::rngs::OsRng;
use rand::RngCore;
use resources::AddressRange;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

// These are GIC address-space location constants.
use crate::AARCH64_GIC_CPUI_BASE;
use crate::AARCH64_GIC_CPUI_SIZE;
use crate::AARCH64_GIC_DIST_BASE;
use crate::AARCH64_GIC_DIST_SIZE;
use crate::AARCH64_GIC_ITS_BASE;
use crate::AARCH64_GIC_ITS_SIZE;
use crate::AARCH64_GIC_REDIST_SIZE;
use crate::AARCH64_PMU_IRQ;
// These are RTC related constants
use crate::AARCH64_RTC_ADDR;
use crate::AARCH64_RTC_IRQ;
use crate::AARCH64_RTC_SIZE;
// These are serial device related constants.
use crate::AARCH64_SERIAL_SPEED;
use crate::AARCH64_VIRTFREQ_BASE;
use crate::AARCH64_VIRTFREQ_SIZE;
use crate::AARCH64_VIRTFREQ_V2_SIZE;
use crate::AARCH64_VMWDT_IRQ;

// This is an arbitrary number to specify the node for the GIC.
// If we had a more complex interrupt architecture, then we'd need an enum for
// these.
const PHANDLE_GIC: u32 = 1;
const PHANDLE_GIC_ITS: u32 = 3;
const PHANDLE_RESTRICTED_DMA_POOL: u32 = 2;

// CPUs are assigned phandles starting with this number.
const PHANDLE_CPU0: u32 = 0x100;

const PHANDLE_OPP_DOMAIN_BASE: u32 = 0x1000;

// pKVM pvIOMMUs are assigned phandles starting with this number.
const PHANDLE_PKVM_PVIOMMU: u32 = 0x2000;

// These are specified by the Linux GIC bindings
const GIC_FDT_IRQ_NUM_CELLS: u32 = 3;
const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;
const GIC_FDT_IRQ_PPI_CPU_SHIFT: u32 = 8;
const GIC_FDT_IRQ_PPI_CPU_MASK: u32 = 0xff << GIC_FDT_IRQ_PPI_CPU_SHIFT;
const IRQ_TYPE_EDGE_RISING: u32 = 0x00000001;
const IRQ_TYPE_LEVEL_HIGH: u32 = 0x00000004;
const IRQ_TYPE_LEVEL_LOW: u32 = 0x00000008;

fn create_cpu_nodes(
    fdt: &mut Fdt,
    num_cpus: u32,
    cpu_mpidr_generator: &impl Fn(usize) -> Option<u64>,
    cpu_clusters: Vec<CpuSet>,
    cpu_capacity: BTreeMap<usize, u32>,
    dynamic_power_coefficient: BTreeMap<usize, u32>,
    cpu_frequencies: BTreeMap<usize, Vec<u32>>,
) -> Result<()> {
    let root_node = fdt.root_mut();
    let cpus_node = root_node.subnode_mut("cpus")?;
    cpus_node.set_prop("#address-cells", 0x1u32)?;
    cpus_node.set_prop("#size-cells", 0x0u32)?;

    for cpu_id in 0..num_cpus {
        let reg = u32::try_from(
            cpu_mpidr_generator(cpu_id.try_into().unwrap()).ok_or(Error::PropertyValueInvalid)?,
        )
        .map_err(|_| Error::PropertyValueTooLarge)?;
        let cpu_name = format!("cpu@{:x}", reg);
        let cpu_node = cpus_node.subnode_mut(&cpu_name)?;
        cpu_node.set_prop("device_type", "cpu")?;
        cpu_node.set_prop("compatible", "arm,armv8")?;
        if num_cpus > 1 {
            cpu_node.set_prop("enable-method", "psci")?;
        }
        cpu_node.set_prop("reg", reg)?;
        cpu_node.set_prop("phandle", PHANDLE_CPU0 + cpu_id)?;

        if let Some(pwr_coefficient) = dynamic_power_coefficient.get(&(cpu_id as usize)) {
            cpu_node.set_prop("dynamic-power-coefficient", *pwr_coefficient)?;
        }
        if let Some(capacity) = cpu_capacity.get(&(cpu_id as usize)) {
            cpu_node.set_prop("capacity-dmips-mhz", *capacity)?;
        }
        // Placed inside cpu nodes for ease of parsing for some secure firmwares(PvmFw).
        if let Some(frequencies) = cpu_frequencies.get(&(cpu_id as usize)) {
            cpu_node.set_prop("operating-points-v2", PHANDLE_OPP_DOMAIN_BASE + cpu_id)?;
            let opp_table_node = cpu_node.subnode_mut(&format!("opp_table{}", cpu_id))?;
            opp_table_node.set_prop("phandle", PHANDLE_OPP_DOMAIN_BASE + cpu_id)?;
            opp_table_node.set_prop("compatible", "operating-points-v2")?;
            for freq in frequencies.iter() {
                let opp_hz = (*freq) as u64 * 1000;
                let opp_node = opp_table_node.subnode_mut(&format!("opp{}", opp_hz))?;
                opp_node.set_prop("opp-hz", opp_hz)?;
            }
        }
    }

    if !cpu_clusters.is_empty() {
        let cpu_map_node = cpus_node.subnode_mut("cpu-map")?;
        for (cluster_idx, cpus) in cpu_clusters.iter().enumerate() {
            let cluster_node = cpu_map_node.subnode_mut(&format!("cluster{}", cluster_idx))?;
            for (core_idx, cpu_id) in cpus.iter().enumerate() {
                let core_node = cluster_node.subnode_mut(&format!("core{}", core_idx))?;
                core_node.set_prop("cpu", PHANDLE_CPU0 + *cpu_id as u32)?;
            }
        }
    }

    Ok(())
}

fn create_gic_node(fdt: &mut Fdt, is_gicv3: bool, has_vgic_its: bool, num_cpus: u64) -> Result<()> {
    let mut gic_reg_prop = [AARCH64_GIC_DIST_BASE, AARCH64_GIC_DIST_SIZE, 0, 0];

    let intc_node = fdt.root_mut().subnode_mut("intc")?;
    if is_gicv3 {
        intc_node.set_prop("compatible", "arm,gic-v3")?;
        gic_reg_prop[2] = AARCH64_GIC_DIST_BASE - (AARCH64_GIC_REDIST_SIZE * num_cpus);
        gic_reg_prop[3] = AARCH64_GIC_REDIST_SIZE * num_cpus;
    } else {
        intc_node.set_prop("compatible", "arm,cortex-a15-gic")?;
        gic_reg_prop[2] = AARCH64_GIC_CPUI_BASE;
        gic_reg_prop[3] = AARCH64_GIC_CPUI_SIZE;
    }
    intc_node.set_prop("#interrupt-cells", GIC_FDT_IRQ_NUM_CELLS)?;
    intc_node.set_prop("interrupt-controller", ())?;
    intc_node.set_prop("reg", &gic_reg_prop)?;
    intc_node.set_prop("phandle", PHANDLE_GIC)?;
    intc_node.set_prop("#address-cells", 2u32)?;
    intc_node.set_prop("#size-cells", 2u32)?;

    if has_vgic_its {
        intc_node.set_prop("ranges", ())?;
        let its_node = intc_node.subnode_mut("msic")?;
        its_node.set_prop("compatible", "arm,gic-v3-its")?;
        its_node.set_prop("msi-controller", ())?;
        its_node.set_prop("phandle", PHANDLE_GIC_ITS)?;
        its_node.set_prop("reg", &[AARCH64_GIC_ITS_BASE, AARCH64_GIC_ITS_SIZE])?;
    }

    add_symbols_entry(fdt, "intc", "/intc")?;

    Ok(())
}

fn create_timer_node(fdt: &mut Fdt, num_cpus: u32) -> Result<()> {
    // These are fixed interrupt numbers for the timer device.
    let irqs = [13, 14, 11, 10];
    let compatible = "arm,armv8-timer";
    let cpu_mask: u32 =
        (((1 << num_cpus) - 1) << GIC_FDT_IRQ_PPI_CPU_SHIFT) & GIC_FDT_IRQ_PPI_CPU_MASK;

    let mut timer_reg_cells = Vec::new();
    for &irq in &irqs {
        timer_reg_cells.push(GIC_FDT_IRQ_TYPE_PPI);
        timer_reg_cells.push(irq);
        timer_reg_cells.push(cpu_mask | IRQ_TYPE_LEVEL_LOW);
    }

    let timer_node = fdt.root_mut().subnode_mut("timer")?;
    timer_node.set_prop("compatible", compatible)?;
    timer_node.set_prop("interrupts", timer_reg_cells)?;
    timer_node.set_prop("always-on", ())?;
    Ok(())
}

fn create_virt_cpufreq_node(fdt: &mut Fdt, num_cpus: u64) -> Result<()> {
    // TODO: b/320770346: add compatible string
    let vcf_node = fdt.root_mut().subnode_mut("cpufreq")?;
    let reg = [AARCH64_VIRTFREQ_BASE, AARCH64_VIRTFREQ_SIZE * num_cpus];

    vcf_node.set_prop("reg", &reg)?;
    Ok(())
}

fn create_virt_cpufreq_v2_node(fdt: &mut Fdt, num_cpus: u64) -> Result<()> {
    let compatible = "qemu,virtual-cpufreq";
    let vcf_node = fdt.root_mut().subnode_mut("cpufreq")?;
    let reg = [AARCH64_VIRTFREQ_BASE, AARCH64_VIRTFREQ_V2_SIZE * num_cpus];

    vcf_node.set_prop("compatible", compatible)?;
    vcf_node.set_prop("reg", &reg)?;
    Ok(())
}

fn create_pmu_node(fdt: &mut Fdt, num_cpus: u32) -> Result<()> {
    let compatible = "arm,armv8-pmuv3";
    let cpu_mask: u32 =
        (((1 << num_cpus) - 1) << GIC_FDT_IRQ_PPI_CPU_SHIFT) & GIC_FDT_IRQ_PPI_CPU_MASK;
    let irq = [
        GIC_FDT_IRQ_TYPE_PPI,
        AARCH64_PMU_IRQ,
        cpu_mask | IRQ_TYPE_LEVEL_HIGH,
    ];

    let pmu_node = fdt.root_mut().subnode_mut("pmu")?;
    pmu_node.set_prop("compatible", compatible)?;
    pmu_node.set_prop("interrupts", &irq)?;
    Ok(())
}

fn create_serial_node(fdt: &mut Fdt, addr: u64, size: u64, irq: u32) -> Result<()> {
    let serial_reg_prop = [addr, size];
    let irq = [GIC_FDT_IRQ_TYPE_SPI, irq, IRQ_TYPE_EDGE_RISING];

    let serial_node = fdt
        .root_mut()
        .subnode_mut(&format!("U6_16550A@{:x}", addr))?;
    serial_node.set_prop("compatible", "ns16550a")?;
    serial_node.set_prop("reg", &serial_reg_prop)?;
    serial_node.set_prop("clock-frequency", AARCH64_SERIAL_SPEED)?;
    serial_node.set_prop("interrupts", &irq)?;

    Ok(())
}

fn create_serial_nodes(fdt: &mut Fdt, serial_devices: &[SerialDeviceInfo]) -> Result<()> {
    for dev in serial_devices {
        create_serial_node(fdt, dev.address, dev.size, dev.irq)?;
    }

    Ok(())
}

fn psci_compatible(version: &PsciVersion) -> Vec<&str> {
    // The PSCI kernel driver only supports compatible strings for the following
    // backward-compatible versions.
    let supported = [(PSCI_1_0, "arm,psci-1.0"), (PSCI_0_2, "arm,psci-0.2")];

    let mut compatible: Vec<_> = supported
        .iter()
        .filter(|&(v, _)| *version >= *v)
        .map(|&(_, c)| c)
        .collect();

    // The PSCI kernel driver also supports PSCI v0.1, which is NOT forward-compatible.
    if compatible.is_empty() {
        compatible = vec!["arm,psci"];
    }

    compatible
}

fn create_psci_node(fdt: &mut Fdt, version: &PsciVersion) -> Result<()> {
    let compatible = psci_compatible(version);
    let psci_node = fdt.root_mut().subnode_mut("psci")?;
    psci_node.set_prop("compatible", compatible.as_slice())?;
    // Only support aarch64 guest
    psci_node.set_prop("method", "hvc")?;
    Ok(())
}

fn create_chosen_node(
    fdt: &mut Fdt,
    cmdline: &str,
    initrd: Option<(GuestAddress, usize)>,
    stdout_path: Option<&str>,
) -> Result<()> {
    let chosen_node = fdt.root_mut().subnode_mut("chosen")?;
    chosen_node.set_prop("linux,pci-probe-only", 1u32)?;
    chosen_node.set_prop("bootargs", cmdline)?;
    if let Some(stdout_path) = stdout_path {
        // Used by android bootloader for boot console output
        chosen_node.set_prop("stdout-path", stdout_path)?;
    }

    let mut kaslr_seed_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut kaslr_seed_bytes);
    let kaslr_seed = u64::from_le_bytes(kaslr_seed_bytes);
    chosen_node.set_prop("kaslr-seed", kaslr_seed)?;

    let mut rng_seed_bytes = [0u8; 256];
    OsRng.fill_bytes(&mut rng_seed_bytes);
    chosen_node.set_prop("rng-seed", &rng_seed_bytes)?;

    if let Some((initrd_addr, initrd_size)) = initrd {
        let initrd_start: u64 = initrd_addr.offset();
        let initrd_end: u64 = initrd_start + initrd_size as u64;
        chosen_node.set_prop("linux,initrd-start", initrd_start)?;
        chosen_node.set_prop("linux,initrd-end", initrd_end)?;
    }

    Ok(())
}

fn create_config_node(fdt: &mut Fdt, kernel_region: AddressRange) -> Result<()> {
    let addr: u32 = kernel_region
        .start
        .try_into()
        .map_err(|_| Error::PropertyValueTooLarge)?;
    let size: u32 = kernel_region
        .len()
        .expect("invalid kernel_region")
        .try_into()
        .map_err(|_| Error::PropertyValueTooLarge)?;

    let config_node = fdt.root_mut().subnode_mut("config")?;
    config_node.set_prop("kernel-address", addr)?;
    config_node.set_prop("kernel-size", size)?;
    Ok(())
}

fn create_kvm_cpufreq_node(fdt: &mut Fdt) -> Result<()> {
    let vcf_node = fdt.root_mut().subnode_mut("cpufreq")?;
    vcf_node.set_prop("compatible", "virtual,kvm-cpufreq")?;
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn get_pkvm_pviommu_ids(platform_dev_resources: &Vec<PlatformBusResources>) -> Result<Vec<u32>> {
    let mut ids = HashSet::new();

    for res in platform_dev_resources {
        for iommu in &res.iommus {
            if let (IommuDevType::PkvmPviommu, Some(id), _) = iommu {
                ids.insert(*id);
            }
        }
    }

    Ok(Vec::from_iter(ids))
}

fn create_pkvm_pviommu_node(fdt: &mut Fdt, index: usize, id: u32) -> Result<u32> {
    let name = format!("pviommu{index}");
    let phandle = PHANDLE_PKVM_PVIOMMU
        .checked_add(index.try_into().unwrap())
        .unwrap();

    let iommu_node = fdt.root_mut().subnode_mut(&name)?;
    iommu_node.set_prop("phandle", phandle)?;
    iommu_node.set_prop("#iommu-cells", 1u32)?;
    iommu_node.set_prop("compatible", "pkvm,pviommu")?;
    iommu_node.set_prop("id", id)?;

    Ok(phandle)
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

/// Location of memory-mapped vm watchdog
#[derive(Copy, Clone)]
pub struct VmWdtConfig {
    /// Physical address of the base of the memory-mapped vm watchdog region.
    pub base: u64,
    /// Size of the vm watchdog region in bytes.
    pub size: u64,
    /// The internal clock frequency of the watchdog.
    pub clock_hz: u32,
    /// The expiration timeout measured in seconds.
    pub timeout_sec: u32,
}

fn create_pci_nodes(
    fdt: &mut Fdt,
    pci_irqs: Vec<(PciAddress, u32, PciInterruptPin)>,
    cfg: PciConfigRegion,
    ranges: &[PciRange],
    dma_pool_phandle: Option<u32>,
    msi_parent_phandle: Option<u32>,
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

    let mut interrupts: Vec<u32> = Vec::new();

    for (address, irq_num, irq_pin) in pci_irqs.iter() {
        // PCI_DEVICE(3)
        interrupts.push(address.to_config_address(0, 8));
        interrupts.push(0);
        interrupts.push(0);

        // INT#(1)
        interrupts.push(irq_pin.to_mask() + 1);

        // CONTROLLER(PHANDLE)
        interrupts.push(PHANDLE_GIC);
        interrupts.push(0);
        interrupts.push(0);

        // CONTROLLER_DATA(3)
        interrupts.push(GIC_FDT_IRQ_TYPE_SPI);
        interrupts.push(*irq_num);
        interrupts.push(IRQ_TYPE_LEVEL_HIGH);
    }

    let mask: &[u32] = &[
        // PCI_DEVICE(3)
        0xf800, // bits 11..15 (device)
        0, 0, // mask off other unit address cells
        // INT#(1)
        0x7, // allow INTA#-INTD# (1 | 2 | 3 | 4)
    ];

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
    pci_node.set_prop("interrupt-map-mask", mask)?;
    pci_node.set_prop("dma-coherent", ())?;
    if let Some(dma_pool_phandle) = dma_pool_phandle {
        pci_node.set_prop("memory-region", dma_pool_phandle)?;
    }
    if let Some(msi_parent_phandle) = msi_parent_phandle {
        pci_node.set_prop("msi-parent", msi_parent_phandle)?;
    }
    Ok(())
}

fn create_rtc_node(fdt: &mut Fdt) -> Result<()> {
    // the kernel driver for pl030 really really wants a clock node
    // associated with an AMBA device or it will fail to probe, so we
    // need to make up a clock node to associate with the pl030 rtc
    // node and an associated handle with a unique phandle value.
    const CLK_PHANDLE: u32 = 24;
    let clock_node = fdt.root_mut().subnode_mut("pclk@3M")?;
    clock_node.set_prop("#clock-cells", 0u32)?;
    clock_node.set_prop("compatible", "fixed-clock")?;
    clock_node.set_prop("clock-frequency", 3141592u32)?;
    clock_node.set_prop("phandle", CLK_PHANDLE)?;

    let rtc_name = format!("rtc@{:x}", AARCH64_RTC_ADDR);
    let reg = [AARCH64_RTC_ADDR, AARCH64_RTC_SIZE];
    let irq = [GIC_FDT_IRQ_TYPE_SPI, AARCH64_RTC_IRQ, IRQ_TYPE_LEVEL_HIGH];

    let rtc_node = fdt.root_mut().subnode_mut(&rtc_name)?;
    rtc_node.set_prop("compatible", "arm,primecell")?;
    rtc_node.set_prop("arm,primecell-periphid", PL030_AMBA_ID)?;
    rtc_node.set_prop("reg", &reg)?;
    rtc_node.set_prop("interrupts", &irq)?;
    rtc_node.set_prop("clocks", CLK_PHANDLE)?;
    rtc_node.set_prop("clock-names", "apb_pclk")?;
    Ok(())
}

/// Create a flattened device tree node for Goldfish Battery device.
///
/// # Arguments
///
/// * `fdt` - An Fdt in which the node is created
/// * `mmio_base` - The MMIO base address of the battery
/// * `irq` - The IRQ number of the battery
fn create_battery_node(fdt: &mut Fdt, mmio_base: u64, irq: u32) -> Result<()> {
    let reg = [mmio_base, GOLDFISHBAT_MMIO_LEN];
    let irqs = [GIC_FDT_IRQ_TYPE_SPI, irq, IRQ_TYPE_LEVEL_HIGH];
    let bat_node = fdt.root_mut().subnode_mut("goldfish_battery")?;
    bat_node.set_prop("compatible", "google,goldfish-battery")?;
    bat_node.set_prop("reg", &reg)?;
    bat_node.set_prop("interrupts", &irqs)?;
    Ok(())
}

fn create_vmwdt_node(fdt: &mut Fdt, vmwdt_cfg: VmWdtConfig, num_cpus: u32) -> Result<()> {
    let vmwdt_name = format!("vmwdt@{:x}", vmwdt_cfg.base);
    let reg = [vmwdt_cfg.base, vmwdt_cfg.size];
    let cpu_mask: u32 =
        (((1 << num_cpus) - 1) << GIC_FDT_IRQ_PPI_CPU_SHIFT) & GIC_FDT_IRQ_PPI_CPU_MASK;
    let irq = [
        GIC_FDT_IRQ_TYPE_PPI,
        AARCH64_VMWDT_IRQ,
        cpu_mask | IRQ_TYPE_EDGE_RISING,
    ];

    let vmwdt_node = fdt.root_mut().subnode_mut(&vmwdt_name)?;
    vmwdt_node.set_prop("compatible", "qemu,vcpu-stall-detector")?;
    vmwdt_node.set_prop("reg", &reg)?;
    vmwdt_node.set_prop("clock-frequency", vmwdt_cfg.clock_hz)?;
    vmwdt_node.set_prop("timeout-sec", vmwdt_cfg.timeout_sec)?;
    vmwdt_node.set_prop("interrupts", &irq)?;
    Ok(())
}

// Add a node path to __symbols__ node of the FDT, so it can be referenced by an overlay.
fn add_symbols_entry(fdt: &mut Fdt, symbol: &str, path: &str) -> Result<()> {
    // Ensure the path points to a valid node with a defined phandle
    let Some(target_node) = fdt.get_node(path) else {
        return Err(Error::InvalidPath(format!("{path} does not exist")));
    };
    target_node
        .get_prop::<u32>("phandle")
        .or_else(|| target_node.get_prop("linux,phandle"))
        .ok_or_else(|| Error::InvalidPath(format!("{path} must have a phandle")))?;
    // Add the label -> path mapping.
    let symbols_node = fdt.root_mut().subnode_mut("__symbols__")?;
    symbols_node.set_prop(symbol, path)?;
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
/// * `fdt_address` - The offset into physical memory for the device tree
/// * `cmdline` - The kernel commandline
/// * `initrd` - An optional tuple of initrd guest physical address and size
/// * `android_fstab` - An optional file holding Android fstab entries
/// * `is_gicv3` - True if gicv3, false if v2
/// * `psci_version` - the current PSCI version
/// * `swiotlb` - Reserve a memory pool for DMA. Tuple of base address and size.
/// * `bat_mmio_base_and_irq` - The battery base address and irq number
/// * `vmwdt_cfg` - The virtual watchdog configuration
/// * `dump_device_tree_blob` - Option path to write DTB to
/// * `vm_generator` - Callback to add additional nodes to DTB. create_vm uses Aarch64Vm::create_fdt
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
    cpu_mpidr_generator: &impl Fn(usize) -> Option<u64>,
    cpu_clusters: Vec<CpuSet>,
    cpu_capacity: BTreeMap<usize, u32>,
    cpu_frequencies: BTreeMap<usize, Vec<u32>>,
    fdt_address: GuestAddress,
    cmdline: &str,
    kernel_region: AddressRange,
    initrd: Option<(GuestAddress, usize)>,
    android_fstab: Option<File>,
    is_gicv3: bool,
    has_vgic_its: bool,
    use_pmu: bool,
    psci_version: PsciVersion,
    swiotlb: Option<(Option<GuestAddress>, u64)>,
    bat_mmio_base_and_irq: Option<(u64, u32)>,
    vmwdt_cfg: VmWdtConfig,
    dump_device_tree_blob: Option<PathBuf>,
    vm_generator: &impl Fn(&mut Fdt, &BTreeMap<&str, u32>) -> cros_fdt::Result<()>,
    dynamic_power_coefficient: BTreeMap<usize, u32>,
    device_tree_overlays: Vec<DtbOverlay>,
    serial_devices: &[SerialDeviceInfo],
    virt_cpufreq_v2: bool,
) -> Result<()> {
    let mut fdt = Fdt::new(&[]);
    let mut phandles_key_cache = Vec::new();
    let mut phandles = BTreeMap::new();
    let mut reserved_memory_regions = reserved_memory_regions_from_guest_mem(guest_mem);

    // The whole thing is put into one giant node with some top level properties
    let root_node = fdt.root_mut();
    root_node.set_prop("interrupt-parent", PHANDLE_GIC)?;
    phandles.insert("intc", PHANDLE_GIC);
    root_node.set_prop("compatible", "linux,dummy-virt")?;
    root_node.set_prop("#address-cells", 0x2u32)?;
    root_node.set_prop("#size-cells", 0x2u32)?;
    if let Some(android_fstab) = android_fstab {
        arch::android::create_android_fdt(&mut fdt, android_fstab)?;
    }
    let stdout_path = serial_devices
        .first()
        .map(|first_serial| format!("/U6_16550A@{:x}", first_serial.address));
    create_chosen_node(&mut fdt, cmdline, initrd, stdout_path.as_deref())?;
    create_config_node(&mut fdt, kernel_region)?;
    create_memory_node(&mut fdt, guest_mem)?;

    let dma_pool_phandle = if let Some((swiotlb_addr, swiotlb_size)) = swiotlb {
        let phandle = PHANDLE_RESTRICTED_DMA_POOL;
        reserved_memory_regions.push(ReservedMemoryRegion {
            address: swiotlb_addr,
            size: swiotlb_size,
            phandle: Some(phandle),
            name: "restricted_dma_reserved",
            compatible: Some("restricted-dma-pool"),
            alignment: Some(base::pagesize() as u64),
            no_map: false,
        });
        phandles.insert("restricted_dma_reserved", phandle);
        Some(phandle)
    } else {
        None
    };

    create_reserved_memory_node(&mut fdt, &reserved_memory_regions)?;

    create_cpu_nodes(
        &mut fdt,
        num_cpus,
        cpu_mpidr_generator,
        cpu_clusters,
        cpu_capacity,
        dynamic_power_coefficient,
        cpu_frequencies.clone(),
    )?;
    create_gic_node(&mut fdt, is_gicv3, has_vgic_its, num_cpus as u64)?;
    create_timer_node(&mut fdt, num_cpus)?;
    if use_pmu {
        create_pmu_node(&mut fdt, num_cpus)?;
    }
    create_serial_nodes(&mut fdt, serial_devices)?;
    create_psci_node(&mut fdt, &psci_version)?;
    create_pci_nodes(
        &mut fdt,
        pci_irqs,
        pci_cfg,
        pci_ranges,
        dma_pool_phandle,
        has_vgic_its.then_some(PHANDLE_GIC_ITS),
    )?;
    create_rtc_node(&mut fdt)?;
    if let Some((bat_mmio_base, bat_irq)) = bat_mmio_base_and_irq {
        create_battery_node(&mut fdt, bat_mmio_base, bat_irq)?;
    }
    create_vmwdt_node(&mut fdt, vmwdt_cfg, num_cpus)?;
    create_kvm_cpufreq_node(&mut fdt)?;
    vm_generator(&mut fdt, &phandles)?;
    if !cpu_frequencies.is_empty() {
        if virt_cpufreq_v2 {
            create_virt_cpufreq_v2_node(&mut fdt, num_cpus as u64)?;
        } else {
            create_virt_cpufreq_node(&mut fdt, num_cpus as u64)?;
        }
    }

    let pviommu_ids = get_pkvm_pviommu_ids(&platform_dev_resources)?;

    let cache_offset = phandles_key_cache.len();
    // Hack to extend the lifetime of the Strings as keys of phandles (i.e. &str).
    phandles_key_cache.extend(pviommu_ids.iter().map(|id| format!("pviommu{id}")));
    let pviommu_phandle_keys = &phandles_key_cache[cache_offset..];

    for (index, (id, key)) in pviommu_ids.iter().zip(pviommu_phandle_keys).enumerate() {
        let phandle = create_pkvm_pviommu_node(&mut fdt, index, *id)?;
        phandles.insert(key, phandle);
    }

    // Done writing base FDT, now apply DT overlays
    apply_device_tree_overlays(
        &mut fdt,
        device_tree_overlays,
        #[cfg(any(target_os = "android", target_os = "linux"))]
        platform_dev_resources,
        #[cfg(any(target_os = "android", target_os = "linux"))]
        &phandles,
    )?;

    let fdt_final = fdt.finish()?;

    if let Some(file_path) = dump_device_tree_blob {
        let mut fd = open_file_or_duplicate(
            &file_path,
            OpenOptions::new()
                .read(true)
                .create(true)
                .truncate(true)
                .write(true),
        )
        .map_err(|e| Error::FdtIoError(e.into()))?;
        fd.write_all(&fdt_final)
            .map_err(|e| Error::FdtDumpIoError(e, file_path.clone()))?;
    }

    if fdt_final.len() > fdt_max_size {
        return Err(Error::TotalSizeTooLarge);
    }

    let written = guest_mem
        .write_at_addr(fdt_final.as_slice(), fdt_address)
        .map_err(|_| Error::FdtGuestMemoryWriteError)?;
    if written < fdt_final.len() {
        return Err(Error::FdtGuestMemoryWriteError);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psci_compatible_v0_1() {
        assert_eq!(
            psci_compatible(&PsciVersion::new(0, 1).unwrap()),
            vec!["arm,psci"]
        );
    }

    #[test]
    fn psci_compatible_v0_2() {
        assert_eq!(
            psci_compatible(&PsciVersion::new(0, 2).unwrap()),
            vec!["arm,psci-0.2"]
        );
    }

    #[test]
    fn psci_compatible_v0_5() {
        // Only the 0.2 version supported by the kernel should be added.
        assert_eq!(
            psci_compatible(&PsciVersion::new(0, 5).unwrap()),
            vec!["arm,psci-0.2"]
        );
    }

    #[test]
    fn psci_compatible_v1_0() {
        // Both 1.0 and 0.2 should be listed, in that order.
        assert_eq!(
            psci_compatible(&PsciVersion::new(1, 0).unwrap()),
            vec!["arm,psci-1.0", "arm,psci-0.2"]
        );
    }

    #[test]
    fn psci_compatible_v1_5() {
        // Only the 1.0 and 0.2 versions supported by the kernel should be listed.
        assert_eq!(
            psci_compatible(&PsciVersion::new(1, 5).unwrap()),
            vec!["arm,psci-1.0", "arm,psci-0.2"]
        );
    }

    #[test]
    fn symbols_entries() {
        const TEST_SYMBOL: &str = "dev";
        const TEST_PATH: &str = "/dev";

        let mut fdt = Fdt::new(&[]);
        add_symbols_entry(&mut fdt, TEST_SYMBOL, TEST_PATH).expect_err("missing node");

        fdt.root_mut().subnode_mut(TEST_SYMBOL).unwrap();
        add_symbols_entry(&mut fdt, TEST_SYMBOL, TEST_PATH).expect_err("missing phandle");

        let intc_node = fdt.get_node_mut(TEST_PATH).unwrap();
        intc_node.set_prop("phandle", 1u32).unwrap();
        add_symbols_entry(&mut fdt, TEST_SYMBOL, TEST_PATH).expect("valid path");

        let symbols = fdt.get_node("/__symbols__").unwrap();
        assert_eq!(symbols.get_prop::<String>(TEST_SYMBOL).unwrap(), TEST_PATH);
    }
}
