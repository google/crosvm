# Memory Layout

## x86-64 guest physical memory map

This is a survey of the existing memory layout for crosvm on x86-64 when booting a Linux kernel. Some of these values are different when booting a BIOS image;
see the source. All addresses are in hexadecimal.

| Name/source link             | Address       | End (exclusive) | Size      | Notes                                                                                    |
| ---------------------------- | ------------- | --------------- | --------- | ---------------------------------------------------------------------------------------- |
| [`START_OF_RAM_32BITS`]      | `0000`        |                 |           | RAM                                                                                      |
| [`ZERO_PAGE_OFFSET`]         | `7000`        |                 |           | Linux boot_params structure                                                              |
| [`BOOT_STACK_POINTER`]       | `8000`        |                 |           | Boot SP value                                                                            |
| [`boot_pml4_addr`]           | `9000`        |                 |           | Boot page table                                                                          |
| [`boot_pdpte_addr`]          | `A000`        |                 |           | Boot page table                                                                          |
| [`boot_pde_addr`]            | `B000`        |                 |           | Boot page table                                                                          |
| [`CMDLINE_OFFSET`]           | `2_0000`      | `2_0800`        | 2 KiB     | Linux kernel command line                                                                |
| [`SETUP_DATA_START`]         | `2_0800`      | `E_0000`        | 766 KiB   | Linux kernel `setup_data` linked list                                                    |
| [`ACPI_HI_RSDP_WINDOW_BASE`] | `E_0000`      |                 |           | ACPI tables                                                                              |
| [`KERNEL_START_OFFSET`]      | `20_0000`     |                 |           | Linux kernel image load address                                                          |
| [`initrd_start`]             | after kernel  |                 |           | Initial RAM disk for Linux kernel (optional)                                             |
| [`END_ADDR_BEFORE_32BITS`]   | after initrd  | `D000_0000`     | ~3.24 GiB | RAM (\<4G)                                                                               |
| [`END_ADDR_BEFORE_32BITS`]   | `D000_0000`   | `F400_0000`     | 576 MiB   | Low (\<4G) MMIO allocation area                                                          |
| [`PCIE_CFG_MMIO_START`]      | `F400_0000`   | `F800_0000`     | 64 MiB    | PCIe enhanced config (ECAM)                                                              |
| [`RESERVED_MEM_SIZE`]        | `F800_0000`   | `1_0000_0000`   | 128 MiB   | LAPIC/IOAPIC/HPET/…                                                                      |
| [`IDENTITY_MAP_ADDR`]        | `FEFF_C000`   |                 |           | Identity map segment                                                                     |
| [`TSS_ADDR`]                 | `FEFF_D000`   |                 |           | Boot task state segment                                                                  |
|                              | `1_0000_0000` |                 |           | RAM (>4G)                                                                                |
|                              | (end of RAM)  |                 |           | High (>4G) MMIO allocation area                                                          |

[`start_of_ram_32bits`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=335?q=START_OF_RAM_32BITS
[`zero_page_offset`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=338?q=ZERO_PAGE_OFFSET
[`boot_stack_pointer`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=332?q=BOOT_STACK_POINTER
[`boot_pml4_addr`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/regs.rs;l=299?q=boot_pml4_addr
[`boot_pdpte_addr`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/regs.rs;l=300?q=boot_pdpte_addr
[`boot_pde_addr`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/regs.rs;l=301?q=boot_pde_addr
[`cmdline_offset`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=342?q=CMDLINE_OFFSET
[`setup_data_start`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=344?q=SETUP_DATA_START
[`acpi_hi_rsdp_window_base`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=357?q=ACPI_HI_RSDP_WINDOW_BASE
[`kernel_start_offset`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=341?q=KERNEL_START_OFFSET
[`initrd_start`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=1633?q=initrd_start
[`end_addr_before_32bits`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=230?q=END_ADDR_BEFORE_32BITS
[`pcie_cfg_mmio_start`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=400?q=PCIE_CFG_MMIO_START
[`reserved_mem_size`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=395?q=RESERVED_MEM_SIZE
[`identity_map_addr`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=339?q=identity_map_addr_start
[`tss_addr`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=339?q=tss_addr_start

## aarch64 guest physical memory map

All addresses are IPA in hexadecimal.

### Common layout

These apply for all boot modes.

| Name/source link                  | Address         | End (exclusive) | Size           | Notes                                                         |
| --------------------------------- | --------------- | --------------- | ----------     | ------------------------------------------------------------- |
| [`SERIAL_ADDR[3]`][serial_addr]   | `2e8`           | `2f0`           | 8 bytes        | Serial port MMIO                                              |
| [`SERIAL_ADDR[1]`][serial_addr]   | `2f8`           | `300`           | 8 bytes        | Serial port MMIO                                              |
| [`SERIAL_ADDR[2]`][serial_addr]   | `3e8`           | `3f0`           | 8 bytes        | Serial port MMIO                                              |
| [`SERIAL_ADDR[0]`][serial_addr]   | `3f8`           | `400`           | 8 bytes        | Serial port MMIO                                              |
| [`AARCH64_RTC_ADDR`]              | `2000`          | `3000`          | 4 KiB          | Real-time clock                                               |
| [`AARCH64_VMWDT_ADDR`]            | `3000`          | `4000`          | 4 KiB          | Watchdog device                                               |
| [`AARCH64_PCI_CFG_BASE`]          | `1_0000`        | `2_0000`        | 64 KiB         | PCI configuration (CAM)                                       |
| [`AARCH64_VIRTFREQ_BASE`]         | `104_0000`      | `105_0000`      | 64 KiB         | Virtual cpufreq device                                        |
| [`AARCH64_PVTIME_IPA_START`]      | `1f0_0000`      | `200_0000`      | 64 KiB         | Paravirtualized time                                          |
| [`AARCH64_MMIO_BASE`]             | `200_0000`      | `400_0000`      | 32 MiB         | Low MMIO allocation area                                      |
| [`AARCH64_GIC_CPUI_BASE`]         | `3ffd_0000`     | `3fff_0000`     | 128 KiB        | vGIC                                                          |
| [`AARCH64_GIC_DIST_BASE`]         | `3fff_0000`     | `4000_0000`     | 64 KiB         | vGIC                                                          |
| [`AARCH64_AXI_BASE`]              | `4000_0000`     |                 |                | Seemingly unused? Is this hard-coded somewhere in the kernel? |
| [`AARCH64_PROTECTED_VM_FW_START`] | `7fc0_0000`     | `8000_0000`     | 4 MiB          | pVM firmware (if running a protected VM)                      |
| [`AARCH64_PHYS_MEM_START`]        | `8000_0000`     |                 | --mem size     | RAM (starts at IPA = 2 GiB)                                   |
| [`get_swiotlb_addr`]              | after RAM       |                 | --swiotlb size | Only present for hypervisors requiring static swiotlb alloc   |
| [`plat_mmio_base`]                | after swiotlb   | +0x800000       | 8 MiB          | Platform device MMIO region                                   |
| [`high_mmio_base`]                | after plat_mmio | max phys addr   |                | High MMIO allocation area                                     |

### Layout when booting a kernel

These apply when no bootloader is passed, so crosvm boots a kernel directly.

| Name/source link          | Address           | End (exclusive) | Size  | Notes                        |
| ------------------------- | ----------------- | --------------- | ----- | ---------------------------- |
| [`AARCH64_KERNEL_OFFSET`] | `8000_0000`       |                 |       | Kernel load location in RAM  |
| [`initrd_addr`]           | after kernel      |                 |       | Linux initrd location in RAM |
| [`fdt_address`]           | before end of RAM |                 | 2 MiB | Flattened device tree in RAM |

### Layout when booting a bootloader

These apply when a bootloader is passed with `--bios`.

| Name/source link                    | Address     | End (exclusive) | Size  | Notes                        |
| ----------------------------------- | ----------- | --------------- | ----- | ---------------------------- |
| [`AARCH64_FDT_OFFSET_IN_BIOS_MODE`] | `8000_0000` | `8020_0000`     | 2 MiB | Flattened device tree in RAM |
| [`AARCH64_BIOS_OFFSET`]             | `8020_0000` |                 |       | Bootloader image in RAM      |

[serial_addr]: https://crsrc.org/o/src/platform/crosvm/arch/src/serial.rs;l=78?q=SERIAL_ADDR
[`aarch64_rtc_addr`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=177?q=AARCH64_RTC_ADDR
[`aarch64_vmwdt_addr`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=187?q=AARCH64_VMWDT_ADDR
[`aarch64_pci_cfg_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=192?q=AARCH64_PCI_CFG_BASE
[`aarch64_virtfreq_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=207?q=AARCH64_VIRTFREQ_BASE
[`aarch64_mmio_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=196?q=AARCH64_MMIO_BASE
[`aarch64_gic_cpui_base`]: https://crsrc.org/o/src/platform/crosvm/devices/src/irqchip/kvm/aarch64.rs;l=106?q=AARCH64_GIC_CPUI_BASE
[`aarch64_gic_dist_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=105?q=AARCH64_GIC_DIST_BASE
[`aarch64_axi_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=86?q=AARCH64_AXI_BASE
[`aarch64_pvtime_ipa_start`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=100?q=AARCH64_PVTIME_IPA_START
[`aarch64_protected_vm_fw_start`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=96?q=AARCH64_PROTECTED_VM_FW_START
[`aarch64_phys_mem_start`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=85?q=AARCH64_PHYS_MEM_START
[`get_swiotlb_addr`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs?q=get_swiotlb_addr
[`plat_mmio_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=835?q=plat_mmio_base
[`high_mmio_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=838?q=high_mmio_base
[`aarch64_kernel_offset`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=76?q=AARCH64_KERNEL_OFFSET
[`initrd_addr`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=409?q=initrd_addr
[`fdt_address`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=301?q=fdt_address
[`aarch64_fdt_offset_in_bios_mode`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=90?q=AARCH64_FDT_OFFSET_IN_BIOS_MODE
[`aarch64_bios_offset`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=92?q=AARCH64_BIOS_OFFSET
