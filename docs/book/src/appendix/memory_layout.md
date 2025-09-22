# Memory Layout

## x86-64 guest physical memory map

This is a survey of the existing memory layout for crosvm on x86-64 when booting a Linux kernel. Some of these values are different when booting a BIOS image;
see the source. All addresses are in hexadecimal.

| Name/source link             | Address       | End (exclusive) | Size      | Notes                                                                                    |
| ---------------------------- | ------------- | --------------- | --------- | ---------------------------------------------------------------------------------------- |
|                              | `0000`        | `A_0000`        | 640 KiB   | RAM (\<1M)                                                                               |
| [`MULTIBOOT_INFO_OFFSET`]    | `6000`        | `7000`          | 4 KiB     | Multiboot info structure                                                                 |
| [`ZERO_PAGE_OFFSET`]         | `7000`        |                 |           | Linux boot_params structure                                                              |
| [`BOOT_STACK_POINTER`]       | `8000`        |                 |           | Boot SP value                                                                            |
| [`boot_pml4_addr`]           | `9000`        | `A000`          | 4 KiB     | Boot page table                                                                          |
| [`boot_pdpte_addr`]          | `A000`        | `B000`          | 4 KiB     | Boot page table                                                                          |
| [`boot_pde_addr`]            | `B000`        | `F000`          | 16 KiB    | Boot page tables                                                                         |
| [`CMDLINE_OFFSET`]           | `2_0000`      | `2_0800`        | 2 KiB     | Linux kernel command line                                                                |
| [`SETUP_DATA_START`]         | `2_0800`      | `9_E800`        | 504 KiB   | Linux kernel `setup_data` linked list                                                    |
| [`MPTABLE_RANGE`]            | `9_E800`      | `A_0000`        | 6 KiB     | MultiProcessor Specification Configuration Table                                         |
| [`ACPI_HI_RSDP_WINDOW_BASE`] | `E_0000`      |                 |           | ACPI tables                                                                              |
| [`mem_1m_to_4g`]             | `10_0000`     | `D000_0000`     | ~3.24 GiB | RAM (\<4G)                                                                               |
| [`KERNEL_START_OFFSET`]      | `20_0000`     |                 |           | Linux kernel image load address                                                          |
| [`initrd_start`]             | after kernel  |                 |           | Initial RAM disk for Linux kernel (optional)                                             |
| [`PROTECTED_VM_FW_START`]    | `7FC0_0000`   | `8000_0000`     | 4 MiB     | pVM firmware (if running a protected VM)                                                 |
| [`pci_mmio_before_32bit`]    | `D000_0000`   | `F400_0000`     | 576 MiB   | Low (\<4G) MMIO allocation area                                                          |
| [`PCIE_CFG_MMIO_START`]      | `F400_0000`   | `F800_0000`     | 64 MiB    | PCIe enhanced config (ECAM)                                                              |
| [`RESERVED_MEM_SIZE`]        | `F800_0000`   | `1_0000_0000`   | 128 MiB   | LAPIC/IOAPIC/HPET/…                                                                      |
| [`IDENTITY_MAP_ADDR`]        | `FEFF_C000`   |                 |           | Identity map segment                                                                     |
| [`TSS_ADDR`]                 | `FEFF_D000`   |                 |           | Boot task state segment                                                                  |
|                              | `1_0000_0000` |                 |           | RAM (>4G)                                                                                |
|                              | (end of RAM)  |                 |           | High (>4G) MMIO allocation area                                                          |

[`multiboot_info_offset`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=381?q=MULITBOOT_INFO_OFFSET
[`zero_page_offset`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=368?q=ZERO_PAGE_OFFSET
[`boot_stack_pointer`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=350?q=BOOT_STACK_POINTER
[`boot_pml4_addr`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/regs.rs;l=297?q=boot_pml4_addr
[`boot_pdpte_addr`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/regs.rs;l=298?q=boot_pdpte_addr
[`boot_pde_addr`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/regs.rs;l=299?q=boot_pde_addr
[`cmdline_offset`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=373?q=CMDLINE_OFFSET
[`setup_data_start`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=375?q=SETUP_DATA_START
[`mptable_range`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/mptable.rs;l=72?q=MPTABLE_RANGE
[`acpi_hi_rsdp_window_base`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=388?q=ACPI_HI_RSDP_WINDOW_BASE
[`kernel_start_offset`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=372?q=KERNEL_START_OFFSET
[`initrd_start`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=1692?q=initrd_start
[`protected_vm_fw_start`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=394?q=PROTECTED_VM_FW_START
[`mem_1m_to_4g`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=737?q=mem_1m_to_4g
[`pci_mmio_before_32bit`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=456?q=pci_mmio_before_32bit
[`pcie_cfg_mmio_start`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=363?q=PCIE_CFG_MMIO_START
[`reserved_mem_size`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=358?q=RESERVED_MEM_SIZE
[`identity_map_addr`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=500?q=identity_map_addr_start
[`tss_addr`]: https://crsrc.org/o/src/platform/crosvm/x86_64/src/lib.rs;l=505?q=tss_addr_start

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
| [`AARCH64_PCI_CAM_BASE_DEFAULT`]  | `1_0000`        | `101_0000`      | 16 MiB         | PCI configuration (CAM)                                       |
| [`AARCH64_VIRTFREQ_BASE`]         | `104_0000`      | `105_0000`      | 64 KiB         | Virtual cpufreq device                                        |
| [`AARCH64_PVTIME_IPA_START`]      | `1ff_0000`      | `200_0000`      | 64 KiB         | Paravirtualized time                                          |
| [`AARCH64_PCI_MEM_BASE_DEFAULT`]  | `200_0000`      | `400_0000`      | 32 MiB         | Low MMIO allocation area                                      |
| [`AARCH64_GIC_CPUI_BASE`]         | `3ffd_0000`     | `3fff_0000`     | 128 KiB        | vGIC                                                          |
| [`AARCH64_GIC_DIST_BASE`]         | `3fff_0000`     | `4000_0000`     | 64 KiB         | vGIC                                                          |
| [`AARCH64_GIC_ITS_BASE`]          | `4000_0000`     | `4002_0000`     | 128 KiB        | vGIC ITS (if enabled)                                         |
| [`AARCH64_PROTECTED_VM_FW_START`] | `7fc0_0000`     | `8000_0000`     | 4 MiB          | pVM firmware (if running a protected VM)                      |
| [`AARCH64_PHYS_MEM_START`]        | `8000_0000`     |                 | --mem size     | RAM (starts at IPA = 2 GiB)                                   |
| [`plat_mmio_base`]                | after RAM       | +0x800000       | 8 MiB          | Platform device MMIO region                                   |
| [`high_mmio_base`]                | after plat_mmio | max phys addr   |                | High MMIO allocation area                                     |

### RAM Layout

The RAM layout depends on the `--fdt-position` setting, which defaults to
`start` when load using `--bios` and to `end` when using `--kernel`.

In `--kernel` mode, the initrd is always loaded immediately after the kernel,
with a 16 MiB alignment.

#### --fdt-position=start

| Name/source link          | Address           | End (exclusive) | Size  | Notes                            |
| ------------------------- | ----------------- | --------------- | ----- | -------------------------------- |
| [`fdt_address`]           | `8000_0000`       | `8020_0000`     | 2 MiB | Flattened device tree in RAM     |
| [`payload_address`]       | `8020_0000`       |                 |       | Kernel/BIOS load location in RAM |

#### --fdt-position=after-payload

| Name/source link          | Address                             | End (exclusive) | Size  | Notes                            |
| ------------------------- | ----------------------------------- | --------------- | ----- | -------------------------------- |
| [`payload_address`]       | `8000_0000`                         |                 |       | Kernel/BIOS load location in RAM |
| [`fdt_address`]           | after payload (2 MiB alignment)     |                 | 2 MiB | Flattened device tree in RAM     |

#### --fdt-position=end

| Name/source link          | Address                             | End (exclusive) | Size  | Notes                            |
| ------------------------- | ----------------------------------- | --------------- | ----- | -------------------------------- |
| [`payload_address`]       | `8000_0000`                         |                 |       | Kernel/BIOS load location in RAM |
| [`fdt_address`]           | before end of RAM (2 MiB alignment) |                 | 2 MiB | Flattened device tree in RAM     |

[serial_addr]: https://crsrc.org/o/src/platform/crosvm/arch/src/serial.rs;l=78?q=SERIAL_ADDR
[`aarch64_rtc_addr`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=177?q=AARCH64_RTC_ADDR
[`aarch64_vmwdt_addr`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=187?q=AARCH64_VMWDT_ADDR
[`aarch64_virtfreq_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=207?q=AARCH64_VIRTFREQ_BASE
[`aarch64_pci_cam_base_default`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=154?q=AARCH64_PCI_CAM_BASE_DEFAULT
[`aarch64_pci_mem_base_default`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=154?q=AARCH64_PCI_MEM_BASE_DEFAULT
[`aarch64_gic_cpui_base`]: https://crsrc.org/o/src/platform/crosvm/devices/src/irqchip/kvm/aarch64.rs;l=106?q=AARCH64_GIC_CPUI_BASE
[`aarch64_gic_dist_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=105?q=AARCH64_GIC_DIST_BASE
[`aarch64_gic_its_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=105?q=AARCH64_GIC_ITS_BASE
[`aarch64_pvtime_ipa_start`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=100?q=AARCH64_PVTIME_IPA_START
[`aarch64_protected_vm_fw_start`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=96?q=AARCH64_PROTECTED_VM_FW_START
[`aarch64_phys_mem_start`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=85?q=AARCH64_PHYS_MEM_START
[`plat_mmio_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=835?q=plat_mmio_base
[`high_mmio_base`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=838?q=high_mmio_base
[`fdt_address`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=301?q=fdt_address
[`payload_address`]: https://crsrc.org/o/src/platform/crosvm/aarch64/src/lib.rs;l=301?q=payload_address
