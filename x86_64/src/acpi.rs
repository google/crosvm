// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use acpi_tables::{facs::FACS, rsdp::RSDP, sdt::SDT};
use base::error;
use data_model::DataInit;
use vm_memory::{GuestAddress, GuestMemory};

pub struct ACPIDevResource {
    pub amls: Vec<u8>,
    pub pm_iobase: u64,
    /// Additional system descriptor tables.
    pub sdts: Vec<SDT>,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LocalAPIC {
    _type: u8,
    _length: u8,
    _processor_id: u8,
    _apic_id: u8,
    _flags: u32,
}

// Safe as LocalAPIC structure only contains raw data
unsafe impl DataInit for LocalAPIC {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IOAPIC {
    _type: u8,
    _length: u8,
    _ioapic_id: u8,
    _reserved: u8,
    _apic_address: u32,
    _gsi_base: u32,
}

// Safe as IOAPIC structure only contains raw data
unsafe impl DataInit for IOAPIC {}

const OEM_REVISION: u32 = 1;
//DSDT
const DSDT_REVISION: u8 = 6;
// FADT
const FADT_LEN: u32 = 276;
const FADT_REVISION: u8 = 6;
const FADT_MINOR_REVISION: u8 = 3;
// FADT flags
const FADT_POWER_BUTTON: u32 = 1 << 4;
const FADT_SLEEP_BUTTON: u32 = 1 << 5;
// FADT fields offset
const FADT_FIELD_FACS_ADDR32: usize = 36;
const FADT_FIELD_DSDT_ADDR32: usize = 40;
const FADT_FIELD_SCI_INTERRUPT: usize = 46;
const FADT_FIELD_SMI_COMMAND: usize = 48;
const FADT_FIELD_PM1A_EVENT_BLK_ADDR: usize = 56;
const FADT_FIELD_PM1A_CONTROL_BLK_ADDR: usize = 64;
const FADT_FIELD_PM1A_EVENT_BLK_LEN: usize = 88;
const FADT_FIELD_PM1A_CONTROL_BLK_LEN: usize = 89;
const FADT_FIELD_FLAGS: usize = 112;
const FADT_FIELD_MINOR_REVISION: usize = 131;
const FADT_FIELD_FACS_ADDR: usize = 132;
const FADT_FIELD_DSDT_ADDR: usize = 140;
const FADT_FIELD_HYPERVISOR_ID: usize = 268;
// MADT
const MADT_LEN: u32 = 44;
const MADT_REVISION: u8 = 5;
// MADT fields offset
const MADT_FIELD_LAPIC_ADDR: usize = 36;
// MADT structure offsets
const MADT_STRUCTURE_TYPE: usize = 0;
const MADT_STRUCTURE_LEN: usize = 1;
// MADT types
const MADT_TYPE_LOCAL_APIC: u8 = 0;
const MADT_TYPE_IO_APIC: u8 = 1;
const MADT_TYPE_INTERRUPT_SOURCE_OVERRIDE: u8 = 2;
// MADT flags
const MADT_ENABLED: u32 = 1;
// XSDT
const XSDT_REVISION: u8 = 1;

fn create_dsdt_table(amls: Vec<u8>) -> SDT {
    let mut dsdt = SDT::new(
        *b"DSDT",
        acpi_tables::HEADER_LEN,
        DSDT_REVISION,
        *b"CROSVM",
        *b"CROSVMDT",
        OEM_REVISION,
    );

    if !amls.is_empty() {
        dsdt.append_slice(amls.as_slice());
    }

    dsdt
}

fn create_facp_table(sci_irq: u16, pm_iobase: u32) -> SDT {
    let mut facp = SDT::new(
        *b"FACP",
        FADT_LEN,
        FADT_REVISION,
        *b"CROSVM",
        *b"CROSVMDT",
        OEM_REVISION,
    );

    let fadt_flags: u32 = FADT_POWER_BUTTON | FADT_SLEEP_BUTTON; // mask POWER and SLEEP BUTTON
    facp.write(FADT_FIELD_FLAGS, fadt_flags);

    // SCI Interrupt
    facp.write(FADT_FIELD_SCI_INTERRUPT, sci_irq);

    // PM1A Event Block Address
    facp.write(FADT_FIELD_PM1A_EVENT_BLK_ADDR, pm_iobase);

    // PM1A Control Block Address
    facp.write(
        FADT_FIELD_PM1A_CONTROL_BLK_ADDR,
        pm_iobase + devices::acpi::ACPIPM_RESOURCE_EVENTBLK_LEN as u32,
    );

    // PM1 Event Block Length
    facp.write(
        FADT_FIELD_PM1A_EVENT_BLK_LEN,
        devices::acpi::ACPIPM_RESOURCE_EVENTBLK_LEN as u8,
    );

    // PM1 Control Block Length
    facp.write(
        FADT_FIELD_PM1A_CONTROL_BLK_LEN,
        devices::acpi::ACPIPM_RESOURCE_CONTROLBLK_LEN as u8,
    );

    facp.write(FADT_FIELD_MINOR_REVISION, FADT_MINOR_REVISION); // FADT minor version
    facp.write(FADT_FIELD_HYPERVISOR_ID, *b"CROSVM"); // Hypervisor Vendor Identity

    facp
}

fn next_offset(offset: GuestAddress, len: u64) -> Option<GuestAddress> {
    // Enforce 64-byte allocation alignment.
    match len % 64 {
        0 => offset.checked_add(len),
        x => offset.checked_add(len.checked_add(64 - x)?),
    }
}

/// Create ACPI tables and return the RSDP.
/// The basic tables DSDT/FACP/MADT/XSDT are constructed in this function.
/// # Arguments
///
/// * `guest_mem` - The guest memory where the tables will be stored.
/// * `num_cpus` - Used to construct the MADT.
/// * `sci_irq` - Used to fill the FACP SCI_INTERRUPT field, which
///               is going to be used by the ACPI drivers to register
///               sci handler.
/// * `acpi_dev_resource` - resouces needed by the ACPI devices for creating tables
pub fn create_acpi_tables(
    guest_mem: &GuestMemory,
    num_cpus: u8,
    sci_irq: u32,
    acpi_dev_resource: ACPIDevResource,
) -> Option<GuestAddress> {
    // RSDP is at the HI RSDP WINDOW
    let rsdp_offset = GuestAddress(super::ACPI_HI_RSDP_WINDOW_BASE);
    let facs_offset = next_offset(rsdp_offset, RSDP::len() as u64)?;
    let mut offset = next_offset(facs_offset, FACS::len() as u64)?;
    let mut dsdt_offset: Option<GuestAddress> = None;
    let mut tables: Vec<u64> = Vec::new();
    let mut facp: Option<SDT> = None;
    let mut host_madt: Option<SDT> = None;

    // User supplied System Description Tables, e.g. SSDT.
    for sdt in acpi_dev_resource.sdts.iter() {
        if sdt.is_signature(b"FACP") {
            facp = Some(sdt.clone());
            continue;
        }
        if sdt.is_signature(b"APIC") {
            host_madt = Some(sdt.clone());
            continue;
        }
        guest_mem.write_at_addr(sdt.as_slice(), offset).ok()?;
        if sdt.is_signature(b"DSDT") {
            dsdt_offset = Some(offset);
        } else {
            tables.push(offset.0);
        }
        offset = next_offset(offset, sdt.len() as u64)?;
    }

    // FACS
    let facs = FACS::new();
    guest_mem.write_at_addr(facs.as_slice(), facs_offset).ok()?;

    // DSDT
    let dsdt_offset = match dsdt_offset {
        Some(dsdt_offset) => dsdt_offset,
        None => {
            let dsdt_offset = offset;
            let dsdt = create_dsdt_table(acpi_dev_resource.amls);
            guest_mem.write_at_addr(dsdt.as_slice(), offset).ok()?;
            offset = next_offset(offset, dsdt.len() as u64)?;
            dsdt_offset
        }
    };

    // FACP aka FADT
    let pm_iobase = acpi_dev_resource.pm_iobase as u32;
    let mut facp = facp.unwrap_or_else(|| create_facp_table(sci_irq as u16, pm_iobase));

    // Crosvm FACP overrides.
    facp.write(FADT_FIELD_SMI_COMMAND, 0u32);
    facp.write(FADT_FIELD_FACS_ADDR32, 0u32);
    facp.write(FADT_FIELD_DSDT_ADDR32, 0u32);
    facp.write(FADT_FIELD_FACS_ADDR, facs_offset.0 as u64);
    facp.write(FADT_FIELD_DSDT_ADDR, dsdt_offset.0 as u64);

    guest_mem.write_at_addr(facp.as_slice(), offset).ok()?;
    tables.push(offset.0);
    offset = next_offset(offset, facp.len() as u64)?;

    // MADT
    let mut madt = SDT::new(
        *b"APIC",
        MADT_LEN,
        MADT_REVISION,
        *b"CROSVM",
        *b"CROSVMDT",
        OEM_REVISION,
    );
    madt.write(
        MADT_FIELD_LAPIC_ADDR,
        super::mptable::APIC_DEFAULT_PHYS_BASE as u32,
    );

    for cpu in 0..num_cpus {
        let lapic = LocalAPIC {
            _type: MADT_TYPE_LOCAL_APIC,
            _length: std::mem::size_of::<LocalAPIC>() as u8,
            _processor_id: cpu,
            _apic_id: cpu,
            _flags: MADT_ENABLED,
        };
        madt.append(lapic);
    }

    madt.append(IOAPIC {
        _type: MADT_TYPE_IO_APIC,
        _length: std::mem::size_of::<IOAPIC>() as u8,
        _apic_address: super::mptable::IO_APIC_DEFAULT_PHYS_BASE,
        ..Default::default()
    });

    if let Some(host_madt) = host_madt {
        let mut idx = MADT_LEN as usize;
        while idx + MADT_STRUCTURE_LEN < host_madt.len() {
            let struct_type = host_madt.as_slice()[idx + MADT_STRUCTURE_TYPE];
            let struct_len = host_madt.as_slice()[idx + MADT_STRUCTURE_LEN] as usize;
            if struct_type == MADT_TYPE_INTERRUPT_SOURCE_OVERRIDE {
                if idx + struct_len <= host_madt.len() {
                    madt.append_slice(&host_madt.as_slice()[idx..(idx + struct_len)]);
                } else {
                    error!("Malformed host MADT");
                }
            }
            idx += struct_len;
        }
    }

    guest_mem.write_at_addr(madt.as_slice(), offset).ok()?;
    tables.push(offset.0);
    offset = next_offset(offset, madt.len() as u64)?;

    // XSDT
    let mut xsdt = SDT::new(
        *b"XSDT",
        acpi_tables::HEADER_LEN,
        XSDT_REVISION,
        *b"CROSVM",
        *b"CROSVMDT",
        OEM_REVISION,
    );
    for table in tables {
        xsdt.append(table);
    }

    guest_mem.write_at_addr(xsdt.as_slice(), offset).ok()?;

    // RSDP
    let rsdp = RSDP::new(*b"CROSVM", offset.0);
    guest_mem.write_at_addr(rsdp.as_slice(), rsdp_offset).ok()?;

    Some(rsdp_offset)
}
