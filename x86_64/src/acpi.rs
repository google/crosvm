// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use acpi_tables::{rsdp::RSDP, sdt::SDT};
use data_model::DataInit;
use sys_util::{GuestAddress, GuestMemory};

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
const FADT_POWER_BUTTON: u32 = (1 << 4);
const FADT_SLEEP_BUTTON: u32 = (1 << 5);
// FADT fields offset
const FADT_FIELD_SCI_INTERRUPT: usize = 46;
const FADT_FIELD_PM1A_EVENT_BLK_ADDR: usize = 56;
const FADT_FIELD_PM1A_CONTROL_BLK_ADDR: usize = 64;
const FADT_FIELD_PM1A_EVENT_BLK_LEN: usize = 88;
const FADT_FIELD_PM1A_CONTROL_BLK_LEN: usize = 89;
const FADT_FIELD_FLAGS: usize = 112;
const FADT_FIELD_MINOR_REVISION: usize = 131;
const FADT_FIELD_DSDT_ADDR: usize = 140;
const FADT_FIELD_HYPERVISOR_ID: usize = 268;
// MADT
const MADT_LEN: u32 = 44;
const MADT_REVISION: u8 = 5;
// MADT fields offset
const MADT_FIELD_LAPIC_ADDR: usize = 36;
// MADT types
const MADT_TYPE_LOCAL_APIC: u8 = 0;
const MADT_TYPE_IO_APIC: u8 = 1;
// MADT flags
const MADT_ENABLED: u32 = 1;
// XSDT
const XSDT_REVISION: u8 = 1;

fn create_dsdt_table() -> SDT {
    // The hex tables in this file are generated from the ASL below with:
    // "iasl -tc <dsdt.asl>"
    // Below is the tables represents by the pm_dsdt_data
    // Name (_S1, Package (0x04)  // _S1_: S1 System State
    // {
    //     One,
    //     One,
    //     Zero,
    //     Zero
    // })
    let pm_dsdt_data = [
        0x08u8, 0x5F, 0x53, 0x31, 0x5f, 0x12, 0x06, 0x04, 0x01, 0x01, 0x00, 0x00,
    ];

    let mut dsdt = SDT::new(
        *b"DSDT",
        acpi_tables::HEADER_LEN,
        DSDT_REVISION,
        *b"CROSVM",
        *b"CROSVMDT",
        OEM_REVISION,
    );
    dsdt.append(pm_dsdt_data);

    dsdt
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
pub fn create_acpi_tables(guest_mem: &GuestMemory, num_cpus: u8, sci_irq: u32) -> GuestAddress {
    // RSDP is at the HI RSDP WINDOW
    let rsdp_offset = GuestAddress(super::ACPI_HI_RSDP_WINDOW_BASE);
    let mut tables: Vec<u64> = Vec::new();

    // DSDT
    let dsdt = create_dsdt_table();
    let dsdt_offset = rsdp_offset.checked_add(RSDP::len() as u64).unwrap();
    guest_mem
        .write_at_addr(dsdt.as_slice(), dsdt_offset)
        .expect("Error writing DSDT table");

    // FACP aka FADT
    // Revision 6 of the ACPI FADT table is 276 bytes long
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
    facp.write(FADT_FIELD_SCI_INTERRUPT, sci_irq as u16);

    // PM1A Event Block Address
    facp.write(
        FADT_FIELD_PM1A_EVENT_BLK_ADDR,
        devices::acpi::ACPIPM_RESOURCE_BASE as u32,
    );

    // PM1A Control Block Address
    facp.write(
        FADT_FIELD_PM1A_CONTROL_BLK_ADDR,
        devices::acpi::ACPIPM_RESOURCE_BASE as u32
            + devices::acpi::ACPIPM_RESOURCE_EVENTBLK_LEN as u32,
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
    facp.write(FADT_FIELD_DSDT_ADDR, dsdt_offset.0 as u64); // X_DSDT

    facp.write(FADT_FIELD_HYPERVISOR_ID, *b"CROSVM"); // Hypervisor Vendor Identity

    let facp_offset = dsdt_offset.checked_add(dsdt.len() as u64).unwrap();
    guest_mem
        .write_at_addr(facp.as_slice(), facp_offset)
        .expect("Error writing FACP table");
    tables.push(facp_offset.0);

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

    let madt_offset = facp_offset.checked_add(facp.len() as u64).unwrap();
    guest_mem
        .write_at_addr(madt.as_slice(), madt_offset)
        .expect("Error writing MADT table");
    tables.push(madt_offset.0);

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

    let xsdt_offset = madt_offset.checked_add(madt.len() as u64).unwrap();
    guest_mem
        .write_at_addr(xsdt.as_slice(), xsdt_offset)
        .expect("Error writing XSDT table");

    // RSDP
    let rsdp = RSDP::new(*b"CROSVM", xsdt_offset.0);
    guest_mem
        .write_at_addr(rsdp.as_slice(), rsdp_offset)
        .expect("Error writing RSDP");

    rsdp_offset
}
