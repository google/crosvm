// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::mem;
use std::result;

use devices::PciAddress;
use devices::PciInterruptPin;
use remain::sorted;
use resources::AddressRange;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::IntoBytes;

use crate::mpspec::*;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// The MP table has too little address space to be stored.
    #[error("The MP table has too little address space to be stored")]
    AddressOverflow,
    /// Failure while zeroing out the memory for the MP table.
    #[error("Failure while zeroing out the memory for the MP table")]
    Clear,
    /// There was too little guest memory to store the entire MP table.
    #[error("There was too little guest memory to store the MP table")]
    NotEnoughMemory,
    /// More than the maximum number of supported CPUs.
    #[error("{0} is more than the maximum number of supported CPUs")]
    TooManyCpus(u8),
    /// Failure to write MP bus entry.
    #[error("Failure to write MP bus entry")]
    WriteMpcBus,
    /// Failure to write MP CPU entry.
    #[error("Failure to write MP CPU entry")]
    WriteMpcCpu,
    /// Failure to write MP interrupt source entry.
    #[error("Failure to write MP interrupt source entry")]
    WriteMpcIntsrc,
    /// Failure to write MP ioapic entry.
    #[error("Failure to write MP ioapic entry")]
    WriteMpcIoapic,
    /// Failure to write MP local interrupt source entry.
    #[error("Failure to write MP local interrupt source entry")]
    WriteMpcLintsrc,
    /// Failure to write MP table header.
    #[error("Failure to write MP table header")]
    WriteMpcTable,
    /// Failure to write the MP floating pointer.
    #[error("Failure to write the MP floating pointer")]
    WriteMpfIntel,
}

pub type Result<T> = result::Result<T, Error>;

// Most of these variables are sourced from the Intel MP Spec 1.4.
const SMP_MAGIC_IDENT: [u8; 4] = *b"_MP_";
const MPC_SIGNATURE: [u8; 4] = *b"PCMP";
const MPC_SPEC: i8 = 4;
const MPC_OEM: [u8; 8] = *b"CROSVM  ";
const MPC_PRODUCT_ID: [u8; 12] = *b"000000000000";
const BUS_TYPE_ISA: [u8; 6] = *b"ISA   ";
const BUS_TYPE_PCI: [u8; 6] = *b"PCI   ";
// source: linux/arch/x86/include/asm/apicdef.h
pub const IO_APIC_DEFAULT_PHYS_BASE: u32 = 0xfec00000;
// source: linux/arch/x86/include/asm/apicdef.h
pub const APIC_DEFAULT_PHYS_BASE: u32 = 0xfee00000;
const APIC_VERSION: u8 = 0x14;
const CPU_STEPPING: u32 = 0x600;
const CPU_FEATURE_APIC: u32 = 0x200;
const CPU_FEATURE_FPU: u32 = 0x001;
/// Place the MP Floating Pointer Structure in the last kilobyte of base memory (639K-640K).
const MP_FLOATING_POINTER_ADDR: u64 = 0x400 * 640 - size_of::<mpf_intel>() as u64;
/// Reserve the last 6K of low memory (below 640K) just before the MP Floating Pointer Structure for
/// the rest of the MP Table.
pub const MPTABLE_RANGE: AddressRange =
    AddressRange::from_start_and_end(0x400 * 634, MP_FLOATING_POINTER_ADDR - 1);

fn compute_checksum(v: &[u8]) -> u8 {
    let mut checksum: u8 = 0;
    for i in v {
        checksum = checksum.wrapping_add(*i);
    }
    checksum
}

fn mpf_intel_compute_checksum(v: &mpf_intel) -> u8 {
    let checksum = compute_checksum(v.as_bytes()).wrapping_sub(v.checksum);
    (!checksum).wrapping_add(1)
}

fn compute_mp_size(num_cpus: u8) -> usize {
    mem::size_of::<mpc_table>()
        + mem::size_of::<mpc_cpu>() * (num_cpus as usize)
        + mem::size_of::<mpc_ioapic>()
        + mem::size_of::<mpc_bus>() * 2
        + mem::size_of::<mpc_intsrc>()
        + mem::size_of::<mpc_intsrc>() * 16
        + mem::size_of::<mpc_lintsrc>() * 2
}

/// Performs setup of the MP table for the given `num_cpus`.
pub fn setup_mptable(
    mem: &GuestMemory,
    num_cpus: u8,
    pci_irqs: &[(PciAddress, u32, PciInterruptPin)],
) -> Result<()> {
    // Write the MP Floating Pointer structure pointing at `MPTABLE_RANGE`. This structure must be
    // in one of a few pre-defined memory areas so the OS can find it; we choose to place it in the
    // last kilobyte of low system memory (639K-640K).
    let mut mpf_intel = mpf_intel::default();
    mpf_intel.signature = SMP_MAGIC_IDENT;
    mpf_intel.length = 1;
    mpf_intel.specification = 4;
    mpf_intel.physptr = MPTABLE_RANGE
        .start
        .try_into()
        .map_err(|_| Error::AddressOverflow)?;
    mpf_intel.checksum = mpf_intel_compute_checksum(&mpf_intel);
    mem.write_obj_at_addr(mpf_intel, GuestAddress(MP_FLOATING_POINTER_ADDR))
        .map_err(|_| Error::WriteMpfIntel)?;

    // Used to keep track of the next base pointer into the MP table.
    let mut base_mp = GuestAddress(MPTABLE_RANGE.start);

    // Calculate ISA bus number in the system, report at least one PCI bus.
    let isa_bus_id = match pci_irqs.iter().max_by_key(|v| v.0.bus) {
        Some(pci_irq) => pci_irq.0.bus + 1,
        _ => 1,
    };
    let mp_size = compute_mp_size(num_cpus);

    // The checked_add here ensures the all of the following base_mp.unchecked_add's will be without
    // overflow.
    if let Some(end_mp) = base_mp.checked_add(mp_size as u64 - 1) {
        if !mem.address_in_range(end_mp) || !MPTABLE_RANGE.contains(end_mp.0) {
            return Err(Error::NotEnoughMemory);
        }
    } else {
        return Err(Error::AddressOverflow);
    }

    mem.get_slice_at_addr(base_mp, mp_size)
        .map_err(|_| Error::Clear)?
        .write_bytes(0);

    // We set the location of the mpc_table here but we can't fill it out until we have the length
    // of the entire table later.
    let table_base = base_mp;
    base_mp = base_mp.unchecked_add(mem::size_of::<mpc_table>() as u64);

    let mut checksum: u8 = 0;
    let ioapicid: u8 = num_cpus
        .checked_add(1)
        .ok_or(Error::TooManyCpus(num_cpus))?;

    for cpu_id in 0..num_cpus {
        let size = mem::size_of::<mpc_cpu>();
        let mpc_cpu = mpc_cpu {
            type_: MP_PROCESSOR as u8,
            apicid: cpu_id,
            apicver: APIC_VERSION,
            cpuflag: CPU_ENABLED as u8
                | if cpu_id == 0 {
                    CPU_BOOTPROCESSOR as u8
                } else {
                    0
                },
            cpufeature: CPU_STEPPING,
            featureflag: CPU_FEATURE_APIC | CPU_FEATURE_FPU,
            ..Default::default()
        };
        mem.write_obj_at_addr(mpc_cpu, base_mp)
            .map_err(|_| Error::WriteMpcCpu)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(mpc_cpu.as_bytes()));
    }
    {
        let size = mem::size_of::<mpc_ioapic>();
        let mpc_ioapic = mpc_ioapic {
            type_: MP_IOAPIC as u8,
            apicid: ioapicid,
            apicver: APIC_VERSION,
            flags: MPC_APIC_USABLE as u8,
            apicaddr: IO_APIC_DEFAULT_PHYS_BASE,
        };
        mem.write_obj_at_addr(mpc_ioapic, base_mp)
            .map_err(|_| Error::WriteMpcIoapic)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(mpc_ioapic.as_bytes()));
    }
    for pci_bus_id in 0..isa_bus_id {
        let size = mem::size_of::<mpc_bus>();
        let mpc_bus = mpc_bus {
            type_: MP_BUS as u8,
            busid: pci_bus_id,
            bustype: BUS_TYPE_PCI,
        };
        mem.write_obj_at_addr(mpc_bus, base_mp)
            .map_err(|_| Error::WriteMpcBus)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(mpc_bus.as_bytes()));
    }
    {
        let size = mem::size_of::<mpc_bus>();
        let mpc_bus = mpc_bus {
            type_: MP_BUS as u8,
            busid: isa_bus_id,
            bustype: BUS_TYPE_ISA,
        };
        mem.write_obj_at_addr(mpc_bus, base_mp)
            .map_err(|_| Error::WriteMpcBus)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(mpc_bus.as_bytes()));
    }
    {
        let size = mem::size_of::<mpc_intsrc>();
        let mpc_intsrc = mpc_intsrc {
            type_: MP_LINTSRC as u8,
            irqtype: mp_irq_source_types_mp_INT as u8,
            irqflag: MP_IRQDIR_DEFAULT as u16,
            srcbus: isa_bus_id,
            srcbusirq: 0,
            dstapic: 0,
            dstirq: 0,
        };
        mem.write_obj_at_addr(mpc_intsrc, base_mp)
            .map_err(|_| Error::WriteMpcIntsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(mpc_intsrc.as_bytes()));
    }
    let sci_irq = super::X86_64_SCI_IRQ as u8;
    // Per kvm_setup_default_irq_routing() in kernel
    for i in (0..sci_irq).chain(std::iter::once(devices::cmos::RTC_IRQ)) {
        let size = mem::size_of::<mpc_intsrc>();
        let mpc_intsrc = mpc_intsrc {
            type_: MP_INTSRC as u8,
            irqtype: mp_irq_source_types_mp_INT as u8,
            irqflag: MP_IRQDIR_DEFAULT as u16,
            srcbus: isa_bus_id,
            srcbusirq: i,
            dstapic: ioapicid,
            dstirq: i,
        };
        mem.write_obj_at_addr(mpc_intsrc, base_mp)
            .map_err(|_| Error::WriteMpcIntsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(mpc_intsrc.as_bytes()));
    }
    // Insert SCI interrupt before PCI interrupts. Set the SCI interrupt
    // to be the default trigger/polarity of PCI bus, which is level/low.
    // This setting can be changed in future if necessary.
    {
        let size = mem::size_of::<mpc_intsrc>();
        let mpc_intsrc = mpc_intsrc {
            type_: MP_INTSRC as u8,
            irqtype: mp_irq_source_types_mp_INT as u8,
            irqflag: (MP_IRQDIR_HIGH | MP_LEVEL_TRIGGER) as u16,
            srcbus: isa_bus_id,
            srcbusirq: sci_irq,
            dstapic: ioapicid,
            dstirq: sci_irq,
        };
        mem.write_obj_at_addr(mpc_intsrc, base_mp)
            .map_err(|_| Error::WriteMpcIntsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(mpc_intsrc.as_bytes()));
    }

    // Insert PCI interrupts after platform IRQs.
    for (address, irq_num, irq_pin) in pci_irqs.iter() {
        let size = mem::size_of::<mpc_intsrc>();
        let mpc_intsrc = mpc_intsrc {
            type_: MP_INTSRC as u8,
            irqtype: mp_irq_source_types_mp_INT as u8,
            irqflag: MP_IRQDIR_DEFAULT as u16,
            srcbus: address.bus,
            srcbusirq: address.dev << 2 | irq_pin.to_mask() as u8,
            dstapic: ioapicid,
            dstirq: u8::try_from(*irq_num).map_err(|_| Error::WriteMpcIntsrc)?,
        };
        mem.write_obj_at_addr(mpc_intsrc, base_mp)
            .map_err(|_| Error::WriteMpcIntsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(mpc_intsrc.as_bytes()));
    }

    let starting_isa_irq_num = pci_irqs
        .iter()
        .map(|(_, irq_num, _)| irq_num + 1)
        .fold(super::X86_64_IRQ_BASE, u32::max) as u8;

    // Finally insert ISA interrupts.
    for i in starting_isa_irq_num..16 {
        let size = mem::size_of::<mpc_intsrc>();
        let mpc_intsrc = mpc_intsrc {
            type_: MP_INTSRC as u8,
            irqtype: mp_irq_source_types_mp_INT as u8,
            irqflag: MP_IRQDIR_DEFAULT as u16,
            srcbus: isa_bus_id,
            srcbusirq: i,
            dstapic: ioapicid,
            dstirq: i,
        };
        mem.write_obj_at_addr(mpc_intsrc, base_mp)
            .map_err(|_| Error::WriteMpcIntsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(mpc_intsrc.as_bytes()));
    }
    {
        let size = mem::size_of::<mpc_lintsrc>();
        let mpc_lintsrc = mpc_lintsrc {
            type_: MP_LINTSRC as u8,
            irqtype: mp_irq_source_types_mp_ExtINT as u8,
            irqflag: MP_IRQDIR_DEFAULT as u16,
            srcbusid: isa_bus_id,
            srcbusirq: 0,
            destapic: 0,
            destapiclint: 0,
        };
        mem.write_obj_at_addr(mpc_lintsrc, base_mp)
            .map_err(|_| Error::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(mpc_lintsrc.as_bytes()));
    }
    {
        let size = mem::size_of::<mpc_lintsrc>();
        let mpc_lintsrc = mpc_lintsrc {
            type_: MP_LINTSRC as u8,
            irqtype: mp_irq_source_types_mp_NMI as u8,
            irqflag: MP_IRQDIR_DEFAULT as u16,
            srcbusid: isa_bus_id,
            srcbusirq: 0,
            destapic: 0xFF, // Per SeaBIOS
            destapiclint: 1,
        };
        mem.write_obj_at_addr(mpc_lintsrc, base_mp)
            .map_err(|_| Error::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size as u64);
        checksum = checksum.wrapping_add(compute_checksum(mpc_lintsrc.as_bytes()));
    }

    // At this point we know the size of the mp_table.
    let table_end = base_mp;

    {
        let mut mpc_table = mpc_table {
            signature: MPC_SIGNATURE,
            length: table_end.offset_from(table_base) as u16,
            spec: MPC_SPEC,
            oem: MPC_OEM,
            productid: MPC_PRODUCT_ID,
            lapic: APIC_DEFAULT_PHYS_BASE,
            ..Default::default()
        };
        checksum = checksum.wrapping_add(compute_checksum(mpc_table.as_bytes()));
        mpc_table.checksum = (!checksum).wrapping_add(1) as i8;
        mem.write_obj_at_addr(mpc_table, table_base)
            .map_err(|_| Error::WriteMpcTable)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_guest_mem() -> GuestMemory {
        GuestMemory::new(&[(GuestAddress(0), 640 * 1024)]).unwrap()
    }

    fn table_entry_size(type_: u8) -> usize {
        match type_ as u32 {
            MP_PROCESSOR => mem::size_of::<mpc_cpu>(),
            MP_BUS => mem::size_of::<mpc_bus>(),
            MP_IOAPIC => mem::size_of::<mpc_ioapic>(),
            MP_INTSRC => mem::size_of::<mpc_intsrc>(),
            MP_LINTSRC => mem::size_of::<mpc_lintsrc>(),
            _ => panic!("unrecognized mpc table entry type: {}", type_),
        }
    }

    #[test]
    fn bounds_check() {
        let num_cpus = 4;
        let mem = test_guest_mem();

        setup_mptable(&mem, num_cpus, &[]).unwrap();
    }

    #[test]
    fn bounds_check_fails() {
        let num_cpus = 255;
        let mem = test_guest_mem();

        assert!(setup_mptable(&mem, num_cpus, &[]).is_err());
    }

    #[test]
    fn mpf_intel_checksum() {
        let num_cpus = 1;
        let mem = test_guest_mem();

        setup_mptable(&mem, num_cpus, &[]).unwrap();

        let mpf_intel = mem
            .read_obj_from_addr(GuestAddress(MP_FLOATING_POINTER_ADDR))
            .unwrap();

        assert_eq!(mpf_intel_compute_checksum(&mpf_intel), mpf_intel.checksum);
    }

    #[test]
    fn mpc_table_checksum() {
        let num_cpus = 4;
        let mem = test_guest_mem();

        setup_mptable(&mem, num_cpus, &[]).unwrap();

        let mpf_intel: mpf_intel = mem
            .read_obj_from_addr(GuestAddress(MP_FLOATING_POINTER_ADDR))
            .unwrap();
        let mpc_offset = GuestAddress(mpf_intel.physptr as u64);
        let mpc_table: mpc_table = mem.read_obj_from_addr(mpc_offset).unwrap();

        let mut buf = vec![0; mpc_table.length as usize];
        mem.read_at_addr(&mut buf[..], mpc_offset).unwrap();
        let mut sum: u8 = 0;
        for &v in &buf {
            sum = sum.wrapping_add(v);
        }

        assert_eq!(sum, 0);
    }

    #[test]
    fn cpu_entry_count() {
        const MAX_CPUS: u8 = 0xff;
        let mem = test_guest_mem();

        for i in 0..MAX_CPUS {
            setup_mptable(&mem, i, &[]).unwrap();

            let mpf_intel: mpf_intel = mem
                .read_obj_from_addr(GuestAddress(MP_FLOATING_POINTER_ADDR))
                .unwrap();
            let mpc_offset = GuestAddress(mpf_intel.physptr as u64);
            let mpc_table: mpc_table = mem.read_obj_from_addr(mpc_offset).unwrap();
            let mpc_end = mpc_offset.checked_add(mpc_table.length as u64).unwrap();

            let mut entry_offset = mpc_offset
                .checked_add(mem::size_of::<mpc_table>() as u64)
                .unwrap();
            let mut cpu_count = 0;
            while entry_offset < mpc_end {
                let entry_type: u8 = mem.read_obj_from_addr(entry_offset).unwrap();
                entry_offset = entry_offset
                    .checked_add(table_entry_size(entry_type) as u64)
                    .unwrap();
                assert!(entry_offset <= mpc_end);
                if entry_type as u32 == MP_PROCESSOR {
                    cpu_count += 1;
                }
            }
            assert_eq!(cpu_count, i);
        }
    }
}
