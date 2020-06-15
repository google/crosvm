// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryInto;

use libc::E2BIG;

use kvm_sys::*;
use sys_util::{
    errno_result, error, ioctl_with_mut_ptr, ioctl_with_mut_ref, ioctl_with_ref, Error, Result,
};

use super::{Kvm, KvmVcpu, KvmVm};
use crate::{
    ClockState, CpuId, CpuIdEntry, DeviceKind, HypervisorX86_64, IoapicRedirectionTableEntry,
    IoapicState, IrqSourceChip, LapicState, PicSelect, PicState, PitChannelState, PitState, Regs,
    VcpuX86_64, VmCap, VmX86_64,
};

type KvmCpuId = kvm::CpuId;

impl Kvm {
    pub fn get_cpuid(&self, kind: u64) -> Result<CpuId> {
        const KVM_MAX_ENTRIES: usize = 256;
        self.get_cpuid_with_initial_capacity(kind, KVM_MAX_ENTRIES)
    }

    fn get_cpuid_with_initial_capacity(&self, kind: u64, initial_capacity: usize) -> Result<CpuId> {
        let mut entries: usize = initial_capacity;

        loop {
            let mut kvm_cpuid = KvmCpuId::new(entries);

            let ret = unsafe {
                // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the
                // memory allocated for the struct. The limit is read from nent within KvmCpuId,
                // which is set to the allocated size above.
                ioctl_with_mut_ptr(self, kind, kvm_cpuid.as_mut_ptr())
            };
            if ret < 0 {
                let err = Error::last();
                match err.errno() {
                    E2BIG => {
                        // double the available memory for cpuid entries for kvm.
                        if let Some(val) = entries.checked_mul(2) {
                            entries = val;
                        } else {
                            return Err(err);
                        }
                    }
                    _ => return Err(err),
                }
            } else {
                return Ok(CpuId::from(&kvm_cpuid));
            }
        }
    }
}

impl HypervisorX86_64 for Kvm {
    fn get_supported_cpuid(&self) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_SUPPORTED_CPUID())
    }

    fn get_emulated_cpuid(&self) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_EMULATED_CPUID())
    }
}

impl KvmVm {
    /// Checks if a particular `VmCap` is available, or returns None if arch-independent
    /// Vm.check_capability() should handle the check.
    pub fn check_capability_arch(&self, c: VmCap) -> Option<bool> {
        match c {
            VmCap::PvClock => Some(true),
            _ => None,
        }
    }

    /// Returns the params to pass to KVM_CREATE_DEVICE for a `kind` device on this arch, or None to
    /// let the arch-independent `KvmVm::create_device` handle it.
    pub fn get_device_params_arch(&self, _kind: DeviceKind) -> Option<kvm_create_device> {
        None
    }

    /// Arch-specific implementation of `Vm::get_pvclock`.
    pub fn get_pvclock_arch(&self) -> Result<ClockState> {
        // Safe because we know that our file is a VM fd, we know the kernel will only write correct
        // amount of memory to our pointer, and we verify the return result.
        let mut clock_data: kvm_clock_data = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_CLOCK(), &mut clock_data) };
        if ret == 0 {
            Ok(ClockState::from(clock_data))
        } else {
            errno_result()
        }
    }

    /// Arch-specific implementation of `Vm::set_pvclock`.
    pub fn set_pvclock_arch(&self, state: &ClockState) -> Result<()> {
        let clock_data = kvm_clock_data::from(*state);
        // Safe because we know that our file is a VM fd, we know the kernel will only read correct
        // amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_CLOCK(), &clock_data) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the state of given interrupt controller by issuing KVM_GET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn get_pic_state(&self, id: PicSelect) -> Result<kvm_pic_state> {
        let mut irqchip_state = kvm_irqchip::default();
        irqchip_state.chip_id = id as u32;
        let ret = unsafe {
            // Safe because we know our file is a VM fd, we know the kernel will only write
            // correct amount of memory to our pointer, and we verify the return result.
            ioctl_with_mut_ref(self, KVM_GET_IRQCHIP(), &mut irqchip_state)
        };
        if ret == 0 {
            Ok(unsafe {
                // Safe as we know that we are retrieving data related to the
                // PIC (primary or secondary) and not IOAPIC.
                irqchip_state.chip.pic
            })
        } else {
            errno_result()
        }
    }

    /// Sets the state of given interrupt controller by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn set_pic_state(&self, id: PicSelect, state: &kvm_pic_state) -> Result<()> {
        let mut irqchip_state = kvm_irqchip::default();
        irqchip_state.chip_id = id as u32;
        irqchip_state.chip.pic = *state;
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_IRQCHIP(), &irqchip_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the state of IOAPIC by issuing KVM_GET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn get_ioapic_state(&self) -> Result<kvm_ioapic_state> {
        let mut irqchip_state = kvm_irqchip::default();
        irqchip_state.chip_id = 2;
        let ret = unsafe {
            // Safe because we know our file is a VM fd, we know the kernel will only write
            // correct amount of memory to our pointer, and we verify the return result.
            ioctl_with_mut_ref(self, KVM_GET_IRQCHIP(), &mut irqchip_state)
        };
        if ret == 0 {
            Ok(unsafe {
                // Safe as we know that we are retrieving data related to the
                // IOAPIC and not PIC.
                irqchip_state.chip.ioapic
            })
        } else {
            errno_result()
        }
    }

    /// Sets the state of IOAPIC by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn set_ioapic_state(&self, state: &kvm_ioapic_state) -> Result<()> {
        let mut irqchip_state = kvm_irqchip::default();
        irqchip_state.chip_id = 2;
        irqchip_state.chip.ioapic = *state;
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_IRQCHIP(), &irqchip_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Creates a PIT as per the KVM_CREATE_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn create_pit(&self) -> Result<()> {
        let pit_config = kvm_pit_config::default();
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_CREATE_PIT2(), &pit_config) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    /// Retrieves the state of PIT by issuing KVM_GET_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_pit`.
    pub fn get_pit_state(&self) -> Result<kvm_pit_state2> {
        // Safe because we know that our file is a VM fd, we know the kernel will only write
        // correct amount of memory to our pointer, and we verify the return result.
        let mut pit_state = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_PIT2(), &mut pit_state) };
        if ret == 0 {
            Ok(pit_state)
        } else {
            errno_result()
        }
    }

    /// Sets the state of PIT by issuing KVM_SET_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_pit`.
    pub fn set_pit_state(&self, pit_state: &kvm_pit_state2) -> Result<()> {
        // Safe because we know that our file is a VM fd, we know the kernel will only read
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_PIT2(), pit_state) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }
}

impl VmX86_64 for KvmVm {
    type Vcpu = KvmVcpu;

    fn create_vcpu(&self, id: usize) -> Result<Self::Vcpu> {
        // create_vcpu is declared separately in VmAArch64 and VmX86, so it can return VcpuAArch64
        // or VcpuX86.  But both use the same implementation in KvmVm::create_vcpu.
        KvmVm::create_vcpu(self, id)
    }
}

impl VcpuX86_64 for KvmVcpu {
    fn get_regs(&self) -> Result<Regs> {
        Ok(Regs {})
    }
}

impl<'a> From<&'a KvmCpuId> for CpuId {
    fn from(kvm_cpuid: &'a KvmCpuId) -> CpuId {
        let kvm_entries = kvm_cpuid.entries_slice();
        let mut cpu_id_entries = Vec::with_capacity(kvm_entries.len());

        for entry in kvm_entries {
            let cpu_id_entry = CpuIdEntry {
                function: entry.function,
                index: entry.index,
                eax: entry.eax,
                ebx: entry.ebx,
                ecx: entry.ecx,
                edx: entry.edx,
            };
            cpu_id_entries.push(cpu_id_entry)
        }
        CpuId { cpu_id_entries }
    }
}

impl From<ClockState> for kvm_clock_data {
    fn from(state: ClockState) -> Self {
        kvm_clock_data {
            clock: state.clock,
            flags: state.flags,
            ..Default::default()
        }
    }
}

impl From<kvm_clock_data> for ClockState {
    fn from(clock_data: kvm_clock_data) -> Self {
        ClockState {
            clock: clock_data.clock,
            flags: clock_data.flags,
        }
    }
}

impl From<&kvm_pic_state> for PicState {
    fn from(item: &kvm_pic_state) -> Self {
        PicState {
            last_irr: item.last_irr,
            irr: item.irr,
            imr: item.imr,
            isr: item.isr,
            priority_add: item.priority_add,
            irq_base: item.irq_base,
            read_reg_select: item.read_reg_select != 0,
            poll: item.poll != 0,
            special_mask: item.special_mask != 0,
            init_state: item.init_state.into(),
            auto_eoi: item.auto_eoi != 0,
            rotate_on_auto_eoi: item.rotate_on_auto_eoi != 0,
            special_fully_nested_mode: item.special_fully_nested_mode != 0,
            use_4_byte_icw: item.init4 != 0,
            elcr: item.elcr,
            elcr_mask: item.elcr_mask,
        }
    }
}

impl From<&PicState> for kvm_pic_state {
    fn from(item: &PicState) -> Self {
        kvm_pic_state {
            last_irr: item.last_irr,
            irr: item.irr,
            imr: item.imr,
            isr: item.isr,
            priority_add: item.priority_add,
            irq_base: item.irq_base,
            read_reg_select: item.read_reg_select as u8,
            poll: item.poll as u8,
            special_mask: item.special_mask as u8,
            init_state: item.init_state as u8,
            auto_eoi: item.auto_eoi as u8,
            rotate_on_auto_eoi: item.rotate_on_auto_eoi as u8,
            special_fully_nested_mode: item.special_fully_nested_mode as u8,
            init4: item.use_4_byte_icw as u8,
            elcr: item.elcr,
            elcr_mask: item.elcr_mask,
        }
    }
}

impl From<&kvm_ioapic_state> for IoapicState {
    fn from(item: &kvm_ioapic_state) -> Self {
        let mut state = IoapicState {
            base_address: item.base_address,
            ioregsel: item.ioregsel,
            ioapicid: item.id,
            current_interrupt_level_bitmap: item.irr,
            redirect_table: [IoapicRedirectionTableEntry::default(); 24],
        };
        for (in_state, out_state) in item.redirtbl.iter().zip(state.redirect_table.iter_mut()) {
            *out_state = in_state.into();
        }
        state
    }
}

impl From<&IoapicRedirectionTableEntry> for kvm_ioapic_state__bindgen_ty_1 {
    fn from(item: &IoapicRedirectionTableEntry) -> Self {
        kvm_ioapic_state__bindgen_ty_1 {
            // IoapicRedirectionTableEntry layout matches the exact bit layout of a hardware
            // ioapic redirection table entry, so we can simply do a 64-bit copy
            bits: item.get(0, 64),
        }
    }
}

impl From<&kvm_ioapic_state__bindgen_ty_1> for IoapicRedirectionTableEntry {
    fn from(item: &kvm_ioapic_state__bindgen_ty_1) -> Self {
        let mut entry = IoapicRedirectionTableEntry::default();
        // Safe because the 64-bit layout of the IoapicRedirectionTableEntry matches the kvm_sys
        // table entry layout
        entry.set(0, 64, unsafe { item.bits as u64 });
        entry
    }
}

impl From<&IoapicState> for kvm_ioapic_state {
    fn from(item: &IoapicState) -> Self {
        let mut state = kvm_ioapic_state {
            base_address: item.base_address,
            ioregsel: item.ioregsel,
            id: item.ioapicid,
            irr: item.current_interrupt_level_bitmap,
            ..Default::default()
        };
        for (in_state, out_state) in item.redirect_table.iter().zip(state.redirtbl.iter_mut()) {
            *out_state = in_state.into();
        }
        state
    }
}

impl From<&LapicState> for kvm_lapic_state {
    fn from(item: &LapicState) -> Self {
        let mut state = kvm_lapic_state::default();
        // There are 64 lapic registers
        for (reg, value) in item.regs.iter().enumerate() {
            // Each lapic register is 16 bytes, but only the first 4 are used
            let reg_offset = 16 * reg;
            let sliceu8 = unsafe {
                // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
                // to_le_bytes() produces an array of u8, not i8(c_char).
                std::mem::transmute::<&mut [i8], &mut [u8]>(
                    &mut state.regs[reg_offset..reg_offset + 4],
                )
            };
            sliceu8.copy_from_slice(&value.to_le_bytes());
        }
        state
    }
}

impl From<&kvm_lapic_state> for LapicState {
    fn from(item: &kvm_lapic_state) -> Self {
        let mut state = LapicState { regs: [0; 64] };
        // There are 64 lapic registers
        for reg in 0..64 {
            // Each lapic register is 16 bytes, but only the first 4 are used
            let reg_offset = 16 * reg;
            let bytes = unsafe {
                // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
                // from_le_bytes() only works on arrays of u8, not i8(c_char).
                std::mem::transmute::<&[i8], &[u8]>(&item.regs[reg_offset..reg_offset + 4])
            };
            state.regs[reg] = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        state
    }
}

impl From<&PitState> for kvm_pit_state2 {
    fn from(item: &PitState) -> Self {
        kvm_pit_state2 {
            channels: [
                kvm_pit_channel_state::from(&item.channels[0]),
                kvm_pit_channel_state::from(&item.channels[1]),
                kvm_pit_channel_state::from(&item.channels[2]),
            ],
            flags: item.flags,
            ..Default::default()
        }
    }
}

impl From<&kvm_pit_state2> for PitState {
    fn from(item: &kvm_pit_state2) -> Self {
        PitState {
            channels: [
                PitChannelState::from(&item.channels[0]),
                PitChannelState::from(&item.channels[1]),
                PitChannelState::from(&item.channels[2]),
            ],
            flags: item.flags,
        }
    }
}

impl From<&PitChannelState> for kvm_pit_channel_state {
    fn from(item: &PitChannelState) -> Self {
        kvm_pit_channel_state {
            count: item.count,
            latched_count: item.latched_count,
            count_latched: item.count_latched as u8,
            status_latched: item.status_latched as u8,
            status: item.status,
            read_state: item.read_state as u8,
            write_state: item.write_state as u8,
            // kvm's write_latch only stores the low byte of the reload value
            write_latch: item.reload_value as u8,
            rw_mode: item.rw_mode as u8,
            mode: item.mode,
            bcd: item.bcd as u8,
            gate: item.gate as u8,
            count_load_time: item.count_load_time as i64,
        }
    }
}

impl From<&kvm_pit_channel_state> for PitChannelState {
    fn from(item: &kvm_pit_channel_state) -> Self {
        PitChannelState {
            count: item.count,
            latched_count: item.latched_count,
            count_latched: item.count_latched.into(),
            status_latched: item.status_latched != 0,
            status: item.status,
            read_state: item.read_state.into(),
            write_state: item.write_state.into(),
            // kvm's write_latch only stores the low byte of the reload value
            reload_value: item.write_latch as u16,
            rw_mode: item.rw_mode.into(),
            mode: item.mode,
            bcd: item.bcd != 0,
            gate: item.gate != 0,
            count_load_time: item.count_load_time as u64,
        }
    }
}

// This function translates an IrqSrouceChip to the kvm u32 equivalent. It has a different
// implementation between x86_64 and aarch64 because the irqchip KVM constants are not defined on
// all architectures.
pub(super) fn chip_to_kvm_chip(chip: IrqSourceChip) -> u32 {
    match chip {
        IrqSourceChip::PicPrimary => KVM_IRQCHIP_PIC_MASTER,
        IrqSourceChip::PicSecondary => KVM_IRQCHIP_PIC_SLAVE,
        IrqSourceChip::Ioapic => KVM_IRQCHIP_IOAPIC,
        _ => {
            error!("Invalid IrqChipSource for X86 {:?}", chip);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeliveryMode, DeliveryStatus, DestinationMode, HypervisorX86_64,
        IoapicRedirectionTableEntry, IoapicState, IrqRoute, IrqSource, IrqSourceChip, LapicState,
        PicInitState, PicState, PitChannelState, PitRWMode, PitRWState, PitState, TriggerMode, Vm,
    };
    use sys_util::{GuestAddress, GuestMemory};

    #[test]
    fn get_supported_cpuid() {
        let hypervisor = Kvm::new().unwrap();
        let cpuid = hypervisor.get_supported_cpuid().unwrap();
        assert!(cpuid.cpu_id_entries.len() > 0);
    }

    #[test]
    fn get_emulated_cpuid() {
        let hypervisor = Kvm::new().unwrap();
        let cpuid = hypervisor.get_emulated_cpuid().unwrap();
        assert!(cpuid.cpu_id_entries.len() > 0);
    }

    #[test]
    fn entries_double_on_error() {
        let hypervisor = Kvm::new().unwrap();
        let cpuid = hypervisor
            .get_cpuid_with_initial_capacity(KVM_GET_SUPPORTED_CPUID(), 4)
            .unwrap();
        assert!(cpuid.cpu_id_entries.len() > 4);
    }

    #[test]
    fn check_vm_arch_capability() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm).unwrap();
        assert!(vm.check_capability(VmCap::PvClock));
    }

    #[test]
    fn pic_state() {
        let state = PicState {
            last_irr: 0b00000001,
            irr: 0b00000010,
            imr: 0b00000100,
            isr: 0b00001000,
            priority_add: 0b00010000,
            irq_base: 0b00100000,
            read_reg_select: false,
            poll: true,
            special_mask: true,
            init_state: PicInitState::Icw3,
            auto_eoi: true,
            rotate_on_auto_eoi: false,
            special_fully_nested_mode: true,
            use_4_byte_icw: true,
            elcr: 0b01000000,
            elcr_mask: 0b10000000,
        };

        let kvm_state = kvm_pic_state::from(&state);

        assert_eq!(kvm_state.last_irr, 0b00000001);
        assert_eq!(kvm_state.irr, 0b00000010);
        assert_eq!(kvm_state.imr, 0b00000100);
        assert_eq!(kvm_state.isr, 0b00001000);
        assert_eq!(kvm_state.priority_add, 0b00010000);
        assert_eq!(kvm_state.irq_base, 0b00100000);
        assert_eq!(kvm_state.read_reg_select, 0);
        assert_eq!(kvm_state.poll, 1);
        assert_eq!(kvm_state.special_mask, 1);
        assert_eq!(kvm_state.init_state, 0b10);
        assert_eq!(kvm_state.auto_eoi, 1);
        assert_eq!(kvm_state.rotate_on_auto_eoi, 0);
        assert_eq!(kvm_state.special_fully_nested_mode, 1);
        assert_eq!(kvm_state.auto_eoi, 1);
        assert_eq!(kvm_state.elcr, 0b01000000);
        assert_eq!(kvm_state.elcr_mask, 0b10000000);

        let orig_state = PicState::from(&kvm_state);
        assert_eq!(state, orig_state);
    }

    #[test]
    fn ioapic_state() {
        let mut entry = IoapicRedirectionTableEntry::default();
        // default entry should be 0
        assert_eq!(entry.get(0, 64), 0);

        // set some values on our entry
        entry.set_vector(0b11111111);
        entry.set_delivery_mode(DeliveryMode::SMI);
        entry.set_dest_mode(DestinationMode::Physical);
        entry.set_delivery_status(DeliveryStatus::Pending);
        entry.set_polarity(1);
        entry.set_remote_irr(true);
        entry.set_trigger_mode(TriggerMode::Level);
        entry.set_interrupt_mask(true);
        entry.set_dest_id(0b10101010);

        // Bit repr as:  destid-reserved--------------------------------flags----vector--
        let bit_repr = 0b1010101000000000000000000000000000000000000000011111001011111111;
        // where flags is [interrupt_mask(1), trigger_mode(Level=1), remote_irr(1), polarity(1),
        //   delivery_status(Pending=1), dest_mode(Physical=0), delivery_mode(SMI=010)]

        assert_eq!(entry.get(0, 64), bit_repr);

        let state = IoapicState {
            base_address: 1,
            ioregsel: 2,
            ioapicid: 4,
            current_interrupt_level_bitmap: 8,
            redirect_table: [entry; 24],
        };

        let kvm_state = kvm_ioapic_state::from(&state);
        assert_eq!(kvm_state.base_address, 1);
        assert_eq!(kvm_state.ioregsel, 2);
        assert_eq!(kvm_state.id, 4);
        assert_eq!(kvm_state.irr, 8);
        assert_eq!(kvm_state.pad, 0);
        // check our entries
        for i in 0..24 {
            assert_eq!(unsafe { kvm_state.redirtbl[i].bits }, bit_repr);
        }

        // compare with a conversion back
        assert_eq!(state, IoapicState::from(&kvm_state));
    }

    #[test]
    fn lapic_state() {
        let mut state = LapicState { regs: [0; 64] };
        // Apic id register, 4 bytes each with a different bit set
        state.regs[2] = 1 | 2 << 8 | 4 << 16 | 8 << 24;

        let kvm_state = kvm_lapic_state::from(&state);

        // check little endian bytes in kvm_state
        for i in 0..4 {
            assert_eq!(
                unsafe { std::mem::transmute::<i8, u8>(kvm_state.regs[32 + i]) } as u8,
                2u8.pow(i as u32)
            );
        }

        // Test converting back to a LapicState
        assert_eq!(state, LapicState::from(&kvm_state));
    }

    #[test]
    fn pit_state() {
        let channel = PitChannelState {
            count: 256,
            latched_count: 512,
            count_latched: PitRWState::LSB,
            status_latched: false,
            status: 7,
            read_state: PitRWState::MSB,
            write_state: PitRWState::Word1,
            reload_value: 8,
            rw_mode: PitRWMode::Both,
            mode: 5,
            bcd: false,
            gate: true,
            count_load_time: 1024,
        };

        let kvm_channel = kvm_pit_channel_state::from(&channel);

        // compare the various field translations
        assert_eq!(kvm_channel.count, 256);
        assert_eq!(kvm_channel.latched_count, 512);
        assert_eq!(kvm_channel.count_latched, 1);
        assert_eq!(kvm_channel.status_latched, 0);
        assert_eq!(kvm_channel.status, 7);
        assert_eq!(kvm_channel.read_state, 2);
        assert_eq!(kvm_channel.write_state, 4);
        assert_eq!(kvm_channel.write_latch, 8);
        assert_eq!(kvm_channel.rw_mode, 3);
        assert_eq!(kvm_channel.mode, 5);
        assert_eq!(kvm_channel.bcd, 0);
        assert_eq!(kvm_channel.gate, 1);
        assert_eq!(kvm_channel.count_load_time, 1024);

        // convert back and compare
        assert_eq!(channel, PitChannelState::from(&kvm_channel));

        // convert the full pitstate
        let state = PitState {
            channels: [channel, channel, channel],
            flags: 255,
        };
        let kvm_state = kvm_pit_state2::from(&state);

        assert_eq!(kvm_state.flags, 255);

        // compare a channel
        assert_eq!(channel, PitChannelState::from(&kvm_state.channels[0]));
        // convert back and compare
        assert_eq!(state, PitState::from(&kvm_state));
    }

    #[test]
    fn clock_handling() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm).unwrap();
        let mut clock_data = vm.get_pvclock().unwrap();
        clock_data.clock += 1000;
        vm.set_pvclock(&clock_data).unwrap();
    }

    #[test]
    fn set_gsi_routing() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm).unwrap();
        vm.create_irq_chip().unwrap();
        vm.set_gsi_routing(&[]).unwrap();
        vm.set_gsi_routing(&[IrqRoute {
            gsi: 1,
            source: IrqSource::Irqchip {
                chip: IrqSourceChip::Ioapic,
                pin: 3,
            },
        }])
        .unwrap();
        vm.set_gsi_routing(&[IrqRoute {
            gsi: 1,
            source: IrqSource::Msi {
                address: 0xf000000,
                data: 0xa0,
            },
        }])
        .unwrap();
        vm.set_gsi_routing(&[
            IrqRoute {
                gsi: 1,
                source: IrqSource::Irqchip {
                    chip: IrqSourceChip::Ioapic,
                    pin: 3,
                },
            },
            IrqRoute {
                gsi: 2,
                source: IrqSource::Msi {
                    address: 0xf000000,
                    data: 0xa0,
                },
            },
        ])
        .unwrap();
    }
}
