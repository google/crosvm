// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Software implementation of an Intel 8259A Programmable Interrupt Controller
// This is a legacy device used by older OSs and briefly during start-up by
// modern OSs that use a legacy BIOS.
// The PIC is connected to the Local APIC on CPU0.

// Terminology note: The 8259A spec refers to "master" and "slave" PITs; the "slave"s are daisy
// chained to the "master"s.
// For the purposes of both using more descriptive terms and avoiding terms with lots of charged
// emotional context, this file refers to them instead as "primary" and "secondary" PITs.

use crate::BusDevice;
use sys_util::{debug, warn};

#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum PicSelect {
    Primary = 0,
    Secondary = 1,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PicInitState {
    Icw1 = 0,
    Icw2 = 1,
    Icw3 = 2,
    Icw4 = 3,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct PicState {
    last_irr: u8,     // Edge detection.
    irr: u8,          // Interrupt Request Register.
    imr: u8,          // Interrupt Mask Register.
    isr: u8,          // Interrupt Service Register.
    priority_add: u8, // Highest priority, for priority rotation.
    irq_base: u8,
    read_reg_select: bool,
    poll: bool,
    special_mask: bool,
    auto_eoi: bool,
    rotate_on_auto_eoi: bool,
    special_fully_nested_mode: bool,
    // PIC takes either 3 or 4 bytes of initialization command word during
    // initialization. use_4_byte_icw is true if 4 bytes of ICW are needed.
    use_4_byte_icw: bool,
    // "Edge/Level Control Registers", for edge trigger selection.
    // When a particular bit is set, the corresponding IRQ is in level-triggered mode. Otherwise it
    // is in edge-triggered mode.
    elcr: u8,
    elcr_mask: u8,
    init_state: Option<PicInitState>,
}

pub struct Pic {
    // TODO(mutexlox): Implement an APIC and add necessary state to the Pic.

    // index 0 (aka PicSelect::Primary) is the primary pic, the rest are secondary.
    pics: [PicState; 2],
}

const PIC_NUM_PINS: u8 = 16;

// Register offsets.
const PIC_PRIMARY: u64 = 0x20;
const PIC_PRIMARY_COMMAND: u64 = PIC_PRIMARY;
const PIC_PRIMARY_DATA: u64 = PIC_PRIMARY + 1;
const PIC_PRIMARY_ELCR: u64 = 0x4d0;

const PIC_SECONDARY: u64 = 0xa0;
const PIC_SECONDARY_COMMAND: u64 = PIC_SECONDARY;
const PIC_SECONDARY_DATA: u64 = PIC_SECONDARY + 1;
const PIC_SECONDARY_ELCR: u64 = 0x4d1;

const LEVEL_HIGH: bool = true;
const LEVEL_LOW: bool = false;
const INVALID_PRIORITY: u8 = 8;
const SPURIOUS_IRQ: u8 = 0x07;
const PRIMARY_PIC_CASCADE_PIN: u8 = 2;
const PRIMARY_PIC_CASCADE_PIN_MASK: u8 = 0x04;
const PRIMARY_PIC_MAX_IRQ: u8 = 7;

// Command Words
const ICW1_MASK: u8 = 0x10;
const OCW3_MASK: u8 = 0x08;

// ICW1 bits
const ICW1_NEED_ICW4: u8 = 0x01; // ICW4 needed
const ICW1_SINGLE_PIC_MODE: u8 = 0x02;
const ICW1_LEVEL_TRIGGER_MODE: u8 = 0x08;

const ICW2_IRQ_BASE_MASK: u8 = 0xf8;

const ICW4_SPECIAL_FULLY_NESTED_MODE: u8 = 0x10;
const ICW4_AUTO_EOI: u8 = 0x02;

// OCW2 bits
const OCW2_IRQ_MASK: u8 = 0x07;
const OCW2_COMMAND_MASK: u8 = 0xe0;
#[derive(Debug, Clone, Copy, PartialEq, enumn::N)]
enum Ocw2 {
    RotateAutoEoiClear = 0x00,
    NonSpecificEoi = 0x20,
    NoOp = 0x40,
    SpecificEoi = 0x60,
    RotateAutoEoiSet = 0x80,
    RotateNonSpecificEoi = 0xa0,
    SetPriority = 0xc0,
    RotateSpecificEoi = 0xe0,
}

// OCW3 bits
const OCW3_POLL_COMMAND: u8 = 0x04;
const OCW3_READ_REGISTER: u8 = 0x02;
// OCW3_READ_IRR (0x00) intentionally omitted.
const OCW3_READ_ISR: u8 = 0x01;
const OCW3_SPECIAL_MASK: u8 = 0x40;
const OCW3_SPECIAL_MASK_VALUE: u8 = 0x20;

impl BusDevice for Pic {
    fn debug_label(&self) -> String {
        "userspace PIC".to_string()
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            warn!("PIC: Bad write size: {}", data.len());
            return;
        }
        match offset {
            PIC_PRIMARY_COMMAND => self.pic_write_command(PicSelect::Primary, data[0]),
            PIC_PRIMARY_DATA => self.pic_write_data(PicSelect::Primary, data[0]),
            PIC_PRIMARY_ELCR => self.pic_write_elcr(PicSelect::Primary, data[0]),
            PIC_SECONDARY_COMMAND => self.pic_write_command(PicSelect::Secondary, data[0]),
            PIC_SECONDARY_DATA => self.pic_write_data(PicSelect::Secondary, data[0]),
            PIC_SECONDARY_ELCR => self.pic_write_elcr(PicSelect::Secondary, data[0]),
            _ => warn!("PIC: Invalid write to offset {}", offset),
        }
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            warn!("PIC: Bad read size: {}", data.len());
            return;
        }
        data[0] = match offset {
            PIC_PRIMARY_COMMAND => self.pic_read_command(PicSelect::Primary),
            PIC_PRIMARY_DATA => self.pic_read_data(PicSelect::Primary),
            PIC_PRIMARY_ELCR => self.pic_read_elcr(PicSelect::Primary),
            PIC_SECONDARY_COMMAND => self.pic_read_command(PicSelect::Secondary),
            PIC_SECONDARY_DATA => self.pic_read_data(PicSelect::Secondary),
            PIC_SECONDARY_ELCR => self.pic_read_elcr(PicSelect::Secondary),
            _ => {
                warn!("PIC: Invalid read from offset {}", offset);
                return;
            }
        };
    }
}

impl Pic {
    pub fn new() -> Pic {
        let mut primary_pic: PicState = Default::default();
        let mut secondary_pic: PicState = Default::default();
        // These two masks are taken from KVM code (but do not appear in the 8259 specification).

        // These IRQ lines are edge triggered, and so have 0 bits in the masks:
        //   - IRQs 0, 1, 8, and 13 are dedicated to special I/O devices on the system board.
        //   - IRQ 2 is the primary pic's cascade line.
        // The primary pic has IRQs 0-7.
        primary_pic.elcr_mask = !((1 << 0) | (1 << 1) | (1 << 2));
        // The secondary PIC has IRQs 8-15, so we subtract 8 from the IRQ number to get the bit
        // that should be masked here. In this case, bits 8 - 8 = 0 and 13 - 8 = 5.
        secondary_pic.elcr_mask = !((1 << 0) | (1 << 5));
        // TODO(mutexlox): Add logic to initialize APIC interrupt-related fields.

        Pic {
            pics: [primary_pic, secondary_pic],
        }
    }

    pub fn service_irq(&mut self, irq: u8, level: bool) -> bool {
        assert!(irq <= 15, "Unexpectedly high value irq: {} vs 15", irq);

        let pic = if irq <= PRIMARY_PIC_MAX_IRQ {
            PicSelect::Primary
        } else {
            PicSelect::Secondary
        };
        Pic::set_irq_internal(&mut self.pics[pic as usize], irq & 7, level);

        self.update_irq()
    }

    /// Determines whether the (primary) PIC is completely masked.
    pub fn masked(&self) -> bool {
        self.pics[PicSelect::Primary as usize].imr == 0xFF
    }

    /// Determines whether the PIC has an interrupt ready.
    pub fn has_interrupt(&self) -> bool {
        self.get_irq(PicSelect::Primary).is_some()
    }

    /// Determines the external interrupt number that the PIC is prepared to inject, if any.
    pub fn get_external_interrupt(&mut self) -> Option<u8> {
        let irq_primary = if let Some(irq) = self.get_irq(PicSelect::Primary) {
            irq
        } else {
            // The architecturally correct behavior in this case is to inject a spurious interrupt.
            // Although this case only occurs as a result of a race condition where the interrupt
            // might also be avoided entirely.  Here we return `None` to avoid the interrupt
            // entirely.  The KVM unit test OS, which several unit tests rely upon, doesn't
            // properly handle spurious interrupts.  Also spurious interrupts are much more common
            // in this code than real hardware because the hardware race is much much much smaller.
            return None;
        };

        Pic::interrupt_ack(&mut self.pics[PicSelect::Primary as usize], irq_primary);
        let int_num = if irq_primary == PRIMARY_PIC_CASCADE_PIN {
            // IRQ on secondary pic.
            let irq_secondary = if let Some(irq) = self.get_irq(PicSelect::Secondary) {
                Pic::interrupt_ack(&mut self.pics[PicSelect::Secondary as usize], irq);
                irq
            } else {
                SPURIOUS_IRQ
            };
            self.pics[PicSelect::Secondary as usize].irq_base + irq_secondary
        } else {
            self.pics[PicSelect::Primary as usize].irq_base + irq_primary
        };

        self.update_irq();
        Some(int_num)
    }

    fn pic_read_command(&mut self, pic_type: PicSelect) -> u8 {
        if self.pics[pic_type as usize].poll {
            let (ret, update_irq_needed) = self.poll_read(pic_type);
            self.pics[pic_type as usize].poll = false;

            if update_irq_needed {
                self.update_irq();
            }

            ret
        } else if self.pics[pic_type as usize].read_reg_select {
            self.pics[pic_type as usize].isr
        } else {
            self.pics[pic_type as usize].irr
        }
    }

    fn pic_read_data(&mut self, pic_type: PicSelect) -> u8 {
        if self.pics[pic_type as usize].poll {
            let (ret, update_needed) = self.poll_read(pic_type);
            self.pics[pic_type as usize].poll = false;
            if update_needed {
                self.update_irq();
            }
            ret
        } else {
            self.pics[pic_type as usize].imr
        }
    }

    fn pic_read_elcr(&mut self, pic_type: PicSelect) -> u8 {
        self.pics[pic_type as usize].elcr
    }

    fn pic_write_command(&mut self, pic_type: PicSelect, value: u8) {
        if value & ICW1_MASK != 0 {
            Pic::init_command_word_1(&mut self.pics[pic_type as usize], value);
        } else if value & OCW3_MASK != 0 {
            Pic::operation_command_word_3(&mut self.pics[pic_type as usize], value);
        } else {
            self.operation_command_word_2(pic_type, value);
        }
    }

    fn pic_write_data(&mut self, pic_type: PicSelect, value: u8) {
        match self.pics[pic_type as usize].init_state {
            Some(PicInitState::Icw1) | None => {
                if self.pics[pic_type as usize].init_state.is_none() {
                    debug!(
                        "PIC: {:?}: Uninitialized data write of {:#x}",
                        pic_type, value
                    );
                }
                self.pics[pic_type as usize].imr = value;
                self.update_irq();
            }
            Some(PicInitState::Icw2) => {
                self.pics[pic_type as usize].irq_base = value & ICW2_IRQ_BASE_MASK;
                self.pics[pic_type as usize].init_state = Some(PicInitState::Icw3);
            }
            Some(PicInitState::Icw3) => {
                if self.pics[pic_type as usize].use_4_byte_icw {
                    self.pics[pic_type as usize].init_state = Some(PicInitState::Icw4);
                } else {
                    self.pics[pic_type as usize].init_state = Some(PicInitState::Icw1);
                }
            }
            Some(PicInitState::Icw4) => {
                self.pics[pic_type as usize].special_fully_nested_mode =
                    (value & ICW4_SPECIAL_FULLY_NESTED_MODE) != 0;
                self.pics[pic_type as usize].auto_eoi = (value & ICW4_AUTO_EOI) != 0;
                self.pics[pic_type as usize].init_state = Some(PicInitState::Icw1);
            }
        }
    }

    fn pic_write_elcr(&mut self, pic_type: PicSelect, value: u8) {
        self.pics[pic_type as usize].elcr = value & !self.pics[pic_type as usize].elcr;
    }

    fn reset_pic(pic: &mut PicState) {
        let edge_irr = pic.irr & !pic.elcr;

        pic.last_irr = 0;
        pic.irr &= pic.elcr;
        pic.imr = 0;
        pic.priority_add = 0;
        pic.special_mask = false;
        pic.read_reg_select = false;
        if !pic.use_4_byte_icw {
            pic.special_fully_nested_mode = false;
            pic.auto_eoi = false;
        }
        pic.init_state = Some(PicInitState::Icw2);

        for irq in 0..PIC_NUM_PINS / 2 {
            if edge_irr & (1 << irq) != 0 {
                Pic::clear_isr(pic, irq);
            }
        }
    }

    /// Determine the priority and whether an update_irq call is needed.
    fn poll_read(&mut self, pic_type: PicSelect) -> (u8, bool) {
        if let Some(mut irq) = self.get_irq(pic_type) {
            irq &= 0xff;
            if pic_type == PicSelect::Secondary {
                self.pics[PicSelect::Primary as usize].isr &= !PRIMARY_PIC_CASCADE_PIN_MASK;
                self.pics[PicSelect::Primary as usize].irr &= !PRIMARY_PIC_CASCADE_PIN_MASK;
            }
            self.pics[pic_type as usize].irr &= !(1 << irq);
            Pic::clear_isr(&mut self.pics[pic_type as usize], irq);
            let update_irq_needed =
                pic_type == PicSelect::Secondary && irq != PRIMARY_PIC_CASCADE_PIN;
            (irq, update_irq_needed)
        } else {
            // Spurious interrupt
            (SPURIOUS_IRQ, true)
        }
    }

    fn get_irq(&self, pic_type: PicSelect) -> Option<u8> {
        let pic = &self.pics[pic_type as usize];
        let mut irq_bitmap = pic.irr & !pic.imr;
        let priority = if let Some(p) = Pic::get_priority(pic, irq_bitmap) {
            p
        } else {
            return None;
        };

        // If the primary is in fully-nested mode, the IRQ coming from the secondary is not taken
        // into account for the priority computation below.
        irq_bitmap = pic.isr;
        if pic_type == PicSelect::Primary && pic.special_fully_nested_mode {
            irq_bitmap &= !PRIMARY_PIC_CASCADE_PIN_MASK;
        }
        let new_priority = Pic::get_priority(pic, irq_bitmap).unwrap_or(INVALID_PRIORITY);
        if priority < new_priority {
            // Higher priority found. IRQ should be generated.
            Some((priority + pic.priority_add) & 7)
        } else {
            None
        }
    }

    fn clear_isr(pic: &mut PicState, irq: u8) {
        assert!(irq <= 7, "Unexpectedly high value for irq: {} vs 7", irq);
        pic.isr &= !(1 << irq);
    }

    fn update_irq(&mut self) -> bool {
        if self.get_irq(PicSelect::Secondary).is_some() {
            // If secondary pic has an IRQ request, signal primary's cascade pin.
            Pic::set_irq_internal(
                &mut self.pics[PicSelect::Primary as usize],
                PRIMARY_PIC_CASCADE_PIN,
                LEVEL_HIGH,
            );
            Pic::set_irq_internal(
                &mut self.pics[PicSelect::Primary as usize],
                PRIMARY_PIC_CASCADE_PIN,
                LEVEL_LOW,
            );
        }

        if self.get_irq(PicSelect::Primary).is_some() {
            // TODO(mutexlox): Signal local interrupt on APIC bus.
            // Note: this does not check if the interrupt is succesfully injected into
            // the CPU, just whether or not one is fired.
            true
        } else {
            false
        }
    }

    /// Set Irq level. If edge is detected, then IRR is set to 1.
    fn set_irq_internal(pic: &mut PicState, irq: u8, level: bool) {
        assert!(irq <= 7, "Unexpectedly high value for irq: {} vs 7", irq);
        let irq_bitmap = 1 << irq;
        if (pic.elcr & irq_bitmap) != 0 {
            // Level-triggered.
            if level {
                // Same IRQ already requested.
                pic.irr |= irq_bitmap;
                pic.last_irr |= irq_bitmap;
            } else {
                pic.irr &= !irq_bitmap;
                pic.last_irr &= !irq_bitmap;
            }
        } else {
            // Edge-triggered
            if level {
                if (pic.last_irr & irq_bitmap) == 0 {
                    // Raising edge detected.
                    pic.irr |= irq_bitmap;
                }
                pic.last_irr |= irq_bitmap;
            } else {
                pic.last_irr &= !irq_bitmap;
            }
        }
    }

    fn get_priority(pic: &PicState, irq_bitmap: u8) -> Option<u8> {
        if irq_bitmap == 0 {
            None
        } else {
            // Find the highest priority bit in irq_bitmap considering the priority
            // rotation mechanism (priority_add).
            let mut priority = 0;
            let mut priority_mask = 1 << ((priority + pic.priority_add) & 7);
            while (irq_bitmap & priority_mask) == 0 {
                priority += 1;
                priority_mask = 1 << ((priority + pic.priority_add) & 7);
            }
            Some(priority)
        }
    }

    /// Move interrupt from IRR to ISR to indicate that the interrupt is injected. If
    /// auto EOI is set, then ISR is immediately cleared (since the purpose of EOI is
    /// to clear ISR bit).
    fn interrupt_ack(pic: &mut PicState, irq: u8) {
        assert!(irq <= 7, "Unexpectedly high value for irq: {} vs 7", irq);

        let irq_bitmap = 1 << irq;
        pic.isr |= irq_bitmap;

        if (pic.elcr & irq_bitmap) == 0 {
            pic.irr &= !irq_bitmap;
        }

        if pic.auto_eoi {
            if pic.rotate_on_auto_eoi {
                pic.priority_add = (irq + 1) & 7;
            }
            Pic::clear_isr(pic, irq);
        }
    }

    fn init_command_word_1(pic: &mut PicState, value: u8) {
        pic.use_4_byte_icw = (value & ICW1_NEED_ICW4) != 0;
        if (value & ICW1_SINGLE_PIC_MODE) != 0 {
            debug!("PIC: Single PIC mode not supported.");
        }
        if (value & ICW1_LEVEL_TRIGGER_MODE) != 0 {
            debug!("PIC: Level triggered IRQ not supported.");
        }
        Pic::reset_pic(pic);
    }

    fn operation_command_word_2(&mut self, pic_type: PicSelect, value: u8) {
        let mut irq = value & OCW2_IRQ_MASK;
        if let Some(cmd) = Ocw2::n(value & OCW2_COMMAND_MASK) {
            match cmd {
                Ocw2::RotateAutoEoiSet => self.pics[pic_type as usize].rotate_on_auto_eoi = true,
                Ocw2::RotateAutoEoiClear => self.pics[pic_type as usize].rotate_on_auto_eoi = false,
                Ocw2::NonSpecificEoi | Ocw2::RotateNonSpecificEoi => {
                    if let Some(priority) = Pic::get_priority(
                        &self.pics[pic_type as usize],
                        self.pics[pic_type as usize].isr,
                    ) {
                        irq = (priority + self.pics[pic_type as usize].priority_add) & 7;
                        if cmd == Ocw2::RotateNonSpecificEoi {
                            self.pics[pic_type as usize].priority_add = (irq + 1) & 7;
                        }
                        Pic::clear_isr(&mut self.pics[pic_type as usize], irq);
                        self.update_irq();
                    }
                }
                Ocw2::SpecificEoi => {
                    Pic::clear_isr(&mut self.pics[pic_type as usize], irq);
                    self.update_irq();
                }
                Ocw2::SetPriority => {
                    self.pics[pic_type as usize].priority_add = (irq + 1) & 7;
                    self.update_irq();
                }
                Ocw2::RotateSpecificEoi => {
                    self.pics[pic_type as usize].priority_add = (irq + 1) & 7;
                    Pic::clear_isr(&mut self.pics[pic_type as usize], irq);
                    self.update_irq();
                }
                Ocw2::NoOp => {} /* noop */
            }
        }
    }

    fn operation_command_word_3(pic: &mut PicState, value: u8) {
        if value & OCW3_POLL_COMMAND != 0 {
            pic.poll = true;
        }
        if value & OCW3_READ_REGISTER != 0 {
            // Select to read ISR or IRR
            pic.read_reg_select = value & OCW3_READ_ISR != 0;
        }
        if value & OCW3_SPECIAL_MASK != 0 {
            pic.special_mask = value & OCW3_SPECIAL_MASK_VALUE != 0;
        }
    }
}

#[cfg(test)]
mod tests {
    // ICW4: Special fully nested mode with no auto EOI.
    const FULLY_NESTED_NO_AUTO_EOI: u8 = 0x11;
    use super::*;

    struct TestData {
        pic: Pic,
    }

    fn set_up() -> TestData {
        let mut pic = Pic::new();
        // Use edge-triggered mode.
        pic.write(PIC_PRIMARY_ELCR, &[0]);
        pic.write(PIC_SECONDARY_ELCR, &[0]);
        TestData { pic }
    }

    /// Convenience wrapper to initialize PIC using 4 ICWs. Validity of values is NOT checked.
    fn icw_init(pic: &mut Pic, pic_type: PicSelect, icw1: u8, icw2: u8, icw3: u8, icw4: u8) {
        let command_offset = match pic_type {
            PicSelect::Primary => PIC_PRIMARY_COMMAND,
            PicSelect::Secondary => PIC_SECONDARY_COMMAND,
        };
        let data_offset = match pic_type {
            PicSelect::Primary => PIC_PRIMARY_DATA,
            PicSelect::Secondary => PIC_SECONDARY_DATA,
        };

        pic.write(command_offset, &[icw1]);
        pic.write(data_offset, &[icw2]);
        pic.write(data_offset, &[icw3]);
        pic.write(data_offset, &[icw4]);
    }

    /// Convenience function for primary ICW init.
    fn icw_init_primary(pic: &mut Pic) {
        // ICW1 0x11: Edge trigger, cascade mode, ICW4 needed.
        // ICW2 0x08: Interrupt vector base address 0x08.
        // ICW3 0xff: Value written does not matter.
        // ICW4 0x13: Special fully nested mode, auto EOI.
        icw_init(pic, PicSelect::Primary, 0x11, 0x08, 0xff, 0x13);
    }

    /// Convenience function for secondary ICW init.
    fn icw_init_secondary(pic: &mut Pic) {
        // ICW1 0x11: Edge trigger, cascade mode, ICW4 needed.
        // ICW2 0x70: Interrupt vector base address 0x70.
        // ICW3 0xff: Value written does not matter.
        // ICW4 0x13: Special fully nested mode, auto EOI.
        icw_init(pic, PicSelect::Secondary, 0x11, 0x70, 0xff, 0x13);
    }

    /// Convenience function for initializing ICW with custom value for ICW4.
    fn icw_init_both_with_icw4(pic: &mut Pic, icw4: u8) {
        // ICW1 0x11: Edge trigger, cascade mode, ICW4 needed.
        // ICW2 0x08: Interrupt vector base address 0x08.
        // ICW3 0xff: Value written does not matter.
        icw_init(pic, PicSelect::Primary, 0x11, 0x08, 0xff, icw4);
        // ICW1 0x11: Edge trigger, cascade mode, ICW4 needed.
        // ICW2 0x70: Interrupt vector base address 0x70.
        // ICW3 0xff: Value written does not matter.
        icw_init(pic, PicSelect::Secondary, 0x11, 0x70, 0xff, icw4);
    }

    fn icw_init_both(pic: &mut Pic) {
        icw_init_primary(pic);
        icw_init_secondary(pic);
    }

    /// Test that elcr register can be written and read correctly.
    #[test]
    fn write_read_elcr() {
        let mut data = set_up();
        let data_write = [0x5f];
        let mut data_read = [0];

        data.pic.write(PIC_PRIMARY_ELCR, &data_write);
        data.pic.read(PIC_PRIMARY_ELCR, &mut data_read);
        assert_eq!(data_read, data_write);

        data.pic.write(PIC_SECONDARY_ELCR, &data_write);
        data.pic.read(PIC_SECONDARY_ELCR, &mut data_read);
        assert_eq!(data_read, data_write);
    }

    /// Test the three-word ICW.
    #[test]
    fn icw_2_step() {
        let mut data = set_up();

        // ICW1
        let mut data_write = [0x10];
        data.pic.write(PIC_PRIMARY_COMMAND, &data_write);

        data_write[0] = 0x08;
        data.pic.write(PIC_PRIMARY_DATA, &data_write);

        data_write[0] = 0xff;
        data.pic.write(PIC_PRIMARY_DATA, &data_write);

        assert_eq!(
            data.pic.pics[PicSelect::Primary as usize].init_state,
            Some(PicInitState::Icw1)
        );
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].irq_base, 0x08);
        assert_eq!(
            data.pic.pics[PicSelect::Primary as usize].use_4_byte_icw,
            false
        );
    }

    /// Verify that PIC is in expected state after initialization.
    #[test]
    fn initial_values() {
        let mut data = set_up();
        icw_init_primary(&mut data.pic);

        let primary_pic = &data.pic.pics[PicSelect::Primary as usize];
        assert_eq!(primary_pic.last_irr, 0x00);
        assert_eq!(primary_pic.irr, 0x00);
        assert_eq!(primary_pic.imr, 0x00);
        assert_eq!(primary_pic.isr, 0x00);
        assert_eq!(primary_pic.priority_add, 0);
        assert_eq!(primary_pic.irq_base, 0x08);
        assert_eq!(primary_pic.read_reg_select, false);
        assert_eq!(primary_pic.poll, false);
        assert_eq!(primary_pic.special_mask, false);
        assert_eq!(primary_pic.init_state, Some(PicInitState::Icw1));
        assert_eq!(primary_pic.auto_eoi, true);
        assert_eq!(primary_pic.rotate_on_auto_eoi, false);
        assert_eq!(primary_pic.special_fully_nested_mode, true);
        assert_eq!(primary_pic.use_4_byte_icw, true);
        assert_eq!(primary_pic.elcr, 0x00);
        assert_eq!(primary_pic.elcr_mask, 0xf8);
    }

    /// Verify effect that OCW has on PIC registers & state.
    #[test]
    fn ocw() {
        let mut data = set_up();

        icw_init_secondary(&mut data.pic);

        // OCW1: Write to IMR.
        data.pic.write(PIC_SECONDARY_DATA, &[0x5f]);

        // OCW2: Set rotate on auto EOI.
        data.pic.write(PIC_SECONDARY_COMMAND, &[0x80]);

        // OCW2: Set priority.
        data.pic.write(PIC_SECONDARY_COMMAND, &[0xc0]);

        // OCW3: Change flags.
        data.pic.write(PIC_SECONDARY_COMMAND, &[0x6b]);

        let mut data_read = [0];
        data.pic.read(PIC_SECONDARY_DATA, &mut data_read);
        assert_eq!(data_read, [0x5f]);

        let secondary_pic = &data.pic.pics[PicSelect::Secondary as usize];

        // Check OCW1 result.
        assert_eq!(secondary_pic.imr, 0x5f);

        // Check OCW2 result.
        assert!(secondary_pic.rotate_on_auto_eoi);
        assert_eq!(secondary_pic.priority_add, 1);

        // Check OCW3 result.
        assert!(secondary_pic.special_mask);
        assert_eq!(secondary_pic.poll, false);
        assert!(secondary_pic.read_reg_select);
    }

    /// Verify that we can set and clear the AutoRotate bit in OCW.
    #[test]
    fn ocw_auto_rotate_set_and_clear() {
        let mut data = set_up();

        icw_init_secondary(&mut data.pic);

        // OCW2: Set rotate on auto EOI.
        data.pic.write(PIC_SECONDARY_COMMAND, &[0x80]);

        let secondary_pic = &data.pic.pics[PicSelect::Secondary as usize];
        assert!(secondary_pic.rotate_on_auto_eoi);

        // OCW2: Clear rotate on auto EOI.
        data.pic.write(PIC_SECONDARY_COMMAND, &[0x00]);

        let secondary_pic = &data.pic.pics[PicSelect::Secondary as usize];
        assert!(!secondary_pic.rotate_on_auto_eoi);
    }

    /// Test basic auto EOI case.
    #[test]
    fn auto_eoi() {
        let mut data = set_up();

        icw_init_both(&mut data.pic);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 12, /*level=*/ true);

        // Check that IRQ is requesting acknowledgment.
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].irr, (1 << 4));
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].isr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].irr, (1 << 2));
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 0);

        // 0x70 is interrupt base on secondary PIC. 0x70 + 4 is the interrupt entry number.
        assert_eq!(data.pic.get_external_interrupt(), Some(0x70 + 4));

        // Check that IRQ is acknowledged and EOI is automatically done.
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].irr, 0);
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].isr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].irr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 0);
    }

    /// Test with fully-nested mode on. When the secondary PIC has an IRQ in service, it shouldn't
    /// be locked out by the primary's priority logic.
    /// This means that the secondary should still be able to request a higher-priority IRQ.
    /// Auto EOI is off in order to keep IRQ in service.
    #[test]
    fn fully_nested_mode_on() {
        let mut data = set_up();

        icw_init_both_with_icw4(&mut data.pic, FULLY_NESTED_NO_AUTO_EOI);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 12, /*level=*/ true);
        assert_eq!(data.pic.get_external_interrupt(), Some(0x70 + 4));

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        // Request higher-priority IRQ on secondary.
        data.pic.service_irq(/*irq=*/ 8, /*level=*/ true);
        assert_eq!(data.pic.get_external_interrupt(), Some(0x70 + 0));

        // Check that IRQ is ack'd and EOI is automatically done.
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].irr, 0);
        assert_eq!(
            data.pic.pics[PicSelect::Secondary as usize].isr,
            (1 << 4) + (1 << 0)
        );
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].irr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 1 << 2);
    }

    /// Test with fully-nested mode off. When the secondary PIC has an IRQ in service, it should
    /// NOT be able to request another higher-priority IRQ.
    /// Auto EOI is off in order to keep IRQ in service.
    #[test]
    fn fully_nested_mode_off() {
        let mut data = set_up();

        // ICW4 0x01: No special fully nested mode, no auto EOI.
        icw_init_both_with_icw4(&mut data.pic, 0x01);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 12, /*level=*/ true);
        assert_eq!(data.pic.get_external_interrupt(), Some(0x70 + 4));

        data.pic.service_irq(/*irq=*/ 8, /*level=*/ true);
        // Primary cannot get any IRQ, so this should not provide any interrupt.
        assert_eq!(data.pic.get_external_interrupt(), None);

        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].irr, 1 << 0);
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].isr, 1 << 4);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].irr, 1 << 2);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 1 << 2);

        // 2 EOIs will cause 2 interrupts.
        // TODO(mutexlox): Verify APIC interaction when it is implemented.

        // OCW2: Non-specific EOI, one for primary and one for secondary.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x20]);
        data.pic.write(PIC_SECONDARY_COMMAND, &[0x20]);

        // Now that the first IRQ is no longer in service, the second IRQ can be ack'd.
        assert_eq!(data.pic.get_external_interrupt(), Some(0x70 + 0));

        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].irr, 0);
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].isr, 1 << 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].irr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 1 << 2);
    }

    /// Write IMR to mask an IRQ. The masked IRQ can't be served until unmasked.
    #[test]
    fn mask_irq() {
        let mut data = set_up();

        icw_init_both_with_icw4(&mut data.pic, FULLY_NESTED_NO_AUTO_EOI);

        // OCW2: Mask IRQ line 6 on secondary (IRQ 14).
        data.pic.write(PIC_SECONDARY_DATA, &[0x40]);

        data.pic.service_irq(/*irq=*/ 14, /*level=*/ true);
        assert_eq!(data.pic.get_external_interrupt(), None);

        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].irr, 1 << 6);
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].isr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].irr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 0);

        // OCW2: Unmask IRQ line 6 on secondary (IRQ 14)
        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.write(PIC_SECONDARY_DATA, &[0x00]);

        // Previously-masked interrupt can now be served.
        assert_eq!(data.pic.get_external_interrupt(), Some(0x70 + 6));

        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].irr, 0);
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].isr, 1 << 6);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].irr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 1 << 2);
    }

    /// Write IMR to mask multiple IRQs. They masked IRQs cannot be served until they're unmasked.
    /// The highest priority IRQ must be served first, no matter the original order of request.
    /// (To simplify the test, we won't check irr and isr and so we'll leave auto EOI on.)
    #[test]
    fn mask_multiple_irq() {
        let mut data = set_up();
        icw_init_both(&mut data.pic);

        // OCW2: Mask *all* IRQ lines on primary and secondary.
        data.pic.write(PIC_PRIMARY_DATA, &[0xff]);
        data.pic.write(PIC_SECONDARY_DATA, &[0xff]);

        data.pic.service_irq(/*irq=*/ 14, /*level=*/ true);
        data.pic.service_irq(/*irq=*/ 4, /*level=*/ true);
        data.pic.service_irq(/*irq=*/ 12, /*level=*/ true);

        // Primary cannot get any IRQs since they're all masked.
        assert_eq!(data.pic.get_external_interrupt(), None);

        // OCW2: Unmask IRQ lines on secondary.
        data.pic.write(PIC_SECONDARY_DATA, &[0x00]);

        // Cascade line is masked, so the primary *still* cannot get any IRQs.
        assert_eq!(data.pic.get_external_interrupt(), None);

        // Unmask cascade line on primary.
        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.write(PIC_PRIMARY_DATA, &[0xfb]);

        // Previously-masked IRQs should now be served in order of priority.
        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        assert_eq!(data.pic.get_external_interrupt(), Some(0x70 + 4));
        assert_eq!(data.pic.get_external_interrupt(), Some(0x70 + 6));

        // Unmask all other IRQ lines on primary.
        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.write(PIC_PRIMARY_DATA, &[0x00]);
        assert_eq!(data.pic.get_external_interrupt(), Some(0x08 + 4));
    }

    /// Test OCW3 poll (reading irr and isr).
    #[test]
    fn ocw3() {
        let mut data = set_up();
        icw_init_both_with_icw4(&mut data.pic, FULLY_NESTED_NO_AUTO_EOI);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        // Poplate some data on irr/isr. IRQ4 will be in isr and IRQ5 in irr.
        data.pic.service_irq(/*irq=*/ 5, /*level=*/ true);
        data.pic.service_irq(/*irq=*/ 4, /*level=*/ true);
        assert_eq!(data.pic.get_external_interrupt(), Some(0x08 + 4));

        // Read primary IRR.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x0a]);
        let mut data_read = [0];
        data.pic.read(PIC_PRIMARY_COMMAND, &mut data_read);
        assert_eq!(data_read[0], 1 << 5);

        // Read primary ISR.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x0b]);
        data_read = [0];
        data.pic.read(PIC_PRIMARY_COMMAND, &mut data_read);
        assert_eq!(data_read[0], 1 << 4);

        // Non-sepcific EOI to end IRQ4.  Then, PIC should signal CPU about IRQ5.
        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x20]);

        // Poll command on primary.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x0c]);
        data_read = [0];
        data.pic.read(PIC_PRIMARY_COMMAND, &mut data_read);
        assert_eq!(data_read[0], 5);
    }

    /// Assert on primary PIC's IRQ2 without any IRQ on secondary asserted. This should result in a
    /// spurious IRQ on secondary.
    #[test]
    fn fake_irq_on_primary_irq2() {
        let mut data = set_up();
        icw_init_both_with_icw4(&mut data.pic, FULLY_NESTED_NO_AUTO_EOI);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 2, /*level=*/ true);
        // 0x70 is secondary IRQ base, 7 is for a spurious IRQ.
        assert_eq!(data.pic.get_external_interrupt(), Some(0x70 + 7));
    }

    /// Raising the same IRQ line twice in edge trigger mode should only send one IRQ request out.
    #[test]
    fn edge_trigger_mode() {
        let mut data = set_up();
        icw_init_both_with_icw4(&mut data.pic, FULLY_NESTED_NO_AUTO_EOI);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 4, /*level=*/ true);
        // get_external_interrupt clears the irr so it is possible to request the same IRQ again.
        assert_eq!(data.pic.get_external_interrupt(), Some(0x08 + 4));

        data.pic.service_irq(/*irq=*/ 4, /*level=*/ true);

        // In edge triggered mode, there should be no IRQ after this EOI.
        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x20]);
    }

    /// Raising the same IRQ line twice in level-triggered mode should send two IRQ requests out.
    #[test]
    fn level_trigger_mode() {
        let mut data = set_up();
        icw_init_both_with_icw4(&mut data.pic, FULLY_NESTED_NO_AUTO_EOI);

        // Turn IRQ4 to level-triggered mode.
        data.pic.write(PIC_PRIMARY_ELCR, &[0x10]);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 4, /*level=*/ true);
        // get_external_interrupt clears the irr so it is possible to request the same IRQ again.
        assert_eq!(data.pic.get_external_interrupt(), Some(0x08 + 4));

        data.pic.service_irq(/*irq=*/ 4, /*level=*/ true);

        // In level-triggered mode, there should be another IRQ request after this EOI.
        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x20]);
    }

    /// Specific EOI command in OCW2.
    #[test]
    fn specific_eoi() {
        let mut data = set_up();
        icw_init_both_with_icw4(&mut data.pic, FULLY_NESTED_NO_AUTO_EOI);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 4, /*level=*/ true);
        assert_eq!(data.pic.get_external_interrupt(), Some(0x08 + 4));

        // Specific EOI command on IRQ3. Primary PIC's ISR should be unaffected since it's targeted
        // at the wrong IRQ number.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x63]);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 1 << 4);

        // Specific EOI command on IRQ4. Primary PIC's ISR should now be cleared.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x64]);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 0);
    }

    /// Test rotate on auto EOI.
    #[test]
    fn rotate_on_auto_eoi() {
        let mut data = set_up();
        icw_init_both(&mut data.pic);

        // OCW3: Clear rotate on auto EOI mode.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x00]);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 5, /*level=*/ true);
        assert_eq!(data.pic.get_external_interrupt(), Some(0x08 + 5));
        data.pic.service_irq(/*irq=*/ 5, /*level=*/ false);

        // EOI automatically happened. Now priority should not be rotated.
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].imr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].last_irr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].priority_add, 0);

        // OCW2: Set rotate on auto EOI mode.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x80]);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 5, /*level*/ true);
        assert_eq!(data.pic.get_external_interrupt(), Some(0x08 + 5));
        data.pic.service_irq(/*irq=*/ 5, /*level=*/ false);

        // EOI automatically happened, and the priority *should* be rotated.
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].priority_add, 6);
    }

    /// Test rotate on specific (non-auto) EOI.
    #[test]
    fn rotate_on_specific_eoi() {
        let mut data = set_up();
        icw_init_both_with_icw4(&mut data.pic, FULLY_NESTED_NO_AUTO_EOI);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 5, /*level=*/ true);
        assert_eq!(data.pic.get_external_interrupt(), Some(0x08 + 5));
        data.pic.service_irq(/*irq=*/ 5, /*level=*/ false);

        // Rotate on specific EOI IRQ4. Since this is a different IRQ number, Should not have an
        // effect on isr.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0xe4]);

        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 1 << 5);

        // Rotate on specific EOI IRQ5. This should clear the isr.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0xe5]);

        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].priority_add, 6);
    }

    /// Test rotate on non-specific EOI.
    #[test]
    fn rotate_non_specific_eoi() {
        let mut data = set_up();
        icw_init_both_with_icw4(&mut data.pic, FULLY_NESTED_NO_AUTO_EOI);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 5, /*level=*/ true);
        assert_eq!(data.pic.get_external_interrupt(), Some(0x08 + 5));
        data.pic.service_irq(/*irq=*/ 5, /*level=*/ false);

        // Rotate on non-specific EOI.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0xa0]);

        // The EOI should have cleared isr.
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 0);
        assert_eq!(data.pic.pics[PicSelect::Primary as usize].priority_add, 6);
    }

    /// Verify that no-op doesn't change state.
    #[test]
    fn no_op_ocw2() {
        let mut data = set_up();
        icw_init_both_with_icw4(&mut data.pic, FULLY_NESTED_NO_AUTO_EOI);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 5, /*level=*/ true);
        assert_eq!(data.pic.get_external_interrupt(), Some(0x08 + 5));
        data.pic.service_irq(/*irq=*/ 5, /*level=*/ false);

        let orig = data.pic.pics[PicSelect::Primary as usize].clone();

        // Run a no-op.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x40]);

        // Nothing should have changed.
        assert_eq!(orig, data.pic.pics[PicSelect::Primary as usize]);
    }

    /// Tests cascade IRQ that happens on secondary PIC.
    #[test]
    fn cascade_irq() {
        let mut data = set_up();
        icw_init_both_with_icw4(&mut data.pic, FULLY_NESTED_NO_AUTO_EOI);

        // TODO(mutexlox): Verify APIC interaction when it is implemented.
        data.pic.service_irq(/*irq=*/ 12, /*level=*/ true);

        assert_eq!(data.pic.pics[PicSelect::Primary as usize].irr, 1 << 2);
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].irr, 1 << 4);

        assert_eq!(data.pic.get_external_interrupt(), Some(0x70 + 4));

        // Check that the IRQ is now acknowledged after get_external_interrupt().
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].irr, 0);
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].isr, 1 << 4);

        // OCW2: Two non-specific EOIs to primary rather than secondary.
        // We need two non-specific EOIs:
        //   - The first resets bit 2 in the primary isr (the highest-priority bit that was set
        //     before the EOI)
        //   - The second resets the secondary PIC's highest-priority isr bit.
        data.pic.write(PIC_PRIMARY_COMMAND, &[0x20]);
        // Rotate non-specific EOI.
        data.pic.write(PIC_SECONDARY_COMMAND, &[0xa0]);

        assert_eq!(data.pic.pics[PicSelect::Primary as usize].isr, 0);
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].isr, 0);
        assert_eq!(data.pic.pics[PicSelect::Secondary as usize].priority_add, 5);
    }
}
