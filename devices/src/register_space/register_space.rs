// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::register::{Register, RegisterInterface, RegisterOffset, RegisterRange, RegisterValue};
use std::collections::btree_map::BTreeMap;

/// Register space repesents a set of registers. It can handle read/write operations.
pub struct RegisterSpace {
    regs: BTreeMap<RegisterRange, Box<dyn RegisterInterface>>,
}

impl RegisterSpace {
    /// Creates a new empty RegisterSpace.
    pub fn new() -> RegisterSpace {
        RegisterSpace {
            regs: BTreeMap::new(),
        }
    }

    /// Add a register to register space.
    pub fn add_register<T: RegisterInterface + 'static>(&mut self, reg: T) {
        let range = reg.range();
        debug_assert!(self.get_register(range.from).is_none());
        if cfg!(debug_assertions) {
            if let Some(r) = self.first_before(range.to) {
                debug_assert!(r.range().to < range.to);
            }
        }

        let insert_result = self.regs.insert(range, Box::new(reg)).is_none();
        debug_assert!(insert_result);
    }

    /// Add an array of registers.
    pub fn add_register_array<T: RegisterValue>(&mut self, regs: &[Register<T>]) {
        for r in regs {
            self.add_register(r.clone());
        }
    }

    /// Read range.
    pub fn read(&self, addr: RegisterOffset, data: &mut [u8]) {
        let mut current_addr: RegisterOffset = addr;
        while current_addr < addr + data.len() as RegisterOffset {
            if let Some(r) = self.get_register(current_addr) {
                // Next addr to read is.
                current_addr = r.range().to + 1;
                r.read(addr, data);
            } else {
                // TODO(jkwang) Add logging for debug here.
                current_addr += 1;
            }
        }
    }

    /// Write range. If the targeted register has a callback, it will be invoked with the new
    /// value.
    pub fn write(&self, addr: RegisterOffset, data: &[u8]) {
        let mut current_addr: RegisterOffset = addr;
        while current_addr < addr + data.len() as RegisterOffset {
            if let Some(r) = self.get_register(current_addr) {
                // Next addr to read is, range is inclusive.
                current_addr = r.range().to + 1;
                r.write(addr, data);
            } else {
                current_addr += 1;
            }
        }
    }

    /// Get first register before this addr.
    fn first_before(&self, addr: RegisterOffset) -> Option<&dyn RegisterInterface> {
        for (range, r) in self.regs.iter().rev() {
            if range.from <= addr {
                return Some(r.as_ref());
            }
        }
        None
    }

    /// Get register at this addr.
    fn get_register(&self, addr: RegisterOffset) -> Option<&dyn RegisterInterface> {
        let r = self.first_before(addr)?;
        let range = r.range();
        if addr <= range.to {
            Some(r)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use sync::Mutex;

    #[test]
    fn regs_no_reg() {
        let regs = RegisterSpace::new();
        let mut data: [u8; 4] = [4, 3, 2, 1];
        // Read should be no op cause no register.
        regs.read(0, &mut data);
        assert_eq!([4, 3, 2, 1], data);
        // Write should be no op.
        regs.write(0, &[0, 0, 0, 0]);
        regs.read(0, &mut data);
        assert_eq!([4, 3, 2, 1], data);
    }

    #[test]
    #[should_panic]
    #[cfg(debug_assertions)]
    fn regs_reg_overlap() {
        let mut regs = RegisterSpace::new();
        regs.add_register(static_register!(
        ty: u32,
        offset: 4,
        value: 11,
        ));

        regs.add_register(static_register!(
        ty: u16,
        offset: 7,
        value: 11,
        ));
    }

    #[test]
    fn regs_static_reg() {
        let mut regs = RegisterSpace::new();
        regs.add_register(static_register!(
            ty: u8,
            offset: 0,
            value: 11,
        ));
        let mut data: [u8; 4] = [4, 3, 2, 1];
        regs.read(0, &mut data);
        assert_eq!([11, 3, 2, 1], data);
        // Write should be no op.
        regs.write(0, &[0, 0, 0, 0]);
        let mut data: [u8; 4] = [4, 3, 2, 1];
        regs.read(0, &mut data);
        assert_eq!([11, 3, 2, 1], data);
    }

    #[test]
    fn regs_static_reg_offset() {
        let mut regs = RegisterSpace::new();
        regs.add_register(static_register!(
            ty: u32,
            offset: 2,
            value: 0xaabbccdd,
        ));
        let mut data: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
        regs.read(0, &mut data);
        assert_eq!([8, 7, 0xdd, 0xcc, 0xbb, 0xaa, 2, 1], data);
        // Write should be no op.
        regs.write(0, &[0, 0, 0, 0, 0, 0, 0, 0]);
        let mut data: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
        regs.read(0, &mut data);
        assert_eq!([8, 7, 0xdd, 0xcc, 0xbb, 0xaa, 2, 1], data);
    }

    #[test]
    fn regs_reg_write() {
        let mut regs = RegisterSpace::new();
        regs.add_register(register!(
            name: "",
            ty: u32,
            offset: 2,
            reset_value: 0xaabbccdd,
        ));
        let mut data: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
        regs.read(0, &mut data);
        assert_eq!([8, 7, 0xdd, 0xcc, 0xbb, 0xaa, 2, 1], data);
        regs.write(0, &[0, 0, 0, 0, 0, 0, 0, 0]);
        let mut data: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
        regs.read(0, &mut data);
        assert_eq!([8, 7, 0, 0, 0, 0, 2, 1], data);
    }

    #[test]
    fn regs_reg_writeable() {
        let mut regs = RegisterSpace::new();
        regs.add_register(register!(
            name: "",
            ty: u32,
            offset: 2,
            reset_value: 0xaabbccdd,
            guest_writeable_mask: 0x00f0000f,
            guest_write_1_to_clear_mask: 0,
        ));
        let mut data: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
        regs.read(0, &mut data);
        assert_eq!([8, 7, 0xdd, 0xcc, 0xbb, 0xaa, 2, 1], data);
        regs.write(0, &[0, 0, 0, 0, 0, 0, 0, 0]);
        let mut data: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
        regs.read(0, &mut data);
        assert_eq!([8, 7, 0xd0, 0xcc, 0x0b, 0xaa, 2, 1], data);
    }

    #[test]
    fn regs_reg_writeable_callback() {
        let state = Arc::new(Mutex::new(0u32));
        let mut regs = RegisterSpace::new();
        let reg = register!(
            name: "",
            ty: u32,
            offset: 2,
            reset_value: 0xaabbccdd,
            guest_writeable_mask: 0x00f0000f,
            guest_write_1_to_clear_mask: 0,
        );
        regs.add_register(reg.clone());
        let state_clone = state.clone();
        reg.set_write_cb(move |val: u32| {
            *state_clone.lock() = val;
            val
        });

        let mut data: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
        regs.read(0, &mut data);
        assert_eq!([8, 7, 0xdd, 0xcc, 0xbb, 0xaa, 2, 1], data);
        regs.write(0, &[0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(0xaa0bccd0, *state.lock());
    }

    #[test]
    fn regs_reg_write_to_clear() {
        let mut regs = RegisterSpace::new();
        regs.add_register(register!(
        name: "",
        ty: u32,
        offset: 2,
        reset_value: 0xaabbccdd,
        guest_writeable_mask: 0xfff0000f,
        guest_write_1_to_clear_mask: 0xf0000000,
        ));
        let mut data: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
        regs.read(0, &mut data);
        assert_eq!([8, 7, 0xdd, 0xcc, 0xbb, 0xaa, 2, 1], data);
        regs.write(0, &[0, 0, 0, 0, 0, 0xad, 0, 0]);
        let mut data: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
        regs.read(0, &mut data);
        assert_eq!([8, 7, 0xd0, 0xcc, 0x0b, 0x0d, 2, 1], data);
    }

    #[test]
    fn regs_reg_array() {
        let mut regs = RegisterSpace::new();
        regs.add_register_array(&register_array!(
            name: "",
            ty: u8,
            cnt: 8,
            base_offset: 10,
            stride: 2,
            reset_value: 0xff,
            guest_writeable_mask: !0,
            guest_write_1_to_clear_mask: 0,
        ));
        let mut data: [u8; 8] = [0; 8];
        regs.read(8, &mut data);
        assert_eq!([0, 0, 0xff, 0, 0xff, 0, 0xff, 0], data);
    }

    #[test]
    fn regs_reg_multi_array() {
        let mut regs = RegisterSpace::new();
        regs.add_register_array(&register_array!(
        name: "",
        ty: u8,
        cnt: 8,
        base_offset: 10,
        stride: 2,
        reset_value: 0xff,
        guest_writeable_mask: !0,
        guest_write_1_to_clear_mask: 0,
        ));
        regs.add_register_array(&register_array!(
        name: "",
        ty: u8,
        cnt: 8,
        base_offset: 11,
        stride: 2,
        reset_value: 0xee,
        guest_writeable_mask: !0,
        guest_write_1_to_clear_mask: 0,
        ));
        let mut data: [u8; 8] = [0; 8];
        regs.read(8, &mut data);
        assert_eq!([0, 0, 0xff, 0xee, 0xff, 0xee, 0xff, 0xee], data);
    }

}
