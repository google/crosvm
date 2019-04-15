// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::boxed::Box;
use std::cmp::{max, min, Ord, Ordering, PartialOrd};
use std::mem::size_of;
use std::sync::{Arc, MutexGuard};
use sync::Mutex;

use data_model::DataInit;
use sys_util::error;

/// Type of offset in the register space.
pub type RegisterOffset = u64;

/// This represents a range of memory in the register space starting.
/// Both from and to are inclusive.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct RegisterRange {
    pub from: RegisterOffset,
    pub to: RegisterOffset,
}

impl Ord for RegisterRange {
    fn cmp(&self, other: &RegisterRange) -> Ordering {
        self.from.cmp(&other.from)
    }
}

impl PartialOrd for RegisterRange {
    fn partial_cmp(&self, other: &RegisterRange) -> Option<Ordering> {
        self.from.partial_cmp(&other.from)
    }
}

impl RegisterRange {
    /// Return true if those range overlaps.
    pub fn overlap_with(&self, other: &RegisterRange) -> bool {
        !(self.from > other.to || self.to < other.from)
    }

    /// Get the overlapping part of two RegisterRange.
    /// Return is Option(overlap_from, overlap_to).
    /// For example, (4,7).overlap_range(5, 8) will be Some(5, 7).
    pub fn overlap_range(&self, other: &RegisterRange) -> Option<RegisterRange> {
        if !self.overlap_with(other) {
            return None;
        }
        Some(RegisterRange {
            from: max(self.from, other.from),
            to: min(self.to, other.to),
        })
    }
}

/// RegisterValue trait should be satisfied by register value types.
pub trait RegisterValue:
    'static
    + Into<u64>
    + Clone
    + DataInit
    + std::ops::BitOr<Self, Output = Self>
    + std::ops::BitAnd<Self, Output = Self>
    + std::ops::Not<Output = Self>
    + std::fmt::LowerHex
{
    // Get byte of the offset.
    fn get_byte(&self, offset: usize) -> u8 {
        let val: u64 = self.clone().into();
        (val >> (offset * 8)) as u8
    }
    // Set masked bits.
    fn set_bits(&mut self, mask: Self) {
        *self = *self | mask;
    }
    // Clear masked bits.
    fn clear_bits(&mut self, mask: Self) {
        *self = *self & (!mask);
    }
}
impl RegisterValue for u8 {}
impl RegisterValue for u16 {}
impl RegisterValue for u32 {}
impl RegisterValue for u64 {}

// Helper function to read a register. If the read range overlaps with value's range, it will load
// corresponding bytes into data.
fn read_reg_helper<T: RegisterValue>(
    val: T,
    val_range: RegisterRange,
    addr: RegisterOffset,
    data: &mut [u8],
) {
    let read_range = RegisterRange {
        from: addr,
        to: addr + data.len() as u64 - 1,
    };

    let overlap = match val_range.overlap_range(&read_range) {
        Some(overlap) => overlap,
        None => {
            error!("calling read_reg_helper with non overlapping range. mmio_register might have a bug");
            return;
        }
    };
    let val_start_idx = (overlap.from - val_range.from) as usize;
    let read_start_idx = (overlap.from - read_range.from) as usize;
    let total_size = (overlap.to - overlap.from) as usize + 1;
    for i in 0..total_size {
        data[read_start_idx + i] = val.get_byte(val_start_idx + i);
    }
}

/// Interface for register, as seen by guest driver.
pub trait RegisterInterface: Send {
    /// Range of this register.
    fn range(&self) -> RegisterRange;
    /// Handle read.
    fn read(&self, addr: RegisterOffset, data: &mut [u8]);
    /// Handle write.
    fn write(&self, _addr: RegisterOffset, _data: &[u8]) {}
    /// Reset this register to default value.
    fn reset(&self) {}
}

// Spec for hardware init Read Only Registers.
// The value of this register won't change.
pub struct StaticRegisterSpec<T: RegisterValue> {
    pub offset: RegisterOffset,
    pub value: T,
}

/// A static register is a register inited by hardware. The value won't change in it's lifetime.
/// All functions implemented on this one is thread safe.
#[derive(Clone)]
pub struct StaticRegister<T>
where
    T: RegisterValue,
{
    spec: &'static StaticRegisterSpec<T>,
}

impl<T> StaticRegister<T>
where
    T: RegisterValue,
{
    /// Create an new static register from spec.
    pub fn new(spec: &'static StaticRegisterSpec<T>) -> StaticRegister<T> {
        StaticRegister { spec }
    }
}

impl<T> RegisterInterface for StaticRegister<T>
where
    T: RegisterValue,
{
    fn range(&self) -> RegisterRange {
        RegisterRange {
            from: self.spec.offset,
            to: self.spec.offset + (size_of::<T>() as u64) - 1,
        }
    }

    fn read(&self, addr: RegisterOffset, data: &mut [u8]) {
        let val_range = self.range();
        read_reg_helper(self.spec.value, val_range, addr, data);
    }
}

/// Macro helps to build a static register.
#[macro_export]
macro_rules! static_register {
    (ty: $ty:ty,offset: $offset:expr,value: $value:expr,) => {{
        use crate::register_space::*;
        static REG_SPEC: StaticRegisterSpec<$ty> = StaticRegisterSpec::<$ty> {
            offset: $offset,
            value: $value,
        };
        StaticRegister::new(&REG_SPEC)
    }};
}

/// Spec for a regular register. It specifies it's location on register space, guest writable mask
/// and guest write to clear mask.
pub struct RegisterSpec<T> {
    pub name: String,
    pub offset: RegisterOffset,
    pub reset_value: T,
    /// Only masked bits could be written by guest.
    pub guest_writeable_mask: T,
    /// When write 1 to bits masked, those bits will be cleared. See Xhci spec 5.1
    /// for more details.
    pub guest_write_1_to_clear_mask: T,
}

struct RegisterInner<T: RegisterValue> {
    spec: RegisterSpec<T>,
    value: T,
    write_cb: Option<Box<dyn Fn(T) -> T + Send>>,
}

/// Register is a thread safe struct. It can be safely changed from any thread.
#[derive(Clone)]
pub struct Register<T: RegisterValue> {
    inner: Arc<Mutex<RegisterInner<T>>>,
}

impl<T: RegisterValue> Register<T> {
    pub fn new(spec: RegisterSpec<T>, val: T) -> Self {
        Register {
            inner: Arc::new(Mutex::new(RegisterInner {
                spec,
                value: val,
                write_cb: None,
            })),
        }
    }

    fn lock(&self) -> MutexGuard<RegisterInner<T>> {
        self.inner.lock()
    }
}

// All functions implemented on this one is thread safe.
impl<T: RegisterValue> RegisterInterface for Register<T> {
    fn range(&self) -> RegisterRange {
        let locked = self.lock();
        let spec = &locked.spec;
        RegisterRange {
            from: spec.offset,
            to: spec.offset + (size_of::<T>() as u64) - 1,
        }
    }

    fn read(&self, addr: RegisterOffset, data: &mut [u8]) {
        let val_range = self.range();
        let value = self.lock().value;
        read_reg_helper(value, val_range, addr, data);
    }

    fn write(&self, addr: RegisterOffset, data: &[u8]) {
        let my_range = self.range();
        let write_range = RegisterRange {
            from: addr,
            to: addr + data.len() as u64 - 1,
        };

        let overlap = match my_range.overlap_range(&write_range) {
            Some(range) => range,
            None => {
                error!("write should not be invoked on this register");
                return;
            }
        };
        let my_start_idx = (overlap.from - my_range.from) as usize;
        let write_start_idx = (overlap.from - write_range.from) as usize;
        let total_size = (overlap.to - overlap.from) as usize + 1;

        let mut reg_value: T = self.lock().value;
        let value: &mut [u8] = reg_value.as_mut_slice();
        for i in 0..total_size {
            value[my_start_idx + i] = self.apply_write_masks_to_byte(
                value[my_start_idx + i],
                data[write_start_idx + i],
                my_start_idx + i,
            );
        }

        // A single u64 register is done by write to lower 32 bit and then higher 32 bit. Callback
        // should only be invoked when higher is written.
        if my_range.to != overlap.to {
            self.lock().value = reg_value;
            return;
        }

        // Taking the callback out of register when executing it. This prevent dead lock if
        // callback want to read current register value.
        // Note that the only source of callback comes from mmio writing, which is synchronized.
        let cb = {
            let mut inner = self.lock();
            match inner.write_cb.take() {
                Some(cb) => cb,
                None => {
                    // Write value if there is no callback.
                    inner.value = reg_value;
                    return;
                }
            }
        };
        // Callback is invoked without holding any lock.
        let value = cb(reg_value);
        let mut inner = self.lock();
        inner.value = value;
        inner.write_cb = Some(cb);
    }

    fn reset(&self) {
        let mut locked = self.lock();
        locked.value = locked.spec.reset_value;
    }
}

impl<T: RegisterValue> Register<T> {
    /// Get current value of this register.
    pub fn get_value(&self) -> T {
        self.lock().value
    }

    /// This function apply "write 1 to clear mask" and "guest writeable mask".
    /// All write operations should go through this, the result of this function
    /// is the new state of correspoding byte.
    pub fn apply_write_masks_to_byte(&self, old_byte: u8, write_byte: u8, offset: usize) -> u8 {
        let locked = self.lock();
        let spec = &locked.spec;
        let guest_write_1_to_clear_mask: u64 = spec.guest_write_1_to_clear_mask.into();
        let guest_writeable_mask: u64 = spec.guest_writeable_mask.into();
        // Mask with w1c mask.
        let w1c_mask = (guest_write_1_to_clear_mask >> (offset * 8)) as u8;
        let val = (!w1c_mask & write_byte) | (w1c_mask & old_byte & !write_byte);
        // Mask with writable mask.
        let w_mask = (guest_writeable_mask >> (offset * 8)) as u8;
        (old_byte & (!w_mask)) | (val & w_mask)
    }

    /// Set a callback. It will be invoked when write happens.
    pub fn set_write_cb<C: 'static + Fn(T) -> T + Send>(&self, callback: C) {
        self.lock().write_cb = Some(Box::new(callback));
    }

    /// Set value from device side. Callback won't be invoked.
    pub fn set_value(&self, val: T) {
        self.lock().value = val;
    }

    /// Set masked bits.
    pub fn set_bits(&self, mask: T) {
        self.lock().value.set_bits(mask);
    }

    /// Clear masked bits.
    pub fn clear_bits(&self, mask: T) {
        self.lock().value.clear_bits(mask);
    }
}

#[macro_export]
macro_rules! register {
    (
        name: $name:tt,
        ty: $ty:ty,
        offset: $offset:expr,
        reset_value: $rv:expr,
        guest_writeable_mask: $mask:expr,
        guest_write_1_to_clear_mask: $w1tcm:expr,
    ) => {{
        use crate::register_space::*;
        let spec: RegisterSpec<$ty> = RegisterSpec::<$ty> {
            name: String::from($name),
            offset: $offset,
            reset_value: $rv,
            guest_writeable_mask: $mask,
            guest_write_1_to_clear_mask: $w1tcm,
        };
        Register::<$ty>::new(spec, $rv)
    }};
    (name: $name:tt, ty: $ty:ty,offset: $offset:expr,reset_value: $rv:expr,) => {{
        use crate::register_space::*;
        let spec: RegisterSpec<$ty> = RegisterSpec::<$ty> {
            name: String::from($name),
            offset: $offset,
            reset_value: $rv,
            guest_writeable_mask: !0,
            guest_write_1_to_clear_mask: 0,
        };
        Register::<$ty>::new(spec, $rv)
    }};
}

#[macro_export]
macro_rules! register_array {
    (
        name: $name:tt,
        ty:
        $ty:ty,cnt:
        $cnt:expr,base_offset:
        $base_offset:expr,stride:
        $stride:expr,reset_value:
        $rv:expr,guest_writeable_mask:
        $gwm:expr,guest_write_1_to_clear_mask:
        $gw1tcm:expr,
    ) => {{
        use crate::register_space::*;
        let mut v: Vec<Register<$ty>> = Vec::new();
        for i in 0..$cnt {
            let offset = $base_offset + ($stride * i) as RegisterOffset;
            let spec: RegisterSpec<$ty> = RegisterSpec::<$ty> {
                name: format!("{}-{}", $name, i),
                offset,
                reset_value: $rv,
                guest_writeable_mask: $gwm,
                guest_write_1_to_clear_mask: $gw1tcm,
            };
            v.push(Register::<$ty>::new(spec, $rv));
        }
        v
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    static REG_SPEC0: StaticRegisterSpec<u8> = StaticRegisterSpec::<u8> {
        offset: 3,
        value: 32,
    };

    static REG_SPEC1: StaticRegisterSpec<u16> = StaticRegisterSpec::<u16> {
        offset: 3,
        value: 32,
    };

    #[test]
    fn static_register_basic_test_u8() {
        let r = StaticRegister::<u8> { spec: &REG_SPEC0 };
        let mut data: [u8; 4] = [0, 0, 0, 0];
        assert_eq!(r.range().from, 3);
        assert_eq!(r.range().to, 3);
        r.read(0, &mut data);
        assert_eq!(data, [0, 0, 0, 32]);
        r.read(2, &mut data);
        assert_eq!(data, [0, 32, 0, 32]);
    }

    #[test]
    fn static_register_basic_test_u16() {
        let r = StaticRegister::<u16> { spec: &REG_SPEC1 };
        let mut data: [u8; 4] = [0, 0, 0, 0];
        assert_eq!(r.range().from, 3);
        assert_eq!(r.range().to, 4);
        r.read(0, &mut data);
        assert_eq!(data, [0, 0, 0, 32]);
        r.read(2, &mut data);
        assert_eq!(data, [0, 32, 0, 32]);
    }

    #[test]
    fn static_register_interface_test() {
        let r: Box<RegisterInterface> = Box::new(static_register! {
            ty: u8,
            offset: 3,
            value: 32,
        });
        let mut data: [u8; 4] = [0, 0, 0, 0];
        assert_eq!(r.range().from, 3);
        assert_eq!(r.range().to, 3);
        r.read(0, &mut data);
        assert_eq!(data, [0, 0, 0, 32]);
        r.read(2, &mut data);
        assert_eq!(data, [0, 32, 0, 32]);
    }

    #[test]
    fn register_basic_rw_test() {
        let r = register! {
            name: "",
            ty: u8,
            offset: 3,
            reset_value: 0xf1,
            guest_writeable_mask: 0xff,
            guest_write_1_to_clear_mask: 0x0,
        };
        let mut data: [u8; 4] = [0, 0, 0, 0];
        assert_eq!(r.range().from, 3);
        assert_eq!(r.range().to, 3);
        r.read(0, &mut data);
        assert_eq!(data, [0, 0, 0, 0xf1]);
        r.read(2, &mut data);
        assert_eq!(data, [0, 0xf1, 0, 0xf1]);
        data = [0, 0, 0, 0xab];
        r.write(0, &data);
        assert_eq!(r.get_value(), 0xab);
        r.reset();
        assert_eq!(r.get_value(), 0xf1);
        r.set_value(0xcc);
        assert_eq!(r.get_value(), 0xcc);
    }

    #[test]
    fn register_basic_writeable_mask_test() {
        let r = register! {
            name: "",
            ty: u8,
            offset: 3,
            reset_value: 0x0,
            guest_writeable_mask: 0xf,
            guest_write_1_to_clear_mask: 0x0,
        };
        let mut data: [u8; 4] = [0, 0, 0, 0];
        assert_eq!(r.range().from, 3);
        assert_eq!(r.range().to, 3);
        r.read(0, &mut data);
        assert_eq!(data, [0, 0, 0, 0]);
        data = [0, 0, 0, 0xab];
        r.write(0, &data);
        assert_eq!(r.get_value(), 0x0b);
        r.reset();
        assert_eq!(r.get_value(), 0x0);
        r.set_value(0xcc);
        assert_eq!(r.get_value(), 0xcc);
    }

    #[test]
    fn register_basic_write_1_to_clear_mask_test() {
        let r = register! {
            name: "",
            ty: u8,
            offset: 3,
            reset_value: 0xf1,
            guest_writeable_mask: 0xff,
            guest_write_1_to_clear_mask: 0xf0,
        };
        let mut data: [u8; 4] = [0, 0, 0, 0];
        assert_eq!(r.range().from, 3);
        assert_eq!(r.range().to, 3);
        r.read(0, &mut data);
        assert_eq!(data, [0, 0, 0, 0xf1]);
        data = [0, 0, 0, 0xfa];
        r.write(0, &data);
        assert_eq!(r.get_value(), 0x0a);
        r.reset();
        assert_eq!(r.get_value(), 0xf1);
        r.set_value(0xcc);
        assert_eq!(r.get_value(), 0xcc);
    }

    #[test]
    fn register_basic_write_1_to_clear_mask_test_u32() {
        let r = register! {
            name: "",
            ty: u32,
            offset: 0,
            reset_value: 0xfff1,
            guest_writeable_mask: 0xff,
            guest_write_1_to_clear_mask: 0xf0,
        };
        let mut data: [u8; 4] = [0, 0, 0, 0];
        assert_eq!(r.range().from, 0);
        assert_eq!(r.range().to, 3);
        r.read(0, &mut data);
        assert_eq!(data, [0xf1, 0xff, 0, 0]);
        data = [0xfa, 0, 0, 0];
        r.write(0, &data);
        assert_eq!(r.get_value(), 0xff0a);
        r.reset();
        assert_eq!(r.get_value(), 0xfff1);
        r.set_value(0xcc);
        assert_eq!(r.get_value(), 0xcc);
    }

    #[test]
    fn register_callback_test() {
        let state = Arc::new(Mutex::new(0u8));
        let r = register! {
            name: "",
            ty: u8,
            offset: 3,
            reset_value: 0xf1,
            guest_writeable_mask: 0xff,
            guest_write_1_to_clear_mask: 0xf0,
        };

        let s2 = state.clone();
        r.set_write_cb(move |val: u8| {
            *s2.lock() = val as u8;
            val
        });
        let data: [u8; 4] = [0, 0, 0, 0xff];
        r.write(0, &data);
        assert_eq!(*state.lock(), 0xf);
        r.set_value(0xab);
        assert_eq!(*state.lock(), 0xf);
        let data: [u8; 1] = [0xfc];
        r.write(3, &data);
        assert_eq!(*state.lock(), 0xc);
    }
}
