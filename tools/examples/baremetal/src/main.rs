// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_std] // don't link the Rust standard library
#![no_main] // disable all Rust-level entry points

use core::arch::asm;
use core::arch::global_asm;
use core::panic::PanicInfo;

use log::*;

global_asm!(include_str!("../src/boot.asm"));

/// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Execute a debug breakpoint instruction to cause a VMEXIT.
    // SAFETY: This instruction will exit the hosting VM, so no further Rust code will execute.
    unsafe {
        asm!("int3");
    }
    // Just in case we are still running somehow, spin forever.
    loop {}
}

#[no_mangle]
pub extern "C" fn main() -> ! {
    com_logger::init();
    error!("Hello World!");
    panic!();
}
