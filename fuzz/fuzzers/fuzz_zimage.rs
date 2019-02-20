#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate kernel_loader;
extern crate libc;
extern crate sys_util;

use sys_util::{GuestAddress, GuestMemory};

use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let mut kimage = Cursor::new(data);
    let mem = GuestMemory::new(&[(GuestAddress(0), data.len() + 0x1000)]).unwrap();
    let _ = kernel_loader::load_kernel(&mem, GuestAddress(0), &mut kimage);
});
