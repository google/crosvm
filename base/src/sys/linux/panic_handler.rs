// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A panic handler for better crash signatures for rust apps.

use std::fs::File;
use std::io;
use std::mem;
use std::panic;
use std::process::abort;

use crate::SafeDescriptor;
use crate::SharedMemory;

const PANIC_MEMFD_NAME: &str = "RUST_PANIC_SIG";

/// Inserts a panic handler that writes the panic info to a memfd called
/// "RUST_PANIC_SIG" before calling the original panic handler. This
/// makes it possible for external crash handlers to recover the panic info.
pub fn install_memfd_handler() {
    let hook = panic::take_hook();
    panic::set_hook(Box::new(move |p| {
        let panic_info = format!("{}\n", &p);
        let panic_bytes = panic_info.as_bytes();
        // On failure, ignore the error and call the original handler.
        if let Ok(panic_memfd) = SharedMemory::new(PANIC_MEMFD_NAME, panic_bytes.len() as u64) {
            let mut panic_memfd = File::from(SafeDescriptor::from(panic_memfd));
            io::Write::write_all(&mut panic_memfd, panic_bytes).ok();
            // Intentionally leak panic_memfd so it is picked up by the crash handler.
            mem::forget(panic_memfd);
        }
        hook(p);

        // If this is a multithreaded program, a panic in one thread will not kill the whole
        // process. Abort so the entire process gets killed and produces a core dump.
        abort();
    }));
}
