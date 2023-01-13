// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Support crate for writing fuzzers in ChromeOS.
//!
//! The major features provided by this crate are:
//!
//! * The [`fuzz_target`] macro which wraps the body of the fuzzing code with
//!   all with all the boilerplate needed to build and run it as a fuzzer on
//!   ChromeOS infrastructure.
//! * The [`FuzzRng`] type that provides a random number generator using fuzzer
//!   input as the source of its randomness.  Fuzzers that need to generate
//!   structured data can use this type in conjunction with the [`rand`] crate
//!   to generate the data they need.
//!
//! # Getting Started
//!
//! To use this crate add it as a dependency to the fuzzer's `Cargo.toml` along
//! with the crate to be fuzzed:
//!
//! ```Cargo.toml
//! [dependencies]
//! cros_fuzz = "*"
//! your_crate = "*"
//! ```
//!
//! Then use the [`fuzz_target`] macro to write the body of the fuzzer.  All
//! fuzzers should use the `#![no_main]` crate attribute as the main function
//! will be provided by the fuzzer runtime.
//!
//! ```rust,ignore
//! #![no_main]
//!
//! use cros_fuzz::fuzz_target;
//! use your_crate::some_function;
//!
//! fuzz_target!(|data: &[u8]| {
//!     some_function(data);
//! });
//! ```
//!
//! [`FuzzRng`]: rand/struct.FuzzRng.html
//! [`fuzz_target`]: macro.fuzz_target.html
//! [`rand`]: https://docs.rs/rand

pub mod rand;

cfg_if::cfg_if! {
    if #[cfg(not(fuzzing))] {
        // A stub implementation that ensures the fuzzer code can be compiled but does not provide
        // any fuzzing functionality.
        #[macro_export]
        macro_rules! fuzz_target {
            (|$bytes:ident| $body:block) => {
                // fuzzers are configured with no_main. To make the binary compile, we manually
                // provide the main function with no_mangle.
                #[no_mangle]
                pub extern fn main($bytes: &[u8]) {
                    $body
                }
            };
            (|$bytes:ident: &[u8]| $body:block) => {
                fuzz_target!(|$bytes| $body);
            };
        }
    } else if #[cfg(feature = "upstream-fuzz")] {
        // libfuzzer implementation used by cargo-fuzz and upstream crosvm infrastructure
        pub use libfuzzer_sys::fuzz_target;
    } else {
        /// LLVMFuzzer implementation used by ChromeOS infrastructure
        ///
        /// The main macro for writing a fuzzer.  The fuzzer runtime will repeatedly
        /// call the body of `fuzz_target!` with a slice of pseudo-random bytes, until
        /// your program hits an error condition (segfault, panic, etc).
        ///
        /// # Examples
        ///
        /// ```
        /// use std::str;
        /// # #[macro_use] extern crate cros_fuzz;
        ///
        /// fuzz_target!(|data: &[u8]| {
        ///     let _ = str::from_utf8(data);
        /// });
        ///
        /// # fn main() {
        /// #    let buf = b"hello, world!";
        /// #    llvm_fuzzer_test_one_input(buf.as_ptr(), buf.len());
        /// # }
        /// ```
        #[macro_export]
        macro_rules! fuzz_target {
            (|$bytes:ident| $body:block) => {
                use std::panic;
                use std::process;
                use std::slice;

                #[export_name = "LLVMFuzzerTestOneInput"]
                fn llvm_fuzzer_test_one_input(data: *const u8, size: usize) -> i32 {
                    // We cannot unwind past ffi boundaries.
                    panic::catch_unwind(|| {
                        // Safe because the libfuzzer runtime will guarantee that `data` is
                        // at least `size` bytes long and that it will be valid for the lifetime
                        // of this function.
                        let $bytes = unsafe { slice::from_raw_parts(data, size) };

                        $body
                    })
                    .err()
                    .map(|_| process::abort());

                    0
                }
            };
            (|$bytes:ident: &[u8]| $body:block) => {
                fuzz_target!(|$bytes| $body);
            };
        }
    }
}
