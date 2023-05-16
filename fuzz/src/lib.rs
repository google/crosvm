// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod rand;

cfg_if::cfg_if! {
    if #[cfg(not(fuzzing))] {
        /// A stub implementation that ensures the fuzzer code can be compiled but does not provide
        /// any fuzzing functionality.
        /// This allows the fuzzer code to be verified in CI without a nightly cargo toolchain.
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
    } else {
        pub use libfuzzer_sys::fuzz_target;
    }
}
