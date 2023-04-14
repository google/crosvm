// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Wraps various methods for calculating hashes (sha256).

cfg_if::cfg_if! {
    if #[cfg(feature = "pure-rust-hashes")] {
        use sha2::Digest;
        use sha2::Sha256;

        pub fn sha256(bytes: [u8]) -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            trace_hash.finalize()[0..32].try_into().unwrap()
        }
    } else if #[cfg(feature = "openssl")] {
        use openssl::sha::sha256;

        pub fn sha256(bytes: [u8]) -> [u8; 32] {
            // We don't just re-export the library. This way, if openssl's Rust
            // interface changes, we will get an obvious compile error here.
            sha256(bytes)
        }
    } else {
        compile_error!("Either openssl or pure-rust-hashes must be selected.");
    }
}
