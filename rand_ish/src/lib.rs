// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::{self, Read};

/// A simple prng based on a Linear congruential generator
/// https://en.wikipedia.org/wiki/Linear_congruential_generator
pub struct SimpleRng {
    seed: u64,
}

impl SimpleRng {
    /// Create a new SimpleRng
    pub fn new(seed: u64) -> SimpleRng {
        SimpleRng { seed }
    }

    /// Generate random u64
    pub fn rng(&mut self) -> u64 {
        // a simple Linear congruential generator
        let a: u64 = 6364136223846793005;
        let c: u64 = 1442695040888963407;
        self.seed = a.wrapping_mul(self.seed).wrapping_add(c);
        self.seed
    }
}

/// Samples `/dev/urandom` and generates a random ASCII string of length `len`
pub fn urandom_str(len: usize) -> io::Result<String> {
    const ASCII_CHARS: &'static [u8] = b"
          ABCDEFGHIJKLMNOPQRSTUVWXYZ\
          abcdefghijklmnopqrstuvwxyz\
          0123456789";

    File::open("/dev/urandom")?
        .bytes()
        .map(|b| b.map(|b| ASCII_CHARS[b as usize % ASCII_CHARS.len()] as char))
        .take(len)
        .collect::<io::Result<String>>()
}
