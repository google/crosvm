// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use bit_field::*;

#[bitfield]
#[bits = 5]
#[derive(Debug, PartialEq)]
pub struct FiveBits(u8);

#[bitfield]
struct Struct {
    prefix: BitField1,
    five_bits: FiveBits,
    suffix: BitField2,
}

#[test]
fn test_enum() {
    let mut s = Struct::new();
    assert_eq!(s.get(0, 8), 0b_0000_0000);

    s.set_five_bits(FiveBits(0b10101));
    assert_eq!(s.get(0, 8), 0b_0010_1010);
    assert_eq!(s.get_five_bits(), FiveBits(0b10101));
}
