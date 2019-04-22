// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use bit_field::*;

#[bitfield]
#[derive(Debug, PartialEq)]
enum TwoBits {
    Zero = 0b00,
    One = 0b01,
    Two = 0b10,
    Three = 0b11,
}

#[bitfield]
#[bits = 3]
#[derive(Debug, PartialEq)]
enum ThreeBits {
    Zero = 0b00,
    One = 0b01,
    Two = 0b10,
    Three = 0b111,
}

#[bitfield]
struct Struct {
    prefix: BitField1,
    two_bits: TwoBits,
    three_bits: ThreeBits,
    suffix: BitField2,
}

#[test]
fn test_enum() {
    let mut s = Struct::new();
    assert_eq!(s.get(0, 8), 0b_0000_0000);
    assert_eq!(s.get_two_bits(), TwoBits::Zero);

    s.set_two_bits(TwoBits::Three);
    assert_eq!(s.get(0, 8), 0b_0000_0110);
    assert_eq!(s.get_two_bits(), TwoBits::Three);

    s.set(0, 8, 0b_1010_1010);
    //                   ^^ TwoBits
    //               ^^_^ Three Bits.
    assert_eq!(s.get_two_bits(), TwoBits::One);
    assert_eq!(s.get_three_bits().unwrap_err().raw_val(), 0b101);

    s.set_three_bits(ThreeBits::Two);
    assert_eq!(s.get(0, 8), 0b_1001_0010);
}
