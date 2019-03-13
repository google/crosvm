extern crate bit_field;

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
struct Struct {
    prefix: BitField1,
    two_bits: TwoBits,
    suffix: BitField5,
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
    assert_eq!(s.get_two_bits(), TwoBits::One);
}
