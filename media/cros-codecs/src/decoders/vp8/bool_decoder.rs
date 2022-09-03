// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// A VP8 boolean decoder based on the implementation in Chromium and GStreamer.
use std::{convert::TryFrom, io::Cursor};

use anyhow::{anyhow, Result};
use bytes::Buf;

const LOTS_OF_BITS: u32 = 0x40000000;
const U8_BITS: usize = u8::BITS as usize;
const BD_VALUE_SIZE: usize = std::mem::size_of::<usize>() * U8_BITS;

const NORM: [u8; 256] = [
    0, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Some bits are "encoded" with a 50/50 probability.
const DEFAULT_PROBABILITY: u8 = 128;

/// The decoder state.
#[derive(Default)]
pub struct BoolDecoder<T> {
    data: Cursor<T>,
    range: usize,
    value: usize,
    count: isize,
}

impl<T: AsRef<[u8]>> BoolDecoder<T> {
    /// Creates a new instance.
    pub fn new(data: T) -> Self {
        Self {
            data: Cursor::new(data),
            range: 255usize,
            value: 0usize,
            count: -8,
        }
    }

    /// Fills more bits from `data` to `value`. We shall keep at least 8 bits of
    /// the current `data` in `value`.
    fn fill(&mut self) -> Result<()> {
        let mut shift =
            (BD_VALUE_SIZE as isize - U8_BITS as isize - (self.count + U8_BITS as isize)) as i32;
        let bits_left = (self.data.remaining() * U8_BITS) as i32;
        let x = shift + U8_BITS as i32 - bits_left;
        let mut loop_end = 0;

        if x >= 0 {
            self.count += LOTS_OF_BITS as isize;
            loop_end = x;
        }

        if x < 0 || bits_left != 0 {
            while shift >= loop_end {
                self.count += U8_BITS as isize;
                self.value |= (self.data.get_u8() as usize) << shift;
                shift -= U8_BITS as i32;
            }
            Ok(())
        } else {
            Err(anyhow!("Out of bits"))
        }
    }

    /// Reads the next bit from the coded stream. The probability of the bit to
    /// be one is probability / 256.
    fn read_bit(&mut self, probability: u8) -> Result<bool> {
        let split = 1 + (((self.range - 1) * probability as usize) >> 8);

        if self.count < 0 {
            self.fill()?;
        }

        let bigsplit = split << (BD_VALUE_SIZE - U8_BITS);

        let bit = if self.value >= bigsplit {
            self.range -= split;
            self.value -= bigsplit;
            true
        } else {
            self.range = split;
            false
        };

        let shift = NORM[self.range];
        self.range <<= shift;
        self.value <<= shift;
        self.count -= isize::from(shift);

        Ok(bit)
    }

    /// Reads a "literal", that is, a "num_bits"-wide unsigned value whose bits
    /// come high- to low-order, with each bit encoded at probability 1/2.
    fn read_literal(&mut self, mut nbits: usize) -> Result<i32> {
        let mut ret = 0;

        while nbits > 0 {
            let bit = self.read_bit(DEFAULT_PROBABILITY)?;
            ret = (ret << 1) | bit as i32;
            nbits -= 1;
        }

        Ok(ret)
    }

    /// Reads a boolean from the coded stream. Returns false if it has reached the
    /// end of data and failed to read the boolean. The probability of out to
    /// be true is probability / 256, e.g., when probability is 0x80, the
    /// chance is 1/2 (i.e., 0x80 / 256).
    pub fn read_bool(&mut self) -> Result<bool> {
        self.read_literal(1).map(|bit| bit != 0)
    }

    /// Reads a boolean from the coded stream. Returns false if it has reached the
    /// end of data and failed to read the boolean. The probability of out to
    /// be true is probability / 256, e.g., when probability is 0x80, the
    /// chance is 1/2 (i.e., 0x80 / 256).
    pub fn read_bool_with_prob(&mut self, probability: u8) -> Result<bool> {
        self.read_bit(probability)
    }

    /// Reads an unsigned literal from the coded stream.
    pub fn read_uint<U: TryFrom<i32>>(&mut self, nbits: usize) -> Result<U> {
        let value = self.read_literal(nbits)?;
        U::try_from(value).map_err(|_| anyhow!("Conversion failed"))
    }

    /// Reads a literal with sign from the coded stream. This is similar to the
    /// read_literal(), it first read a "num_bits"-wide unsigned value, and then
    /// read an extra bit as the sign of the literal.
    pub fn read_sint<U: TryFrom<i32>>(&mut self, nbits: usize) -> Result<U> {
        let mut value = self.read_literal(nbits)?;
        let sign = self.read_bool()?;

        if sign {
            value = -value;
        }

        U::try_from(value).map_err(|_| anyhow!("Conversion failed"))
    }

    /// Returns the current coded value.
    pub fn value(&self) -> usize {
        self.value >> (BD_VALUE_SIZE - U8_BITS)
    }

    /// Returns the number of bytes in the `value` buffer.
    pub fn count(&self) -> isize {
        (U8_BITS as isize + self.count) % U8_BITS as isize
    }

    /// Returns the range of the current coded value.
    pub fn range(&self) -> usize {
        self.range
    }

    /// Returns the current bit position.
    pub fn pos(&self) -> usize {
        let mut bit_count = (self.count + 8) as usize;

        if bit_count > BD_VALUE_SIZE {
            bit_count = std::cmp::max(0, bit_count - LOTS_OF_BITS as usize);
        }

        let pos = self.data.position() as usize;
        pos * U8_BITS - bit_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NUM_BITS_TO_TEST: usize = 100;

    /// 100 zeros with probability of 0x80.
    const DATA_ZEROS_AND_EVEN_PROBABILITIES: [u8; 14] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// 100 ones with probability of 0x80.
    const DATA_ONES_AND_EVEN_PROBABILITIES: [u8; 14] = [
        0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0x20,
    ];

    /// [0, 1, 0, 1, ..., 1] with probability [0, 1, 2, 3, ..., 99].
    const DATA_PARITIES_AND_INCREASING_PROBABILITIES: [u8; 21] = [
        0x00, 0x02, 0x08, 0x31, 0x8e, 0xca, 0xab, 0xe2, 0xc8, 0x31, 0x12, 0xb3, 0x2c, 0x19, 0x90,
        0xc6, 0x6a, 0xeb, 0x17, 0x52, 0x30,
    ];

    // All tests adapted from:
    // https://chromium.googlesource.com/chromium/src/+/refs/heads/main/media/parsers/vp8_bool_decoder_unittest.cc

    #[test]
    fn decode_bools_with_zeros_and_even_probabilities() {
        let mut bd = BoolDecoder::new(&DATA_ZEROS_AND_EVEN_PROBABILITIES[..]);
        assert!(bd.pos() == 0);

        for i in 0..NUM_BITS_TO_TEST {
            assert!(!bd.read_bool_with_prob(0x80).unwrap());
            assert_eq!(i, bd.pos());
        }
    }

    #[test]
    fn decode_literals_with_zeros_and_even_probabilities() {
        // Adapted from:
        // https://chromium.googlesource.com/chromium/src/+/refs/heads/main/media/parsers/vp8_bool_decoder_unittest.cc
        let mut bd = BoolDecoder::new(&DATA_ZEROS_AND_EVEN_PROBABILITIES[..]);
        assert!(bd.pos() == 0);

        assert!(bd.read_literal(1).unwrap() == 0);
        assert!(bd.read_literal(32).unwrap() == 0);
        assert!(bd.read_sint::<i32>(1).unwrap() == 0);
        assert!(bd.read_sint::<i32>(31).unwrap() == 0);
    }

    #[test]
    fn decode_bools_with_ones_and_even_probabilities() {
        let mut bd = BoolDecoder::new(&DATA_ONES_AND_EVEN_PROBABILITIES[..]);
        assert!(bd.pos() == 0);

        for i in 0..NUM_BITS_TO_TEST {
            assert!(bd.read_bool_with_prob(0x80).unwrap());
            assert_eq!(i + 1, bd.pos());
        }
    }

    #[test]
    fn decode_literals_with_ones_and_even_probabilities() {
        let mut bd = BoolDecoder::new(&DATA_ONES_AND_EVEN_PROBABILITIES[..]);
        assert!(bd.pos() == 0);

        assert!(bd.read_literal(1).unwrap() == 1);
        assert!(bd.read_literal(31).unwrap() == 0x7fffffff);
        assert!(bd.read_sint::<i32>(1).unwrap() == -1);
        assert!(bd.read_sint::<i32>(31).unwrap() == -0x7fffffff);
    }

    #[test]
    fn decode_bools_with_parities_and_increasing_probabilities() {
        let mut bd = BoolDecoder::new(&DATA_PARITIES_AND_INCREASING_PROBABILITIES[..]);
        assert!(bd.pos() == 0);

        for i in 0..NUM_BITS_TO_TEST {
            let bit = bd.read_bool_with_prob(i as u8).unwrap();

            if i % 2 == 0 {
                assert!(!bit);
            } else {
                assert!(bit);
            }
        }
    }
}
