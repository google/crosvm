// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use zerocopy::AsBytes;
use zerocopy::FromBytes;

#[repr(packed)]
#[derive(Clone, Copy, Default, FromBytes, AsBytes)]
pub struct RSDP {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    _rsdt_addr: u32,
    pub length: u32,
    pub xsdt_addr: u64,
    pub extended_checksum: u8,
    _reserved: [u8; 3],
}

impl RSDP {
    pub fn new(oem_id: [u8; 6], xsdt_addr: u64) -> Self {
        let mut rsdp = RSDP {
            signature: *b"RSD PTR ",
            checksum: 0,
            oem_id,
            revision: 2,
            _rsdt_addr: 0,
            length: std::mem::size_of::<RSDP>() as u32,
            xsdt_addr,
            extended_checksum: 0,
            _reserved: [0; 3],
        };

        rsdp.checksum = super::generate_checksum(&rsdp.as_bytes()[0..19]);
        rsdp.extended_checksum = super::generate_checksum(rsdp.as_bytes());
        rsdp
    }

    pub fn len() -> usize {
        std::mem::size_of::<RSDP>()
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::AsBytes;

    use super::RSDP;

    #[test]
    fn test_rsdp() {
        let rsdp = RSDP::new(*b"CHYPER", 0xdead_beef);
        let sum = rsdp
            .as_bytes()
            .iter()
            .fold(0u8, |acc, x| acc.wrapping_add(*x));
        assert_eq!(sum, 0);
        let sum: u8 = rsdp
            .as_bytes()
            .iter()
            .fold(0u8, |acc, x| acc.wrapping_add(*x));
        assert_eq!(sum, 0);
    }
}
