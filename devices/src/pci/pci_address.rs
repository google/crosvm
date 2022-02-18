// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

/// PCI Device Address, AKA Bus:Device.Function
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PciAddress {
    pub bus: u8,
    pub dev: u8,  /* u5 */
    pub func: u8, /* u3 */
}

impl Display for PciAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:04x}:{:02x}.{:0x}", self.bus, self.dev, self.func)
    }
}

impl PciAddress {
    const BUS_MASK: u32 = 0x00ff;
    const DEVICE_BITS_NUM: usize = 5;
    const DEVICE_MASK: u32 = 0x1f;
    const FUNCTION_BITS_NUM: usize = 3;
    const FUNCTION_MASK: u32 = 0x07;
    const REGISTER_OFFSET: usize = 2;

    /// Construct PciAddress and register tuple from CONFIG_ADDRESS value.
    pub fn from_config_address(config_address: u32, register_bits_num: usize) -> (Self, usize) {
        let bus_offset = register_bits_num + Self::FUNCTION_BITS_NUM + Self::DEVICE_BITS_NUM;
        let bus = ((config_address >> bus_offset) & Self::BUS_MASK) as u8;
        let dev_offset = register_bits_num + Self::FUNCTION_BITS_NUM;
        let dev = ((config_address >> dev_offset) & Self::DEVICE_MASK) as u8;
        let func = ((config_address >> register_bits_num) & Self::FUNCTION_MASK) as u8;
        let register_mask: u32 = (1_u32 << (register_bits_num - Self::REGISTER_OFFSET)) - 1;
        let register = ((config_address >> Self::REGISTER_OFFSET) & register_mask) as usize;

        (PciAddress { bus, dev, func }, register)
    }

    /// Construct PciAddress from string domain:bus:device.function.
    pub fn from_string(address: &str) -> Self {
        let mut func_dev_bus_domain = address
            .split(|c| c == ':' || c == '.')
            .map(|v| u8::from_str_radix(v, 16).unwrap_or_default())
            .rev()
            .collect::<Vec<u8>>();
        func_dev_bus_domain.resize(4, 0);
        PciAddress {
            bus: func_dev_bus_domain[2],
            dev: func_dev_bus_domain[1],
            func: func_dev_bus_domain[0],
        }
    }

    /// Encode PciAddress into CONFIG_ADDRESS value.
    pub fn to_config_address(&self, register: usize, register_bits_num: usize) -> u32 {
        let bus_offset = register_bits_num + Self::FUNCTION_BITS_NUM + Self::DEVICE_BITS_NUM;
        let dev_offset = register_bits_num + Self::FUNCTION_BITS_NUM;
        let register_mask: u32 = (1_u32 << (register_bits_num - Self::REGISTER_OFFSET)) - 1;
        ((Self::BUS_MASK & self.bus as u32) << bus_offset)
            | ((Self::DEVICE_MASK & self.dev as u32) << dev_offset)
            | ((Self::FUNCTION_MASK & self.func as u32) << register_bits_num)
            | ((register_mask & register as u32) << Self::REGISTER_OFFSET)
    }

    /// Convert B:D:F PCI address to unsigned 32 bit integer
    pub fn to_u32(&self) -> u32 {
        ((Self::BUS_MASK & self.bus as u32) << (Self::FUNCTION_BITS_NUM + Self::DEVICE_BITS_NUM))
            | ((Self::DEVICE_MASK & self.dev as u32) << Self::FUNCTION_BITS_NUM)
            | (Self::FUNCTION_MASK & self.func as u32)
    }

    /// Returns true if the address points to PCI root host-bridge.
    pub fn is_root(&self) -> bool {
        matches!(
            &self,
            PciAddress {
                bus: 0,
                dev: 0,
                func: 0
            }
        )
    }
}
