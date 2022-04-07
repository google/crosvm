// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::str::FromStr;

use remain::sorted;
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;

#[derive(Debug, PartialEq)]
pub enum PciAddressComponent {
    Domain,
    Bus,
    Device,
    Function,
}

#[derive(ThisError, Debug, PartialEq)]
#[sorted]
pub enum Error {
    #[error("{0:?} out of range")]
    ComponentOutOfRange(PciAddressComponent),
    #[error("{0:?} failed to parse as hex")]
    InvalidHex(PciAddressComponent),
    #[error("Missing delimiter between {0:?} and {1:?}")]
    MissingDelimiter(PciAddressComponent, PciAddressComponent),
    #[error("Too many components in PCI address")]
    TooManyComponents,
}

pub type Result<T> = std::result::Result<T, Error>;

/// PCI Device Address, AKA Bus:Device.Function
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PciAddress {
    pub bus: u8,
    pub dev: u8,  /* u5 */
    pub func: u8, /* u3 */
}

impl Display for PciAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let domain = 0;
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{:0x}",
            domain, self.bus, self.dev, self.func,
        )
    }
}

/// Construct PciAddress from string [domain:]bus:device.function.
impl FromStr for PciAddress {
    type Err = Error;

    fn from_str(address: &str) -> std::result::Result<Self, Self::Err> {
        let (dev_bus_domain, func) = address.rsplit_once('.').ok_or(Error::MissingDelimiter(
            PciAddressComponent::Device,
            PciAddressComponent::Function,
        ))?;
        let func = u32::from_str_radix(func, 16)
            .map_err(|_| Error::InvalidHex(PciAddressComponent::Function))?;

        let (bus_domain, dev) = dev_bus_domain
            .rsplit_once(':')
            .ok_or(Error::MissingDelimiter(
                PciAddressComponent::Bus,
                PciAddressComponent::Device,
            ))?;
        let dev = u32::from_str_radix(dev, 16)
            .map_err(|_| Error::InvalidHex(PciAddressComponent::Device))?;

        // Domain is optional; if unspecified, the rest of the string is the bus, and domain
        // defaults to 0.
        let (domain, bus) = bus_domain.rsplit_once(':').unwrap_or(("0", bus_domain));
        let bus = u32::from_str_radix(bus, 16)
            .map_err(|_| Error::InvalidHex(PciAddressComponent::Bus))?;

        if domain.contains(':') {
            return Err(Error::TooManyComponents);
        }

        let domain = u32::from_str_radix(domain, 16)
            .map_err(|_| Error::InvalidHex(PciAddressComponent::Domain))?;

        Self::new(domain, bus, dev, func)
    }
}

impl PciAddress {
    const BUS_MASK: u32 = 0x00ff;
    const DEVICE_BITS_NUM: usize = 5;
    const DEVICE_MASK: u32 = 0x1f;
    const FUNCTION_BITS_NUM: usize = 3;
    const FUNCTION_MASK: u32 = 0x07;
    const REGISTER_OFFSET: usize = 2;

    /// Construct PciAddress from separate domain, bus, device, and function numbers.
    pub fn new(domain: u32, bus: u32, dev: u32, func: u32) -> Result<Self> {
        if bus > Self::BUS_MASK {
            return Err(Error::ComponentOutOfRange(PciAddressComponent::Bus));
        }

        if dev > Self::DEVICE_MASK {
            return Err(Error::ComponentOutOfRange(PciAddressComponent::Device));
        }

        if func > Self::FUNCTION_MASK {
            return Err(Error::ComponentOutOfRange(PciAddressComponent::Function));
        }

        // PciAddress does not store domain for now, so disallow anything other than domain 0.
        if domain > 0 {
            return Err(Error::ComponentOutOfRange(PciAddressComponent::Domain));
        }

        Ok(PciAddress {
            bus: bus as u8,
            dev: dev as u8,
            func: func as u8,
        })
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string() {
        assert_eq!(
            PciAddress::from_str("0000:00:00.0").unwrap(),
            PciAddress {
                bus: 0,
                dev: 0,
                func: 0
            }
        );
        assert_eq!(
            PciAddress::from_str("00:00.0").unwrap(),
            PciAddress {
                bus: 0,
                dev: 0,
                func: 0
            }
        );
        assert_eq!(
            PciAddress::from_str("01:02.3").unwrap(),
            PciAddress {
                bus: 1,
                dev: 2,
                func: 3
            }
        );
        assert_eq!(
            PciAddress::from_str("ff:1f.7").unwrap(),
            PciAddress {
                bus: 0xff,
                dev: 0x1f,
                func: 7,
            }
        );
    }

    #[test]
    fn from_string_missing_func_delim() {
        assert_eq!(
            PciAddress::from_str("1").expect_err("parse should fail"),
            Error::MissingDelimiter(PciAddressComponent::Device, PciAddressComponent::Function)
        );
    }

    #[test]
    fn from_string_missing_dev_delim() {
        assert_eq!(
            PciAddress::from_str("2.1").expect_err("parse should fail"),
            Error::MissingDelimiter(PciAddressComponent::Bus, PciAddressComponent::Device)
        );
    }

    #[test]
    fn from_string_extra_components() {
        assert_eq!(
            PciAddress::from_str("0:0:0:0.0").expect_err("parse should fail"),
            Error::TooManyComponents
        );
    }

    #[test]
    fn from_string_invalid_func_hex() {
        assert_eq!(
            PciAddress::from_str("0000:00:00.g").expect_err("parse should fail"),
            Error::InvalidHex(PciAddressComponent::Function)
        );
    }

    #[test]
    fn from_string_invalid_func_range() {
        assert_eq!(
            PciAddress::from_str("0000:00:00.8").expect_err("parse should fail"),
            Error::ComponentOutOfRange(PciAddressComponent::Function)
        );
    }

    #[test]
    fn from_string_invalid_dev_hex() {
        assert_eq!(
            PciAddress::from_str("0000:00:gg.0").expect_err("parse should fail"),
            Error::InvalidHex(PciAddressComponent::Device)
        );
    }

    #[test]
    fn from_string_invalid_dev_range() {
        assert_eq!(
            PciAddress::from_str("0000:00:20.0").expect_err("parse should fail"),
            Error::ComponentOutOfRange(PciAddressComponent::Device)
        );
    }

    #[test]
    fn from_string_invalid_bus_hex() {
        assert_eq!(
            PciAddress::from_str("0000:gg:00.0").expect_err("parse should fail"),
            Error::InvalidHex(PciAddressComponent::Bus)
        );
    }

    #[test]
    fn from_string_invalid_bus_range() {
        assert_eq!(
            PciAddress::from_str("0000:100:00.0").expect_err("parse should fail"),
            Error::ComponentOutOfRange(PciAddressComponent::Bus)
        );
    }

    #[test]
    fn from_string_invalid_domain_hex() {
        assert_eq!(
            PciAddress::from_str("gggg:00:00.0").expect_err("parse should fail"),
            Error::InvalidHex(PciAddressComponent::Domain)
        );
    }

    #[test]
    fn from_string_invalid_domain_range() {
        assert_eq!(
            PciAddress::from_str("0001:00:00.0").expect_err("parse should fail"),
            Error::ComponentOutOfRange(PciAddressComponent::Domain)
        );
    }

    #[test]
    fn format_simple() {
        assert_eq!(
            PciAddress::new(0, 1, 2, 3).unwrap().to_string(),
            "0000:01:02.3"
        );
    }

    #[test]
    fn format_max() {
        assert_eq!(
            PciAddress::new(0, 0xff, 0x1f, 7).unwrap().to_string(),
            "0000:ff:1f.7"
        );
    }
}
