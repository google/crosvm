// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::fmt::Display;
use std::path::Path;
use std::str::FromStr;

use remain::sorted;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use thiserror::Error as ThisError;

/// Identifies a single component of a [`PciAddress`].
#[derive(Debug, PartialEq, Eq)]
pub enum PciAddressComponent {
    Domain,
    Bus,
    Device,
    Function,
}

/// PCI address parsing and conversion errors.
#[derive(ThisError, Debug, PartialEq, Eq)]
#[sorted]
pub enum Error {
    /// The specified component was outside the valid range.
    #[error("{0:?} out of range")]
    ComponentOutOfRange(PciAddressComponent),
    /// The specified component could not be parsed as a hexadecimal number.
    #[error("{0:?} failed to parse as hex")]
    InvalidHex(PciAddressComponent),
    /// The given PCI device path is invalid
    #[error("Invalid PCI device path")]
    InvalidHostPath,
    /// A delimiter (`:` or `.`) between the two specified components was missing or incorrect.
    #[error("Missing delimiter between {0:?} and {1:?}")]
    MissingDelimiter(PciAddressComponent, PciAddressComponent),
    /// The PCI address contained more than the expected number of components.
    #[error("Too many components in PCI address")]
    TooManyComponents,
}

pub type Result<T> = std::result::Result<T, Error>;

/// PCI Device Address, AKA Bus:Device.Function
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PciAddress {
    /// Bus number, in the range `0..=255`.
    pub bus: u8,
    /// Device number, in the range `0..=31`.
    pub dev: u8,
    /// Function number, in the range `0..=7`.
    pub func: u8,
}

impl Serialize for PciAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PciAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Convert `PciAddress` to a human-readable string format.
///
/// The display format will always include the domain component, even if it is zero.
///
/// # Example
///
/// ```
/// use devices::PciAddress;
///
/// let pci_address = PciAddress::new(0x0000, 0x03, 0x14, 0x1)?;
/// assert_eq!(pci_address.to_string(), "0000:03:14.1");
/// # Ok::<(), devices::PciAddressError>(())
/// ```
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

/// Construct `PciAddress` from string "\[domain:\]bus:device.function".
/// Each component of the address is unprefixed hexadecimal.
///
/// # Example
///
/// ```
/// use std::str::FromStr;
/// use devices::PciAddress;
///
/// let pci_address = PciAddress::from_str("d7:15.4")?;
/// assert_eq!(pci_address.bus, 0xd7);
/// assert_eq!(pci_address.dev, 0x15);
/// assert_eq!(pci_address.func, 0x4);
/// # Ok::<(), devices::PciAddressError>(())
/// ```
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
    #[doc(hidden)]
    const BUS_MASK: u32 = 0x00ff;
    #[doc(hidden)]
    const DEVICE_BITS_NUM: usize = 5;
    #[doc(hidden)]
    const DEVICE_MASK: u32 = 0x1f;
    #[doc(hidden)]
    const FUNCTION_BITS_NUM: usize = 3;
    #[doc(hidden)]
    const FUNCTION_MASK: u32 = 0x07;
    #[doc(hidden)]
    const REGISTER_OFFSET: usize = 2;

    /// Construct [`PciAddress`] from separate domain, bus, device, and function numbers.
    ///
    /// # Arguments
    ///
    /// * `domain` - The PCI domain number. Must be `0` in the current implementation.
    /// * `bus` - The PCI bus number. Must be in the range `0..=255`.
    /// * `dev` - The PCI device number. Must be in the range `0..=31`.
    /// * `func` - The PCI function number. Must be in the range `0..=7`.
    ///
    /// # Errors
    ///
    /// If any component is out of the valid range, this function will return
    /// [`Error::ComponentOutOfRange`].
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

    /// Decode a [`PciAddress`] and register index from a CONFIG_ADDRESS value.
    ///
    /// The configuration address should be in the format used with the PCI CAM or ECAM
    /// configuration space access mechanisms, with the lowest bits encoding a register index and
    /// the bits above that encoding the PCI function (3 bits), device (5 bits), and bus (8 bits).
    /// The low two bits of the configuration address, which are technically part of the register
    /// number, are ignored, since PCI configuration space accesses must be DWORD (4-byte) aligned.
    ///
    /// On success, returns a [`PciAddress`] and the extracted register index in DWORDs.
    ///
    /// # Arguments
    ///
    /// * `config_address` - The PCI configuration address.
    /// * `register_bits_num` - The size of the register value in bits.
    ///
    /// # Example
    ///
    /// ```
    /// use devices::PciAddress;
    ///
    /// let (pci_address, register_index) = PciAddress::from_config_address(0x32a354, 8);
    /// assert_eq!(pci_address.bus, 0x32);
    /// assert_eq!(pci_address.dev, 0x14);
    /// assert_eq!(pci_address.func, 0x3);
    /// assert_eq!(register_index, 0x15);
    /// ```
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

    /// Construct [`PciAddress`] from a system PCI path
    ///
    /// # Arguments
    ///
    /// * `path` - The system PCI path. The file name of this path must be a valid PCI address.
    ///
    /// # Errors
    ///
    /// If the path given is invalid or filename is an invalid PCI address, this function will
    /// return error.
    pub fn from_path(path: &Path) -> Result<Self> {
        let os_str = path.file_name().ok_or(Error::InvalidHostPath)?;
        let pci_str = os_str.to_str().ok_or(Error::InvalidHostPath)?;
        PciAddress::from_str(pci_str)
    }

    /// Encode [`PciAddress`] into CONFIG_ADDRESS value.
    ///
    /// See [`PciAddress::from_config_address()`] for details of the encoding.
    ///
    /// # Arguments
    ///
    /// * `register` - The register index in DWORDs.
    /// * `register_bits_num` - The width of the register field, not including the two lowest bits.
    ///
    /// # Example
    ///
    /// ```
    /// use devices::PciAddress;
    ///
    /// let pci_address = PciAddress::new(0x0000, 0x32, 0x14, 0x3)?;
    /// let config_address = pci_address.to_config_address(0x15, 8);
    /// assert_eq!(config_address, 0x32a354);
    /// # Ok::<(), devices::PciAddressError>(())
    /// ```
    pub fn to_config_address(&self, register: usize, register_bits_num: usize) -> u32 {
        let bus_offset = register_bits_num + Self::FUNCTION_BITS_NUM + Self::DEVICE_BITS_NUM;
        let dev_offset = register_bits_num + Self::FUNCTION_BITS_NUM;
        let register_mask: u32 = (1_u32 << (register_bits_num - Self::REGISTER_OFFSET)) - 1;
        ((Self::BUS_MASK & self.bus as u32) << bus_offset)
            | ((Self::DEVICE_MASK & self.dev as u32) << dev_offset)
            | ((Self::FUNCTION_MASK & self.func as u32) << register_bits_num)
            | ((register_mask & register as u32) << Self::REGISTER_OFFSET)
    }

    /// Convert B:D:F PCI address to unsigned 32 bit integer.
    ///
    /// The bus, device, and function numbers are packed into an integer as follows:
    ///
    /// | Bits 15-8 | Bits 7-3 | Bits 2-0 |
    /// |-----------|----------|----------|
    /// |    Bus    |  Device  | Function |
    pub fn to_u32(&self) -> u32 {
        ((Self::BUS_MASK & self.bus as u32) << (Self::FUNCTION_BITS_NUM + Self::DEVICE_BITS_NUM))
            | ((Self::DEVICE_MASK & self.dev as u32) << Self::FUNCTION_BITS_NUM)
            | (Self::FUNCTION_MASK & self.func as u32)
    }

    /// Convert D:F PCI address to a linux style devfn.
    ///
    /// The device and function numbers are packed into an u8 as follows:
    ///
    /// | Bits 7-3 | Bits 2-0 |
    /// |----------|----------|
    /// |  Device  | Function |
    pub fn devfn(&self) -> u8 {
        (self.dev << Self::FUNCTION_BITS_NUM) | self.func
    }

    /// Convert D:F PCI address to an ACPI _ADR.
    ///
    /// The device and function numbers are packed into an u32 as follows:
    ///
    /// | Bits 31-16 | Bits 15-0 |
    /// |------------|-----------|
    /// |   Device   | Function  |
    pub fn acpi_adr(&self) -> u32 {
        ((Self::DEVICE_MASK & self.dev as u32) << 16) | (Self::FUNCTION_MASK & self.func as u32)
    }

    /// Returns true if the address points to PCI root host-bridge.
    ///
    /// This is true if and only if this is the all-zero address (`00:0.0`).
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

    #[test]
    fn serialize_json() {
        assert_eq!(
            serde_json::to_string(&PciAddress::new(0, 0xa5, 0x1f, 3).unwrap()).unwrap(),
            "\"0000:a5:1f.3\""
        );
    }

    #[test]
    fn deserialize_json() {
        assert_eq!(
            serde_json::from_str::<PciAddress>("\"0000:a5:1f.3\"").unwrap(),
            PciAddress {
                bus: 0xa5,
                dev: 0x1f,
                func: 3,
            }
        );
    }
}
