// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::mem::size_of;
use std::ops::Deref;

use base::warn;
use zerocopy::FromBytes;

use crate::types;
use crate::types::Descriptor;
use crate::types::DescriptorHeader;
use crate::types::EndpointDescriptor;
use crate::Error;
use crate::Result;

#[derive(Clone)]
pub struct DeviceDescriptorTree {
    // Full descriptor tree in the original format returned by the device.
    raw: Vec<u8>,
    inner: types::DeviceDescriptor,
    // Map of bConfigurationValue to ConfigDescriptor
    config_descriptors: BTreeMap<u8, ConfigDescriptorTree>,
    // Map of config index to bConfigurationValue.
    config_values: BTreeMap<u8, u8>,
}

#[derive(Clone)]
pub struct ConfigDescriptorTree {
    offset: usize,
    inner: types::ConfigDescriptor,
    // Map of (bInterfaceNumber, bAlternateSetting) to InterfaceDescriptor
    interface_descriptors: BTreeMap<(u8, u8), InterfaceDescriptorTree>,
}

#[derive(Clone)]
pub struct InterfaceDescriptorTree {
    offset: usize,
    inner: types::InterfaceDescriptor,
    // Map of bEndpointAddress to EndpointDescriptor
    endpoint_descriptors: BTreeMap<u8, EndpointDescriptor>,
}

impl DeviceDescriptorTree {
    pub fn get_config_descriptor(&self, config_value: u8) -> Option<&ConfigDescriptorTree> {
        self.config_descriptors.get(&config_value)
    }

    /// Retrieve the Nth configuration descriptor in the device descriptor.
    /// `config_index`: 0-based index into the list of configuration descriptors.
    pub fn get_config_descriptor_by_index(
        &self,
        config_index: u8,
    ) -> Option<&ConfigDescriptorTree> {
        self.config_descriptors
            .get(self.config_values.get(&config_index)?)
    }

    /// Access the raw descriptor tree as a slice of bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for DeviceDescriptorTree {
    type Target = types::DeviceDescriptor;

    fn deref(&self) -> &types::DeviceDescriptor {
        &self.inner
    }
}

impl ConfigDescriptorTree {
    /// Get interface by number and alt setting.
    pub fn get_interface_descriptor(
        &self,
        interface_num: u8,
        alt_setting: u8,
    ) -> Option<&InterfaceDescriptorTree> {
        self.interface_descriptors
            .get(&(interface_num, alt_setting))
    }

    /// Get the offset of this configuration descriptor within the raw descriptor tree.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl Deref for ConfigDescriptorTree {
    type Target = types::ConfigDescriptor;

    fn deref(&self) -> &types::ConfigDescriptor {
        &self.inner
    }
}

impl InterfaceDescriptorTree {
    pub fn get_endpoint_descriptor(&self, ep_idx: u8) -> Option<&EndpointDescriptor> {
        self.endpoint_descriptors.get(&ep_idx)
    }

    /// Get the offset of this interface descriptor within the raw descriptor tree.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl Deref for InterfaceDescriptorTree {
    type Target = types::InterfaceDescriptor;

    fn deref(&self) -> &types::InterfaceDescriptor {
        &self.inner
    }
}

/// Given `data` containing a full set of descriptors as provided by the Linux kernel
/// usbdevfs `descriptors` file, parse the descriptors into a tree data structure.
pub fn parse_usbfs_descriptors(data: &[u8]) -> Result<DeviceDescriptorTree> {
    let mut offset = 0;

    // Find the next descriptor of type T and return it and its offset.
    // Any other descriptors encountered while searching for the expected type are skipped.
    // The `offset` parameter will be advanced to point to the next byte after the returned
    // descriptor.
    fn next_descriptor<T: Descriptor + FromBytes>(
        data: &[u8],
        offset: &mut usize,
    ) -> Result<(T, usize)> {
        let desc_type = T::descriptor_type() as u8;
        loop {
            let hdr = DescriptorHeader::read_from(
                data.get(*offset..*offset + size_of::<DescriptorHeader>())
                    .ok_or(Error::DescriptorParse)?,
            )
            .ok_or(Error::DescriptorParse)?;
            if hdr.bDescriptorType == desc_type {
                if usize::from(hdr.bLength) < size_of::<DescriptorHeader>() + size_of::<T>() {
                    return Err(Error::DescriptorParse);
                }

                let desc_offset = *offset;

                *offset += size_of::<DescriptorHeader>();
                let desc = T::read_from(
                    data.get(*offset..*offset + size_of::<T>())
                        .ok_or(Error::DescriptorParse)?,
                )
                .ok_or(Error::DescriptorParse)?;
                *offset += hdr.bLength as usize - size_of::<DescriptorHeader>();
                return Ok((desc, desc_offset));
            } else {
                // Finding a ConfigDescriptor while looking for InterfaceDescriptor means
                // that we should advance to the next device configuration.
                if desc_type == types::InterfaceDescriptor::descriptor_type() as u8
                    && hdr.bDescriptorType == types::ConfigDescriptor::descriptor_type() as u8
                {
                    return Err(Error::DescriptorParse);
                }

                // Make sure we make forward progress.
                if hdr.bLength == 0 {
                    return Err(Error::DescriptorParse);
                }

                // Skip this entire descriptor, since it's not the right type.
                *offset += hdr.bLength as usize;
            }
        }
    }

    let (raw_device_descriptor, _) = next_descriptor::<types::DeviceDescriptor>(data, &mut offset)?;
    let mut device_descriptor = DeviceDescriptorTree {
        raw: data.into(),
        inner: raw_device_descriptor,
        config_descriptors: BTreeMap::new(),
        config_values: BTreeMap::new(),
    };

    for cfg_idx in 0..device_descriptor.bNumConfigurations {
        if let Ok((raw_config_descriptor, config_offset)) =
            next_descriptor::<types::ConfigDescriptor>(&device_descriptor.raw, &mut offset)
        {
            let mut config_descriptor = ConfigDescriptorTree {
                offset: config_offset,
                inner: raw_config_descriptor,
                interface_descriptors: BTreeMap::new(),
            };

            while let Ok((raw_interface_descriptor, interface_offset)) =
                next_descriptor::<types::InterfaceDescriptor>(&device_descriptor.raw, &mut offset)
            {
                let mut interface_descriptor = InterfaceDescriptorTree {
                    offset: interface_offset,
                    inner: raw_interface_descriptor,
                    endpoint_descriptors: BTreeMap::new(),
                };

                for ep_idx in 0..interface_descriptor.bNumEndpoints {
                    if let Ok((endpoint_descriptor, _)) =
                        next_descriptor::<EndpointDescriptor>(&device_descriptor.raw, &mut offset)
                    {
                        interface_descriptor
                            .endpoint_descriptors
                            .insert(ep_idx, endpoint_descriptor);
                    } else {
                        warn!("Could not read endpoint descriptor {}", ep_idx);
                        break;
                    }
                }

                config_descriptor.interface_descriptors.insert(
                    (
                        interface_descriptor.bInterfaceNumber,
                        interface_descriptor.bAlternateSetting,
                    ),
                    interface_descriptor,
                );
            }

            for intf_idx in 0..config_descriptor.bNumInterfaces {
                if config_descriptor
                    .interface_descriptors
                    .get(&(intf_idx, 0))
                    .is_none()
                {
                    warn!("device interface {} has no interface descriptors", intf_idx);
                }
            }

            device_descriptor
                .config_values
                .insert(cfg_idx, config_descriptor.bConfigurationValue);
            device_descriptor
                .config_descriptors
                .insert(config_descriptor.bConfigurationValue, config_descriptor);
        } else {
            warn!("Could not read config descriptor {}", cfg_idx);
            break;
        }
    }

    Ok(device_descriptor)
}

#[cfg(test)]
#[allow(clippy::useless_conversion)]
mod tests {
    use super::*;
    #[test]
    fn parse_descriptors_mass_storage() {
        let data: &[u8] = &[
            0x12, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x09, 0x81, 0x07, 0x80, 0x55, 0x10, 0x00,
            0x01, 0x02, 0x03, 0x01, 0x09, 0x02, 0x2C, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32, 0x09,
            0x04, 0x00, 0x00, 0x02, 0x08, 0x06, 0x50, 0x00, 0x07, 0x05, 0x81, 0x02, 0x00, 0x04,
            0x00, 0x06, 0x30, 0x0F, 0x00, 0x00, 0x00, 0x07, 0x05, 0x02, 0x02, 0x00, 0x04, 0x00,
            0x06, 0x30, 0x0F, 0x00, 0x00, 0x00,
        ];

        let d = parse_usbfs_descriptors(data).expect("parse_usbfs_descriptors failed");

        // The seemingly-redundant u16::from() calls avoid borrows of packed fields.

        assert_eq!(u16::from(d.bcdUSB), 0x03_00);
        assert_eq!(d.bDeviceClass, 0x00);
        assert_eq!(d.bDeviceSubClass, 0x00);
        assert_eq!(d.bDeviceProtocol, 0x00);
        assert_eq!(d.bMaxPacketSize0, 9);
        assert_eq!(u16::from(d.idVendor), 0x0781);
        assert_eq!(u16::from(d.idProduct), 0x5580);
        assert_eq!(u16::from(d.bcdDevice), 0x00_10);
        assert_eq!(d.iManufacturer, 1);
        assert_eq!(d.iProduct, 2);
        assert_eq!(d.iSerialNumber, 3);
        assert_eq!(d.bNumConfigurations, 1);

        let c = d
            .get_config_descriptor(1)
            .expect("could not get config descriptor 1");
        assert_eq!(u16::from(c.wTotalLength), 44);
        assert_eq!(c.bNumInterfaces, 1);
        assert_eq!(c.bConfigurationValue, 1);
        assert_eq!(c.iConfiguration, 0);
        assert_eq!(c.bmAttributes, 0x80);
        assert_eq!(c.bMaxPower, 50);

        let i = c
            .get_interface_descriptor(0, 0)
            .expect("could not get interface descriptor 0 alt setting 0");
        assert_eq!(i.bInterfaceNumber, 0);
        assert_eq!(i.bAlternateSetting, 0);
        assert_eq!(i.bNumEndpoints, 2);
        assert_eq!(i.bInterfaceClass, 0x08);
        assert_eq!(i.bInterfaceSubClass, 0x06);
        assert_eq!(i.bInterfaceProtocol, 0x50);
        assert_eq!(i.iInterface, 0);

        let e = i
            .get_endpoint_descriptor(0)
            .expect("could not get endpoint 0 descriptor");
        assert_eq!(e.bEndpointAddress, 0x81);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0400);
        assert_eq!(e.bInterval, 0);

        let e = i
            .get_endpoint_descriptor(1)
            .expect("could not get endpoint 1 descriptor");
        assert_eq!(e.bEndpointAddress, 0x02);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0400);
        assert_eq!(e.bInterval, 0);
    }

    #[test]
    fn parse_descriptors_servo() {
        let data: &[u8] = &[
            0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0xd1, 0x18, 0x1b, 0x50, 0x00, 0x01,
            0x01, 0x02, 0x03, 0x01, 0x09, 0x02, 0x7c, 0x00, 0x06, 0x01, 0x04, 0xc0, 0xfa, 0x09,
            0x04, 0x00, 0x00, 0x02, 0xff, 0x50, 0x01, 0x06, 0x07, 0x05, 0x81, 0x02, 0x40, 0x00,
            0x0a, 0x07, 0x05, 0x01, 0x02, 0x40, 0x00, 0x00, 0x09, 0x04, 0x02, 0x00, 0x02, 0xff,
            0x52, 0x01, 0x05, 0x07, 0x05, 0x83, 0x02, 0x40, 0x00, 0x0a, 0x07, 0x05, 0x03, 0x02,
            0x40, 0x00, 0x00, 0x09, 0x04, 0x03, 0x00, 0x02, 0xff, 0x50, 0x01, 0x07, 0x07, 0x05,
            0x84, 0x02, 0x10, 0x00, 0x0a, 0x07, 0x05, 0x04, 0x02, 0x10, 0x00, 0x00, 0x09, 0x04,
            0x04, 0x00, 0x02, 0xff, 0x50, 0x01, 0x08, 0x07, 0x05, 0x85, 0x02, 0x10, 0x00, 0x0a,
            0x07, 0x05, 0x05, 0x02, 0x10, 0x00, 0x00, 0x09, 0x04, 0x05, 0x00, 0x02, 0xff, 0x53,
            0xff, 0x09, 0x07, 0x05, 0x86, 0x02, 0x40, 0x00, 0x0a, 0x07, 0x05, 0x06, 0x02, 0x40,
            0x00, 0x00,
        ];

        // Note: configuration 1 has bNumInterfaces == 6, but it actually only contains 5
        // interface descriptors. This causes us to try to read beyond EOF, which should be
        // silently ignored by parse_usbfs_descriptors so that we can use the rest of the
        // descriptors.
        let d = parse_usbfs_descriptors(data).expect("parse_usbfs_descriptors failed");

        // The seemingly-redundant u16::from() calls avoid borrows of packed fields.

        assert_eq!(u16::from(d.bcdUSB), 0x02_00);
        assert_eq!(d.bDeviceClass, 0x00);
        assert_eq!(d.bDeviceSubClass, 0x00);
        assert_eq!(d.bDeviceProtocol, 0x00);
        assert_eq!(d.bMaxPacketSize0, 64);
        assert_eq!(u16::from(d.idVendor), 0x18d1);
        assert_eq!(u16::from(d.idProduct), 0x501b);
        assert_eq!(u16::from(d.bcdDevice), 0x01_00);
        assert_eq!(d.iManufacturer, 1);
        assert_eq!(d.iProduct, 2);
        assert_eq!(d.iSerialNumber, 3);
        assert_eq!(d.bNumConfigurations, 1);

        let c = d
            .get_config_descriptor(1)
            .expect("could not get config descriptor 1");
        assert_eq!(u16::from(c.wTotalLength), 124);
        assert_eq!(c.bNumInterfaces, 6);
        assert_eq!(c.bConfigurationValue, 1);
        assert_eq!(c.iConfiguration, 4);
        assert_eq!(c.bmAttributes, 0xc0);
        assert_eq!(c.bMaxPower, 250);

        let i = c
            .get_interface_descriptor(0, 0)
            .expect("could not get interface descriptor 0 alt setting 0");
        assert_eq!(i.bInterfaceNumber, 0);
        assert_eq!(i.bAlternateSetting, 0);
        assert_eq!(i.bNumEndpoints, 2);
        assert_eq!(i.bInterfaceClass, 0xff);
        assert_eq!(i.bInterfaceSubClass, 0x50);
        assert_eq!(i.bInterfaceProtocol, 0x01);
        assert_eq!(i.iInterface, 6);

        let e = i
            .get_endpoint_descriptor(0)
            .expect("could not get endpoint 0 descriptor");
        assert_eq!(e.bEndpointAddress, 0x81);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0040);
        assert_eq!(e.bInterval, 10);

        let e = i
            .get_endpoint_descriptor(1)
            .expect("could not get endpoint 1 descriptor");
        assert_eq!(e.bEndpointAddress, 0x01);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0040);
        assert_eq!(e.bInterval, 0);

        let i = c
            .get_interface_descriptor(2, 0)
            .expect("could not get interface descriptor 2 alt setting 0");
        assert_eq!(i.bInterfaceNumber, 2);
        assert_eq!(i.bAlternateSetting, 0);
        assert_eq!(i.bNumEndpoints, 2);
        assert_eq!(i.bInterfaceClass, 0xff);
        assert_eq!(i.bInterfaceSubClass, 0x52);
        assert_eq!(i.bInterfaceProtocol, 0x01);
        assert_eq!(i.iInterface, 5);

        let e = i
            .get_endpoint_descriptor(0)
            .expect("could not get endpoint 0 descriptor");
        assert_eq!(e.bEndpointAddress, 0x83);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0040);
        assert_eq!(e.bInterval, 10);

        let e = i
            .get_endpoint_descriptor(1)
            .expect("could not get endpoint 1 descriptor");
        assert_eq!(e.bEndpointAddress, 0x03);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0040);
        assert_eq!(e.bInterval, 0);

        let i = c
            .get_interface_descriptor(3, 0)
            .expect("could not get interface descriptor 3 alt setting 0");
        assert_eq!(i.bInterfaceNumber, 3);
        assert_eq!(i.bAlternateSetting, 0);
        assert_eq!(i.bNumEndpoints, 2);
        assert_eq!(i.bInterfaceClass, 0xff);
        assert_eq!(i.bInterfaceSubClass, 0x50);
        assert_eq!(i.bInterfaceProtocol, 0x01);
        assert_eq!(i.iInterface, 7);

        let e = i
            .get_endpoint_descriptor(0)
            .expect("could not get endpoint 0 descriptor");
        assert_eq!(e.bEndpointAddress, 0x84);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0010);
        assert_eq!(e.bInterval, 10);

        let e = i
            .get_endpoint_descriptor(1)
            .expect("could not get endpoint 1 descriptor");
        assert_eq!(e.bEndpointAddress, 0x04);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0010);
        assert_eq!(e.bInterval, 0);

        let i = c
            .get_interface_descriptor(4, 0)
            .expect("could not get interface descriptor 4 alt setting 0");
        assert_eq!(i.bInterfaceNumber, 4);
        assert_eq!(i.bAlternateSetting, 0);
        assert_eq!(i.bNumEndpoints, 2);
        assert_eq!(i.bInterfaceClass, 0xff);
        assert_eq!(i.bInterfaceSubClass, 0x50);
        assert_eq!(i.bInterfaceProtocol, 0x01);
        assert_eq!(i.iInterface, 8);

        let e = i
            .get_endpoint_descriptor(0)
            .expect("could not get endpoint 0 descriptor");
        assert_eq!(e.bEndpointAddress, 0x85);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0010);
        assert_eq!(e.bInterval, 10);

        let e = i
            .get_endpoint_descriptor(1)
            .expect("could not get endpoint 1 descriptor");
        assert_eq!(e.bEndpointAddress, 0x05);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0010);
        assert_eq!(e.bInterval, 0);

        let i = c
            .get_interface_descriptor(5, 0)
            .expect("could not get interface descriptor 5 alt setting 0");
        assert_eq!(i.bInterfaceNumber, 5);
        assert_eq!(i.bAlternateSetting, 0);
        assert_eq!(i.bNumEndpoints, 2);
        assert_eq!(i.bInterfaceClass, 0xff);
        assert_eq!(i.bInterfaceSubClass, 0x53);
        assert_eq!(i.bInterfaceProtocol, 0xff);
        assert_eq!(i.iInterface, 9);

        let e = i
            .get_endpoint_descriptor(0)
            .expect("could not get endpoint 0 descriptor");
        assert_eq!(e.bEndpointAddress, 0x86);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0040);
        assert_eq!(e.bInterval, 10);

        let e = i
            .get_endpoint_descriptor(1)
            .expect("could not get endpoint 1 descriptor");
        assert_eq!(e.bEndpointAddress, 0x06);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0040);
        assert_eq!(e.bInterval, 0);
    }

    #[test]
    fn parse_descriptors_adb() {
        let data: &[u8] = &[
            0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0xd1, 0x18, 0xe7, 0x4e, 0x10, 0x03,
            0x01, 0x02, 0x03, 0x01, 0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0x80, 0xfa, 0x09,
            0x04, 0x00, 0x00, 0x02, 0xff, 0x42, 0x01, 0x05, 0x07, 0x05, 0x01, 0x02, 0x00, 0x02,
            0x00, 0x07, 0x05, 0x81, 0x02, 0x00, 0x02, 0x00,
        ];

        let d = parse_usbfs_descriptors(data).expect("parse_usbfs_descriptors failed");

        // The seemingly-redundant u16::from() calls avoid borrows of packed fields.

        assert_eq!(u16::from(d.bcdUSB), 0x02_00);
        assert_eq!(d.bDeviceClass, 0x00);
        assert_eq!(d.bDeviceSubClass, 0x00);
        assert_eq!(d.bDeviceProtocol, 0x00);
        assert_eq!(d.bMaxPacketSize0, 64);
        assert_eq!(u16::from(d.idVendor), 0x18d1);
        assert_eq!(u16::from(d.idProduct), 0x4ee7);
        assert_eq!(u16::from(d.bcdDevice), 0x03_10);
        assert_eq!(d.iManufacturer, 1);
        assert_eq!(d.iProduct, 2);
        assert_eq!(d.iSerialNumber, 3);
        assert_eq!(d.bNumConfigurations, 1);

        let c = d
            .get_config_descriptor(1)
            .expect("could not get config descriptor 1");
        assert_eq!(u16::from(c.wTotalLength), 32);
        assert_eq!(c.bNumInterfaces, 1);
        assert_eq!(c.bConfigurationValue, 1);
        assert_eq!(c.iConfiguration, 0);
        assert_eq!(c.bmAttributes, 0x80);
        assert_eq!(c.bMaxPower, 250);

        let i = c
            .get_interface_descriptor(0, 0)
            .expect("could not get interface descriptor 0 alt setting 0");
        assert_eq!(i.bInterfaceNumber, 0);
        assert_eq!(i.bAlternateSetting, 0);
        assert_eq!(i.bNumEndpoints, 2);
        assert_eq!(i.bInterfaceClass, 0xff);
        assert_eq!(i.bInterfaceSubClass, 0x42);
        assert_eq!(i.bInterfaceProtocol, 0x01);
        assert_eq!(i.iInterface, 5);

        let e = i
            .get_endpoint_descriptor(0)
            .expect("could not get endpoint 0 descriptor");
        assert_eq!(e.bEndpointAddress, 0x01);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x200);
        assert_eq!(e.bInterval, 0);

        let e = i
            .get_endpoint_descriptor(1)
            .expect("could not get endpoint 1 descriptor");
        assert_eq!(e.bEndpointAddress, 0x81);
        assert_eq!(e.bmAttributes, 0x02);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x0200);
        assert_eq!(e.bInterval, 0);
    }

    #[test]
    fn parse_descriptors_multiple_altsettings() {
        let data: &[u8] = &[
            // DeviceDescriptor
            0x12, 0x01, 0x00, 0x02, 0xef, 0x02, 0x01, 0x40, 0x6d, 0x04, 0x43, 0x08, 0x13, 0x00,
            0x00, 0x02, 0x01, 0x01, // ConfigDescriptor
            0x09, 0x02, 0x0d, 0x0a, 0x03, 0x01, 0x00, 0x80, 0xfa,
            // InterfaceDescriptor 0, 0
            0x09, 0x04, 0x00, 0x00, 0x01, 0x0e, 0x01, 0x00, 0x00, // EndpointDescriptor
            0x07, 0x05, 0x86, 0x03, 0x40, 0x00, 0x08, // InterfaceDescriptor 1, 0
            0x09, 0x04, 0x01, 0x00, 0x00, 0x0e, 0x02, 0x00, 0x00,
            // InterfaceDescriptor 1, 1
            0x09, 0x04, 0x01, 0x01, 0x01, 0x0e, 0x02, 0x00, 0x00, // EndpointDescriptor
            0x07, 0x05, 0x81, 0x05, 0xc0, 0x00, 0x01, // InterfaceDescriptor 2, 0
            0x09, 0x04, 0x02, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
        ];

        let d = parse_usbfs_descriptors(data).expect("parse_usbfs_descriptors failed");

        // The seemingly-redundant u16::from() calls avoid borrows of packed fields.

        assert_eq!(u16::from(d.bcdUSB), 0x02_00);
        assert_eq!(d.bDeviceClass, 0xef);
        assert_eq!(d.bDeviceSubClass, 0x02);
        assert_eq!(d.bDeviceProtocol, 0x01);
        assert_eq!(d.bMaxPacketSize0, 64);
        assert_eq!(u16::from(d.idVendor), 0x046d);
        assert_eq!(u16::from(d.idProduct), 0x0843);
        assert_eq!(u16::from(d.bcdDevice), 0x00_13);
        assert_eq!(d.iManufacturer, 0);
        assert_eq!(d.iProduct, 2);
        assert_eq!(d.iSerialNumber, 1);
        assert_eq!(d.bNumConfigurations, 1);

        let c = d
            .get_config_descriptor(1)
            .expect("could not get config descriptor 1");
        assert_eq!(u16::from(c.wTotalLength), 2573);
        assert_eq!(c.bNumInterfaces, 3);
        assert_eq!(c.bConfigurationValue, 1);
        assert_eq!(c.iConfiguration, 0);
        assert_eq!(c.bmAttributes, 0x80);
        assert_eq!(c.bMaxPower, 250);

        let i = c
            .get_interface_descriptor(0, 0)
            .expect("could not get interface descriptor 0 alt setting 0");
        assert_eq!(i.bInterfaceNumber, 0);
        assert_eq!(i.bAlternateSetting, 0);
        assert_eq!(i.bNumEndpoints, 1);
        assert_eq!(i.bInterfaceClass, 0x0e);
        assert_eq!(i.bInterfaceSubClass, 0x01);
        assert_eq!(i.bInterfaceProtocol, 0x00);
        assert_eq!(i.iInterface, 0x00);

        let e = i
            .get_endpoint_descriptor(0)
            .expect("could not get endpoint 0 descriptor");
        assert_eq!(e.bEndpointAddress, 0x86);
        assert_eq!(e.bmAttributes, 0x03);
        assert_eq!(u16::from(e.wMaxPacketSize), 0x40);
        assert_eq!(e.bInterval, 0x08);

        let i = c
            .get_interface_descriptor(1, 0)
            .expect("could not get interface descriptor 1 alt setting 0");
        assert_eq!(i.bInterfaceNumber, 1);
        assert_eq!(i.bAlternateSetting, 0);
        assert_eq!(i.bNumEndpoints, 0);
        assert_eq!(i.bInterfaceClass, 0x0e);
        assert_eq!(i.bInterfaceSubClass, 0x02);
        assert_eq!(i.bInterfaceProtocol, 0x00);
        assert_eq!(i.iInterface, 0x00);

        let i = c
            .get_interface_descriptor(1, 1)
            .expect("could not get interface descriptor 1 alt setting 1");
        assert_eq!(i.bInterfaceNumber, 1);
        assert_eq!(i.bAlternateSetting, 1);
        assert_eq!(i.bNumEndpoints, 1);
        assert_eq!(i.bInterfaceClass, 0x0e);
        assert_eq!(i.bInterfaceSubClass, 0x02);
        assert_eq!(i.bInterfaceProtocol, 0x00);
        assert_eq!(i.iInterface, 0x00);

        let e = i
            .get_endpoint_descriptor(0)
            .expect("could not get endpoint 0 descriptor");
        assert_eq!(e.bEndpointAddress, 0x81);
        assert_eq!(e.bmAttributes, 0x05);
        assert_eq!(u16::from(e.wMaxPacketSize), 0xc0);
        assert_eq!(e.bInterval, 0x01);

        let i = c
            .get_interface_descriptor(2, 0)
            .expect("could not get interface descriptor 2 alt setting 0");
        assert_eq!(i.bInterfaceNumber, 2);
        assert_eq!(i.bAlternateSetting, 0);
        assert_eq!(i.bNumEndpoints, 0);
        assert_eq!(i.bInterfaceClass, 0x01);
        assert_eq!(i.bInterfaceSubClass, 0x01);
        assert_eq!(i.bInterfaceProtocol, 0x00);
        assert_eq!(i.iInterface, 0x00);
    }

    #[test]
    fn parse_descriptors_length_0() {
        // Device descriptor followed by a bogus descriptor with bLength == 0.
        // Note that this was generated by a fuzzer, so field values may not make sense.
        let data: &[u8] = &[
            0x10, 0x00, 0x18, 0x25, 0x80, 0x80, 0xAC, 0x03, 0x22, 0x05, 0x00, 0x00, 0x00, 0x00,
            0xC3, 0x2A, 0x00, 0x32, 0x00,
        ];

        let d = parse_usbfs_descriptors(data);
        if d.is_ok() {
            panic!("parse_usbfs_descriptors should have failed");
        }
    }
}
