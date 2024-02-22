// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::os::raw::c_int;

use base::handle_eintr_errno;
use base::ioctl_ior_nr;

use crate::usb::backend::fido_backend::constants;
use crate::usb::backend::fido_backend::error::Error;
use crate::usb::backend::fido_backend::error::Result;

#[repr(C)]
#[derive(Clone)]
pub struct HidrawReportDescriptor {
    pub size: u32,
    pub value: [u8; constants::HID_MAX_DESCRIPTOR_SIZE],
}

pub const HID_IO_TYPE: u32 = 'H' as u32;

ioctl_ior_nr!(HIDIOCGRDESCSIZE, HID_IO_TYPE, 0x01, c_int);
ioctl_ior_nr!(HIDIOCGRDESC, HID_IO_TYPE, 0x02, HidrawReportDescriptor);

/// Verifies that the given `hidraw` file handle is a valid FIDO device.
/// In case it is not, it returns an `InvalidHidrawDevice` erro.
pub fn verify_is_fido_device(hidraw: &File) -> Result<()> {
    let mut desc_size: c_int = 0;
    // SAFETY:
    // Safe because:
    // - We check the return value after the call.
    // - ioctl(HIDIOCGRDDESCSIZE) does not hold the descriptor after the call.
    unsafe {
        let ret = handle_eintr_errno!(base::ioctl_with_mut_ref(
            hidraw,
            HIDIOCGRDESCSIZE(),
            &mut desc_size
        ));
        if ret < 0 || (desc_size as usize) < constants::HID_REPORT_DESC_HEADER.len() {
            return Err(Error::InvalidHidrawDevice);
        }
    }

    let mut descriptor = HidrawReportDescriptor {
        size: desc_size as u32,
        value: [0; constants::HID_MAX_DESCRIPTOR_SIZE],
    };

    // SAFETY:
    // Safe because:
    // - We check the return value after the call.
    // - ioctl(HIDIOCGRDESC) does not hold the descriptor after the call.
    unsafe {
        let ret = handle_eintr_errno!(base::ioctl_with_mut_ref(
            hidraw,
            HIDIOCGRDESC(),
            &mut descriptor
        ));
        if ret < 0 {
            return Err(Error::InvalidHidrawDevice);
        }
    }

    if descriptor.value[..constants::HID_REPORT_DESC_HEADER.len()]
        != *constants::HID_REPORT_DESC_HEADER
    {
        return Err(Error::InvalidHidrawDevice);
    }
    Ok(())
}
