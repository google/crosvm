// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::os::raw::c_uint;
use std::ptr::null;

use base::ioctl_ior_nr;
use base::ioctl_iow_nr;
use base::ioctl_with_mut_ref;
use base::ioctl_with_ptr;
use base::ioctl_with_ref;
use base::AsRawDescriptor;
use data_model::Le32;
use linux_input_sys::constants::*;

use super::virtio_input_absinfo;
use super::virtio_input_bitmap;
use super::virtio_input_device_ids;
use super::InputError;
use super::Result;

const EVDEV: c_uint = 69;

#[repr(C)]
#[derive(Copy, Clone)]
struct evdev_buffer {
    buffer: [std::os::raw::c_uchar; 128],
}

impl evdev_buffer {
    fn new() -> evdev_buffer {
        evdev_buffer { buffer: [0u8; 128] }
    }

    fn get(&self, bit: usize) -> bool {
        let idx = bit / 8;
        let inner_bit = bit % 8;
        self.buffer
            .get(idx)
            .map_or(false, |val| val & (1u8 << inner_bit) != 0)
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct evdev_id {
    bustype: u16,
    vendor: u16,
    product: u16,
    version: u16,
}

impl evdev_id {
    fn new() -> evdev_id {
        evdev_id {
            bustype: 0,
            vendor: 0,
            product: 0,
            version: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct evdev_abs_info {
    // These should technically by signed ints, but Le32 is only compatible with u32 and we only
    // forward the bytes but don't care about its actual values.
    value: u32,
    minimum: u32,
    maximum: u32,
    fuzz: u32,
    flat: u32,
    resolution: u32,
}

impl evdev_abs_info {
    fn new() -> evdev_abs_info {
        evdev_abs_info {
            value: 0,
            minimum: 0,
            maximum: 0,
            fuzz: 0,
            flat: 0,
            resolution: 0,
        }
    }
}

impl From<evdev_abs_info> for virtio_input_absinfo {
    fn from(other: evdev_abs_info) -> Self {
        virtio_input_absinfo {
            min: Le32::from(other.minimum),
            max: Le32::from(other.maximum),
            fuzz: Le32::from(other.fuzz),
            flat: Le32::from(other.flat),
        }
    }
}

ioctl_ior_nr!(EVIOCGID, EVDEV, 0x02, evdev_id);
ioctl_ior_nr!(EVIOCGNAME, EVDEV, 0x06, evdev_buffer);
ioctl_ior_nr!(EVIOCGUNIQ, EVDEV, 0x08, evdev_buffer);
ioctl_ior_nr!(EVIOCGPROP, EVDEV, 0x09, evdev_buffer);
ioctl_ior_nr!(EVIOCGBIT, EVDEV, 0x20 + evt, evdev_buffer, evt);
ioctl_ior_nr!(EVIOCGABS, EVDEV, 0x40 + abs, evdev_abs_info, abs);
ioctl_iow_nr!(EVIOCGRAB, EVDEV, 0x90, u32);

fn errno() -> base::Error {
    base::Error::last()
}

/// Gets id information from an event device (see EVIOCGID ioctl for details).
pub fn device_ids<T: AsRawDescriptor>(descriptor: &T) -> Result<virtio_input_device_ids> {
    let mut dev_id = evdev_id::new();
    let len = {
        // SAFETY:
        // Safe because the kernel won't write more than size of evdev_id and we check the return
        // value
        unsafe { ioctl_with_mut_ref(descriptor, EVIOCGID(), &mut dev_id) }
    };
    if len < 0 {
        return Err(InputError::EvdevIdError(errno()));
    }
    Ok(virtio_input_device_ids::new(
        dev_id.bustype,
        dev_id.vendor,
        dev_id.product,
        dev_id.version,
    ))
}

/// Gets the name of an event device (see EVIOCGNAME ioctl for details).
pub fn name<T: AsRawDescriptor>(descriptor: &T) -> Result<Vec<u8>> {
    let mut name = evdev_buffer::new();
    let len = {
        // SAFETY:
        // Safe because the kernel won't write more than size of evdev_buffer and we check the
        // return value
        unsafe { ioctl_with_mut_ref(descriptor, EVIOCGNAME(), &mut name) }
    };
    if len < 0 {
        return Err(InputError::EvdevNameError(errno()));
    }
    Ok(name.buffer[0..len as usize].to_vec())
}

/// Gets the unique (serial) name of an event device (see EVIOCGUNIQ ioctl for details).
pub fn serial_name<T: AsRawDescriptor>(descriptor: &T) -> Result<Vec<u8>> {
    let mut uniq = evdev_buffer::new();
    let len = {
        // SAFETY:
        // Safe because the kernel won't write more than size of evdev_buffer and we check the
        // return value
        unsafe { ioctl_with_mut_ref(descriptor, EVIOCGUNIQ(), &mut uniq) }
    };
    if len < 0 {
        return Err(InputError::EvdevSerialError(errno()));
    }
    Ok(uniq.buffer[0..len as usize].to_vec())
}

/// Gets the properties of an event device (see EVIOCGPROP ioctl for details).
pub fn properties<T: AsRawDescriptor>(descriptor: &T) -> Result<virtio_input_bitmap> {
    let mut props = evdev_buffer::new();
    let len = {
        // SAFETY:
        // Safe because the kernel won't write more than size of evdev_buffer and we check the
        // return value
        unsafe { ioctl_with_mut_ref(descriptor, EVIOCGPROP(), &mut props) }
    };
    if len < 0 {
        return Err(InputError::EvdevPropertiesError(errno()));
    }
    Ok(virtio_input_bitmap::new(props.buffer))
}

/// Gets the event types supported by an event device as well as the event codes supported for each
/// type (see EVIOCGBIT ioctl for details).
pub fn supported_events<T: AsRawDescriptor>(
    descriptor: &T,
) -> Result<BTreeMap<u16, virtio_input_bitmap>> {
    let mut evts: BTreeMap<u16, virtio_input_bitmap> = BTreeMap::new();

    let mut evt_types = evdev_buffer::new();
    let len = {
        // SAFETY:
        // Safe because the kernel won't write more than size of evdev_buffer and we check the
        // return value
        unsafe { ioctl_with_mut_ref(descriptor, EVIOCGBIT(0), &mut evt_types) }
    };
    if len < 0 {
        return Err(InputError::EvdevEventTypesError(errno()));
    }

    // no need to ask for zero (EV_SYN) since it's always supported and treated as a special case
    for ev in 1..EV_MAX {
        if ev == EV_REP || !evt_types.get(ev as usize) {
            // Event type not supported, skip it.
            continue;
        }
        // Create a new zero-filled buffer every time to avoid carry-overs.
        let mut evt_codes = evdev_buffer::new();
        let len = {
            // SAFETY:
            // Safe because the kernel won't write more than size of evdev_buffer and we check the
            // return value
            unsafe { ioctl_with_mut_ref(descriptor, EVIOCGBIT(ev as c_uint), &mut evt_codes) }
        };
        if len < 0 {
            return Err(InputError::EvdevEventTypesError(errno()));
        }
        evts.insert(ev, virtio_input_bitmap::new(evt_codes.buffer));
    }
    Ok(evts)
}

/// Gets the absolute axes of an event device (see EVIOCGABS ioctl for details).
pub fn abs_info<T: AsRawDescriptor>(descriptor: &T) -> BTreeMap<u16, virtio_input_absinfo> {
    let mut map: BTreeMap<u16, virtio_input_absinfo> = BTreeMap::new();

    for abs in 0..ABS_MAX {
        // Create a new one, zero-ed out every time to avoid carry-overs.
        let mut abs_info = evdev_abs_info::new();
        let ret = {
            // SAFETY:
            // Safe because the kernel won't write more than size of evdev_buffer and we check the
            // return value
            unsafe { ioctl_with_mut_ref(descriptor, EVIOCGABS(abs as c_uint), &mut abs_info) }
        };
        if ret == 0 {
            map.insert(abs, virtio_input_absinfo::from(abs_info));
        }
    }
    map
}

/// Grabs an event device (see EVIOCGGRAB ioctl for details). After this function succeeds the given
/// descriptor has exclusive access to the device, effectively making it unusable for any other process in
/// the host.
pub fn grab_evdev<T: AsRawDescriptor>(descriptor: &mut T) -> Result<()> {
    let val: u32 = 1;
    let ret = {
        // SAFETY:
        // Safe because the kernel only read the value of the ptr and we check the return value
        unsafe { ioctl_with_ref(descriptor, EVIOCGRAB(), &val) }
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(InputError::EvdevGrabError(errno()))
    }
}

pub fn ungrab_evdev<T: AsRawDescriptor>(descriptor: &mut T) -> Result<()> {
    let ret = {
        // SAFETY:
        // Safe because the kernel only reads the value of the ptr (doesn't dereference) and
        // we check the return value
        unsafe { ioctl_with_ptr(descriptor, EVIOCGRAB(), null::<u32>()) }
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(InputError::EvdevGrabError(errno()))
    }
}
