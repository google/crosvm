// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Generated with bindgen libusb.h -no-prepend-enum-name -o bindings.rs.
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#[allow(clippy::all)]
mod bindings;

#[macro_use]
pub mod error;
pub mod config_descriptor;
pub mod device_handle;
pub mod endpoint_descriptor;
pub mod hotplug;
pub mod interface_descriptor;
pub mod libusb_context;
pub mod libusb_device;
pub mod types;
pub mod usb_transfer;
