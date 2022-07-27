// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! USB device access and descriptor manipulation.

mod descriptor;
mod device;
mod error;
mod types;

pub use self::descriptor::parse_usbfs_descriptors;
pub use self::descriptor::ConfigDescriptorTree;
pub use self::descriptor::DeviceDescriptorTree;
pub use self::descriptor::InterfaceDescriptorTree;
pub use self::device::Device;
pub use self::device::Transfer;
pub use self::device::TransferStatus;
pub use self::error::Error;
pub use self::error::Result;
pub use self::types::control_request_type;
pub use self::types::ConfigDescriptor;
pub use self::types::ControlRequestDataPhaseTransferDirection;
pub use self::types::ControlRequestRecipient;
pub use self::types::ControlRequestType;
pub use self::types::DescriptorHeader;
pub use self::types::DescriptorType;
pub use self::types::DeviceDescriptor;
pub use self::types::EndpointDescriptor;
pub use self::types::EndpointDirection;
pub use self::types::EndpointType;
pub use self::types::InterfaceDescriptor;
pub use self::types::StandardControlRequest;
pub use self::types::UsbRequestSetup;
pub use self::types::ENDPOINT_DIRECTION_OFFSET;
