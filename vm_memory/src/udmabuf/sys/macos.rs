// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::error;
use base::SafeDescriptor;

use crate::udmabuf::UdmabufDriverTrait;
use crate::udmabuf::UdmabufError;
use crate::udmabuf::UdmabufResult;
use crate::GuestAddress;
use crate::GuestMemory;

/// This struct is a no-op because udmabuf driver is not supported on macOS.
pub struct MacosUdmabufDriver;

impl UdmabufDriverTrait for MacosUdmabufDriver {
    fn new() -> UdmabufResult<MacosUdmabufDriver> {
        error!("udmabuf is unsupported on macOS");
        Err(UdmabufError::UdmabufUnsupported)
    }

    fn create_udmabuf(
        &self,
        _mem: &GuestMemory,
        _iovecs: &[(GuestAddress, usize)],
    ) -> UdmabufResult<SafeDescriptor> {
        error!("udmabuf is unsupported on macOS");
        Err(UdmabufError::UdmabufUnsupported)
    }
}
