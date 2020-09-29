// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::IrqChip;
use hypervisor::DeviceKind;

pub trait IrqChipAArch64: IrqChip {
    /// Get the version of VGIC that this chip is emulating. Currently KVM may either implement
    /// VGIC version 2 or 3.
    fn get_vgic_version(&self) -> DeviceKind;
}
