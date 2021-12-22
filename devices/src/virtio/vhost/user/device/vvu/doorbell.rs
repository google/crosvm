// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::Event;

use crate::vfio::{VfioDevice, VfioRegionAddr};
use crate::virtio::SignalableInterrupt;

/// Doorbell region in the VVU device's additional BAR.
/// Writing to this area will sends a signal to the sibling VM's vhost-user device.
pub struct DoorbellRegion {
    pub vfio: Arc<VfioDevice>,
    pub index: u8,
    pub addr: VfioRegionAddr,
}

impl SignalableInterrupt for DoorbellRegion {
    fn signal(&self, _vector: u16, _interrupt_status_mask: u32) {
        // Write `1` to the doorbell, which will be forwarded to the sibling's call FD.
        self.vfio.region_write_to_addr(&1, &self.addr, 0);
    }

    fn signal_config_changed(&self) {}

    fn get_resample_evt(&self) -> Option<&Event> {
        None
    }

    fn do_interrupt_resample(&self) {}
}
