// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::error;
use base::Event;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use vmm_vhost::Error as VhostError;
use vmm_vhost::Result as VhostResult;

use crate::vfio::VfioDevice;
use crate::virtio::vhost::user::device::vvu::pci::VvuPciCaps;
use crate::virtio::SignalableInterrupt;

/// Doorbell region in the VVU device's additional BAR.
/// Writing to this area will sends a signal to the sibling VM's vhost-user device.
#[derive(Clone)]
pub struct DoorbellRegion {
    addr: u64,
    mmap: Arc<MemoryMapping>,
}

impl DoorbellRegion {
    /// Initialize a new DoorbellRegion structure given a queue index, the vfio
    /// device, and the VvuPciCaps.
    pub fn new(
        queue_index: u8,
        device: &Arc<VfioDevice>,
        caps: &VvuPciCaps,
    ) -> VhostResult<DoorbellRegion> {
        let base = caps.doorbell_base_addr();
        let addr = base.addr + (queue_index as u64 * caps.doorbell_off_multiplier() as u64);
        let mmap_region = device.get_region_mmap(base.index);
        let region_offset = device.get_region_offset(base.index);
        let offset = region_offset + mmap_region[0].offset;

        let mmap = MemoryMappingBuilder::new(mmap_region[0].size as usize)
            .from_file(device.device_file())
            .offset(offset)
            .build()
            .map_err(|e| {
                error!("Failed to mmap vfio memory region: {}", e);
                VhostError::InvalidOperation
            })?;
        let mmap = Arc::new(mmap);
        Ok(DoorbellRegion { addr, mmap })
    }
}

impl SignalableInterrupt for DoorbellRegion {
    fn signal(&self, _vector: u16, _interrupt_status_mask: u32) {
        // Write `1` to the doorbell, which will be forwarded to the sibling's call FD.
        // It's okay to not handle a failure here because if this fails we cannot recover
        // anyway. The mmap address should be correct as initialized in the 'new()' function
        // according to the given vfio device.
        self.mmap
            .write_obj_volatile(1_u8, self.addr as usize)
            .expect("unable to write to mmap area");
    }

    fn signal_config_changed(&self) {}

    fn get_resample_evt(&self) -> Option<&Event> {
        None
    }

    fn do_interrupt_resample(&self) {}
}
