// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Tube;

/// All the tube types that can be "registered" with the platform specific `fn run_control`
/// implementation. These tubes are generally one half of a tube pair, with the other half held by
/// a device.
#[remain::sorted]
pub enum AnyControlTube {
    // See `BalloonTube`.
    Balloon(Tube),
    // Sends `DiskControlCommand`.
    Disk(Tube),
    /// Receives `FsMappingRequest`.
    Fs(Tube),
    // Sends `GpuControlCommand`.
    Gpu(Tube),
    /// Receives `IrqHandlerRequest`.
    IrqTube(Tube),
    // Sends `PvClockCommand`.
    PvClock(Tube),
    // Sends `SndControlCommand`.
    Snd(Tube),
    /// Receives `VmRequest`.
    Vm(Tube),
    VmMemoryTube {
        tube: Tube,
        /// See devices::virtio::VirtioDevice.expose_shared_memory_region_with_viommu
        expose_with_viommu: bool,
    },
    /// Receives `VmMemoryMappingRequest`.
    VmMsync(Tube),
}
