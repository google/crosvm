// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::AsRawDescriptor;
use base::RawDescriptor;
use base::WaitContext;

use crate::DisplayEventToken;
use crate::DisplayT;
use crate::EventDevice;
use crate::GpuDisplay;
use crate::GpuDisplayExt;
use crate::GpuDisplayResult;

pub(crate) trait MacosDisplayT: DisplayT {}

impl GpuDisplayExt for GpuDisplay {
    fn import_event_device(&mut self, event_device: EventDevice) -> GpuDisplayResult<u32> {
        let new_event_device_id = self.next_id;

        self.wait_ctx.add(
            &event_device,
            DisplayEventToken::EventDevice {
                event_device_id: new_event_device_id,
            },
        )?;
        self.event_devices.insert(new_event_device_id, event_device);

        self.next_id += 1;
        Ok(new_event_device_id)
    }

    fn handle_event_device(&mut self, event_device_id: u32) {
        if let Some(event_device) = self.event_devices.get(&event_device_id) {
            let _ = event_device.recv_event_encoded();
        }
    }
}

pub trait MacosGpuDisplayExt {
    /// Opens a stub display (no actual display on macOS yet).
    fn open_stub() -> GpuDisplayResult<GpuDisplay>;
}

impl MacosGpuDisplayExt for GpuDisplay {
    fn open_stub() -> GpuDisplayResult<GpuDisplay> {
        use crate::gpu_display_stub::DisplayStub;

        let display = DisplayStub::new()?;

        let wait_ctx = WaitContext::new()?;
        wait_ctx.add(&display, DisplayEventToken::Display)?;

        Ok(GpuDisplay {
            inner: Box::new(display),
            next_id: 1,
            event_devices: Default::default(),
            surfaces: Default::default(),
            wait_ctx,
        })
    }
}

impl AsRawDescriptor for GpuDisplay {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.wait_ctx.as_raw_descriptor()
    }
}
