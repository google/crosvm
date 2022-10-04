// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Weak;

use base::AsRawDescriptor;
use base::RawDescriptor;
use base::WaitContext;
use metrics::Metrics;

use crate::gpu_display_win::DisplayProperties;
use crate::gpu_display_win::DisplayWin;
use crate::DisplayEventToken;
use crate::DisplayT;
use crate::EventDevice;
use crate::GpuDisplay;
use crate::GpuDisplayExt;
use crate::GpuDisplayResult;
use crate::WindowProcedureThread;

pub(crate) trait WinDisplayT: DisplayT {
    /// Imports an event device into the display backend.
    fn import_event_device(
        &mut self,
        _event_device_id: u32,
        _event_device: EventDevice,
    ) -> GpuDisplayResult<()> {
        Ok(())
    }
}

impl GpuDisplayExt for GpuDisplay {
    fn import_event_device(&mut self, event_device: EventDevice) -> GpuDisplayResult<u32> {
        let new_event_device_id = self.next_id;
        self.inner
            .import_event_device(new_event_device_id, event_device)?;

        self.next_id += 1;
        Ok(new_event_device_id)
    }
}

pub trait WinGpuDisplayExt {
    fn open_winapi(
        wndproc_thread: WindowProcedureThread,
        win_metrics: Option<Weak<Metrics>>,
        display_properties: DisplayProperties,
    ) -> GpuDisplayResult<GpuDisplay>;
}

impl WinGpuDisplayExt for GpuDisplay {
    fn open_winapi(
        wndproc_thread: WindowProcedureThread,
        win_metrics: Option<Weak<Metrics>>,
        display_properties: DisplayProperties,
    ) -> GpuDisplayResult<GpuDisplay> {
        let display = DisplayWin::new(wndproc_thread, win_metrics, display_properties)?;

        let wait_ctx = WaitContext::new()?;
        wait_ctx.add(&display, DisplayEventToken::Display)?;

        Ok(GpuDisplay {
            inner: Box::new(display),
            next_id: 1,
            event_devices: Default::default(),
            surfaces: Default::default(),
            imports: Default::default(),
            wait_ctx,
            is_x: false,
        })
    }
}

impl AsRawDescriptor for GpuDisplay {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.inner.as_raw_descriptor()
    }
}
