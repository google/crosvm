// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod math_util;
pub mod surface;
mod thread_message_util;
mod window;
mod window_message_dispatcher;
mod window_message_processor;
pub mod window_procedure_thread;

use std::num::NonZeroU32;
use std::sync::mpsc::channel;
use std::sync::Weak;
use std::time::Duration;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::AsRawDescriptor;
use base::Event;
use base::EventWaitResult;
use base::RawDescriptor;
use euclid::size2;
use euclid::Size2D;
use math_util::Size2DCheckedCast;
use metrics::Metrics;
pub use surface::NoopSurface as Surface;
use vm_control::gpu::DisplayMode;
use vm_control::gpu::DisplayParameters;
use window_message_processor::DisplaySendToWndProc;
pub use window_procedure_thread::WindowProcedureThread;

use crate::DisplayT;
use crate::EventDevice;
use crate::GpuDisplayError;
use crate::GpuDisplayResult;
use crate::GpuDisplaySurface;
use crate::SurfaceType;
use crate::SysDisplayT;

pub(crate) type ObjectId = NonZeroU32;

pub struct VirtualDisplaySpace;
pub struct HostWindowSpace;

#[derive(Clone)]
pub struct DisplayProperties {
    pub start_hidden: bool,
    pub is_fullscreen: bool,
    pub window_width: u32,
    pub window_height: u32,
}

impl From<&DisplayParameters> for DisplayProperties {
    fn from(params: &DisplayParameters) -> Self {
        let is_fullscreen = matches!(params.mode, DisplayMode::BorderlessFullScreen(_));
        let (window_width, window_height) = params.get_window_size();

        Self {
            start_hidden: params.hidden,
            is_fullscreen,
            window_width,
            window_height,
        }
    }
}

pub struct DisplayWin {
    wndproc_thread: WindowProcedureThread<Surface>,
    display_closed_event: Event,
    win_metrics: Option<Weak<Metrics>>,
    display_properties: DisplayProperties,
    is_surface_created: bool,
}

impl DisplayWin {
    pub fn new(
        wndproc_thread: WindowProcedureThread<Surface>,
        win_metrics: Option<Weak<Metrics>>,
        display_properties: DisplayProperties,
    ) -> Result<DisplayWin, GpuDisplayError> {
        // The display should be closed once the WndProc thread terminates.
        let display_closed_event =
            wndproc_thread
                .try_clone_thread_terminated_event()
                .map_err(|e| {
                    error!("Failed to create DisplayWin: {:?}", e);
                    GpuDisplayError::Allocate
                })?;
        Ok(Self {
            wndproc_thread,
            display_closed_event,
            win_metrics,
            display_properties,
            is_surface_created: false,
        })
    }

    /// Posts a create surface command to the WndProc thread and waits until the creation finishes
    /// to check the result.
    fn create_surface_internal(
        &mut self,
        virtual_display_size: Size2D<i32, VirtualDisplaySpace>,
    ) -> Result<()> {
        let metrics = self.win_metrics.clone();
        let display_properties = self.display_properties.clone();
        // This function should not return until surface creation finishes. Besides, we would like
        // to know if the creation succeeds. Hence, we use channels to wait to see the result.
        let (result_sender, result_receiver) = channel();

        // Post a message to the WndProc thread to create the surface.
        self.wndproc_thread
            .post_display_command(DisplaySendToWndProc::CreateSurface {
                function: Box::new(move |window, display_event_dispatcher| {
                    Surface::create(
                        window,
                        &virtual_display_size,
                        metrics,
                        &display_properties,
                        display_event_dispatcher,
                    )
                }),
                callback: Box::new(move |success| {
                    if let Err(e) = result_sender.send(success) {
                        error!("Failed to send surface creation result: {}", e);
                    }
                }),
            })?;

        // Block until the surface creation finishes and check the result.
        match result_receiver.recv() {
            Ok(true) => Ok(()),
            Ok(false) => bail!("WndProc thread failed to create surface!"),
            Err(e) => bail!("Failed to receive surface creation result: {}", e),
        }
    }

    fn import_event_device_internal(
        &mut self,
        event_device_id: u32,
        event_device: EventDevice,
    ) -> Result<()> {
        match ObjectId::new(event_device_id) {
            Some(event_device_id) => {
                self.wndproc_thread
                    .post_display_command(DisplaySendToWndProc::ImportEventDevice {
                        event_device_id,
                        event_device,
                    })
                    .context("Failed to send ImportEventDevice message")?;
                Ok(())
            }
            None => bail!("{} cannot be converted to ObjectId", event_device_id),
        }
    }
}

impl AsRawDescriptor for DisplayWin {
    /// Event handling is done on the GPU worker thread on other platforms. However, due to the way
    /// Windows GUI system works, we have to do that on the WndProc thread instead, and we only
    /// notify the event loop in the GPU worker thread of the display closure event.
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.display_closed_event.as_raw_descriptor()
    }
}

impl DisplayT for DisplayWin {
    fn create_surface(
        &mut self,
        parent_surface_id: Option<u32>,
        _surface_id: u32,
        virtual_display_width: u32,
        virtual_display_height: u32,
        surface_type: SurfaceType,
    ) -> GpuDisplayResult<Box<dyn GpuDisplaySurface>> {
        if parent_surface_id.is_some() {
            return Err(GpuDisplayError::Unsupported);
        }

        if !matches!(surface_type, SurfaceType::Scanout) {
            return Err(GpuDisplayError::Unsupported);
        }

        // Gfxstream allows for attaching a window only once along the initialization, so we only
        // create the surface once. See details in b/179319775.
        if !self.is_surface_created {
            match self.create_surface_internal(
                size2(virtual_display_width, virtual_display_height).checked_cast(),
            ) {
                Ok(_) => self.is_surface_created = true,
                Err(e) => {
                    error!("Failed to create surface: {:?}", e);
                    return Err(GpuDisplayError::Allocate);
                }
            }
        }

        Ok(Box::new(SurfaceWin {
            display_closed_event: self.display_closed_event.try_clone().map_err(|e| {
                error!("Failed to clone display_closed_event: {}", e);
                GpuDisplayError::Allocate
            })?,
        }))
    }
}

impl SysDisplayT for DisplayWin {
    fn import_event_device(
        &mut self,
        event_device_id: u32,
        event_device: EventDevice,
    ) -> GpuDisplayResult<()> {
        self.import_event_device_internal(event_device_id, event_device)
            .map_err(|e| {
                GpuDisplayError::FailedEventDeviceImport(format!(
                    "Failed to import event device (ID: {}): {:?}",
                    event_device_id, e
                ))
            })
    }
}

/// The display logic for Windows is quite different from other platforms since display events are
/// not handled on the GPU worker thread, but handled by `Surface` class that lives in the WndProc
/// thread. `SurfaceWin` will live in the GPU worker thread and provide limited functionalities.
pub(crate) struct SurfaceWin {
    display_closed_event: Event,
}

impl GpuDisplaySurface for SurfaceWin {
    /// The entire VM will be shut down when this function returns true. We don't want that happen
    /// until we know our display is expected to be closed.
    fn close_requested(&self) -> bool {
        match self
            .display_closed_event
            .wait_timeout(Duration::from_secs(0))
        {
            Ok(EventWaitResult::Signaled) => true,
            Ok(EventWaitResult::TimedOut) => false,
            Err(e) => {
                error!("Failed to read whether display is closed: {}", e);
                false
            }
        }
    }
}
