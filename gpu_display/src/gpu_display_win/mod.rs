// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod keyboard_input_manager;
mod math_util;
mod mouse_input_manager;
pub mod surface;
mod virtual_display_manager;
mod window;
mod window_manager;
mod window_message_dispatcher;
mod window_message_processor;
pub mod window_procedure_thread;

use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::mpsc::channel;
use std::sync::Weak;
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use base::error;
use base::info;
use base::warn;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Event;
use base::EventWaitResult;
use base::RawDescriptor;
use base::ReadNotifier;
use base::SendTube;
use euclid::size2;
use euclid::Size2D;
use math_util::Size2DCheckedCast;
use metrics::sys::windows::Metrics;
pub use surface::Surface;
use vm_control::gpu::DisplayMode;
use vm_control::gpu::DisplayParameters;
use vm_control::ModifyWaitContext;
use window_message_processor::DisplaySendToWndProc;
pub use window_procedure_thread::WindowProcedureThread;
pub use window_procedure_thread::WindowProcedureThreadBuilder;

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
    wndproc_thread: Rc<WindowProcedureThread>,
    close_requested_event: Event,
    win_metrics: Option<Weak<Metrics>>,
    display_properties: DisplayProperties,
    is_surface_created: bool,
    #[allow(dead_code)]
    gpu_display_wait_descriptor_ctrl: SendTube,
    event_device_wait_descriptor_requests: Vec<ModifyWaitContext>,
}

impl DisplayWin {
    pub fn new(
        wndproc_thread: WindowProcedureThread,
        win_metrics: Option<Weak<Metrics>>,
        display_properties: DisplayProperties,
        gpu_display_wait_descriptor_ctrl: SendTube,
    ) -> Result<DisplayWin, GpuDisplayError> {
        let close_requested_event =
            wndproc_thread
                .try_clone_close_requested_event()
                .map_err(|e| {
                    error!("Failed to create DisplayWin: {:?}", e);
                    GpuDisplayError::Allocate
                })?;
        Ok(Self {
            wndproc_thread: Rc::new(wndproc_thread),
            close_requested_event,
            win_metrics,
            display_properties,
            is_surface_created: false,
            gpu_display_wait_descriptor_ctrl,
            event_device_wait_descriptor_requests: Vec::new(),
        })
    }

    /// Posts a create surface command to the WndProc thread and waits until the creation finishes
    /// to check the result.
    fn create_surface_internal(
        &mut self,
        surface_id: u32,
        scanout_id: u32,
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
                scanout_id,
                function: Box::new(move |window, display_event_dispatcher| {
                    Surface::new(
                        surface_id,
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
                // This is safe because the winproc thread (which owns the event device after we
                // send it there below) will be dropped before the GPU worker thread (which is
                // where we're sending this descriptor).
                let req = ModifyWaitContext::Add(Descriptor(
                    event_device.get_read_notifier().as_raw_descriptor(),
                ));

                if let Err(e) = self.wndproc_thread.post_display_command(
                    DisplaySendToWndProc::ImportEventDevice {
                        event_device_id,
                        event_device,
                    },
                ) {
                    bail!("Failed to post ImportEventDevice message: {:?}", e);
                }

                if self.is_surface_created {
                    if let Err(e) = self.gpu_display_wait_descriptor_ctrl.send(&req) {
                        bail!(
                            "failed to send event device descriptor to \
                            GPU worker's wait context: {:?}",
                            e
                        )
                    }
                } else {
                    self.event_device_wait_descriptor_requests.push(req);
                }

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
        self.close_requested_event.as_raw_descriptor()
    }
}

impl DisplayT for DisplayWin {
    fn create_surface(
        &mut self,
        parent_surface_id: Option<u32>,
        surface_id: u32,
        scanout_id: Option<u32>,
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
        if let Err(e) = self.create_surface_internal(
            surface_id,
            scanout_id.expect("scanout id is required"),
            size2(virtual_display_width, virtual_display_height).checked_cast(),
        ) {
            error!("Failed to create surface: {:?}", e);
            return Err(GpuDisplayError::Allocate);
        }
        self.is_surface_created = true;

        // Now that the window is ready, we can start listening for inbound (guest -> host) events
        // on our event devices.
        for req in self.event_device_wait_descriptor_requests.drain(..) {
            if let Err(e) = self.gpu_display_wait_descriptor_ctrl.send(&req) {
                error!(
                    "failed to send event device descriptor to GPU worker's wait context: {:?}",
                    e
                );
                return Err(GpuDisplayError::FailedEventDeviceListen(e));
            }
        }

        Ok(Box::new(SurfaceWin {
            surface_id,
            wndproc_thread: Rc::downgrade(&self.wndproc_thread),
            close_requested_event: self.close_requested_event.try_clone().map_err(|e| {
                error!("Failed to clone close_requested_event: {}", e);
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

    fn handle_event_device(&mut self, event_device_id: u32) {
        match ObjectId::new(event_device_id) {
            Some(event_device_id) => {
                if let Err(e) = self
                    .wndproc_thread
                    .post_display_command(DisplaySendToWndProc::HandleEventDevice(event_device_id))
                {
                    error!(
                        "Failed to route guest -> host input_event; event device (ID: {:?}): {:?}",
                        event_device_id, e
                    );
                }
            }
            None => error!(
                "Failed to route guest -> host input_event; {} cannot be converted to ObjectId",
                event_device_id
            ),
        }
    }
}

/// The display logic for Windows is quite different from other platforms since display events are
/// not handled on the GPU worker thread, but handled by `Surface` class that lives in the WndProc
/// thread. `SurfaceWin` will live in the GPU worker thread and provide limited functionalities.
pub(crate) struct SurfaceWin {
    surface_id: u32,
    wndproc_thread: std::rc::Weak<WindowProcedureThread>,
    close_requested_event: Event,
}

impl GpuDisplaySurface for SurfaceWin {
    /// The entire VM will be shut down when this function returns true. We don't want that happen
    /// until we know our display is expected to be closed.
    fn close_requested(&self) -> bool {
        match self
            .close_requested_event
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

impl Drop for SurfaceWin {
    fn drop(&mut self) {
        info!("Dropping surface {}", self.surface_id);
        // Let the WndProc thread release `Surface` and return the associated window to the pool.
        // If the WndProc thread has already done so and has shut down, it is benign to hit an error
        // below since we can no longer deliver this notification.
        if let Some(wndproc_thread) = self.wndproc_thread.upgrade() {
            if let Err(e) =
                wndproc_thread.post_display_command(DisplaySendToWndProc::ReleaseSurface {
                    surface_id: self.surface_id,
                })
            {
                warn!(
                    "Failed to post ReleaseSurface message (benign if message loop has \
                    shut down): {:?}",
                    e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use base::Tube;

    use super::*;

    #[test]
    fn can_create_2_window_proc_threads() {
        let threads = (0..2)
            .map(|_| {
                let (main_ime_tube, _device_ime_tube) =
                    Tube::pair().expect("failed to create IME tube");
                let wndproc_thread_builder = WindowProcedureThread::builder();
                #[cfg(feature = "kiwi")]
                let wndproc_thread_builder = {
                    let mut wndproc_thread_builder = wndproc_thread_builder;
                    wndproc_thread_builder
                        .set_display_tube(None)
                        .set_ime_tube(Some(_device_ime_tube));
                    wndproc_thread_builder
                };
                (
                    wndproc_thread_builder.start_thread().unwrap(),
                    main_ime_tube,
                )
            })
            .collect::<Vec<_>>();
        drop(threads);
    }
}
