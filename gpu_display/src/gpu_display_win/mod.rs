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

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::sync::Weak;
use std::time::Duration;

use anyhow::bail;
use anyhow::format_err;
#[cfg(feature = "vulkan_display")]
use anyhow::Context;
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
use metrics::sys::windows::Metrics;
pub use surface::Surface;
use sync::Mutex;
use sync::Waitable;
use vm_control::gpu::DisplayParameters;
use vm_control::ModifyWaitContext;
use window_message_processor::DisplaySendToWndProc;
pub use window_procedure_thread::WindowProcedureThread;
pub use window_procedure_thread::WindowProcedureThreadBuilder;

#[cfg(feature = "vulkan_display")]
use crate::gpu_display_win::window::BasicWindow;
#[cfg(feature = "vulkan_display")]
use crate::vulkan::VulkanDisplay;
use crate::DisplayExternalResourceImport;
use crate::DisplayT;
use crate::EventDevice;
use crate::FlipToExtraInfo;
use crate::GpuDisplayError;
use crate::GpuDisplayResult;
use crate::GpuDisplaySurface;
use crate::MouseMode;
use crate::SemaphoreTimepoint;
use crate::SurfaceType;
use crate::SysDisplayT;
use crate::VulkanCreateParams;

pub(crate) type ObjectId = NonZeroU32;

pub struct VirtualDisplaySpace;
pub struct HostWindowSpace;

pub enum VulkanDisplayWrapper {
    Uninitialized,
    #[cfg(feature = "vulkan_display")]
    Initialized(VulkanDisplay),
}

pub struct DisplayWin {
    wndproc_thread: Rc<WindowProcedureThread>,
    close_requested_event: Event,
    win_metrics: Option<Weak<Metrics>>,
    is_surface_created: bool,
    #[allow(dead_code)]
    gpu_display_wait_descriptor_ctrl: SendTube,
    event_device_wait_descriptor_requests: Vec<ModifyWaitContext>,
    vulkan_displays: HashMap<u32, Arc<Mutex<VulkanDisplayWrapper>>>,
    #[allow(dead_code)]
    vulkan_display_create_params: Option<VulkanCreateParams>,
}

impl DisplayWin {
    pub fn new(
        wndproc_thread: WindowProcedureThread,
        win_metrics: Option<Weak<Metrics>>,
        gpu_display_wait_descriptor_ctrl: SendTube,
        vulkan_display_create_params: Option<VulkanCreateParams>,
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
            is_surface_created: false,
            gpu_display_wait_descriptor_ctrl,
            event_device_wait_descriptor_requests: Vec::new(),
            vulkan_displays: HashMap::new(),
            vulkan_display_create_params,
        })
    }

    /// Posts a create surface command to the WndProc thread and waits until the creation finishes
    /// to check the result.
    fn create_surface_internal(
        &mut self,
        surface_id: u32,
        scanout_id: u32,
        display_params: &DisplayParameters,
    ) -> Result<Arc<Mutex<VulkanDisplayWrapper>>> {
        let display_params_clone = display_params.clone();
        let metrics = self.win_metrics.clone();
        #[cfg(feature = "vulkan_display")]
        let vulkan_create_params = self.vulkan_display_create_params.clone();
        // This function should not return until surface creation finishes. Besides, we would like
        // to know if the creation succeeds. Hence, we use channels to wait to see the result.
        let (result_sender, result_receiver) = channel();
        #[allow(unused_variables)]
        let (vulkan_display_sender, vulkan_display_receiver) = channel();

        // Post a message to the WndProc thread to create the surface.
        self.wndproc_thread
            .post_display_command(DisplaySendToWndProc::CreateSurface {
                scanout_id,
                function: Box::new(move |window, display_event_dispatcher| {
                    #[cfg(feature = "vulkan_display")]
                    let vulkan_display = {
                        let create_display_closure =
                            |VulkanCreateParams {
                                 vulkan_library,
                                 device_uuid,
                                 driver_uuid,
                             }| {
                                // SAFETY: Safe because vulkan display lives longer than window
                                // (because for Windows, we keep the
                                // windows alive for the entire life of the
                                // emulator).
                                unsafe {
                                    let initial_host_viewport_size = window
                                        .get_client_rect()
                                        .with_context(|| "retrieve window client area size")?
                                        .size;
                                    VulkanDisplay::new(
                                        vulkan_library,
                                        window.handle() as _,
                                        &initial_host_viewport_size.cast_unit(),
                                        device_uuid,
                                        driver_uuid,
                                    )
                                    .with_context(|| "create vulkan display")
                                }
                            };
                        let vulkan_display = vulkan_create_params
                            .map(create_display_closure)
                            .transpose()?;
                        let vulkan_display = match vulkan_display {
                            Some(vulkan_display) => {
                                VulkanDisplayWrapper::Initialized(vulkan_display)
                            }
                            None => VulkanDisplayWrapper::Uninitialized,
                        };
                        let vulkan_display = Arc::new(Mutex::new(vulkan_display));
                        vulkan_display_sender
                            .send(Arc::clone(&vulkan_display))
                            .map_err(|_| {
                                format_err!("Failed to send vulkan display back to caller.")
                            })?;
                        vulkan_display
                    };

                    #[cfg(not(feature = "vulkan_display"))]
                    let vulkan_display = Arc::new(Mutex::new(VulkanDisplayWrapper::Uninitialized));

                    Surface::new(
                        surface_id,
                        window,
                        metrics,
                        &display_params_clone,
                        display_event_dispatcher,
                        vulkan_display,
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
            Ok(true) => vulkan_display_receiver.recv().map_err(|_| {
                format_err!(
                    "Failed to receive the vulkan display from the surface creation routine."
                )
            }),
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
        display_params: &DisplayParameters,
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
        let vulkan_display = match self.create_surface_internal(
            surface_id,
            scanout_id.expect("scanout id is required"),
            display_params,
        ) {
            Err(e) => {
                error!("Failed to create surface: {:?}", e);
                return Err(GpuDisplayError::Allocate);
            }
            Ok(display) => display,
        };
        self.is_surface_created = true;
        self.vulkan_displays
            .insert(surface_id, Arc::clone(&vulkan_display));

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
            vulkan_display,
        }))
    }

    fn import_resource(
        &mut self,
        #[allow(unused_variables)] import_id: u32,
        surface_id: u32,
        #[allow(unused_variables)] external_display_resource: DisplayExternalResourceImport,
    ) -> Result<()> {
        match self.vulkan_displays.get(&surface_id) {
            Some(vulkan_display) => match *vulkan_display.lock() {
                #[cfg(feature = "vulkan_display")]
                VulkanDisplayWrapper::Initialized(ref mut vulkan_display) => {
                    match external_display_resource {
                        DisplayExternalResourceImport::VulkanImage {
                            descriptor,
                            metadata,
                        } => {
                            vulkan_display.import_image(import_id, descriptor, metadata)?;
                        }
                        DisplayExternalResourceImport::VulkanTimelineSemaphore { descriptor } => {
                            vulkan_display.import_semaphore(import_id, descriptor)?;
                        }
                        DisplayExternalResourceImport::Dmabuf { .. } => {
                            bail!("gpu_display_win does not support importing dmabufs")
                        }
                    }
                    Ok(())
                }
                VulkanDisplayWrapper::Uninitialized => {
                    bail!("VulkanDisplay is not initialized for this surface")
                }
            },
            None => {
                bail!("No VulkanDisplay for surface id {}", surface_id)
            }
        }
    }

    #[allow(unused_variables)]
    fn release_import(&mut self, surface_id: u32, import_id: u32) {
        #[cfg(feature = "vulkan_display")]
        if let Some(vulkan_display) = self.vulkan_displays.get(&surface_id) {
            if let VulkanDisplayWrapper::Initialized(ref mut vulkan_display) =
                *vulkan_display.lock()
            {
                vulkan_display.delete_imported_image_or_semaphore(import_id);
            }
        }
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
    #[allow(dead_code)]
    vulkan_display: Arc<Mutex<VulkanDisplayWrapper>>,
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

    fn set_mouse_mode(&mut self, mouse_mode: MouseMode) {
        if let Some(wndproc_thread) = self.wndproc_thread.upgrade() {
            if let Err(e) =
                wndproc_thread.post_display_command(DisplaySendToWndProc::SetMouseMode {
                    surface_id: self.surface_id,
                    mouse_mode,
                })
            {
                warn!("Failed to post SetMouseMode message: {:?}", e);
            }
        }
    }

    #[cfg(not(feature = "vulkan_display"))]
    fn flip_to(
        &mut self,
        _import_id: u32,
        _acquire_timepoint: Option<SemaphoreTimepoint>,
        _release_timepoint: Option<SemaphoreTimepoint>,
        _extra_info: Option<FlipToExtraInfo>,
    ) -> Result<Waitable> {
        bail!("vulkan_display feature is not enabled")
    }

    #[cfg(feature = "vulkan_display")]
    fn flip_to(
        &mut self,
        import_id: u32,
        acquire_timepoint: Option<SemaphoreTimepoint>,
        release_timepoint: Option<SemaphoreTimepoint>,
        extra_info: Option<FlipToExtraInfo>,
    ) -> Result<Waitable> {
        let last_layout_transition = match extra_info {
            Some(FlipToExtraInfo::Vulkan {
                old_layout,
                new_layout,
            }) => (old_layout, new_layout),
            None => {
                bail!("vulkan display flip_to requires old and new layout in extra_info")
            }
        };

        let release_timepoint =
            release_timepoint.ok_or(anyhow::anyhow!("release timepoint must be non-None"))?;

        match *self.vulkan_display.lock() {
            VulkanDisplayWrapper::Initialized(ref mut vulkan_display) => vulkan_display.post(
                import_id,
                last_layout_transition,
                acquire_timepoint,
                release_timepoint,
            ),
            VulkanDisplayWrapper::Uninitialized => {
                bail!("VulkanDisplay is not initialized for this surface")
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
