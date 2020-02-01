// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap as Map;
use std::num::NonZeroU32;
use std::rc::Rc;

use super::protocol::GpuResponse;
use data_model::*;
use gpu_display::*;
use sys_util::{error, GuestMemory};

pub trait VirtioResource {
    fn width(&self) -> u32;

    fn height(&self) -> u32;

    fn import_to_display(&mut self, display: &Rc<RefCell<GpuDisplay>>) -> Option<u32>;

    /// Performs a transfer to the given resource in the host from its backing in guest memory.
    fn write_from_guest_memory(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        src_offset: u64,
        _mem: &GuestMemory,
    );

    /// Reads from this resource in the host to a volatile slice of memory.
    fn read_to_volatile(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        dst: VolatileSlice,
        dst_stride: u32,
    );
}

/// Handles some of the common functionality across the virtio 2D and 3D backends.
pub struct VirtioBackend {
    pub display: Rc<RefCell<GpuDisplay>>,
    pub display_width: u32,
    pub display_height: u32,
    pub scanout_resource_id: Option<NonZeroU32>,
    pub scanout_surface_id: Option<u32>,
    pub cursor_resource_id: Option<NonZeroU32>,
    pub cursor_surface_id: Option<u32>,
    // Maps event devices to scanout number.
    pub event_devices: Map<u32, u32>,
}

impl VirtioBackend {
    pub fn import_event_device(&mut self, event_device: EventDevice, scanout: u32) {
        // TODO(zachr): support more than one scanout.
        if scanout != 0 {
            error!("got nonzero scanout: {:}, but only support zero.", scanout);
            return;
        }

        let mut display = self.display.borrow_mut();
        let event_device_id = match display.import_event_device(event_device) {
            Ok(id) => id,
            Err(e) => {
                error!("error importing event device: {}", e);
                return;
            }
        };
        self.scanout_surface_id
            .map(|s| display.attach_event_device(s, event_device_id));
        self.event_devices.insert(event_device_id, scanout);
    }

    /// Gets the list of supported display resolutions as a slice of `(width, height)` tuples.
    pub fn display_info(&self) -> [(u32, u32); 1] {
        [(self.display_width, self.display_height)]
    }

    /// Processes the internal `display` events and returns `true` if the main display was closed.
    pub fn process_display(&mut self) -> bool {
        let mut display = self.display.borrow_mut();
        display.dispatch_events();
        self.scanout_surface_id
            .map(|s| display.close_requested(s))
            .unwrap_or(false)
    }

    /// Sets the given resource id as the source of scanout to the display.
    pub fn set_scanout(&mut self, resource_id: u32) -> GpuResponse {
        let mut display = self.display.borrow_mut();
        if resource_id == 0 {
            if let Some(surface_id) = self.scanout_surface_id.take() {
                display.release_surface(surface_id);
            }
            self.scanout_resource_id = None;
            GpuResponse::OkNoData
        } else {
            self.scanout_resource_id = NonZeroU32::new(resource_id);

            if self.scanout_surface_id.is_none() {
                match display.create_surface(None, self.display_width, self.display_height) {
                    Ok(surface_id) => {
                        self.scanout_surface_id = Some(surface_id);
                        for (event_device_id, _) in &self.event_devices {
                            display.attach_event_device(surface_id, *event_device_id);
                        }
                    }
                    Err(e) => error!("failed to create display surface: {}", e),
                }
            }
            GpuResponse::OkNoData
        }
    }

    pub fn flush_resource(
        &mut self,
        resource: &mut dyn VirtioResource,
        resource_id: u32,
    ) -> GpuResponse {
        let mut response = GpuResponse::OkNoData;

        if let Some(scannout_resource_id) = self.scanout_resource_id {
            if scannout_resource_id.get() == resource_id {
                response = self.flush_scannout_resource_to_surface(resource);
            }
        }

        if response != GpuResponse::OkNoData {
            return response;
        }

        if let Some(cursor_resource_id) = self.cursor_resource_id {
            if cursor_resource_id.get() == resource_id {
                response = self.flush_cursor_resource_to_surface(resource);
            }
        }

        response
    }

    pub fn flush_scannout_resource_to_surface(
        &mut self,
        resource: &mut dyn VirtioResource,
    ) -> GpuResponse {
        match self.scanout_surface_id {
            Some(surface_id) => self.flush_resource_to_surface(resource, surface_id),
            None => GpuResponse::OkNoData,
        }
    }

    pub fn flush_cursor_resource_to_surface(
        &mut self,
        resource: &mut dyn VirtioResource,
    ) -> GpuResponse {
        match self.cursor_surface_id {
            Some(surface_id) => self.flush_resource_to_surface(resource, surface_id),
            None => GpuResponse::OkNoData,
        }
    }

    pub fn flush_resource_to_surface(
        &mut self,
        resource: &mut dyn VirtioResource,
        surface_id: u32,
    ) -> GpuResponse {
        if let Some(import_id) = resource.import_to_display(&self.display) {
            self.display.borrow_mut().flip_to(surface_id, import_id);
            return GpuResponse::OkNoData;
        }

        // Import failed, fall back to a copy.
        let mut display = self.display.borrow_mut();
        // Prevent overwriting a buffer that is currently being used by the compositor.
        if display.next_buffer_in_use(surface_id) {
            return GpuResponse::OkNoData;
        }

        let fb = match display.framebuffer_region(
            surface_id,
            0,
            0,
            self.display_width,
            self.display_height,
        ) {
            Some(fb) => fb,
            None => {
                error!("failed to access framebuffer for surface {}", surface_id);
                return GpuResponse::ErrUnspec;
            }
        };

        resource.read_to_volatile(
            0,
            0,
            self.display_width,
            self.display_height,
            fb.as_volatile_slice(),
            fb.stride(),
        );

        display.flip(surface_id);

        GpuResponse::OkNoData
    }

    /// Updates the cursor's memory to the given id, and sets its position to the given coordinates.
    pub fn update_cursor(
        &mut self,
        id: u32,
        x: u32,
        y: u32,
        resource: Option<&mut dyn VirtioResource>,
    ) -> GpuResponse {
        if id == 0 {
            if let Some(surface_id) = self.cursor_surface_id.take() {
                self.display.borrow_mut().release_surface(surface_id);
            }
            self.cursor_resource_id = None;
            GpuResponse::OkNoData
        } else if let Some(resource) = resource {
            self.cursor_resource_id = NonZeroU32::new(id);

            if self.cursor_surface_id.is_none() {
                match self.display.borrow_mut().create_surface(
                    self.scanout_surface_id,
                    resource.width(),
                    resource.height(),
                ) {
                    Ok(surface_id) => self.cursor_surface_id = Some(surface_id),
                    Err(e) => {
                        error!("failed to create cursor surface: {}", e);
                        return GpuResponse::ErrUnspec;
                    }
                }
            }

            let cursor_surface_id = self.cursor_surface_id.unwrap();
            self.display
                .borrow_mut()
                .set_position(cursor_surface_id, x, y);

            // Gets the resource's pixels into the display by importing the buffer.
            if let Some(import_id) = resource.import_to_display(&self.display) {
                self.display
                    .borrow_mut()
                    .flip_to(cursor_surface_id, import_id);
                return GpuResponse::OkNoData;
            }

            // Importing failed, so try copying the pixels into the surface's slower shared memory
            // framebuffer.
            if let Some(fb) = self.display.borrow_mut().framebuffer(cursor_surface_id) {
                resource.read_to_volatile(
                    0,
                    0,
                    resource.width(),
                    resource.height(),
                    fb.as_volatile_slice(),
                    fb.stride(),
                )
            }
            self.display.borrow_mut().flip(cursor_surface_id);
            GpuResponse::OkNoData
        } else {
            GpuResponse::ErrInvalidResourceId
        }
    }

    /// Moves the cursor's position to the given coordinates.
    pub fn move_cursor(&mut self, x: u32, y: u32) -> GpuResponse {
        if let Some(cursor_surface_id) = self.cursor_surface_id {
            if let Some(scanout_surface_id) = self.scanout_surface_id {
                let mut display = self.display.borrow_mut();
                display.set_position(cursor_surface_id, x, y);
                display.commit(scanout_surface_id);
            }
        }
        GpuResponse::OkNoData
    }
}
