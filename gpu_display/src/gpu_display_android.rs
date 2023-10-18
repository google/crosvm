// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::panic::catch_unwind;
use std::process::abort;
use std::sync::Arc;
use std::sync::Mutex;

use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::VolatileSlice;

use crate::DisplayT;
use crate::GpuDisplayError;
use crate::GpuDisplayFramebuffer;
use crate::GpuDisplayResult;
use crate::GpuDisplaySurface;
use crate::SurfaceType;
use crate::SysDisplayT;

// Structs and functions from display_android.cpp:
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct android_display_context {
    pub _bindgen_opaque_blob: [u32; 1usize],
}

#[allow(non_camel_case_types)]
pub type android_display_error_callback_type =
    ::std::option::Option<unsafe extern "C" fn(message: *const ::std::os::raw::c_char)>;

extern "C" {
    fn create_android_display_context(
        service_name: *const ::std::os::raw::c_char,
        error_callback: android_display_error_callback_type,
    ) -> *mut android_display_context;

    fn destroy_android_display_context(
        error_callback: android_display_error_callback_type,
        self_: *mut *mut android_display_context,
    );

    fn get_android_display_width(
        error_callback: android_display_error_callback_type,
        self_: *mut android_display_context,
    ) -> u32;

    fn get_android_display_height(
        error_callback: android_display_error_callback_type,
        self_: *mut android_display_context,
    ) -> u32;

    fn blit_android_display(
        error_callback: android_display_error_callback_type,
        self_: *mut android_display_context,
        width: u32,
        height: u32,
        bytes: *mut u8,
    );
}

unsafe extern "C" fn error_callback(message: *const ::std::os::raw::c_char) {
    catch_unwind(|| {
        assert!(!message.is_null());
        // SAFETY: message is always a valid utf8-encoded C string.
        let msg = unsafe {
            #[allow(clippy::unnecessary_cast)] // c_char can be *const u8 or *const i8 depending on
            // arch
            std::str::from_utf8(std::slice::from_raw_parts(
                message as *const u8,
                libc::strlen(message),
            ))
            .unwrap()
        };
        error!("{}", msg);
    })
    .unwrap_or_else(|_| abort())
}

struct AndroidDisplayContext(*mut android_display_context);
// SAFETY: safe because access to the context is protected by a lock
unsafe impl Sync for AndroidDisplayContext {}
// SAFETY: pointers are safe to send between threads
unsafe impl Send for AndroidDisplayContext {}

impl Drop for AndroidDisplayContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Safe given that we checked the pointer for non-null and it should always be
            // of the correct type.
            unsafe {
                destroy_android_display_context(Some(error_callback), &mut self.0);
            }
        }
    }
}

#[allow(dead_code)]
struct Buffer {
    width: u32,
    height: u32,
    bytes_per_pixel: u32,
    bytes: Vec<u8>,
}

impl Buffer {
    fn as_volatile_slice(&mut self) -> VolatileSlice {
        VolatileSlice::new(self.bytes.as_mut_slice())
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn stride(&self) -> usize {
        (self.bytes_per_pixel as usize) * (self.width as usize)
    }

    fn bytes_per_pixel(&self) -> usize {
        self.bytes_per_pixel as usize
    }
}

struct AndroidSurface {
    context: Arc<Mutex<AndroidDisplayContext>>,
    buffer: Buffer,
}

impl GpuDisplaySurface for AndroidSurface {
    fn framebuffer(&mut self) -> Option<GpuDisplayFramebuffer> {
        let framebuffer = &mut self.buffer;
        let framebuffer_stride = framebuffer.stride() as u32;
        let framebuffer_bytes_per_pixel = framebuffer.bytes_per_pixel() as u32;
        Some(GpuDisplayFramebuffer::new(
            framebuffer.as_volatile_slice(),
            framebuffer_stride,
            framebuffer_bytes_per_pixel,
        ))
    }

    fn flip(&mut self) {
        let w = self.buffer.width();
        let h = self.buffer.height();
        let _context = self.context.lock().map(|context| {
            // SAFETY: self.buffer is not leaked outside of this function
            unsafe {
                blit_android_display(
                    Some(error_callback),
                    context.0,
                    w,
                    h,
                    self.buffer.bytes.as_mut_ptr(),
                )
            };
        });
    }
}

impl Drop for AndroidSurface {
    fn drop(&mut self) {}
}

pub struct DisplayAndroid {
    context: Arc<Mutex<AndroidDisplayContext>>,
    /// This event is never triggered and is used solely to fulfill AsRawDescriptor.
    event: Event,
}

impl DisplayAndroid {
    pub fn new(service_name: &str) -> GpuDisplayResult<DisplayAndroid> {
        let event = Event::new().map_err(|_| GpuDisplayError::CreateEvent)?;

        let service_name = CString::new(service_name).or(Err(
            GpuDisplayError::InvalidAndroidDisplayServiceName(service_name.to_string()),
        ))?;

        let context = AndroidDisplayContext(
            // SAFETY: service_name is not leaked outside of this function
            unsafe { create_android_display_context(service_name.as_ptr(), Some(error_callback)) },
        );
        if context.0.is_null() {
            return Err(GpuDisplayError::Unsupported);
        }

        Ok(DisplayAndroid {
            context: Arc::new(Mutex::new(context)),
            event,
        })
    }
}

impl DisplayT for DisplayAndroid {
    fn create_surface(
        &mut self,
        parent_surface_id: Option<u32>,
        _surface_id: u32,
        _scanout_id: Option<u32>,
        requested_width: u32,
        requested_height: u32,
        _surf_type: SurfaceType,
    ) -> GpuDisplayResult<Box<dyn GpuDisplaySurface>> {
        if parent_surface_id.is_some() {
            return Err(GpuDisplayError::Unsupported);
        }

        let (android_width, android_height): (u32, u32) = self
            .context
            .lock()
            .map(|context| {
                let android_width: u32 =
                    // SAFETY: context is not leaked outside of this function
                    unsafe { get_android_display_width(Some(error_callback), context.0) };
                let android_height: u32 =
                    // SAFETY: context is not leaked outside of this function
                    unsafe { get_android_display_height(Some(error_callback), context.0) };
                (android_width, android_height)
            })
            .map_err(|_| GpuDisplayError::Unsupported)?;

        if requested_width != android_width {
            warn!(
                "Display surface width ({}) doesn't match Android Surface width ({}).",
                requested_width, android_width
            );
        }

        if requested_height != android_height {
            warn!(
                "Display surface height ({}) doesn't match Android Surface height ({}).",
                requested_height, android_height
            );
        }

        let bytes_per_pixel = 4;
        let bytes_total =
            (requested_width as u64) * (requested_height as u64) * (bytes_per_pixel as u64);
        Ok(Box::new(AndroidSurface {
            context: self.context.clone(),
            buffer: Buffer {
                width: requested_width,
                height: requested_height,
                bytes_per_pixel,
                bytes: vec![0; bytes_total as usize],
            },
        }))
    }
}

impl SysDisplayT for DisplayAndroid {}

impl AsRawDescriptor for DisplayAndroid {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.event.as_raw_descriptor()
    }
}
