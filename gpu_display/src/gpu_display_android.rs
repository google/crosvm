// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::c_char;
use std::ffi::CStr;
use std::ffi::CString;
use std::panic::catch_unwind;
use std::process::abort;
use std::ptr::NonNull;
use std::rc::Rc;
use std::slice;

use base::error;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::VolatileSlice;
use vm_control::gpu::DisplayParameters;

use crate::DisplayT;
use crate::GpuDisplayError;
use crate::GpuDisplayFramebuffer;
use crate::GpuDisplayResult;
use crate::GpuDisplaySurface;
use crate::SurfaceType;
use crate::SysDisplayT;

// Opaque blob
#[repr(C)]
pub(crate) struct AndroidDisplayContext {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

// Opaque blob
#[repr(C)]
pub(crate) struct AndroidDisplaySurface {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

// Should be the same as ANativeWindow_Buffer in android/native_window.h
// Note that this struct is part of NDK; guaranteed to be stable, so we use it directly across the
// FFI.
#[repr(C)]
pub(crate) struct ANativeWindow_Buffer {
    width: i32,
    height: i32,
    stride: i32, // in number of pixels, NOT bytes
    format: i32,
    bits: *mut u8,
    reserved: [u32; 6],
}

pub(crate) type ErrorCallback = unsafe extern "C" fn(message: *const c_char);

extern "C" {
    /// Constructs an AndroidDisplayContext for this backend. This awlays returns a valid (ex:
    /// non-null) handle to the context. The `name` parameter is from crosvm commandline and the
    /// client of crosvm will use it to locate and communicate to the AndroidDisplayContext. For
    /// example, this can be a path to UNIX domain socket where a RPC binder server listens on.
    /// `error_callback` is a function pointer to an error reporting function, and will be used by
    /// this and other functions below when something goes wrong. The returned context should be
    /// destroyed by calling `destroy_android_display_context` if this backend is no longer in use.
    fn create_android_display_context(
        name: *const c_char,
        error_callback: ErrorCallback,
    ) -> *mut AndroidDisplayContext;

    /// Destroys the AndroidDisplayContext created from `create_android_display_context`.
    fn destroy_android_display_context(self_: *mut AndroidDisplayContext);

    /// Creates an Android Surface (which is also called as Window) of given size. If the surface
    /// can't be created for whatever reason, null pointer is returned, in which case we shouldn't
    /// proceed further.
    fn create_android_surface(
        ctx: *mut AndroidDisplayContext,
        width: u32,
        height: u32,
        for_cursor: bool,
    ) -> *mut AndroidDisplaySurface;

    /// Destroys the Android surface created from `create_android_surface`.
    #[allow(dead_code)]
    fn destroy_android_surface(
        ctx: *mut AndroidDisplayContext,
        surface: *mut AndroidDisplaySurface,
    );

    /// Obtains one buffer from the given Android Surface. The information about the buffer (buffer
    /// address, size, stride, etc) is reported via the `ANativeWindow_Buffer` struct. It shouldn't
    /// be null. The size of the buffer is guaranteed to be bigger than (width * stride * 4) bytes.
    /// This function locks the buffer for the client, which means the caller has the exclusive
    /// access to the buffer until it is returned back to Android display stack (surfaceflinger) by
    /// calling `post_android_surface_buffer`. This function may fail (in which case false is
    /// returned), then the caller shouldn't try to read `out_buffer` or use the buffer in any way.
    fn get_android_surface_buffer(
        ctx: *mut AndroidDisplayContext,
        surface: *mut AndroidDisplaySurface,
        out_buffer: *mut ANativeWindow_Buffer,
    ) -> bool;

    fn set_android_surface_position(ctx: *mut AndroidDisplayContext, x: u32, y: u32);

    /// Posts the buffer obtained from `get_android_surface_buffer` to the Android display system
    /// so that it can be displayed on the screen. Once this is called, the caller shouldn't use
    /// the buffer any more.
    fn post_android_surface_buffer(
        ctx: *mut AndroidDisplayContext,
        surface: *mut AndroidDisplaySurface,
    );
}

unsafe extern "C" fn error_callback(message: *const c_char) {
    catch_unwind(|| {
        error!(
            "{}",
            // SAFETY: message is null terminated
            unsafe { CStr::from_ptr(message) }.to_string_lossy()
        )
    })
    .unwrap_or_else(|_| abort())
}

struct AndroidDisplayContextWrapper(NonNull<AndroidDisplayContext>);

impl Drop for AndroidDisplayContextWrapper {
    fn drop(&mut self) {
        // SAFETY: this object is constructed from create_android_display_context
        unsafe { destroy_android_display_context(self.0.as_ptr()) };
    }
}

impl Default for ANativeWindow_Buffer {
    fn default() -> Self {
        Self {
            width: 0,
            height: 0,
            stride: 0,
            format: 0,
            bits: std::ptr::null_mut(),
            reserved: [0u32; 6],
        }
    }
}

impl From<ANativeWindow_Buffer> for GpuDisplayFramebuffer<'_> {
    fn from(anb: ANativeWindow_Buffer) -> Self {
        // TODO: check anb.format to see if it's ARGB8888?
        // TODO: infer bpp from anb.format?
        const BYTES_PER_PIXEL: u32 = 4;
        let stride_bytes = BYTES_PER_PIXEL * u32::try_from(anb.stride).unwrap();
        let buffer_size = stride_bytes * u32::try_from(anb.height).unwrap();
        let buffer =
            // SAFETY: get_android_surface_buffer guarantees that bits points to a valid buffer and
            // the buffer remains available until post_android_surface_buffer is called.
            unsafe { slice::from_raw_parts_mut(anb.bits, buffer_size.try_into().unwrap()) };
        Self::new(VolatileSlice::new(buffer), stride_bytes, BYTES_PER_PIXEL)
    }
}

struct AndroidSurface {
    context: Rc<AndroidDisplayContextWrapper>,
    surface: NonNull<AndroidDisplaySurface>,
}

impl GpuDisplaySurface for AndroidSurface {
    fn framebuffer(&mut self) -> Option<GpuDisplayFramebuffer> {
        let mut anb = ANativeWindow_Buffer::default();
        // SAFETY: context and surface are opaque handles and buf is used as the out parameter to
        // hold the return values.
        let success = unsafe {
            get_android_surface_buffer(
                self.context.0.as_ptr(),
                self.surface.as_ptr(),
                &mut anb as *mut ANativeWindow_Buffer,
            )
        };
        if success {
            Some(anb.into())
        } else {
            None
        }
    }

    fn flip(&mut self) {
        // SAFETY: context and surface are opaque handles.
        unsafe { post_android_surface_buffer(self.context.0.as_ptr(), self.surface.as_ptr()) }
    }

    fn set_position(&mut self, x: u32, y: u32) {
        // SAFETY: context is an opaque handle.
        unsafe { set_android_surface_position(self.context.0.as_ptr(), x, y) };
    }
}

pub struct DisplayAndroid {
    context: Rc<AndroidDisplayContextWrapper>,
    /// This event is never triggered and is used solely to fulfill AsRawDescriptor.
    event: Event,
}

impl DisplayAndroid {
    pub fn new(name: &str) -> GpuDisplayResult<DisplayAndroid> {
        let name = CString::new(name).unwrap();
        let context = NonNull::new(
            // SAFETY: service_name is not leaked outside of this function
            unsafe { create_android_display_context(name.as_ptr(), error_callback) },
        )
        .ok_or(GpuDisplayError::Unsupported)?;
        let context = AndroidDisplayContextWrapper(context);
        let event = Event::new().map_err(|_| GpuDisplayError::CreateEvent)?;
        Ok(DisplayAndroid {
            context: context.into(),
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
        display_params: &DisplayParameters,
        _surf_type: SurfaceType,
    ) -> GpuDisplayResult<Box<dyn GpuDisplaySurface>> {
        let (requested_width, requested_height) = display_params.get_virtual_display_size();
        // SAFETY: context is an opaque handle.
        let surface = NonNull::new(unsafe {
            create_android_surface(
                self.context.0.as_ptr(),
                requested_width,
                requested_height,
                parent_surface_id.is_some(),
            )
        })
        .ok_or(GpuDisplayError::CreateSurface)?;

        Ok(Box::new(AndroidSurface {
            context: self.context.clone(),
            surface,
        }))
    }
}

impl SysDisplayT for DisplayAndroid {}

impl AsRawDescriptor for DisplayAndroid {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.event.as_raw_descriptor()
    }
}
