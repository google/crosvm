// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A crate for creating [DRM](https://en.wikipedia.org/wiki/Direct_Rendering_Manager) managed
//! buffer objects. Such objects are useful for exporting as DMABUFs/prime FDs, texturing, render
//! targets, memory mapping, and scanout.
//!
//! # Examples
//!
//! ```rust
//! # use std::error::Error;
//! # use std::fs::File;
//! # use std::result::Result;
//! # use gpu_buffer::*;
//! # fn test() -> Result<(), Box<Error>> {
//! let drm_card = File::open("/dev/dri/card0")?;
//! let device = Device::new(drm_card).map_err(|_| "failed to create device")?;
//! let bo = device
//!     .create_buffer(1024,
//!                    512,
//!                    Format::new(b'X', b'R', b'2', b'4'),
//!                    Flags::empty().use_scanout(true))
//!     .map_err(|_| "failed to create buffer")?;
//! assert_eq!(bo.width(), 1024);
//! assert_eq!(bo.height(), 512);
//! assert_eq!(bo.format(), Format::new(b'X', b'R', b'2', b'4'));
//! assert_eq!(bo.num_planes(), 1);
//! # Ok(())
//! # }
//! ```

mod drm_formats;
mod raw;
pub mod rendernode;

use std::ffi::CStr;
use std::fmt::{self, Display};
use std::fs::File;
use std::os::raw::c_char;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::rc::Rc;
use std::result::Result;

use data_model::VolatileMemoryError;

use crate::drm_formats::*;
use crate::raw::*;

#[derive(Debug)]
pub enum Error {
    GbmFailed,
    ExportFailed(sys_util::Error),
    MapFailed,
    UnknownFormat(Format),
    CheckedArithmetic {
        field1: (&'static str, usize),
        field2: (&'static str, usize),
        op: &'static str,
    },
    InvalidPrecondition {
        field1: (&'static str, usize),
        field2: (&'static str, usize),
        op: &'static str,
    },
    Memcopy(VolatileMemoryError),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            GbmFailed => write!(f, "internal GBM failure"),
            ExportFailed(e) => write!(f, "export failed: {}", e),
            MapFailed => write!(f, "map failed"),
            CheckedArithmetic {
                field1: (label1, value1),
                field2: (label2, value2),
                op,
            } => write!(
                f,
                "arithmetic failed: {}({}) {} {}({})",
                label1, value1, op, label2, value2
            ),
            InvalidPrecondition {
                field1: (label1, value1),
                field2: (label2, value2),
                op,
            } => write!(
                f,
                "invalid precondition: {}({}) {} {}({})",
                label1, value1, op, label2, value2
            ),
            UnknownFormat(format) => write!(f, "unknown format {:?}", format),
            Memcopy(e) => write!(f, "error copying memory: {}", e),
        }
    }
}

/// A [fourcc](https://en.wikipedia.org/wiki/FourCC) format identifier.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Format(u32);

impl Format {
    /// Constructs a format identifer using a fourcc byte sequence.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gpu_buffer::Format;
    ///
    /// let format = Format::new(b'X', b'R', b'2', b'4');
    /// println!("format: {:?}", format);
    /// ```
    #[inline(always)]
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Format {
        Format(a as u32 | (b as u32) << 8 | (c as u32) << 16 | (d as u32) << 24)
    }

    /// Returns the fourcc code as a sequence of bytes.
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 4] {
        let f = self.0;
        [f as u8, (f >> 8) as u8, (f >> 16) as u8, (f >> 24) as u8]
    }

    /// Returns the number of bytes per pixel for the given plane, suitable for making copies
    /// to/from the plane.
    pub fn bytes_per_pixel(&self, plane: usize) -> Option<usize> {
        let b = self.to_bytes();

        // NV12 and NV21 have 2 planes with 1 byte per pixel.
        if (b == DRM_FORMAT_NV12 || b == DRM_FORMAT_NV21) && plane < 2 {
            return Some(1);
        }

        // YVU420 has 3 planes, all with the same 1 byte per pixel.
        if b == DRM_FORMAT_YVU420 && plane < 3 {
            return Some(1);
        }

        if plane != 0 {
            return None;
        }

        let bpp = match self.to_bytes() {
            DRM_FORMAT_BGR233 => 1,
            DRM_FORMAT_C8 => 1,
            DRM_FORMAT_R8 => 1,
            DRM_FORMAT_RGB332 => 1,
            DRM_FORMAT_ABGR1555 => 2,
            DRM_FORMAT_ABGR4444 => 2,
            DRM_FORMAT_ARGB1555 => 2,
            DRM_FORMAT_ARGB4444 => 2,
            DRM_FORMAT_BGR565 => 2,
            DRM_FORMAT_BGRA4444 => 2,
            DRM_FORMAT_BGRA5551 => 2,
            DRM_FORMAT_BGRX4444 => 2,
            DRM_FORMAT_BGRX5551 => 2,
            DRM_FORMAT_GR88 => 2,
            DRM_FORMAT_RG88 => 2,
            DRM_FORMAT_RGB565 => 2,
            DRM_FORMAT_RGBA4444 => 2,
            DRM_FORMAT_RGBA5551 => 2,
            DRM_FORMAT_RGBX4444 => 2,
            DRM_FORMAT_RGBX5551 => 2,
            DRM_FORMAT_UYVY => 2,
            DRM_FORMAT_VYUY => 2,
            DRM_FORMAT_XBGR1555 => 2,
            DRM_FORMAT_XBGR4444 => 2,
            DRM_FORMAT_XRGB1555 => 2,
            DRM_FORMAT_XRGB4444 => 2,
            DRM_FORMAT_YUYV => 2,
            DRM_FORMAT_YVYU => 2,
            DRM_FORMAT_BGR888 => 3,
            DRM_FORMAT_RGB888 => 3,
            DRM_FORMAT_ABGR2101010 => 4,
            DRM_FORMAT_ABGR8888 => 4,
            DRM_FORMAT_ARGB2101010 => 4,
            DRM_FORMAT_ARGB8888 => 4,
            DRM_FORMAT_AYUV => 4,
            DRM_FORMAT_BGRA1010102 => 4,
            DRM_FORMAT_BGRA8888 => 4,
            DRM_FORMAT_BGRX1010102 => 4,
            DRM_FORMAT_BGRX8888 => 4,
            DRM_FORMAT_RGBA1010102 => 4,
            DRM_FORMAT_RGBA8888 => 4,
            DRM_FORMAT_RGBX1010102 => 4,
            DRM_FORMAT_RGBX8888 => 4,
            DRM_FORMAT_XBGR2101010 => 4,
            DRM_FORMAT_XBGR8888 => 4,
            DRM_FORMAT_XRGB2101010 => 4,
            DRM_FORMAT_XRGB8888 => 4,
            _ => return None,
        };
        Some(bpp)
    }
}

impl From<u32> for Format {
    fn from(u: u32) -> Format {
        Format(u)
    }
}

impl From<Format> for u32 {
    fn from(f: Format) -> u32 {
        f.0
    }
}

impl fmt::Debug for Format {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let b = self.to_bytes();
        if b.iter().all(u8::is_ascii_graphic) {
            write!(
                f,
                "fourcc({}{}{}{})",
                b[0] as char, b[1] as char, b[2] as char, b[3] as char
            )
        } else {
            write!(
                f,
                "fourcc(0x{:02x}{:02x}{:02x}{:02x})",
                b[0], b[1], b[2], b[3]
            )
        }
    }
}

/// Usage flags for constructing a buffer object.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Flags(u32);

impl Flags {
    /// Returns empty set of flags.
    #[inline(always)]
    pub fn empty() -> Flags {
        Flags(0)
    }

    /// Returns the given set of raw `GBM_BO` flags wrapped in a `Flags` struct.
    #[inline(always)]
    pub fn new(raw: u32) -> Flags {
        Flags(raw)
    }

    /// Sets the scanout flag's presence
    #[inline(always)]
    pub fn use_scanout(self, e: bool) -> Flags {
        if e {
            Flags(self.0 | GBM_BO_USE_SCANOUT)
        } else {
            Flags(self.0 & !GBM_BO_USE_SCANOUT)
        }
    }

    /// Sets the cursor flag's presence
    #[inline(always)]
    pub fn use_cursor(self, e: bool) -> Flags {
        if e {
            Flags(self.0 | GBM_BO_USE_CURSOR)
        } else {
            Flags(self.0 & !GBM_BO_USE_CURSOR)
        }
    }

    /// Sets the cursor 64x64 flag's presence
    #[inline(always)]
    pub fn use_cursor64(self, e: bool) -> Flags {
        if e {
            Flags(self.0 | GBM_BO_USE_CURSOR_64X64)
        } else {
            Flags(self.0 & !GBM_BO_USE_CURSOR_64X64)
        }
    }

    /// Sets the rendering flag's presence
    #[inline(always)]
    pub fn use_rendering(self, e: bool) -> Flags {
        if e {
            Flags(self.0 | GBM_BO_USE_RENDERING)
        } else {
            Flags(self.0 & !GBM_BO_USE_RENDERING)
        }
    }

    /// Sets the linear flag's presence
    #[inline(always)]
    pub fn use_linear(self, e: bool) -> Flags {
        if e {
            Flags(self.0 | GBM_BO_USE_LINEAR)
        } else {
            Flags(self.0 & !GBM_BO_USE_LINEAR)
        }
    }

    /// Sets the texturing flag's presence
    #[inline(always)]
    pub fn use_texturing(self, e: bool) -> Flags {
        if e {
            Flags(self.0 | GBM_BO_USE_TEXTURING)
        } else {
            Flags(self.0 & !GBM_BO_USE_TEXTURING)
        }
    }
}

struct DeviceInner {
    _fd: File,
    gbm: *mut gbm_device,
}

impl Drop for DeviceInner {
    fn drop(self: &mut DeviceInner) {
        // Safe because DeviceInner is only constructed with a valid gbm_device.
        unsafe {
            gbm_device_destroy(self.gbm);
        }
    }
}

/// A device capable of allocating `Buffer`.
#[derive(Clone)]
pub struct Device(Rc<DeviceInner>);

impl Device {
    /// Returns a new `Device` using the given `fd` opened from a device in `/dev/dri/`.
    pub fn new(fd: File) -> Result<Device, ()> {
        // gbm_create_device is safe to call with a valid fd, and we check that a valid one is
        // returned. The FD is not of the appropriate kind (i.e. not a DRM device),
        // gbm_create_device should reject it.
        let gbm = unsafe { gbm_create_device(fd.as_raw_fd()) };
        if gbm.is_null() {
            Err(())
        } else {
            Ok(Device(Rc::new(DeviceInner { _fd: fd, gbm })))
        }
    }

    /// Copies and returns name of GBM backend.
    pub fn get_backend_name(&self) -> String {
        let backend_name: *const c_char = unsafe { gbm_device_get_backend_name(self.0.gbm) };
        let c_str: &CStr = unsafe { CStr::from_ptr(backend_name) };
        let str_slice: &str = c_str.to_str().unwrap_or("");
        str_slice.to_owned()
    }

    /// Creates a new buffer with the given metadata.
    pub fn create_buffer(
        &self,
        width: u32,
        height: u32,
        format: Format,
        usage: Flags,
    ) -> Result<Buffer, Error> {
        // This is safe because only a valid gbm_device is used and the return value is checked.
        let bo = unsafe { gbm_bo_create(self.0.gbm, width, height, format.0, usage.0) };
        if bo.is_null() {
            Err(Error::GbmFailed)
        } else {
            Ok(Buffer(bo, self.clone()))
        }
    }
}

/// An allocation from a `Device`.
pub struct Buffer(*mut gbm_bo, Device);

impl Buffer {
    /// The device
    pub fn device(&self) -> &Device {
        &self.1
    }

    /// Width in pixels.
    pub fn width(&self) -> u32 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_width(self.0) }
    }

    /// Height in pixels.
    pub fn height(&self) -> u32 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_height(self.0) }
    }

    /// Length in bytes of one row of the buffer.
    pub fn stride(&self) -> u32 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_stride(self.0) }
    }

    /// Length in bytes of the stride or tiling.
    pub fn stride_or_tiling(&self) -> u32 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_stride_or_tiling(self.0) }
    }

    /// `Format` of the buffer.
    pub fn format(&self) -> Format {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { Format(gbm_bo_get_format(self.0)) }
    }

    /// Format modifier flags for the buffer.
    pub fn format_modifier(&self) -> u64 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_modifier(self.0) }
    }

    /// Number of planes present in this buffer.
    pub fn num_planes(&self) -> usize {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_plane_count(self.0) }
    }

    /// Handle as u64 for the given plane.
    pub fn plane_handle(&self, plane: usize) -> u64 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_handle_for_plane(self.0, plane).u64 }
    }

    /// Offset in bytes for the given plane.
    pub fn plane_offset(&self, plane: usize) -> u32 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_offset(self.0, plane) }
    }

    /// Length in bytes of one row for the given plane.
    pub fn plane_stride(&self, plane: usize) -> u32 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_stride_for_plane(self.0, plane) }
    }

    /// Size of a plane, in bytes.
    pub fn plane_size(&self, plane: usize) -> u32 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_plane_size(self.0, plane) }
    }

    /// Exports a new dmabuf/prime file descriptor for the given plane.
    pub fn export_plane_fd(&self, plane: usize) -> Result<File, i32> {
        // This is always safe to call with a valid gbm_bo pointer.
        match unsafe { gbm_bo_get_plane_fd(self.0, plane) } {
            fd if fd >= 0 => Ok(unsafe { File::from_raw_fd(fd) }),
            ret => Err(ret),
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_destroy(self.0) }
    }
}

impl AsRawFd for Buffer {
    fn as_raw_fd(&self) -> RawFd {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_fd(self.0) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_model::VolatileMemory;
    use std::fmt::Write;

    #[test]
    fn format_debug() {
        let f = Format::new(b'X', b'R', b'2', b'4');
        let mut buf = String::new();
        write!(&mut buf, "{:?}", f).unwrap();
        assert_eq!(buf, "fourcc(XR24)");

        let f = Format::new(0, 1, 2, 16);
        let mut buf = String::new();
        write!(&mut buf, "{:?}", f).unwrap();
        assert_eq!(buf, "fourcc(0x00010210)");
    }

    #[test]
    fn format_bytes_per_pixel() {
        let f = Format::new(b'X', b'R', b'2', b'4');
        assert_eq!(f.bytes_per_pixel(0), Some(4));
        assert_eq!(f.bytes_per_pixel(1), None);
        let f = Format::new(b'N', b'V', b'1', b'2');
        assert_eq!(f.bytes_per_pixel(0), Some(1));
        assert_eq!(f.bytes_per_pixel(1), Some(1));
        assert_eq!(f.bytes_per_pixel(2), None);
        let f = Format::new(b'R', b'8', b' ', b' ');
        assert_eq!(f.bytes_per_pixel(0), Some(1));
        assert_eq!(f.bytes_per_pixel(1), None);
        let f = Format::new(b'B', b'G', b'2', b'4');
        assert_eq!(f.bytes_per_pixel(0), Some(3));
        assert_eq!(f.bytes_per_pixel(1), None);
        let f = Format::new(b'G', b'R', b'8', b'8');
        assert_eq!(f.bytes_per_pixel(0), Some(2));
        assert_eq!(f.bytes_per_pixel(1), None);
        let f = Format::new(b'Z', b'A', b'C', b'H');
        assert_eq!(f.bytes_per_pixel(0), None);
    }

    #[test]
    #[ignore] // no access to /dev/dri
    fn open_device() {
        let drm_card = File::open("/dev/dri/card0").expect("failed to open card");
        Device::new(drm_card).expect("failed to create device with card");
    }

    #[test]
    #[ignore] // no access to /dev/dri
    fn create_buffer() {
        let drm_card = File::open("/dev/dri/card0").expect("failed to open card");
        let device = Device::new(drm_card).expect("failed to create device with card");
        let bo = device
            .create_buffer(
                1024,
                512,
                Format::new(b'X', b'R', b'2', b'4'),
                Flags::empty().use_scanout(true),
            )
            .expect("failed to create buffer");

        assert_eq!(bo.width(), 1024);
        assert_eq!(bo.height(), 512);
        assert_eq!(bo.format(), Format::new(b'X', b'R', b'2', b'4'));
        assert_eq!(bo.num_planes(), 1);
    }

    #[test]
    #[ignore] // no access to /dev/dri
    fn export_buffer() {
        let drm_card = File::open("/dev/dri/card0").expect("failed to open card");
        let device = Device::new(drm_card).expect("failed to create device with card");
        let bo = device
            .create_buffer(
                1024,
                1024,
                Format::new(b'X', b'R', b'2', b'4'),
                Flags::empty().use_scanout(true),
            )
            .expect("failed to create buffer");
        bo.export_plane_fd(0).expect("failed to export plane");
    }
}
