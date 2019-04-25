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

use std::cmp::min;
use std::fmt::{self, Display};
use std::fs::File;
use std::isize;
use std::os::raw::c_void;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::null_mut;
use std::rc::Rc;
use std::result::Result;

use data_model::{VolatileMemory, VolatileMemoryError, VolatileSlice};

use crate::drm_formats::*;
use crate::raw::*;

const MAP_FAILED: *mut c_void = (-1isize as *mut _);

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

macro_rules! checked_arithmetic {
    ($x:ident $op:ident $y:ident $op_name:expr) => {
        $x.$op($y).ok_or_else(|| Error::CheckedArithmetic {
            field1: (stringify!($x), $x as usize),
            field2: (stringify!($y), $y as usize),
            op: $op_name,
        })
    };
    ($x:ident + $y:ident) => {
        checked_arithmetic!($x checked_add $y "+")
    };
    ($x:ident - $y:ident) => {
        checked_arithmetic!($x checked_sub $y "-")
    };
    ($x:ident * $y:ident) => {
        checked_arithmetic!($x checked_mul $y "*")
    };
}

macro_rules! checked_range {
    ($x:expr; <= $y:expr) => {
        if $x <= $y {
            Ok(())
        } else {
            Err(Error::InvalidPrecondition {
                field1: (stringify!($x), $x as usize),
                field2: (stringify!($y), $y as usize),
                op: "<=",
            })
        }
    };
    ($x:ident <= $y:ident) => {
        check_range!($x; <= $y)
    };
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

    fn map(
        &self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        plane: usize,
        flags: u32,
    ) -> Result<BufferMapping, Error> {
        checked_range!(checked_arithmetic!(x + width)?; <= self.width())?;
        checked_range!(checked_arithmetic!(y + height)?; <= self.height())?;
        checked_range!(plane; <= self.num_planes())?;

        let bytes_per_pixel = self
            .format()
            .bytes_per_pixel(plane)
            .ok_or(Error::UnknownFormat(self.format()))? as u32;

        let mut stride = 0;
        let mut map_data = null_mut();
        // Safe because only a valid gbm_bo object is used and the return value is checked. Only
        // pointers coerced from stack references are used for returned values, and we trust gbm to
        // only write as many bytes as the size of the pointed to values.
        let mapping = unsafe {
            gbm_bo_map(
                self.0,
                x,
                y,
                width,
                height,
                flags,
                &mut stride,
                &mut map_data,
                plane,
            )
        };
        if mapping == MAP_FAILED {
            return Err(Error::MapFailed);
        }

        // The size of returned slice is equal the size of a row in bytes multiplied by the height
        // of the mapped region, subtracted by the offset into the first mapped row. The 'x' and
        // 'y's in the below diagram of a 2D buffer are bytes in the mapping. The first 'y' is what
        // the mapping points to in memory, and the '-'s are unmapped bytes of the buffer.
        // |----------|
        // |--stride--|
        // |-----yyyyx| h
        // |xxxxxyyyyx| e
        // |xxxxxyyyyx| i
        // |xxxxxyyyyx| g
        // |xxxxxyyyyx| h
        // |xxxxxyyyyx| t
        // |----------|
        let size = checked_arithmetic!(stride * height)?;
        let x_offset_bytes = checked_arithmetic!(x * bytes_per_pixel)?;
        let slice_size = checked_arithmetic!(size - x_offset_bytes)? as u64;

        Ok(BufferMapping {
            // Safe because the chunk of memory starting at mapping with size `slice_size` is valid
            // and tied to the lifetime of `buffer_mapping`.
            slice: unsafe { VolatileSlice::new(mapping as *mut u8, slice_size) },
            stride,
            map_data,
            buffer: self,
        })
    }

    /// Reads the given subsection of the buffer to `dst`.
    pub fn read_to_volatile(
        &self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        plane: usize,
        dst: VolatileSlice,
    ) -> Result<(), Error> {
        if width == 0 || height == 0 {
            return Ok(());
        }

        let mapping = self.map(x, y, width, height, plane, GBM_BO_TRANSFER_READ)?;

        if x == 0 && width == self.width() {
            mapping.as_volatile_slice().copy_to_volatile_slice(dst);
        } else {
            // This path is more complicated because there are gaps in the data between lines.
            let width = width as u64;
            let stride = mapping.stride() as u64;
            let bytes_per_pixel = match self.format().bytes_per_pixel(plane) {
                Some(bpp) => bpp as u64,
                None => return Err(Error::UnknownFormat(self.format())),
            };
            let line_copy_size = checked_arithmetic!(width * bytes_per_pixel)?;
            let src = mapping.as_volatile_slice();
            for yy in 0..(height as u64) {
                let line_offset = checked_arithmetic!(yy * stride)?;
                let src_line = src
                    .get_slice(line_offset, line_copy_size)
                    .map_err(Error::Memcopy)?;
                let dst_line = dst
                    .get_slice(line_offset, line_copy_size)
                    .map_err(Error::Memcopy)?;
                src_line.copy_to_volatile_slice(dst_line);
            }
        }

        Ok(())
    }

    /// Writes to the given subsection of the buffer from `sgs`.
    pub fn write_from_sg<'a, S: Iterator<Item = VolatileSlice<'a>>>(
        &self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        plane: usize,
        src_offset: usize,
        mut sgs: S,
    ) -> Result<(), Error> {
        if width == 0 || height == 0 {
            return Ok(());
        }

        checked_range!(src_offset; <= isize::MAX as usize)?;

        let mapping = self.map(x, y, width, height, plane, GBM_BO_TRANSFER_WRITE)?;
        let mut dst_slice = mapping.as_volatile_slice();
        let stride = mapping.stride() as u64;
        let mut height = height as u64;
        let mut src_offset = src_offset as u64;

        if x == 0 && width == self.width() {
            // This path is a simple copy from the scatter gather iterator to the buffer objection,
            // with no gaps in the data.
            let mut copy_size = checked_arithmetic!(stride * height)?;
            for sg in sgs {
                // Skip src_offset into this scatter gather item, or the entire thing if offset is
                // larger.
                let sg_size = match sg.size().checked_sub(src_offset) {
                    Some(sg_remaining_size) => sg_remaining_size,
                    None => {
                        src_offset -= sg.size();
                        continue;
                    }
                };
                let copy_sg_size = min(sg_size, copy_size);
                let src_slice = sg
                    .get_slice(src_offset, copy_sg_size)
                    .map_err(Error::Memcopy)?;
                src_slice.copy_to_volatile_slice(dst_slice);

                src_offset = 0;
                dst_slice = dst_slice.offset(copy_sg_size).map_err(Error::Memcopy)?;
                copy_size -= copy_sg_size;
                if copy_size == 0 {
                    break;
                }
            }
        } else {
            let width = width as u64;
            // This path is more complicated because there are gaps in the data between lines.
            let bytes_per_pixel = self.format().bytes_per_pixel(plane).unwrap_or(0) as u64;
            let line_copy_size = checked_arithmetic!(width * bytes_per_pixel)?;
            let line_end_skip = checked_arithmetic!(stride - line_copy_size)?;
            let mut remaining_line_copy_size = line_copy_size;
            let mut sg_opt = sgs.next();
            while let Some(sg) = sg_opt {
                // Skip src_offset into this scatter gather item, or the entire thing if offset is
                // larger.
                let sg_size = match sg.size().checked_sub(src_offset) {
                    None | Some(0) => {
                        src_offset -= sg.size();
                        sg_opt = sgs.next();
                        continue;
                    }
                    Some(sg_remaining_size) => sg_remaining_size,
                };
                let copy_sg_size = min(sg_size, remaining_line_copy_size);
                let src_slice = sg
                    .get_slice(src_offset, copy_sg_size)
                    .map_err(Error::Memcopy)?;
                src_slice.copy_to_volatile_slice(dst_slice);

                src_offset += copy_sg_size;
                dst_slice = dst_slice.offset(copy_sg_size).map_err(Error::Memcopy)?;
                remaining_line_copy_size -= copy_sg_size;
                if remaining_line_copy_size == 0 {
                    remaining_line_copy_size = line_copy_size;
                    height -= 1;
                    if height == 0 {
                        break;
                    }

                    src_offset += line_end_skip;
                    dst_slice = dst_slice.offset(line_end_skip).map_err(Error::Memcopy)?;
                }
            }
        }

        Ok(())
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

struct BufferMapping<'a> {
    slice: VolatileSlice<'a>,
    stride: u32,
    map_data: *mut c_void,
    buffer: &'a Buffer,
}

impl<'a> BufferMapping<'a> {
    fn as_volatile_slice(&self) -> VolatileSlice {
        self.slice
    }

    fn stride(&self) -> u32 {
        self.stride
    }
}

impl<'a> Drop for BufferMapping<'a> {
    fn drop(&mut self) {
        // safe because the gbm_bo is assumed to be valid and the map_data is the same one given by
        // gbm_bo_map.
        unsafe {
            gbm_bo_unmap(self.buffer.0, self.map_data);
        }
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

    #[test]
    #[ignore] // no access to /dev/dri
    fn buffer_transfer() {
        let drm_card = File::open("/dev/dri/card0").expect("failed to open card");
        let device = Device::new(drm_card).expect("failed to create device with card");
        let bo = device
            .create_buffer(
                1024,
                1024,
                Format::new(b'X', b'R', b'2', b'4'),
                Flags::empty().use_scanout(true).use_linear(true),
            )
            .expect("failed to create buffer");
        let mut dst: Vec<u8> = Vec::new();
        dst.resize((bo.stride() * bo.height()) as usize, 0x4A);
        let dst_len = dst.len() as u64;
        bo.write_from_sg(
            0,
            0,
            1024,
            1024,
            0,
            0,
            [dst.as_mut_slice().get_slice(0, dst_len).unwrap()]
                .iter()
                .cloned(),
        )
        .expect("failed to read bo");
        bo.read_to_volatile(
            0,
            0,
            1024,
            1024,
            0,
            dst.as_mut_slice().get_slice(0, dst_len).unwrap(),
        )
        .expect("failed to read bo");
        assert!(dst.iter().all(|&x| x == 0x4A));
    }
}
