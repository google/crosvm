// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod decoders;
pub mod utils;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolution {
    pub width: u32,
    pub height: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DecodedFormat {
    NV12,
    I420,
}

/// Copies `src` into `dst` as NV12, removing any extra padding.
pub fn nv12_copy(
    src: &[u8],
    mut dst: &mut [u8],
    width: u32,
    height: u32,
    strides: [u32; 3],
    offsets: [u32; 3],
) {
    let width = width.try_into().unwrap();
    let height = height.try_into().unwrap();
    let data = src;

    let mut src = &data[offsets[0] as usize..];

    // Copy luma
    for _ in 0..height {
        dst[..width].copy_from_slice(&src[..width]);
        dst = &mut dst[width..];
        src = &src[strides[0] as usize..];
    }

    // Advance to the offset of the chroma plane
    let mut src = &data[offsets[1] as usize..];

    // Copy chroma
    for _ in 0..height / 2 {
        dst[..width].copy_from_slice(&src[..width]);
        dst = &mut dst[width..];
        src = &src[strides[1_usize] as usize..];
    }
}

/// Copies `src` into `dst` as I420, removing any extra padding.
pub fn i420_copy(
    src: &[u8],
    mut dst: &mut [u8],
    width: u32,
    height: u32,
    strides: [u32; 3],
    offsets: [u32; 3],
) {
    let width = width.try_into().unwrap();
    let height = height.try_into().unwrap();
    let data = src;

    let mut src = &data[offsets[0] as usize..];

    // Copy luma
    for _ in 0..height {
        dst[..width].copy_from_slice(&src[..width]);
        dst = &mut dst[width..];
        src = &src[strides[0] as usize..];
    }

    // Advance to the offset of the U plane
    let mut src = &data[offsets[1] as usize..];

    // Copy U
    for _ in 0..height / 2 {
        dst[..width].copy_from_slice(&src[..width]);
        dst = &mut dst[width..];
        src = &src[strides[1_usize] as usize..];
    }

    // Advance to the offset of the V plane
    let mut src = &data[offsets[2] as usize..];

    // Copy V
    for _ in 0..height / 2 {
        dst[..width].copy_from_slice(&src[..width]);
        dst = &mut dst[width..];
        src = &src[strides[2_usize] as usize..];
    }
}
