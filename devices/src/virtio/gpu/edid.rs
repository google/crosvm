// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of the EDID specification provided by software.
//! EDID spec: <https://glenwing.github.io/docs/VESA-EEDID-A2.pdf>

use std::fmt;
use std::fmt::Debug;

use super::protocol::GpuResponse::*;
use super::protocol::VirtioGpuResult;
use crate::virtio::gpu::GpuDisplayParameters;

const EDID_DATA_LENGTH: usize = 128;
const DEFAULT_HORIZONTAL_BLANKING: u16 = 560;
const DEFAULT_VERTICAL_BLANKING: u16 = 50;
const DEFAULT_HORIZONTAL_FRONT_PORCH: u16 = 64;
const DEFAULT_VERTICAL_FRONT_PORCH: u16 = 1;
const DEFAULT_HORIZONTAL_SYNC_PULSE: u16 = 192;
const DEFAULT_VERTICAL_SYNC_PULSE: u16 = 3;
const MILLIMETERS_PER_INCH: f32 = 25.4;

const DATA_BLOCK_TYPE_1_DETAILED_TIMING: u8 = 0x3;
const DATA_BLOCK_TYPE_1_DETAILED_TIMING_SIZE: u8 = 20;
const DATA_BLOCK_TYPE_1_DETAILED_TIMING_VERSION: u8 = 0x13;
const DISPLAYID_EXT: u8 = 0x70;

/// This class is used to create the Extended Display Identification Data (EDID), which will be
/// exposed to the guest system.
///
/// We ignore most of the spec, the point here being for us to provide enough for graphics to work
/// and to allow us to configure the resolution and refresh rate (via the preferred timing mode
/// pixel clock).
///
/// The EDID spec defines a number of methods to provide mode information, but in priority order the
/// "detailed" timing information is first, so we provide a single block of detailed timing
/// information and no other form of timing information.
#[repr(C)]
pub struct EdidBytes {
    bytes: Vec<u8>,
}

impl EdidBytes {
    /// Creates a virtual EDID block.
    pub fn new(info: &DisplayInfo) -> VirtioGpuResult {
        let mut edid = vec![0u8; EDID_DATA_LENGTH * 2];

        populate_header(&mut edid);
        populate_edid_version(&mut edid);
        populate_size(&mut edid, info);
        populate_standard_timings(&mut edid)?;

        let display_name_block = &mut edid[54..72];
        populate_display_name(display_name_block);

        // We add one extension edid.
        edid[126] = 1;
        calculate_checksum(&mut edid, 127);

        let display_id_extension = &mut edid[EDID_DATA_LENGTH..EDID_DATA_LENGTH * 2];
        display_id_extension[0] = DISPLAYID_EXT; // This is a display id extensions block.

        // Just populate a single display right now, starting at index 1.
        populate_displayid_detailed_timings(display_id_extension, 1, info);

        calculate_checksum(display_id_extension, 127);

        Ok(OkEdid(Box::new(Self { bytes: edid })))
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Debug for EdidBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.bytes[..].fmt(f)
    }
}

impl PartialEq for EdidBytes {
    fn eq(&self, other: &EdidBytes) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

#[derive(Copy, Clone)]
pub struct Resolution {
    width: u32,
    height: u32,
}

impl Resolution {
    fn new(width: u32, height: u32) -> Resolution {
        Resolution { width, height }
    }

    fn get_aspect_ratio(&self) -> (u32, u32) {
        let divisor = gcd(self.width, self.height);
        (self.width / divisor, self.height / divisor)
    }
}

fn gcd(x: u32, y: u32) -> u32 {
    match y {
        0 => x,
        _ => gcd(y, x % y),
    }
}

#[derive(Copy, Clone)]
pub struct DisplayInfo {
    resolution: Resolution,
    refresh_rate: u32,
    horizontal_blanking: u16,
    vertical_blanking: u16,
    horizontal_front: u16,
    vertical_front: u16,
    horizontal_sync: u16,
    vertical_sync: u16,
    width_millimeters: u16,
    height_millimeters: u16,
}

impl DisplayInfo {
    /// Only width, height and refresh rate are required for the graphics stack to work, so instead
    /// of pulling actual numbers from the system, we just use some typical values to populate other
    /// fields for now.
    pub fn new(params: &GpuDisplayParameters) -> Self {
        let (width, height) = params.get_virtual_display_size();

        let width_millimeters = if params.horizontal_dpi() != 0 {
            ((width as f32 / params.horizontal_dpi() as f32) * MILLIMETERS_PER_INCH) as u16
        } else {
            0
        };
        let height_millimeters = if params.vertical_dpi() != 0 {
            ((height as f32 / params.vertical_dpi() as f32) * MILLIMETERS_PER_INCH) as u16
        } else {
            0
        };

        Self {
            resolution: Resolution::new(width, height),
            refresh_rate: params.refresh_rate,
            horizontal_blanking: DEFAULT_HORIZONTAL_BLANKING,
            vertical_blanking: DEFAULT_VERTICAL_BLANKING,
            horizontal_front: DEFAULT_HORIZONTAL_FRONT_PORCH,
            vertical_front: DEFAULT_VERTICAL_FRONT_PORCH,
            horizontal_sync: DEFAULT_HORIZONTAL_SYNC_PULSE,
            vertical_sync: DEFAULT_VERTICAL_SYNC_PULSE,
            width_millimeters,
            height_millimeters,
        }
    }

    pub fn width(&self) -> u32 {
        self.resolution.width
    }

    pub fn height(&self) -> u32 {
        self.resolution.height
    }

    pub fn width_centimeters(&self) -> u8 {
        (self.width_millimeters / 10) as u8
    }

    pub fn height_centimeters(&self) -> u8 {
        (self.height_millimeters / 10) as u8
    }
}

fn populate_display_name(edid_block: &mut [u8]) {
    // Display Product Name String Descriptor Tag
    edid_block[0..5].clone_from_slice(&[0x00, 0x00, 0x00, 0xFC, 0x00]);
    edid_block[5..].clone_from_slice("CrosvmDisplay".as_bytes());
}

fn populate_displayid_detailed_timings(block: &mut [u8], start_index: usize, info: &DisplayInfo) {
    // A single display id detailed timing block is 28 bytes:
    //  4 bytes for the display id hdr
    //  3 bytes for the display id block
    //  20 bytes for the actual detailed timing data
    //  1 byte for the checksum
    let block = &mut block[start_index..start_index + 28];
    block[0] = DATA_BLOCK_TYPE_1_DETAILED_TIMING_VERSION; // This doesn't seem to be used by the
                                                          // kernel.
    block[1] = DATA_BLOCK_TYPE_1_DETAILED_TIMING_SIZE + 3; // Size of this data without this header.
    block[2] = DATA_BLOCK_TYPE_1_DETAILED_TIMING; // Prod id. This doesn't seem to matter.
    block[3] = 0; // Extension count

    block[4] = DATA_BLOCK_TYPE_1_DETAILED_TIMING; // Structure of detailed timing info.
    block[5] = 0x00; // Revision
    block[6] = DATA_BLOCK_TYPE_1_DETAILED_TIMING_SIZE; // Length of the actual timing information,
                                                       // must be 20 for
                                                       // DATA_BLOCK_TYPE_1_DETAILED_TIMING.

    // The pixel clock is what controls the refresh timing information.
    //
    // The formula for getting refresh rate out of this value is:
    //   refresh_rate = clk * 10000 / (htotal * vtotal)
    // Solving for clk:
    //   clk = (refresh_rate * htotal * votal) / 10000
    //
    // where:
    //   clk - The setting here
    //   vtotal - Total lines
    //   htotal - Total pixels per line
    //
    // Value here is pixel clock + 10,000, in 10khz steps.
    //
    // Pseudocode of kernel logic for vrefresh:
    //    vtotal := mode->vtotal;
    //    calc_val := (clock * 1000) / htotal
    //    refresh := (calc_val + vtotal / 2) / vtotal
    //    if flags & INTERLACE: refresh *= 2
    //    if flags & DBLSCAN: refresh /= 2
    //    if vscan > 1: refresh /= vscan

    let htotal = info.width() + (info.horizontal_blanking as u32);
    let vtotal = info.height() + (info.vertical_blanking as u32);
    let clock = info
        .refresh_rate
        .checked_mul(htotal)
        .and_then(|x| x.checked_mul(vtotal))
        .map(|x| x / 10000)
        .unwrap_or_else(|| {
            panic!(
                concat!(
                    "attempt to multiply with overflow: info.refresh_rate = {}, info.width = {}, ",
                    "info.horizontal_blanking = {}, info.height() = {}, info.vertical_blanking = {}"
                ),
                info.refresh_rate,
                info.width(),
                info.horizontal_blanking,
                info.height(),
                info.vertical_blanking
            )
        });

    // 3 bytes for clock.
    block[7] = (clock & 0xff) as u8;
    block[8] = ((clock & 0xff00) >> 8) as u8;
    block[9] = ((clock & 0xff0000) >> 16) as u8;

    // Next byte is flags.
    block[10] = 0x88;

    // Note: We subtract 1 from all of these values because the kernel will then add 1 to all of
    // them when they are read.
    let hblanking = info.horizontal_blanking.saturating_sub(1);
    let horizontal_blanking_lsb: u8 = (hblanking & 0xFF) as u8;
    let horizontal_blanking_msb: u8 = ((hblanking >> 8) & 0x0F) as u8;

    let vblanking = info.vertical_blanking.saturating_sub(1);
    let vertical_blanking_lsb: u8 = (vblanking & 0xFF) as u8;
    let vertical_blanking_msb: u8 = ((vblanking >> 8) & 0x0F) as u8;

    let width = info.width().saturating_sub(1);
    let width_lsb: u8 = (width & 0xFF) as u8;
    let width_msb: u8 = ((width >> 8) & 0x0F) as u8;

    let vertical_active: u32 = info.height().saturating_sub(1);
    let vertical_active_lsb: u8 = (vertical_active & 0xFF) as u8;
    let vertical_active_msb: u8 = ((vertical_active >> 8) & 0x0F) as u8;

    let hfront = info.horizontal_front.saturating_sub(1);
    let horizontal_front_lsb: u8 = (hfront & 0xFF) as u8; // least sig 8 bits
    let horizontal_front_msb: u8 = ((hfront >> 8) & 0x03) as u8; // most sig 2 bits

    let hsync = info.horizontal_sync.saturating_sub(1);
    let horizontal_sync_lsb: u8 = (hsync & 0xFF) as u8; // least sig 8 bits
    let horizontal_sync_msb: u8 = ((hsync >> 8) & 0x03) as u8; // most sig 2 bits

    let vfront = info.vertical_front.saturating_sub(1);
    let vertical_front_lsb: u8 = (vfront & 0x0F) as u8; // least sig 4 bits
    let vertical_front_msb: u8 = ((vfront >> 8) & 0x0F) as u8; // most sig 2 bits

    let vsync = info.vertical_sync.saturating_sub(1);
    let vertical_sync_lsb: u8 = (vsync & 0xFF) as u8; // least sig 4 bits
    let vertical_sync_msb: u8 = ((vsync >> 8) & 0x0F) as u8; // most sig 2 bits

    block[11] = width_lsb;
    block[12] = width_msb;
    block[13] = horizontal_blanking_lsb;
    block[14] = horizontal_blanking_msb;
    block[15] = horizontal_front_lsb;
    block[16] = horizontal_front_msb;
    block[17] = horizontal_sync_lsb;
    block[18] = horizontal_sync_msb;
    block[19] = vertical_active_lsb;
    block[20] = vertical_active_msb;
    block[21] = vertical_blanking_lsb;
    block[22] = vertical_blanking_msb;
    block[23] = vertical_front_lsb;
    block[24] = vertical_front_msb;
    block[25] = vertical_sync_lsb;
    block[26] = vertical_sync_msb;

    calculate_checksum(block, 27);
}

// The EDID header. This is defined by the EDID spec.
fn populate_header(edid: &mut [u8]) {
    edid[0] = 0x00;
    edid[1] = 0xFF;
    edid[2] = 0xFF;
    edid[3] = 0xFF;
    edid[4] = 0xFF;
    edid[5] = 0xFF;
    edid[6] = 0xFF;
    edid[7] = 0x00;

    let manufacturer_name: [char; 3] = ['G', 'G', 'L'];
    // 00001 -> A, 00010 -> B, etc
    let manufacturer_id: u16 = manufacturer_name
        .iter()
        .map(|c| (*c as u8 - b'A' + 1) & 0x1F)
        .fold(0u16, |res, lsb| (res << 5) | (lsb as u16));
    edid[8..10].copy_from_slice(&manufacturer_id.to_be_bytes());

    let manufacture_product_id: u16 = 1;
    edid[10..12].copy_from_slice(&manufacture_product_id.to_le_bytes());

    let serial_id: u32 = 1;
    edid[12..16].copy_from_slice(&serial_id.to_le_bytes());

    let manufacture_week: u8 = 8;
    edid[16] = manufacture_week;

    let manufacture_year: u32 = 2022;
    edid[17] = (manufacture_year - 1990u32) as u8;
}

// The standard timings are 8 timing modes with a lower priority (and different data format)
// than the 4 detailed timing modes.
fn populate_standard_timings(edid: &mut [u8]) -> VirtioGpuResult {
    let resolutions = [
        Resolution::new(1440, 900),
        Resolution::new(1600, 900),
        Resolution::new(800, 600),
        Resolution::new(1680, 1050),
        Resolution::new(1856, 1392),
        Resolution::new(1280, 1024),
        Resolution::new(1400, 1050),
        Resolution::new(1920, 1200),
    ];

    // Index 0 is horizontal pixels / 8 - 31
    // Index 1 is a combination of the refresh_rate - 60 (so we are setting to 0, for now) and two
    // bits for the aspect ratio.
    for (index, r) in resolutions.iter().enumerate() {
        edid[0x26 + (index * 2)] = (r.width / 8 - 31) as u8;
        let ar_bits = match r.get_aspect_ratio() {
            (8, 5) => 0x0,
            (4, 3) => 0x1,
            (5, 4) => 0x2,
            (16, 9) => 0x3,
            (x, y) => return Err(ErrEdid(format!("Unsupported aspect ratio: {} {}", x, y))),
        };
        edid[0x27 + (index * 2)] = ar_bits;
    }
    Ok(OkNoData)
}

// Per the EDID spec, needs to be 1 and 4.
fn populate_edid_version(edid: &mut [u8]) {
    edid[18] = 1;
    edid[19] = 4;
}

fn populate_size(edid: &mut [u8], info: &DisplayInfo) {
    edid[21] = info.width_centimeters();
    edid[22] = info.height_centimeters();
}

fn calculate_checksum(block: &mut [u8], length: usize) {
    let mut checksum: u8 = 0;
    for byte in block.iter().take(length) {
        checksum = checksum.wrapping_add(*byte);
    }

    if checksum != 0 {
        checksum = 255 - checksum + 1;
    }

    block[length] = checksum;
}
