// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub static FW_CFG_FILE_FIRST: usize = 0;

// FWCfgFile is exposed to the the guest so that the guest may search for the entry with the desired
// filename and obtain its 16-bit-wide select key to write to the control register
pub struct FwCfgFile {
    pub size: u32,
    pub select: u16,
    pub reserved: u16,
    pub name: String, // a char[56]
}

// Contains metadata about the entries stored in fw_cfg. FwCfgFile is exposed to the the guest so
// that the guest may search for the entry with the desired filename and obtain its 16-bit-wide
// select key to write to the control register pub struct FwCfgFile { pub size: u32, pub select:
// u16, pub name: String, }
pub struct FwCfgFiles {
    pub f: Vec<FwCfgFile>,
}

// Contains the actual data. The data is represented as an array of u8 to conviently pass a data
// item byte-by-byte when read() is called on that item
pub struct FwCfgEntry {
    pub allow_write: bool,
    pub data: Vec<u8>,
}
