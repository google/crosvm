// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! fw_cfg device implementing QEMU's Firmware Configuration interface
//! <https://www.qemu.org/docs/master/specs/fw_cfg.html>

use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::Suspendable;
#[cfg(windows)]
use base::error;
use serde::Deserialize;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;
use std::collections::HashSet;
use std::path::PathBuf;
use thiserror::Error as ThisError;

mod fw_cfg_base;
use fw_cfg_base::FwCfgEntry;
use fw_cfg_base::FwCfgFile;
use fw_cfg_base::FwCfgFiles;
use fw_cfg_base::FW_CFG_FILE_FIRST;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Ran out of file slots")]
    InsufficientFileSlots,

    #[error("File already exists")]
    FileAlreadyExists,

    #[error("Data blob's size too large: overflowed u32")]
    SizeOverflow,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Deserialize, Serialize, FromKeyValues, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct FwCfgParameters {
    pub name: Option<String>,
    pub string: Option<String>,
    pub path: Option<PathBuf>,
}

// Device exposed to the rest of crosvm. Contains the of fw_cfg device in addition to arrays of
// FwCfgEntry and FwCfgFile.cur_entry keeps the index of the currently selected entry  cur_offset
// keeps the byte offset within cur_entry. Storing cur_offset is neccessary because the data IO port
// is only 8 bits wide, so a call to read() will only retrieve one 8 bit chunk of data at a time.
// cur_offset allows for a data item larger than 8 bits to be read through multiple calls to read(),
// maintaining the position of the current read and incrementing across calls to read().
#[allow(dead_code)] // Putting this here temporarily. cur_entry/pffset will be used in read() and write()
pub struct FwCfgDevice {
    file_slots: u16,
    entries: Vec<FwCfgEntry>,
    files: FwCfgFiles,
    cur_entry: u16,
    cur_offset: u32,
    file_names: HashSet<String>,
}

impl FwCfgDevice {
    pub fn new(file_slots: u16, _fw_cfg_parameters: Vec<FwCfgParameters>) -> FwCfgDevice {
        FwCfgDevice {
            file_slots,
            entries: Vec::new(),
            files: FwCfgFiles { f: Vec::new() },
            cur_entry: 0,
            cur_offset: 0,
            file_names: HashSet::new(),
        }
    }

    /// Adds a file to the device.
    ///
    /// # Arguments
    ///
    /// - `filename`: Name of file. Must be valid a Unix-style filename
    /// - `data`: File data as bytes
    pub fn add_file(&mut self, filename: &str, data: Vec<u8>) -> Result<()> {
        // Adds a data blob to the device under the name filename. This entails creating an
        // FwCfgEntry and its associated FwCfgFile and adding them to FwCfgDevice.

        if self.files.f.len() >= self.file_slots as usize {
            return Err(Error::InsufficientFileSlots);
        }

        // No need to worry about endianess in this function. We will deal with this in read(). We
        // are only using FwCfgFile internally.
        let index = self.files.f.len();

        if self.file_names.contains(filename) {
            return Err(Error::FileAlreadyExists);
        }

        let size = data.len().try_into().map_err(|_| Error::SizeOverflow)?;

        let new_file = FwCfgFile {
            size,
            select: (FW_CFG_FILE_FIRST + index) as u16,
            name: filename.to_owned(),
            reserved: 0,
        };

        self.add_bytes(data);
        self.files.f.push(new_file);
        self.file_names.insert(filename.to_string());
        Ok(())
    }

    // Add a FwCfgEntry to FwCfgDevice's entries array so that it can be accessed at the selector
    // index specified by the caller of read()
    fn add_bytes(&mut self, data: Vec<u8>) {
        let new_entry = FwCfgEntry {
            allow_write: false,
            data,
        };
        self.entries.push(new_entry);
    }
}

// We implement two 8-bit registers: a Selector(Control) Register and a Data Register
impl BusDevice for FwCfgDevice {
    fn device_id(&self) -> DeviceId {
        super::CrosvmDeviceId::FwCfg.into()
    }

    fn debug_label(&self) -> String {
        "FwCfg".to_owned()
    }

    fn read(&mut self, _info: BusAccessInfo, data: &mut [u8]) {
        // TODO: fill in according to Qemu fw_cfg spec
        data[0] = 0x66; // Harcoded value. Confirmed that this value is successfully read by OVMF.
    }

    fn write(&mut self, _info: BusAccessInfo, _data: &[u8]) {
        // TODO: fill in according to Qemu fw_cfg spec
    }
}

impl Suspendable for FwCfgDevice {
    fn sleep(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_keyvalue::*;
    const MAGIC_BYTE: u8 = 111;
    const MAGIC_BYTE_ALT: u8 = 222;
    const FILENAME: &str = "/test/device/crosvmval";

    fn from_serial_arg(options: &str) -> std::result::Result<FwCfgParameters, ParseError> {
        from_key_values(options)
    }

    fn get_default_params() -> Vec<FwCfgParameters> {
        vec![FwCfgParameters {
            name: None,
            string: None,
            path: None,
        }]
    }

    #[test]
    fn params_from_key_values() {
        let params = from_serial_arg("").unwrap();
        assert_eq!(
            params,
            FwCfgParameters {
                name: None,
                string: None,
                path: None,
            }
        );
        let params = from_serial_arg("name=foo,path=/path/to/input").unwrap();

        assert_eq!(
            params,
            FwCfgParameters {
                name: Some("foo".into()),
                path: Some("/path/to/input".into()),
                string: None,
            }
        );

        let params = from_serial_arg("name=bar,string=testdata").unwrap();

        assert_eq!(
            params,
            FwCfgParameters {
                name: Some("bar".into()),
                string: Some("testdata".into()),
                path: None,
            }
        );
    }

    #[test]
    // Write a simple one byte file and confirm that an entry is properly created
    fn write_one_byte_file() {
        let mut fw_cfg = FwCfgDevice::new(100, get_default_params());
        let data = vec![MAGIC_BYTE];
        fw_cfg.add_file(FILENAME, data).expect("File insert failed");
        let ind = fw_cfg.entries.len();
        assert_eq!(
            ind, 1,
            "Insertion into fw_cfg failed: Index is wrong. expected {}, got {},
                 ",
            1, ind
        );
        assert_eq!(
            fw_cfg.entries[ind - 1].data,
            vec![MAGIC_BYTE],
            "Insertion failed: unexpected fw_cfg entry values"
        );
    }

    #[test]
    // Write a simple four byte file and confirm that an entry is properly created
    fn write_four_byte_file() {
        let mut fw_cfg = FwCfgDevice::new(100, get_default_params());
        let data = vec![MAGIC_BYTE, MAGIC_BYTE_ALT, MAGIC_BYTE, MAGIC_BYTE_ALT];
        fw_cfg.add_file(FILENAME, data).expect("File insert failed");
        let ind = fw_cfg.entries.len();
        assert_eq!(
            ind, 1,
            "Insertion into fw_cfg failed: Index is wrong. expected {}, got {}",
            1, ind
        );
        assert_eq!(
            fw_cfg.entries[ind - 1].data,
            vec![MAGIC_BYTE, MAGIC_BYTE_ALT, MAGIC_BYTE, MAGIC_BYTE_ALT],
            "Insertion failed: unexpected fw_cfg entry values"
        );
    }

    #[test]
    #[should_panic]
    // Attempt to add a file to an fw_cfg device w/ no fileslots and assert that nothing gets inserted
    fn write_file_one_slot_expect_noop() {
        let mut fw_cfg = FwCfgDevice::new(0, get_default_params());
        let data = vec![MAGIC_BYTE];
        fw_cfg.add_file(FILENAME, data).expect("File insert failed");
    }

    #[test]
    #[should_panic]
    // Attempt to add two files to an fw_cfg w/ only one fileslot and assert only first insert succeeds.
    fn write_two_files_no_slots_expect_noop_on_second() {
        let mut fw_cfg = FwCfgDevice::new(1, get_default_params());
        let data = vec![MAGIC_BYTE];
        let data2 = vec![MAGIC_BYTE_ALT];
        fw_cfg.add_file(FILENAME, data).expect("File insert failed");
        assert_eq!(
            fw_cfg.entries.len(),
            1,
            "Insertion into fw_cfg failed: Expected {} elements, got {}",
            1,
            fw_cfg.entries.len()
        );
        fw_cfg
            .add_file(FILENAME, data2)
            .expect("File insert failed");
    }
}
