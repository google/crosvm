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
use std::fs;
use std::iter::repeat;
use std::path::PathBuf;
use thiserror::Error as ThisError;

pub const FW_CFG_BASE_PORT: u64 = 0x510;
pub const FW_CFG_WIDTH: u64 = 0x4;
// For the 16-bit selector, the 2nd highest-order bit represents whether the data port will be read
// or written to. Because this has been deprecrated by Qemu, this bit is useless. The highest order
// bit represents whether the selected configuration item is arch-specific. Therefore, only the
// lower 14 bits are used for indexing and we mask the two highest bits off with
// FW_CFG_SELECTOR_SELECT_MASK. 16384 = 2^14.
pub const FW_CFG_MAX_FILE_SLOTS: usize = 16384 - FW_CFG_FILE_FIRST;
const FW_CFG_FILE_FIRST: usize = 0x0020;
const FW_CFG_SELECTOR_PORT_OFFSET: u64 = 0x0;
const FW_CFG_DATA_PORT_OFFSET: u64 = 0x1;
const FW_CFG_SELECTOR_RW_MASK: u16 = 0x2000;
const FW_CFG_SELECTOR_ARCH_MASK: u16 = 0x4000;
const FW_CFG_SELECTOR_SELECT_MASK: u16 = 0xbfff;
const FW_CFG_SIGNATURE: [u8; 4] = [b'Q', b'E', b'M', b'U'];
const FW_CFG_REVISION: [u8; 4] = [0, 0, 0, 1];
const FW_CFG_SIGNATURE_SELECTOR: u16 = 0x0000;
const FW_CFG_REVISION_SELECTOR: u16 = 0x0001;
const FW_CFG_FILE_DIR_SELECTOR: u16 = 0x0019;
// Code that uses fw_cfg expects to read a char[56] for filenames
const FW_CFG_FILENAME_SIZE: usize = 56;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Ran out of file slots")]
    InsufficientFileSlots,

    #[error("File already exists")]
    FileAlreadyExists,

    #[error("Data blob's size too large: overflowed u32")]
    SizeOverflow,

    #[error("too many entries: oveflows u16 selector")]
    IndexOverflow,

    #[error("Filename must be less than 55 characters long")]
    FileNameTooLong,

    #[error("Unable to open file {0} for fw_cfg")]
    FileOpen(PathBuf),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Deserialize, Serialize, FromKeyValues, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct FwCfgParameters {
    pub name: Option<String>,
    pub string: Option<String>,
    pub path: Option<PathBuf>,
}

#[derive(PartialEq)]
pub enum FwCfgItemType {
    GenericItem,
    ArchSpecificItem,
    FileDir,
    Signature,
    RevisionVector,
}

impl FwCfgItemType {
    fn value(&self) -> usize {
        match self {
            FwCfgItemType::ArchSpecificItem => 1,
            _ => 0,
        }
    }
}

// Contains metadata about the entries stored in fw_cfg.
// FwCfgFile is exposed to the the guest
// so that the guest may search for the entry
// with the desired filename and obtain its 16-bit-wide select
// key to write to the control register
struct FwCfgFile {
    pub size: u32,
    pub select: u16,
    pub name: String,
}

// Contains the actual data. The data is represented as an
// array of u8 to conviently pass
// a data item byte-by-byte when read() is called
// on that item
#[derive(Clone)]
struct FwCfgEntry {
    pub allow_write: bool,
    pub data: Vec<u8>,
}

// Device exposed to the rest of crosvm. Contains state information in addition to arrays of
// FwCfgEntry and FwCfgFile. cur_entry keeps the index of the currently selected entry. cur_offset
// keeps the byte offset within cur_entry. Storing cur_offset is neccessary because the data IO port
// is only 8 bits wide, so a call to read() will only retrieve one 8 bit chunk of data at a time.
// cur_offset allows for a data item larger than 8 bits to be read through multiple calls to read(),
// maintaining the position of the current read and incrementing across calls to read().
pub struct FwCfgDevice {
    file_slots: usize,
    // entries[0] holds generic fw_cfg items in addition to special items (file dir, signature, and
    // revision vector). entries[1] holds arch-specific items.
    entries: [Vec<FwCfgEntry>; 2],
    files: Vec<FwCfgFile>,
    cur_item_type: FwCfgItemType,
    cur_entry: u16,
    cur_offset: usize,
    file_names: HashSet<String>,
}

impl FwCfgDevice {
    pub fn new(file_slots: usize, fw_cfg_parameters: Vec<FwCfgParameters>) -> Result<FwCfgDevice> {
        let mut device = FwCfgDevice {
            file_slots,
            entries: [
                vec![
                    FwCfgEntry {
                        allow_write: false,
                        data: vec![]
                    };
                    FW_CFG_FILE_FIRST
                ],
                Vec::new(),
            ],
            files: Vec::new(),
            cur_item_type: FwCfgItemType::GenericItem,
            cur_entry: 0,
            cur_offset: 0,
            file_names: HashSet::new(),
        };

        for param in fw_cfg_parameters {
            if let Some(_name) = &param.name {
                let data: Vec<u8> = if let Some(string) = &param.string {
                    string.as_bytes().to_vec()
                } else if let Ok(bytes) = fs::read(param.clone().path.unwrap()) {
                    bytes
                } else {
                    return Err(Error::FileOpen(param.path.unwrap()));
                };

                // The file added from the command line will be a generic item. QEMU does not
                // give users the option to specify whether the user-specified blob is
                // arch-specific, so we won't either.
                device.add_file(&param.name.unwrap(), data, FwCfgItemType::GenericItem)?
            }
        }

        device.add_bytes(FW_CFG_SIGNATURE.to_vec(), FwCfgItemType::Signature);
        device.add_bytes(FW_CFG_REVISION.to_vec(), FwCfgItemType::RevisionVector);

        Ok(device)
    }

    /// Adds a file to the device.
    ///
    /// # Arguments
    ///
    /// - `filename`: Name of file. Must be valid a Unix-style filename
    /// - `data`: File data as bytes
    pub fn add_file(
        &mut self,
        filename: &str,
        data: Vec<u8>,
        item_type: FwCfgItemType,
    ) -> Result<()> {
        // Adds a data blob to the device under the name filename. This entails creating an
        // FwCfgEntry and its associated FwCfgFile and adding them to FwCfgDevice.

        if self.files.len() >= FW_CFG_MAX_FILE_SLOTS || self.files.len() >= self.file_slots {
            return Err(Error::InsufficientFileSlots);
        }

        if filename.len() > FW_CFG_FILENAME_SIZE - 1 {
            return Err(Error::FileNameTooLong);
        }

        // No need to worry about endianess in this function. We will deal with this in read(). We
        // are only using FwCfgFile internally.
        let index = self.entries[item_type.value()].len();

        if self.file_names.contains(filename) {
            return Err(Error::FileAlreadyExists);
        }

        // Since the size field of an entry is stored as a u32, the largest file that can be stored
        // in the device is 2^32 - 1 ~ 4GB
        let size: u32 = data.len().try_into().map_err(|_| Error::SizeOverflow)?;

        let mut select: u16 = (index).try_into().map_err(|_| Error::IndexOverflow)?;

        if item_type == FwCfgItemType::ArchSpecificItem {
            select |= FW_CFG_SELECTOR_ARCH_MASK;
        }

        let new_file = FwCfgFile {
            size,
            select,
            name: filename.to_owned(),
        };

        self.add_bytes(data, item_type);
        self.files.push(new_file);
        self.file_names.insert(filename.to_string());
        // We need to update the file_dir entry every time we insert a new file.
        self.update_file_dir_entry();

        Ok(())
    }

    fn add_bytes(&mut self, data: Vec<u8>, item_type: FwCfgItemType) {
        // Add a FwCfgEntry to FwCfgDevice's entries array

        let new_entry = FwCfgEntry {
            allow_write: false,
            data,
        };

        match item_type {
            FwCfgItemType::GenericItem | FwCfgItemType::ArchSpecificItem => {
                self.entries[item_type.value()].push(new_entry)
            }
            FwCfgItemType::FileDir => {
                self.entries[item_type.value()][FW_CFG_FILE_DIR_SELECTOR as usize] = new_entry
            }
            FwCfgItemType::Signature => {
                self.entries[item_type.value()][FW_CFG_SIGNATURE_SELECTOR as usize] = new_entry
            }
            FwCfgItemType::RevisionVector => {
                self.entries[item_type.value()][FW_CFG_REVISION_SELECTOR as usize] = new_entry
            }
        }
    }

    fn update_file_dir_entry(&mut self) {
        let mut raw_file_dir: Vec<u8> = Vec::new();
        // casting to u32 should not be problematic. insert_file() assures that there can be no
        // more than 2^14 items in the device.
        let files_dir_count = self.files.len() as u32;
        raw_file_dir.extend_from_slice(&files_dir_count.to_be_bytes());

        for file in &self.files {
            raw_file_dir.extend_from_slice(&file.size.to_be_bytes());
            raw_file_dir.extend_from_slice(&file.select.to_be_bytes());
            // The caller expects a "reserved" field to be present on each FwCfgFile. Since
            // we always set the field to zero, we don't bother to store it on FwCfgDevice and
            // return zero unconditionally.
            raw_file_dir.extend_from_slice(&[0, 0]);
            raw_file_dir.extend_from_slice(file.name.as_bytes());
            // Padding for c-style char[]
            raw_file_dir.extend(repeat(0).take(FW_CFG_FILENAME_SIZE - file.name.as_bytes().len()));
        }

        self.add_bytes(raw_file_dir, FwCfgItemType::FileDir);
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

    // Read a byte from the FwCfgDevice. The byte read is based on the current state of the device.
    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }

        // Attemping to read anything other than the data port is a NOP
        if info.offset == FW_CFG_DATA_PORT_OFFSET {
            let entries_index = self.cur_entry as usize;
            // If the caller attempts to read bytes past the current entry, read returns
            // zero
            if self.cur_offset
                >= self.entries[self.cur_item_type.value()][entries_index]
                    .data
                    .len()
            {
                data[0] = 0x00;
                return;
            }
            data[0] = self.entries[self.cur_item_type.value()][entries_index].data[self.cur_offset];
            self.cur_offset += 1;
        }
    }

    // Write to the FwCfgDevice. Used to set the select register.
    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        // Attempting to write to any port other than the data port is a NOP
        if info.offset == FW_CFG_SELECTOR_PORT_OFFSET {
            if data.len() != 2 {
                return;
            }

            let Ok(selector) = data.try_into().map(u16::from_le_bytes) else {return};

            self.cur_offset = 0;

            match selector {
                FW_CFG_FILE_DIR_SELECTOR => {
                    self.cur_entry = FW_CFG_FILE_DIR_SELECTOR;
                }
                FW_CFG_REVISION_SELECTOR => {
                    self.cur_entry = FW_CFG_REVISION_SELECTOR;
                }
                FW_CFG_SIGNATURE_SELECTOR => {
                    self.cur_entry = FW_CFG_SIGNATURE_SELECTOR;
                }
                _ => {
                    let entries_index = selector as usize;

                    // Checks if the 15th bit is set. The bit indicates whether the fw_cfg item
                    // selected is archetecture specific.
                    if (FW_CFG_SELECTOR_ARCH_MASK & selector) > 0 {
                        self.cur_item_type = FwCfgItemType::ArchSpecificItem;
                    } else {
                        self.cur_item_type = FwCfgItemType::GenericItem;
                    }

                    // Check if the selector key is valid.
                    if self.entries[self.cur_item_type.value()].len() <= entries_index {
                        return;
                    }

                    // Checks if the 14th bit is set. The bit indicates whether the fw_cfg item
                    // selected is going to be written to or only read via the data port. Since
                    // writes to the data port have been deprecated as of Qemu v2.4, we don't
                    // support them either. This code is only included for clarity.
                    if (FW_CFG_SELECTOR_RW_MASK & selector) > 0 {
                        self.entries[self.cur_item_type.value()][entries_index].allow_write = true;
                    } else {
                        self.entries[self.cur_item_type.value()][entries_index].allow_write = false;
                    }

                    // Checks if the 15th bit is set. The bit indicates whether the fw_cfg item
                    // selected is archetecture specific.
                    if (FW_CFG_SELECTOR_ARCH_MASK & selector) > 0 {
                        self.cur_item_type = FwCfgItemType::ArchSpecificItem;
                    } else {
                        self.cur_item_type = FwCfgItemType::GenericItem;
                    }

                    // Only the lower 14 bits are used for actual indexing. The 14th bit
                    // determines whether the data item will be written to or only read
                    // from the data port. The 15th bit determines whether the selected
                    // configuration item is architecture specific. Therefore, we mask the 14th
                    // and 15th bit off.
                    self.cur_entry = selector & FW_CFG_SELECTOR_SELECT_MASK;
                }
            }
        }
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
    use crate::FW_CFG_BASE_PORT;
    use serde_keyvalue::*;
    const MAGIC_BYTE: u8 = 111;
    const MAGIC_BYTE_ALT: u8 = 222;
    const FILENAME: &str = "/test/device/crosvmval";
    const FILENAMES: [&str; 6] = [
        "test/hello.txt",
        "user/data/mydata.txt",
        "bruschetta/user/foo",
        "valid_unix/me/home/dir/back.txt",
        "/dev/null",
        "google/unix/sys/maple.txt",
    ];

    fn default_params() -> Vec<FwCfgParameters> {
        vec![FwCfgParameters {
            name: None,
            string: None,
            path: None,
        }]
    }

    fn get_contents() -> [Vec<u8>; 6] {
        [
            b"CROSVM".to_vec(),
            b"GOOGLE".to_vec(),
            b"FWCONFIG".to_vec(),
            b"PIZZA".to_vec(),
            b"CHROMEOS".to_vec(),
            b"42".to_vec(),
        ]
    }

    fn make_device(
        filenames: &[&str],
        contents: &[Vec<u8>],
        params: &[FwCfgParameters],
        file_slots: &usize,
    ) -> Result<FwCfgDevice> {
        let mut device = FwCfgDevice::new(*file_slots, params.to_owned())?;
        let count = filenames.len();

        for i in 0..count {
            device.add_file(
                filenames[i],
                contents[i].clone(),
                FwCfgItemType::GenericItem,
            )?;
        }

        Ok(device)
    }

    fn from_serial_arg(options: &str) -> std::result::Result<FwCfgParameters, ParseError> {
        from_key_values(options)
    }

    fn read_u32(device: &mut FwCfgDevice, bai: BusAccessInfo, data: &mut [u8]) -> u32 {
        let mut bytes: [u8; 4] = [0, 0, 0, 0];
        device.read(bai, data);
        bytes[0] = data[0];
        device.read(bai, data);
        bytes[1] = data[0];
        device.read(bai, data);
        bytes[2] = data[0];
        device.read(bai, data);
        bytes[3] = data[0];

        u32::from_be_bytes(bytes)
    }

    fn read_u16(device: &mut FwCfgDevice, bai: BusAccessInfo, data: &mut [u8]) -> u16 {
        let mut bytes: [u8; 2] = [0, 0];
        device.read(bai, data);
        bytes[0] = data[0];
        device.read(bai, data);
        bytes[1] = data[0];

        u16::from_be_bytes(bytes)
    }

    fn read_u8(device: &mut FwCfgDevice, bai: BusAccessInfo, data: &mut [u8]) -> u8 {
        let mut bytes: [u8; 1] = [0];
        device.read(bai, data);
        bytes[0] = data[0];
        u8::from_be_bytes(bytes)
    }

    fn read_char_56(device: &mut FwCfgDevice, bai: BusAccessInfo, data: &mut [u8]) -> String {
        let mut c: char = read_u8(device, bai, data) as char;
        let mut count = 1; //start at 1 b/c called read_u8 above
        let mut name: String = String::new();
        while c != '\0' {
            name.push(c);
            c = read_u8(device, bai, data) as char;
            count += 1;
        }
        while count < FW_CFG_FILENAME_SIZE {
            read_u8(device, bai, data);
            count += 1;
        }
        name
    }

    fn get_entry(
        device: &mut FwCfgDevice,
        mut bai: BusAccessInfo,
        size: usize,
        selector: u16,
    ) -> Vec<u8> {
        let mut data: Vec<u8> = vec![0];
        let mut blob: Vec<u8> = Vec::new();

        bai.address = FW_CFG_BASE_PORT;
        bai.offset = FW_CFG_SELECTOR_PORT_OFFSET;
        let selector: [u8; 2] = selector.to_le_bytes();
        device.write(bai, &selector);

        bai.offset = FW_CFG_DATA_PORT_OFFSET;

        for _i in 0..size {
            read_u8(device, bai, &mut data[..]);
            blob.push(data[0]);
        }

        blob
    }

    fn assert_read_entries(filenames: &[&str], device: &mut FwCfgDevice, bai: BusAccessInfo) {
        let data_len = device.entries[0][0 + FW_CFG_FILE_FIRST].data.len();
        assert_eq!(
            get_entry(device, bai, data_len, (0 + FW_CFG_FILE_FIRST) as u16),
            device.entries[0][0 + FW_CFG_FILE_FIRST].data
        );

        for i in (FW_CFG_FILE_FIRST + 1)..filenames.len() {
            let data_len = device.entries[0][i].data.len();
            assert_eq!(
                get_entry(device, bai, data_len, (i + FW_CFG_FILE_FIRST) as u16),
                device.entries[0][i].data
            );
        }
    }

    fn assert_read_file_dir(
        filenames: &[&str],
        contents: &[Vec<u8>],
        device: &mut FwCfgDevice,
        bai: BusAccessInfo,
    ) {
        let mut data: Vec<u8> = vec![0];
        let file_count = read_u32(device, bai, &mut data[..]);
        assert_eq!(file_count, filenames.len() as u32);

        for i in 0..filenames.len() {
            let file_size = read_u32(device, bai, &mut data[..]);
            assert_eq!(file_size, contents[i].len() as u32);

            let file_select = read_u16(device, bai, &mut data[..]);
            assert_eq!(file_select - (FW_CFG_FILE_FIRST as u16), i as u16);

            let file_reserved = read_u16(device, bai, &mut data[..]);
            assert_eq!(file_reserved, 0);

            let file_name = read_char_56(device, bai, &mut data[..]);
            assert_eq!(file_name, FILENAMES[i]);
        }
    }
    fn setup_read(
        filenames: &[&str],
        contents: &[Vec<u8>],
        selector: u16,
    ) -> (FwCfgDevice, BusAccessInfo) {
        let mut device = make_device(
            filenames,
            contents,
            &default_params(),
            &(filenames.len() + 5),
        )
        .unwrap();
        let mut bai = BusAccessInfo {
            offset: FW_CFG_SELECTOR_PORT_OFFSET,
            address: FW_CFG_BASE_PORT,
            id: 0,
        };
        let selector: [u8; 2] = selector.to_le_bytes();
        device.write(bai, &selector);
        bai.offset = FW_CFG_DATA_PORT_OFFSET;

        (device, bai)
    }

    #[test]
    // Attempt to build FwCfgParams from key value pairs
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
    // Try to cause underflow by using a selector less than FW_CFG_FILE_FIRST but not one of the
    // special selectors
    fn attempt_underflow_read() {
        let (_device, _bai) = setup_read(
            &FILENAMES,
            &get_contents(),
            (FW_CFG_FILE_FIRST - 0x05) as u16,
        );
    }

    #[test]
    // Write a simple one byte file and confirm that an entry is properly created
    fn write_one_byte_file() {
        let mut fw_cfg = FwCfgDevice::new(100, default_params()).unwrap();
        let data = vec![MAGIC_BYTE];
        fw_cfg
            .add_file(FILENAME, data, FwCfgItemType::GenericItem)
            .expect("File insert failed");
        let ind = fw_cfg.entries[0].len();
        assert_eq!(
            ind,
            FW_CFG_FILE_FIRST + 1,
            "Insertion into fw_cfg failed: Index is wrong. expected {}, got {},
                 ",
            FW_CFG_FILE_FIRST + 1,
            ind
        );
        assert_eq!(
            fw_cfg.entries[0][ind - 1].data,
            vec![MAGIC_BYTE],
            "Insertion failed: unexpected fw_cfg entry values"
        );
    }

    #[test]
    // Write a simple four byte file and confirm that an entry is properly created
    fn write_four_byte_file() {
        let mut fw_cfg = FwCfgDevice::new(100, default_params()).unwrap();
        let data = vec![MAGIC_BYTE, MAGIC_BYTE_ALT, MAGIC_BYTE, MAGIC_BYTE_ALT];
        fw_cfg
            .add_file(FILENAME, data, FwCfgItemType::GenericItem)
            .expect("File insert failed");
        let ind = fw_cfg.entries[0].len();
        assert_eq!(
            ind,
            FW_CFG_FILE_FIRST + 1,
            "Insertion into fw_cfg failed: Index is wrong. expected {}, got {}",
            FW_CFG_FILE_FIRST + 1,
            ind
        );
        assert_eq!(
            fw_cfg.entries[0][ind - 1].data,
            vec![MAGIC_BYTE, MAGIC_BYTE_ALT, MAGIC_BYTE, MAGIC_BYTE_ALT],
            "Insertion failed: unexpected fw_cfg entry values"
        );
    }

    #[test]
    #[should_panic]
    // Attempt to add a file to an fw_cfg device w/ no fileslots and assert that nothing gets inserted
    fn write_file_one_slot_expect_nop() {
        let mut fw_cfg = FwCfgDevice::new(0, default_params()).unwrap();
        let data = vec![MAGIC_BYTE];
        fw_cfg
            .add_file(FILENAME, data, FwCfgItemType::GenericItem)
            .expect("File insert failed");
    }

    #[test]
    #[should_panic]
    // Attempt to add two files to an fw_cfg w/ only one fileslot and assert only first insert succeeds.
    fn write_two_files_no_slots_expect_nop_on_second() {
        let mut fw_cfg = FwCfgDevice::new(1, default_params()).unwrap();
        let data = vec![MAGIC_BYTE];
        let data2 = vec![MAGIC_BYTE_ALT];
        fw_cfg
            .add_file(FILENAME, data, FwCfgItemType::GenericItem)
            .expect("File insert failed");
        assert_eq!(
            fw_cfg.entries[0].len(),
            1,
            "Insertion into fw_cfg failed: Expected {} elements, got {}",
            1,
            fw_cfg.entries[0].len()
        );
        fw_cfg
            .add_file(FILENAME, data2, FwCfgItemType::GenericItem)
            .expect("File insert failed");
    }

    #[test]
    // Attempt to read a FwCfgDevice's signature
    fn read_fw_cfg_signature() {
        let mut data: Vec<u8> = vec![0];
        let (mut device, bai) = setup_read(&FILENAMES, &get_contents(), FW_CFG_SIGNATURE_SELECTOR);
        // To logically compare the revison vector to FW_CFG_REVISION byte-by-byte, we must use to_be_bytes()
        // since we are comparing byte arrays, not integers.
        let signature = read_u32(&mut device, bai, &mut data[..]).to_be_bytes();
        assert_eq!(signature, FW_CFG_SIGNATURE);
    }

    #[test]
    // Attempt to read a FwCfgDevice's revision bit vector
    fn read_fw_cfg_revision() {
        let mut data: Vec<u8> = vec![0];
        let (mut device, bai) = setup_read(&FILENAMES, &get_contents(), FW_CFG_REVISION_SELECTOR);
        // To logically compare the revison vector to FW_CFG_REVISION byte-by-byte, we must use to_be_bytes()
        // since we are comparing byte arrays, not integers.
        let revision = read_u32(&mut device, bai, &mut data[..]).to_be_bytes();
        assert_eq!(revision, FW_CFG_REVISION);
    }

    #[test]
    // Attempt to read a FwCfgDevice's file directory
    fn read_file_dir() {
        let contents = get_contents();
        let (mut device, bai) = setup_read(&FILENAMES, &contents, FW_CFG_FILE_DIR_SELECTOR);
        assert_read_file_dir(&FILENAMES, &contents, &mut device, bai);
    }

    #[test]
    // Attempt to read all of a FwCfgDevice's entries
    fn read_fw_cfg_entries() {
        let contents = get_contents();
        let (mut device, bai) = setup_read(&FILENAMES, &contents, (0 + FW_CFG_FILE_FIRST) as u16);

        assert_read_entries(&FILENAMES, &mut device, bai);
    }

    #[test]
    // Attempt to read revision, file dir, and entries in random order to make
    // sure that proper state is maintained.
    fn read_whole_device() {
        let contents = get_contents();
        let mut data: Vec<u8> = vec![0];

        let (mut device, mut bai) = setup_read(&FILENAMES, &contents, FW_CFG_REVISION_SELECTOR);

        let revision = read_u32(&mut device, bai, &mut data[..]).to_be_bytes();
        assert_eq!(revision, FW_CFG_REVISION);

        let i = FILENAMES.len() - 1;
        let data_len = device.entries[0][i].data.len();
        assert_eq!(
            get_entry(&mut device, bai, data_len, (i + FW_CFG_FILE_FIRST) as u16),
            device.entries[0][i].data
        );

        bai.address = FW_CFG_BASE_PORT;
        bai.offset = FW_CFG_SELECTOR_PORT_OFFSET;
        device.write(bai, &FW_CFG_FILE_DIR_SELECTOR.to_le_bytes());
        bai.offset = FW_CFG_DATA_PORT_OFFSET;

        assert_read_file_dir(&FILENAMES, &contents, &mut device, bai);

        let data_len = device.entries[0][FW_CFG_FILE_FIRST + 0].data.len();
        assert_eq!(
            get_entry(&mut device, bai, data_len, (0 + FW_CFG_FILE_FIRST) as u16),
            device.entries[0][FW_CFG_FILE_FIRST + 0].data
        );
    }

    #[test]
    // Assert that the device maintains proper state after reads of random length.
    fn read_incorrect_bytes() {
        let contents = get_contents();
        let mut data: Vec<u8> = vec![0];
        let (mut device, mut bai) =
            setup_read(&FILENAMES, &contents, (0 + FW_CFG_FILE_FIRST) as u16);

        for _i in 1..1000 {
            let _random_bytes = read_u32(&mut device, bai, &mut data[..]);
        }

        bai.address = FW_CFG_BASE_PORT;
        device.write(bai, &FW_CFG_FILE_DIR_SELECTOR.to_le_bytes());
        bai.offset = FW_CFG_DATA_PORT_OFFSET;

        for _i in 1..10000 {
            let mut data: Vec<u8> = vec![0];
            let _random_bytes = read_u32(&mut device, bai, &mut data[..]);
        }

        bai.address = FW_CFG_BASE_PORT;
        bai.offset = FW_CFG_SELECTOR_PORT_OFFSET;
        device.write(bai, &FW_CFG_FILE_DIR_SELECTOR.to_le_bytes());
        bai.offset = FW_CFG_DATA_PORT_OFFSET;

        assert_read_file_dir(&FILENAMES, &contents, &mut device, bai);

        let i = FILENAMES.len() - 1;

        bai.address = FW_CFG_BASE_PORT;
        bai.offset = FW_CFG_SELECTOR_PORT_OFFSET;
        device.write(bai, &(FW_CFG_FILE_FIRST + i).to_le_bytes());
        bai.offset = FW_CFG_DATA_PORT_OFFSET;

        for _i in 1..1000 {
            let _random_bytes = read_u32(&mut device, bai, &mut data[..]);
        }

        assert_read_entries(&FILENAMES, &mut device, bai);
    }
}
