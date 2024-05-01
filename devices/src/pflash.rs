// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Programmable flash device that supports the minimum interface that OVMF
//! requires. This is purpose-built to allow OVMF to store UEFI variables in
//! the same way that it stores them on QEMU.
//!
//! For that reason it's heavily based on [QEMU's pflash implementation], while
//! taking even more shortcuts, chief among them being the complete lack of CFI
//! tables, which systems would normally use to learn how to use the device.
//!
//! In addition to full-width reads, we only support single byte writes,
//! block erases, and status requests, which OVMF uses to probe the device to
//! determine if it is pflash.
//!
//! Note that without SMM support in crosvm (which it doesn't yet have) this
//! device is directly accessible to potentially malicious kernels. With SMM
//! and the appropriate changes to this device this could be made more secure
//! by ensuring only the BIOS is able to touch the pflash.
//!
//! [QEMU's pflash implementation]: https://github.com/qemu/qemu/blob/master/hw/block/pflash_cfi01.c

use std::path::PathBuf;

use anyhow::bail;
use base::error;
use base::VolatileSlice;
use disk::DiskFile;
use serde::Deserialize;
use serde::Serialize;

use crate::pci::CrosvmDeviceId;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::Suspendable;

const COMMAND_WRITE_BYTE: u8 = 0x10;
const COMMAND_BLOCK_ERASE: u8 = 0x20;
const COMMAND_CLEAR_STATUS: u8 = 0x50;
const COMMAND_READ_STATUS: u8 = 0x70;
const COMMAND_BLOCK_ERASE_CONFIRM: u8 = 0xd0;
const COMMAND_READ_ARRAY: u8 = 0xff;

const STATUS_READY: u8 = 0x80;

fn pflash_parameters_default_block_size() -> u32 {
    // 4K
    4 * (1 << 10)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PflashParameters {
    pub path: PathBuf,
    #[serde(default = "pflash_parameters_default_block_size")]
    pub block_size: u32,
}

#[derive(Debug)]
enum State {
    ReadArray,
    ReadStatus,
    BlockErase(u64),
    Write(u64),
}

pub struct Pflash {
    image: Box<dyn DiskFile>,
    image_size: u64,
    block_size: u32,

    state: State,
    status: u8,
}

impl Pflash {
    pub fn new(image: Box<dyn DiskFile>, block_size: u32) -> anyhow::Result<Pflash> {
        if !block_size.is_power_of_two() {
            bail!("Block size {} is not a power of 2", block_size);
        }
        let image_size = image.get_len()?;
        if image_size % block_size as u64 != 0 {
            bail!(
                "Disk size {} is not a multiple of block size {}",
                image_size,
                block_size
            );
        }

        Ok(Pflash {
            image,
            image_size,
            block_size,
            state: State::ReadArray,
            status: STATUS_READY,
        })
    }
}

impl BusDevice for Pflash {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::Pflash.into()
    }

    fn debug_label(&self) -> String {
        "pflash".to_owned()
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        let offset = info.offset;
        match &self.state {
            State::ReadArray => {
                if offset + data.len() as u64 >= self.image_size {
                    error!("pflash read request beyond disk");
                    return;
                }
                if let Err(e) = self
                    .image
                    .read_exact_at_volatile(VolatileSlice::new(data), offset)
                {
                    error!("pflash failed to read: {}", e);
                }
            }
            State::ReadStatus => {
                self.state = State::ReadArray;
                for d in data {
                    *d = self.status;
                }
            }
            _ => {
                error!(
                    "pflash received unexpected read in state {:?}, recovering to ReadArray mode",
                    self.state
                );
                self.state = State::ReadArray;
            }
        }
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        if data.len() > 1 {
            error!("pflash write request for >1 byte, ignoring");
            return;
        }
        let data = data[0];
        let offset = info.offset;

        match self.state {
            State::Write(expected_offset) => {
                self.state = State::ReadArray;
                self.status = STATUS_READY;

                if offset != expected_offset {
                    error!("pflash received write for offset {} that doesn't match offset from WRITE_BYTE command {}", offset, expected_offset);
                    return;
                }
                if offset >= self.image_size {
                    error!(
                        "pflash offset {} greater than image size {}",
                        offset, self.image_size
                    );
                    return;
                }

                if let Err(e) = self
                    .image
                    .write_all_at_volatile(VolatileSlice::new(&mut [data]), offset)
                {
                    error!("failed to write to pflash: {}", e);
                }
            }
            State::BlockErase(expected_offset) => {
                self.state = State::ReadArray;
                self.status = STATUS_READY;

                if data != COMMAND_BLOCK_ERASE_CONFIRM {
                    error!("pflash write data {} after BLOCK_ERASE command, wanted COMMAND_BLOCK_ERASE_CONFIRM", data);
                    return;
                }
                if offset != expected_offset {
                    error!("pflash offset {} for BLOCK_ERASE_CONFIRM command does not match the one for BLOCK_ERASE {}", offset, expected_offset);
                    return;
                }
                if offset >= self.image_size {
                    error!(
                        "pflash block erase attempt offset {} beyond image size {}",
                        offset, self.image_size
                    );
                    return;
                }
                if offset % self.block_size as u64 != 0 {
                    error!(
                        "pflash block erase offset {} not on block boundary with block size {}",
                        offset, self.block_size
                    );
                    return;
                }

                if let Err(e) = self.image.write_all_at_volatile(
                    VolatileSlice::new(&mut [0xff].repeat(self.block_size.try_into().unwrap())),
                    offset,
                ) {
                    error!("pflash failed to erase block: {}", e);
                }
            }
            _ => {
                // If we're not expecting anything else then assume this is a
                // command to transition states.
                let command = data;

                match command {
                    COMMAND_READ_ARRAY => {
                        self.state = State::ReadArray;
                        self.status = STATUS_READY;
                    }
                    COMMAND_READ_STATUS => self.state = State::ReadStatus,
                    COMMAND_CLEAR_STATUS => {
                        self.state = State::ReadArray;
                        self.status = 0;
                    }
                    COMMAND_WRITE_BYTE => self.state = State::Write(offset),
                    COMMAND_BLOCK_ERASE => self.state = State::BlockErase(offset),
                    _ => {
                        error!("received unexpected/unsupported pflash command {}, ignoring and returning to read mode", command);
                        self.state = State::ReadArray
                    }
                }
            }
        }
    }
}

impl Suspendable for Pflash {
    fn sleep(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use base::FileReadWriteAtVolatile;
    use tempfile::tempfile;

    use super::*;

    const IMAGE_SIZE: usize = 4 * (1 << 20); // 4M
    const BLOCK_SIZE: u32 = 4 * (1 << 10); // 4K

    fn empty_image() -> Box<dyn DiskFile> {
        let f = Box::new(tempfile().unwrap());
        f.write_all_at_volatile(VolatileSlice::new(&mut [0xff].repeat(IMAGE_SIZE)), 0)
            .unwrap();
        f
    }

    fn new(f: Box<dyn DiskFile>) -> Pflash {
        Pflash::new(f, BLOCK_SIZE).unwrap()
    }

    fn off(offset: u64) -> BusAccessInfo {
        BusAccessInfo {
            offset,
            address: 0,
            id: 0,
        }
    }

    #[test]
    fn read() {
        let f = empty_image();
        let mut want = [0xde, 0xad, 0xbe, 0xef];
        let offset = 0x1000;
        f.write_all_at_volatile(VolatileSlice::new(&mut want), offset)
            .unwrap();

        let mut pflash = new(f);
        let mut got = [0u8; 4];
        pflash.read(off(offset), &mut got[..]);
        assert_eq!(want, got);
    }

    #[test]
    fn write() {
        let f = empty_image();
        let want = [0xdeu8];
        let offset = 0x1000;

        let mut pflash = new(f);
        pflash.write(off(offset), &[COMMAND_WRITE_BYTE]);
        pflash.write(off(offset), &want);

        // Make sure the data reads back correctly over the bus...
        pflash.write(off(0), &[COMMAND_READ_ARRAY]);
        let mut got = [0u8; 1];
        pflash.read(off(offset), &mut got);
        assert_eq!(want, got);

        // And from the backing file itself...
        pflash
            .image
            .read_exact_at_volatile(VolatileSlice::new(&mut got), offset)
            .unwrap();
        assert_eq!(want, got);

        // And when we recreate the device.
        let mut pflash = new(pflash.image);
        pflash.read(off(offset), &mut got);
        assert_eq!(want, got);

        // Finally make sure our status is ready.
        let mut got = [0u8; 4];
        pflash.write(off(offset), &[COMMAND_READ_STATUS]);
        pflash.read(off(offset), &mut got);
        let want = [STATUS_READY; 4];
        assert_eq!(want, got);
    }

    #[test]
    fn erase() {
        let f = empty_image();
        let mut data = [0xde, 0xad, 0xbe, 0xef];
        let offset = 0x1000;
        f.write_all_at_volatile(VolatileSlice::new(&mut data), offset)
            .unwrap();
        f.write_all_at_volatile(VolatileSlice::new(&mut data), offset * 2)
            .unwrap();

        let mut pflash = new(f);
        pflash.write(off(offset), &[COMMAND_BLOCK_ERASE]);
        pflash.write(off(offset), &[COMMAND_BLOCK_ERASE_CONFIRM]);

        pflash.write(off(0), &[COMMAND_READ_ARRAY]);
        let mut got = [0u8; 4];
        pflash.read(off(offset), &mut got);
        let want = [0xffu8; 4];
        assert_eq!(want, got);

        let want = data;
        pflash.read(off(offset * 2), &mut got);
        assert_eq!(want, got);

        // Make sure our status is ready.
        pflash.write(off(offset), &[COMMAND_READ_STATUS]);
        pflash.read(off(offset), &mut got);
        let want = [STATUS_READY; 4];
        assert_eq!(want, got);
    }

    #[test]
    fn status() {
        let f = empty_image();
        let mut data = [0xde, 0xad, 0xbe, 0xff];
        let offset = 0x0;
        f.write_all_at_volatile(VolatileSlice::new(&mut data), offset)
            .unwrap();

        let mut pflash = new(f);

        // Make sure we start off in the "ready" status.
        pflash.write(off(offset), &[COMMAND_READ_STATUS]);
        let mut got = [0u8; 4];
        pflash.read(off(offset), &mut got);
        let want = [STATUS_READY; 4];
        assert_eq!(want, got);

        // Make sure we can clear the status properly.
        pflash.write(off(offset), &[COMMAND_CLEAR_STATUS]);
        pflash.write(off(offset), &[COMMAND_READ_STATUS]);
        pflash.read(off(offset), &mut got);
        let want = [0; 4];
        assert_eq!(want, got);

        // We implicitly jump back into READ_ARRAY mode after reading the,
        // status but for OVMF's probe we require that this doesn't actually
        // affect the cleared status.
        pflash.read(off(offset), &mut got);
        pflash.write(off(offset), &[COMMAND_READ_STATUS]);
        pflash.read(off(offset), &mut got);
        let want = [0; 4];
        assert_eq!(want, got);
    }

    #[test]
    fn overwrite() {
        let f = empty_image();
        let data = [0];
        let offset = off((16 * IMAGE_SIZE).try_into().unwrap());

        // Ensure a write past the pflash device doesn't grow the backing file.
        let mut pflash = new(f);
        let old_size = pflash.image.get_len().unwrap();
        assert_eq!(old_size, IMAGE_SIZE as u64);

        pflash.write(offset, &[COMMAND_WRITE_BYTE]);
        pflash.write(offset, &data);

        let new_size = pflash.image.get_len().unwrap();
        assert_eq!(new_size, IMAGE_SIZE as u64);
    }
}
