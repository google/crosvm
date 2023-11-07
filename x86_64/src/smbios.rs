// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::result;
use std::slice;

use arch::SmbiosOptions;
use remain::sorted;
use thiserror::Error;
use uuid::Uuid;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// The SMBIOS table has too little address space to be stored.
    #[error("The SMBIOS table has too little address space to be stored")]
    AddressOverflow,
    /// Failure while zeroing out the memory for the SMBIOS table.
    #[error("Failure while zeroing out the memory for the SMBIOS table")]
    Clear,
    /// Invalid table entry point checksum
    #[error("Failure to verify host SMBIOS entry checksum")]
    InvalidChecksum,
    /// Incorrect or not readable host SMBIOS data
    #[error("Failure to read host SMBIOS data")]
    InvalidInput,
    /// Failure while reading SMBIOS data file
    #[error("Failure while reading SMBIOS data file")]
    IoFailed,
    /// There was too little guest memory to store the entire SMBIOS table.
    #[error("There was too little guest memory to store the SMBIOS table")]
    NotEnoughMemory,
    /// A provided string contained a null character
    #[error("a provided SMBIOS string contains a null character")]
    StringHasNullCharacter,
    /// Too many OEM strings provided
    #[error("Too many OEM strings were provided, limited to 255")]
    TooManyOemStrings,
    /// Failure to write additional data to memory
    #[error("Failure to write additional data to memory")]
    WriteData,
    /// Failure to write SMBIOS entrypoint structure
    #[error("Failure to write SMBIOS entrypoint structure")]
    WriteSmbiosEp,
}

pub type Result<T> = result::Result<T, Error>;

const SMBIOS_START: u64 = 0xf0000; // First possible location per the spec.

// Constants sourced from SMBIOS Spec 3.2.0.
const SM3_MAGIC_IDENT: &[u8; 5usize] = b"_SM3_";
const BIOS_INFORMATION: u8 = 0;
const SYSTEM_INFORMATION: u8 = 1;
const OEM_STRING: u8 = 11;
const END_OF_TABLE: u8 = 127;
const PCI_SUPPORTED: u64 = 1 << 7;
const IS_VIRTUAL_MACHINE: u8 = 1 << 4;

const DEFAULT_SMBIOS_BIOS_VENDOR: &str = "crosvm";
const DEFAULT_SMBIOS_BIOS_VERSION: &str = "0";
const DEFAULT_SMBIOS_MANUFACTURER: &str = "ChromiumOS";
const DEFAULT_SMBIOS_PRODUCT_NAME: &str = "crosvm";

fn compute_checksum<T: Copy>(v: &T) -> u8 {
    // Safe because we are only reading the bytes within the size of the `T` reference `v`.
    let v_slice = unsafe { slice::from_raw_parts(v as *const T as *const u8, mem::size_of::<T>()) };
    let mut checksum: u8 = 0;
    for i in v_slice.iter() {
        checksum = checksum.wrapping_add(*i);
    }
    (!checksum).wrapping_add(1)
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromZeroes, FromBytes, AsBytes)]
pub struct Smbios23Intermediate {
    pub signature: [u8; 5usize],
    pub checksum: u8,
    pub length: u16,
    pub address: u32,
    pub count: u16,
    pub revision: u8,
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromZeroes, FromBytes, AsBytes)]
pub struct Smbios23Entrypoint {
    pub signature: [u8; 4usize],
    pub checksum: u8,
    pub length: u8,
    pub majorver: u8,
    pub minorver: u8,
    pub max_size: u16,
    pub revision: u8,
    pub reserved: [u8; 5usize],
    pub dmi: Smbios23Intermediate,
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromZeroes, FromBytes, AsBytes)]
pub struct Smbios30Entrypoint {
    pub signature: [u8; 5usize],
    pub checksum: u8,
    pub length: u8,
    pub majorver: u8,
    pub minorver: u8,
    pub docrev: u8,
    pub revision: u8,
    pub reserved: u8,
    pub max_size: u32,
    pub physptr: u64,
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromZeroes, FromBytes, AsBytes)]
pub struct SmbiosBiosInfo {
    pub typ: u8,
    pub length: u8,
    pub handle: u16,
    pub vendor: u8,
    pub version: u8,
    pub start_addr: u16,
    pub release_date: u8,
    pub rom_size: u8,
    pub characteristics: u64,
    pub characteristics_ext1: u8,
    pub characteristics_ext2: u8,
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromZeroes, FromBytes, AsBytes)]
pub struct SmbiosSysInfo {
    pub typ: u8,
    pub length: u8,
    pub handle: u16,
    pub manufacturer: u8,
    pub product_name: u8,
    pub version: u8,
    pub serial_number: u8,
    pub uuid: [u8; 16usize],
    pub wake_up_type: u8,
    pub sku: u8,
    pub family: u8,
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromZeroes, FromBytes, AsBytes)]
pub struct SmbiosOemStrings {
    pub typ: u8,
    pub length: u8,
    pub handle: u16,
    pub count: u8,
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromZeroes, FromBytes, AsBytes)]
pub struct SmbiosEndOfTable {
    pub typ: u8,
    pub length: u8,
    pub handle: u16,
}

fn write_and_incr<T: AsBytes + FromBytes>(
    mem: &GuestMemory,
    val: T,
    mut curptr: GuestAddress,
) -> Result<GuestAddress> {
    mem.write_obj_at_addr(val, curptr)
        .map_err(|_| Error::WriteData)?;
    curptr = curptr
        .checked_add(mem::size_of::<T>() as u64)
        .ok_or(Error::NotEnoughMemory)?;
    Ok(curptr)
}

fn write_string(mem: &GuestMemory, val: &str, mut curptr: GuestAddress) -> Result<GuestAddress> {
    for c in val.as_bytes().iter() {
        if *c == 0 {
            return Err(Error::StringHasNullCharacter);
        }
        curptr = write_and_incr(mem, *c, curptr)?;
    }
    curptr = write_and_incr(mem, 0_u8, curptr)?;
    Ok(curptr)
}

pub fn setup_smbios(mem: &GuestMemory, options: &SmbiosOptions, bios_size: u64) -> Result<()> {
    let physptr = GuestAddress(SMBIOS_START)
        .checked_add(mem::size_of::<Smbios30Entrypoint>() as u64)
        .ok_or(Error::NotEnoughMemory)?;
    let mut curptr = physptr;
    let mut handle = 0;

    {
        handle += 1;

        // BIOS ROM size is encoded as 64K * (n + 1)
        let rom_size = (bios_size >> 16)
            .saturating_sub(1)
            .try_into()
            .unwrap_or(0xFF);

        let smbios_biosinfo = SmbiosBiosInfo {
            typ: BIOS_INFORMATION,
            length: mem::size_of::<SmbiosBiosInfo>() as u8,
            handle,
            vendor: 1,  // First string written in this section
            version: 2, // Second string written in this section
            characteristics: PCI_SUPPORTED,
            characteristics_ext2: IS_VIRTUAL_MACHINE,
            rom_size,
            ..Default::default()
        };
        curptr = write_and_incr(mem, smbios_biosinfo, curptr)?;
        curptr = write_string(
            mem,
            options
                .bios_vendor
                .as_deref()
                .unwrap_or(DEFAULT_SMBIOS_BIOS_VENDOR),
            curptr,
        )?;
        curptr = write_string(
            mem,
            options
                .bios_version
                .as_deref()
                .unwrap_or(DEFAULT_SMBIOS_BIOS_VERSION),
            curptr,
        )?;
        curptr = write_and_incr(mem, 0_u8, curptr)?;
    }

    {
        handle += 1;
        let smbios_sysinfo = SmbiosSysInfo {
            typ: SYSTEM_INFORMATION,
            length: mem::size_of::<SmbiosSysInfo>() as u8,
            handle,
            // PC vendors consistently use little-endian ordering for reasons
            uuid: options.uuid.unwrap_or(Uuid::nil()).to_bytes_le(),
            manufacturer: 1, // First string written in this section
            product_name: 2, // Second string written in this section
            serial_number: if options.serial_number.is_some() {
                3 // Third string written in this section
            } else {
                0 // Serial number not specified
            },
            ..Default::default()
        };
        curptr = write_and_incr(mem, smbios_sysinfo, curptr)?;
        curptr = write_string(
            mem,
            options
                .manufacturer
                .as_deref()
                .unwrap_or(DEFAULT_SMBIOS_MANUFACTURER),
            curptr,
        )?;
        curptr = write_string(
            mem,
            options
                .product_name
                .as_deref()
                .unwrap_or(DEFAULT_SMBIOS_PRODUCT_NAME),
            curptr,
        )?;
        if let Some(serial_number) = options.serial_number.as_deref() {
            curptr = write_string(mem, serial_number, curptr)?;
        }
        curptr = write_and_incr(mem, 0u8, curptr)?;
    }

    if !options.oem_strings.is_empty() {
        // AFAIK nothing prevents us from creating multiple OEM string tables
        // if we have more than 255 strings, but 255 already seems pretty
        // excessive.
        if options.oem_strings.len() > u8::MAX.into() {
            return Err(Error::TooManyOemStrings);
        }
        handle += 1;
        let smbios_oemstring = SmbiosOemStrings {
            typ: OEM_STRING,
            length: mem::size_of::<SmbiosOemStrings>() as u8,
            handle,
            count: options.oem_strings.len() as u8,
        };
        curptr = write_and_incr(mem, smbios_oemstring, curptr)?;
        for oem_string in &options.oem_strings {
            curptr = write_string(mem, oem_string, curptr)?;
        }
        curptr = write_and_incr(mem, 0u8, curptr)?;
    }

    {
        handle += 1;
        let smbios_sysinfo = SmbiosEndOfTable {
            typ: END_OF_TABLE,
            length: mem::size_of::<SmbiosEndOfTable>() as u8,
            handle,
        };
        curptr = write_and_incr(mem, smbios_sysinfo, curptr)?;
        curptr = write_and_incr(mem, 0_u8, curptr)?; // No strings
        curptr = write_and_incr(mem, 0_u8, curptr)?; // Structure terminator
    }

    {
        let mut smbios_ep = Smbios30Entrypoint::default();
        smbios_ep.signature = *SM3_MAGIC_IDENT;
        smbios_ep.length = mem::size_of::<Smbios30Entrypoint>() as u8;
        // SMBIOS rev 3.2.0
        smbios_ep.majorver = 0x03;
        smbios_ep.minorver = 0x02;
        smbios_ep.docrev = 0x00;
        smbios_ep.revision = 0x01; // SMBIOS 3.0
        smbios_ep.max_size = curptr.offset_from(physptr) as u32;
        smbios_ep.physptr = physptr.offset();
        smbios_ep.checksum = compute_checksum(&smbios_ep);
        mem.write_obj_at_addr(smbios_ep, GuestAddress(SMBIOS_START))
            .map_err(|_| Error::WriteSmbiosEp)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_size() {
        assert_eq!(
            mem::size_of::<Smbios23Entrypoint>(),
            0x1fusize,
            concat!("Size of: ", stringify!(Smbios23Entrypoint))
        );
        assert_eq!(
            mem::size_of::<Smbios30Entrypoint>(),
            0x18usize,
            concat!("Size of: ", stringify!(Smbios30Entrypoint))
        );
        assert_eq!(
            mem::size_of::<SmbiosBiosInfo>(),
            0x14usize,
            concat!("Size of: ", stringify!(SmbiosBiosInfo))
        );
        assert_eq!(
            mem::size_of::<SmbiosSysInfo>(),
            0x1busize,
            concat!("Size of: ", stringify!(SmbiosSysInfo))
        );
        assert_eq!(
            mem::size_of::<SmbiosOemStrings>(),
            0x5usize,
            concat!("Size of: ", stringify!(SmbiosOemStrings))
        );
        assert_eq!(
            mem::size_of::<SmbiosEndOfTable>(),
            0x4usize,
            concat!("Size of: ", stringify!(SmbiosEndOfTable))
        );
    }

    #[test]
    fn entrypoint_checksum() {
        let mem = GuestMemory::new(&[(GuestAddress(SMBIOS_START), 4096)]).unwrap();

        // Use default 3.0 SMBIOS format.
        setup_smbios(&mem, &SmbiosOptions::default(), 0).unwrap();

        let smbios_ep: Smbios30Entrypoint =
            mem.read_obj_from_addr(GuestAddress(SMBIOS_START)).unwrap();

        assert_eq!(compute_checksum(&smbios_ep), 0);
    }
}
