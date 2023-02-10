// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;
use std::io::prelude::*;
use std::mem;
use std::path::Path;
use std::path::PathBuf;
use std::result;
use std::slice;

use remain::sorted;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

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
    /// A provided OEM string contained a null character
    #[error("a provided SMBIOS OEM string contains a null character")]
    OemStringHasNullCharacter,
    /// Failure while opening SMBIOS data file
    #[error("Failure while opening SMBIOS data file {1}: {0}")]
    OpenFailed(std::io::Error, PathBuf),
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

// Constants sourced from SMBIOS Spec 2.3.1.
const SM2_MAGIC_IDENT: &[u8; 4usize] = b"_SM_";

// Constants sourced from SMBIOS Spec 3.2.0.
const SM3_MAGIC_IDENT: &[u8; 5usize] = b"_SM3_";
const BIOS_INFORMATION: u8 = 0;
const SYSTEM_INFORMATION: u8 = 1;
const OEM_STRING: u8 = 11;
const END_OF_TABLE: u8 = 127;
const PCI_SUPPORTED: u64 = 1 << 7;
const IS_VIRTUAL_MACHINE: u8 = 1 << 4;

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
#[derive(Default, Clone, Copy, FromBytes, AsBytes)]
pub struct Smbios23Intermediate {
    pub signature: [u8; 5usize],
    pub checksum: u8,
    pub length: u16,
    pub address: u32,
    pub count: u16,
    pub revision: u8,
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromBytes, AsBytes)]
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
#[derive(Default, Clone, Copy, FromBytes, AsBytes)]
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
#[derive(Default, Clone, Copy, FromBytes, AsBytes)]
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
#[derive(Default, Clone, Copy, FromBytes, AsBytes)]
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
#[derive(Default, Clone, Copy, FromBytes, AsBytes)]
pub struct SmbiosOemStrings {
    pub typ: u8,
    pub length: u8,
    pub handle: u16,
    pub count: u8,
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
        curptr = write_and_incr(mem, *c, curptr)?;
    }
    curptr = write_and_incr(mem, 0_u8, curptr)?;
    Ok(curptr)
}

fn setup_smbios_from_file(mem: &GuestMemory, path: &Path) -> Result<()> {
    let mut sme_path = PathBuf::from(path);
    sme_path.push("smbios_entry_point");
    let mut sme = Vec::new();
    OpenOptions::new()
        .read(true)
        .open(&sme_path)
        .map_err(|e| Error::OpenFailed(e, sme_path))?
        .read_to_end(&mut sme)
        .map_err(|_| Error::IoFailed)?;

    let mut dmi_path = PathBuf::from(path);
    dmi_path.push("DMI");
    let mut dmi = Vec::new();
    OpenOptions::new()
        .read(true)
        .open(&dmi_path)
        .map_err(|e| Error::OpenFailed(e, dmi_path))?
        .read_to_end(&mut dmi)
        .map_err(|_| Error::IoFailed)?;

    // Try SMBIOS 3.0 format.
    if sme.len() == mem::size_of::<Smbios30Entrypoint>() && sme.starts_with(SM3_MAGIC_IDENT) {
        let mut smbios_ep = Smbios30Entrypoint::default();
        smbios_ep.as_bytes_mut().copy_from_slice(&sme);

        let physptr = GuestAddress(SMBIOS_START)
            .checked_add(mem::size_of::<Smbios30Entrypoint>() as u64)
            .ok_or(Error::NotEnoughMemory)?;

        mem.write_at_addr(&dmi, physptr)
            .map_err(|_| Error::NotEnoughMemory)?;

        // Update EP DMI location
        smbios_ep.physptr = physptr.offset();
        smbios_ep.checksum = 0;
        smbios_ep.checksum = compute_checksum(&smbios_ep);

        mem.write_obj_at_addr(smbios_ep, GuestAddress(SMBIOS_START))
            .map_err(|_| Error::NotEnoughMemory)?;

        return Ok(());
    }

    // Try SMBIOS 2.3 format.
    if sme.len() == mem::size_of::<Smbios23Entrypoint>() && sme.starts_with(SM2_MAGIC_IDENT) {
        let mut smbios_ep = Smbios23Entrypoint::default();
        smbios_ep.as_bytes_mut().copy_from_slice(&sme);

        let physptr = GuestAddress(SMBIOS_START)
            .checked_add(mem::size_of::<Smbios23Entrypoint>() as u64)
            .ok_or(Error::NotEnoughMemory)?;

        mem.write_at_addr(&dmi, physptr)
            .map_err(|_| Error::NotEnoughMemory)?;

        // Update EP DMI location
        smbios_ep.dmi.address = physptr.offset() as u32;
        smbios_ep.dmi.checksum = 0;
        smbios_ep.dmi.checksum = compute_checksum(&smbios_ep.dmi);
        smbios_ep.checksum = 0;
        smbios_ep.checksum = compute_checksum(&smbios_ep);

        mem.write_obj_at_addr(smbios_ep, GuestAddress(SMBIOS_START))
            .map_err(|_| Error::WriteSmbiosEp)?;

        return Ok(());
    }

    Err(Error::InvalidInput)
}

pub fn setup_smbios(
    mem: &GuestMemory,
    dmi_path: Option<PathBuf>,
    oem_strings: &[String],
) -> Result<()> {
    if let Some(dmi_path) = dmi_path {
        return setup_smbios_from_file(mem, &dmi_path);
    }

    let physptr = GuestAddress(SMBIOS_START)
        .checked_add(mem::size_of::<Smbios30Entrypoint>() as u64)
        .ok_or(Error::NotEnoughMemory)?;
    let mut curptr = physptr;
    let mut handle = 0;

    {
        handle += 1;
        let smbios_biosinfo = SmbiosBiosInfo {
            typ: BIOS_INFORMATION,
            length: mem::size_of::<SmbiosBiosInfo>() as u8,
            handle,
            vendor: 1,  // First string written in this section
            version: 2, // Second string written in this section
            characteristics: PCI_SUPPORTED,
            characteristics_ext2: IS_VIRTUAL_MACHINE,
            ..Default::default()
        };
        curptr = write_and_incr(mem, smbios_biosinfo, curptr)?;
        curptr = write_string(mem, "crosvm", curptr)?;
        curptr = write_string(mem, "0", curptr)?;
        curptr = write_and_incr(mem, 0_u8, curptr)?;
    }

    {
        handle += 1;
        let smbios_sysinfo = SmbiosSysInfo {
            typ: SYSTEM_INFORMATION,
            length: mem::size_of::<SmbiosSysInfo>() as u8,
            handle,
            manufacturer: 1, // First string written in this section
            product_name: 2, // Second string written in this section
            ..Default::default()
        };
        curptr = write_and_incr(mem, smbios_sysinfo, curptr)?;
        curptr = write_string(mem, "ChromiumOS", curptr)?;
        curptr = write_string(mem, "crosvm", curptr)?;
        curptr = write_and_incr(mem, 0u8, curptr)?;
    }

    if !oem_strings.is_empty() {
        // AFAIK nothing prevents us from creating multiple OEM string tables
        // if we have more than 255 strings, but 255 already seems pretty
        // excessive.
        if oem_strings.len() > u8::MAX.into() {
            return Err(Error::TooManyOemStrings);
        }
        handle += 1;
        let smbios_oemstring = SmbiosOemStrings {
            typ: OEM_STRING,
            length: mem::size_of::<SmbiosOemStrings>() as u8,
            handle,
            count: oem_strings.len() as u8,
        };
        curptr = write_and_incr(mem, smbios_oemstring, curptr)?;
        for oem_string in oem_strings {
            if oem_string.contains("\0") {
                return Err(Error::OemStringHasNullCharacter);
            }
            curptr = write_string(mem, oem_string, curptr)?;
        }
        curptr = write_and_incr(mem, 0u8, curptr)?;
    }

    {
        handle += 1;
        let smbios_sysinfo = SmbiosSysInfo {
            typ: END_OF_TABLE,
            length: mem::size_of::<SmbiosSysInfo>() as u8,
            handle,
            ..Default::default()
        };
        curptr = write_and_incr(mem, smbios_sysinfo, curptr)?;
        curptr = write_and_incr(mem, 0_u8, curptr)?;
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
        )
    }

    #[test]
    fn entrypoint_checksum() {
        let mem = GuestMemory::new(&[(GuestAddress(SMBIOS_START), 4096)]).unwrap();

        // Use default 3.0 SMBIOS format.
        setup_smbios(&mem, None, &Vec::new()).unwrap();

        let smbios_ep: Smbios30Entrypoint =
            mem.read_obj_from_addr(GuestAddress(SMBIOS_START)).unwrap();

        assert_eq!(compute_checksum(&smbios_ep), 0);
    }
}
