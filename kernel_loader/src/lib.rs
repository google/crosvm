// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate sys_util;

use std::mem;
use std::ffi::CStr;
use std::io::{Read, Seek, SeekFrom};

#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod elf;

#[derive(Debug, PartialEq)]
pub enum Error {
    BigEndianElfOnLittle,
    CommandLineOverflow,
    ImagePastRamEnd,
    InvalidElfMagicNumber,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderOffset,
    ReadElfHeader,
    ReadKernelImage,
    ReadProgramHeader,
    SeekKernelStart,
    SeekElfStart,
    SeekProgramHeader,
}
pub type Result<T> = std::result::Result<T, Error>;

/// Loads a kernel from a vmlinux elf image to a slice
///
/// # Arguments
///
/// * `guest_mem` - A u8 slice that will be partially overwritten by the kernel.
/// * `kernel_start` - The offset into `guest_mem` at which to load the kernel.
/// * `kernel_image` - Input vmlinux image.
pub fn load_kernel<F>(guest_mem: &mut [u8], kernel_start: usize, kernel_image: &mut F) -> Result<()>
    where F: Read + Seek
{
    let mut ehdr: elf::Elf64_Ehdr = Default::default();
    kernel_image.seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekElfStart)?;
    unsafe {
        // read_struct is safe when reading a POD struct.  It can be used and dropped without issue.
        sys_util::read_struct(kernel_image, &mut ehdr).map_err(|_| Error::ReadElfHeader)?;
    }

    // Sanity checks
    if ehdr.e_ident[elf::EI_MAG0 as usize] != elf::ELFMAG0 as u8 ||
       ehdr.e_ident[elf::EI_MAG1 as usize] != elf::ELFMAG1 ||
       ehdr.e_ident[elf::EI_MAG2 as usize] != elf::ELFMAG2 ||
       ehdr.e_ident[elf::EI_MAG3 as usize] != elf::ELFMAG3 {
        return Err(Error::InvalidElfMagicNumber);
    }
    if ehdr.e_ident[elf::EI_DATA as usize] != elf::ELFDATA2LSB as u8 {
        return Err(Error::BigEndianElfOnLittle);
    }
    if ehdr.e_phentsize as usize != mem::size_of::<elf::Elf64_Phdr>() {
        return Err(Error::InvalidProgramHeaderSize);
    }
    if (ehdr.e_phoff as usize) < mem::size_of::<elf::Elf64_Ehdr>() {
        // If the program header is backwards, bail.
        return Err(Error::InvalidProgramHeaderOffset);
    }

    kernel_image.seek(SeekFrom::Start(ehdr.e_phoff))
        .map_err(|_| Error::SeekProgramHeader)?;
    let phdrs: Vec<elf::Elf64_Phdr> = unsafe {
        // Reading the structs is safe for a slice of POD structs.
        sys_util::read_struct_slice(kernel_image, ehdr.e_phnum as usize)
            .map_err(|_| Error::ReadProgramHeader)?
    };

    // Read in each section pointed to by the program headers.
    for phdr in phdrs.iter() {
        if (phdr.p_type & elf::PT_LOAD) == 0 || phdr.p_filesz == 0 {
            continue;
        }

        let mem_offset = phdr.p_paddr as usize + kernel_start;
        let mem_end = mem_offset + phdr.p_filesz as usize;
        if mem_end > guest_mem.len() {
            return Err(Error::ImagePastRamEnd);
        }
        let mut dst = &mut guest_mem[mem_offset..mem_end];
        kernel_image.seek(SeekFrom::Start(phdr.p_offset))
            .map_err(|_| Error::SeekKernelStart)?;
        kernel_image.read_exact(dst)
            .map_err(|_| Error::ReadKernelImage)?;
    }

    Ok(())
}

/// Writes the command line string to the given memory slice.
///
/// # Arguments
///
/// * `guest_mem` - A u8 slice that will be partially overwritten by the command line.
/// * `kernel_start` - The offset into `guest_mem` at which to load the command line.
/// * `cmdline` - The kernel command line.
pub fn load_cmdline(guest_mem: &mut [u8], offset: usize, cmdline: &CStr) -> Result<()> {
    let len = cmdline.to_bytes().len();
    if len <= 0 {
        return Ok(());
    }

    let end = offset + len + 1; // Extra for null termination.
    if end > guest_mem.len() {
        return Err(Error::CommandLineOverflow);
    }
    let cmdline_slice = &mut guest_mem[offset..end];
    for (i, s) in cmdline_slice.iter_mut().enumerate() {
        *s = cmdline.to_bytes().get(i).map_or(0, |c| (*c as u8));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use super::*;

    #[test]
    fn cmdline_overflow() {
        let mut mem = vec![0; 50];
        assert_eq!(Err(Error::CommandLineOverflow),
                   load_cmdline(mem.as_mut_slice(),
                                45,
                                CStr::from_bytes_with_nul(b"12345\0").unwrap()));
    }

    #[test]
    fn cmdline_write_end() {
        let mut mem = vec![0; 50];
        assert_eq!(Ok(()),
                   load_cmdline(mem.as_mut_slice(),
                                45,
                                CStr::from_bytes_with_nul(b"1234\0").unwrap()));
        assert_eq!(mem[45], '1' as u8);
        assert_eq!(mem[46], '2' as u8);
        assert_eq!(mem[47], '3' as u8);
        assert_eq!(mem[48], '4' as u8);
        assert_eq!(mem[49], '\0' as u8);
    }

    // Elf64 image that prints hello world on x86_64.
    fn make_elf_bin() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(include_bytes!("test_elf.bin"));
        v
    }

    #[test]
    fn load_elf() {
        let image = make_elf_bin();
        let mut mem = Vec::<u8>::with_capacity(0x8000);
        unsafe {
            mem.set_len(0x8000);
        }
        assert_eq!(Ok(()),
                   load_kernel(mem.as_mut_slice(), 0x0, &mut Cursor::new(&image)));
    }

    #[test]
    fn bad_magic() {
        let mut mem = Vec::<u8>::with_capacity(0x8000);
        unsafe {
            mem.set_len(0x8000);
        }
        let mut bad_image = make_elf_bin();
        bad_image[0x1] = 0x33;
        assert_eq!(Err(Error::InvalidElfMagicNumber),
                   load_kernel(mem.as_mut_slice(), 0x0, &mut Cursor::new(&bad_image)));
    }

    #[test]
    fn bad_endian() {
        // Only little endian is supported
        let mut mem = Vec::<u8>::with_capacity(0x8000);
        unsafe {
            mem.set_len(0x8000);
        }
        let mut bad_image = make_elf_bin();
        bad_image[0x5] = 2;
        assert_eq!(Err(Error::BigEndianElfOnLittle),
                   load_kernel(mem.as_mut_slice(), 0x0, &mut Cursor::new(&bad_image)));
    }

    #[test]
    fn bad_phoff() {
        // program header has to be past the end of the elf header
        let mut mem = Vec::<u8>::with_capacity(0x8000);
        unsafe {
            mem.set_len(0x8000);
        }
        let mut bad_image = make_elf_bin();
        bad_image[0x20] = 0x10;
        assert_eq!(Err(Error::InvalidProgramHeaderOffset),
                   load_kernel(mem.as_mut_slice(), 0x0, &mut Cursor::new(&bad_image)));
    }
}
