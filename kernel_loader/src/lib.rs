// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;
use std::fmt::{self, Display};
use std::io::{Read, Seek, SeekFrom};
use std::mem;
use std::os::unix::io::AsRawFd;

use sys_util::{GuestAddress, GuestMemory};

#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(clippy::all)]
mod elf;

#[derive(Debug, PartialEq)]
pub enum Error {
    BigEndianElfOnLittle,
    CommandLineCopy,
    CommandLineOverflow,
    InvalidElfMagicNumber,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderOffset,
    InvalidProgramHeaderAddress,
    ReadElfHeader,
    ReadKernelImage,
    ReadProgramHeader,
    SeekKernelStart,
    SeekElfStart,
    SeekProgramHeader,
}
pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        let description = match self {
            BigEndianElfOnLittle => "trying to load big-endian binary on little-endian machine",
            CommandLineCopy => "failed writing command line to guest memory",
            CommandLineOverflow => "command line overflowed guest memory",
            InvalidElfMagicNumber => "invalid Elf magic number",
            InvalidProgramHeaderSize => "invalid program header size",
            InvalidProgramHeaderOffset => "invalid program header offset",
            InvalidProgramHeaderAddress => "invalid Program Header Address",
            ReadElfHeader => "unable to read elf header",
            ReadKernelImage => "unable to read kernel image",
            ReadProgramHeader => "unable to read program header",
            SeekKernelStart => "unable to seek to kernel start",
            SeekElfStart => "unable to seek to elf start",
            SeekProgramHeader => "unable to seek to program header",
        };

        write!(f, "kernel loader: {}", description)
    }
}

/// Loads a kernel from a vmlinux elf image to a slice
///
/// # Arguments
///
/// * `guest_mem` - The guest memory region the kernel is written to.
/// * `kernel_start` - The offset into `guest_mem` at which to load the kernel.
/// * `kernel_image` - Input vmlinux image.
pub fn load_kernel<F>(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    kernel_image: &mut F,
) -> Result<u64>
where
    F: Read + Seek + AsRawFd,
{
    let mut ehdr: elf::Elf64_Ehdr = Default::default();
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekElfStart)?;
    unsafe {
        // read_struct is safe when reading a POD struct.  It can be used and dropped without issue.
        sys_util::read_struct(kernel_image, &mut ehdr).map_err(|_| Error::ReadElfHeader)?;
    }

    // Sanity checks
    if ehdr.e_ident[elf::EI_MAG0 as usize] != elf::ELFMAG0 as u8
        || ehdr.e_ident[elf::EI_MAG1 as usize] != elf::ELFMAG1
        || ehdr.e_ident[elf::EI_MAG2 as usize] != elf::ELFMAG2
        || ehdr.e_ident[elf::EI_MAG3 as usize] != elf::ELFMAG3
    {
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

    kernel_image
        .seek(SeekFrom::Start(ehdr.e_phoff))
        .map_err(|_| Error::SeekProgramHeader)?;
    let phdrs: Vec<elf::Elf64_Phdr> = unsafe {
        // Reading the structs is safe for a slice of POD structs.
        sys_util::read_struct_slice(kernel_image, ehdr.e_phnum as usize)
            .map_err(|_| Error::ReadProgramHeader)?
    };

    let mut kernel_end = 0;

    // Read in each section pointed to by the program headers.
    for phdr in &phdrs {
        if phdr.p_type != elf::PT_LOAD || phdr.p_filesz == 0 {
            continue;
        }

        kernel_image
            .seek(SeekFrom::Start(phdr.p_offset))
            .map_err(|_| Error::SeekKernelStart)?;

        let mem_offset = kernel_start
            .checked_add(phdr.p_paddr)
            .ok_or(Error::InvalidProgramHeaderAddress)?;
        guest_mem
            .read_to_memory(mem_offset, kernel_image, phdr.p_filesz as usize)
            .map_err(|_| Error::ReadKernelImage)?;

        kernel_end = mem_offset.offset() + phdr.p_memsz;
    }

    Ok(kernel_end)
}

/// Writes the command line string to the given memory slice.
///
/// # Arguments
///
/// * `guest_mem` - A u8 slice that will be partially overwritten by the command line.
/// * `guest_addr` - The address in `guest_mem` at which to load the command line.
/// * `cmdline` - The kernel command line.
pub fn load_cmdline(
    guest_mem: &GuestMemory,
    guest_addr: GuestAddress,
    cmdline: &CStr,
) -> Result<()> {
    let len = cmdline.to_bytes().len();
    if len == 0 {
        return Ok(());
    }

    let end = guest_addr
        .checked_add(len as u64 + 1)
        .ok_or(Error::CommandLineOverflow)?; // Extra for null termination.
    if end > guest_mem.end_addr() {
        return Err(Error::CommandLineOverflow)?;
    }

    guest_mem
        .write_at_addr(cmdline.to_bytes_with_nul(), guest_addr)
        .map_err(|_| Error::CommandLineCopy)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use sys_util::{GuestAddress, GuestMemory, SharedMemory};

    const MEM_SIZE: u64 = 0x8000;

    fn create_guest_mem() -> GuestMemory {
        GuestMemory::new(&vec![(GuestAddress(0x0), MEM_SIZE)]).unwrap()
    }

    #[test]
    fn cmdline_overflow() {
        let gm = create_guest_mem();
        let cmdline_address = GuestAddress(MEM_SIZE - 5);
        assert_eq!(
            Err(Error::CommandLineOverflow),
            load_cmdline(
                &gm,
                cmdline_address,
                CStr::from_bytes_with_nul(b"12345\0").unwrap()
            )
        );
    }

    #[test]
    fn cmdline_write_end() {
        let gm = create_guest_mem();
        let mut cmdline_address = GuestAddress(45);
        assert_eq!(
            Ok(()),
            load_cmdline(
                &gm,
                cmdline_address,
                CStr::from_bytes_with_nul(b"1234\0").unwrap()
            )
        );
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, '1' as u8);
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, '2' as u8);
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, '3' as u8);
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, '4' as u8);
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, '\0' as u8);
    }

    // Elf64 image that prints hello world on x86_64.
    fn make_elf_bin() -> File {
        let elf_bytes = include_bytes!("test_elf.bin");
        let mut shm = SharedMemory::new(None).expect("failed to create shared memory");
        shm.set_size(elf_bytes.len() as u64)
            .expect("failed to set shared memory size");
        shm.write_all(elf_bytes)
            .expect("failed to write elf to shared memoy");
        shm.into()
    }

    fn mutate_elf_bin(mut f: &File, offset: u64, val: u8) {
        f.seek(SeekFrom::Start(offset))
            .expect("failed to seek file");
        f.write(&[val])
            .expect("failed to write mutated value to file");
    }

    #[test]
    fn load_elf() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut image = make_elf_bin();
        assert_eq!(Ok(16613), load_kernel(&gm, kernel_addr, &mut image));
    }

    #[test]
    fn bad_magic() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut bad_image = make_elf_bin();
        mutate_elf_bin(&bad_image, 0x1, 0x33);
        assert_eq!(
            Err(Error::InvalidElfMagicNumber),
            load_kernel(&gm, kernel_addr, &mut bad_image)
        );
    }

    #[test]
    fn bad_endian() {
        // Only little endian is supported
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut bad_image = make_elf_bin();
        mutate_elf_bin(&bad_image, 0x5, 2);
        assert_eq!(
            Err(Error::BigEndianElfOnLittle),
            load_kernel(&gm, kernel_addr, &mut bad_image)
        );
    }

    #[test]
    fn bad_phoff() {
        // program header has to be past the end of the elf header
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut bad_image = make_elf_bin();
        mutate_elf_bin(&bad_image, 0x20, 0x10);
        assert_eq!(
            Err(Error::InvalidProgramHeaderOffset),
            load_kernel(&gm, kernel_addr, &mut bad_image)
        );
    }
}
