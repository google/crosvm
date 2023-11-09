// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux kernel ELF file loader.

use std::ffi::CStr;
use std::mem;

use base::FileReadWriteAtVolatile;
use data_model::VolatileSlice;
use remain::sorted;
use resources::AddressRange;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(clippy::all)]
mod elf;

mod arm64;

pub use arm64::load_arm64_kernel;

#[sorted]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("trying to load big-endian binary on little-endian machine")]
    BigEndianOnLittle,
    #[error("failed writing command line to guest memory")]
    CommandLineCopy,
    #[error("command line overflowed guest memory")]
    CommandLineOverflow,
    #[error("invalid elf class")]
    InvalidElfClass,
    #[error("invalid elf version")]
    InvalidElfVersion,
    #[error("invalid entry point")]
    InvalidEntryPoint,
    #[error("invalid kernel offset")]
    InvalidKernelOffset,
    #[error("invalid kernel size")]
    InvalidKernelSize,
    #[error("invalid magic number")]
    InvalidMagicNumber,
    #[error("invalid Program Header Address")]
    InvalidProgramHeaderAddress,
    #[error("invalid Program Header memory size")]
    InvalidProgramHeaderMemSize,
    #[error("invalid program header offset")]
    InvalidProgramHeaderOffset,
    #[error("invalid program header size")]
    InvalidProgramHeaderSize,
    #[error("no loadable program headers found")]
    NoLoadableProgramHeaders,
    #[error("program header address out of allowed address range")]
    ProgramHeaderAddressOutOfRange,
    #[error("unable to read header")]
    ReadHeader,
    #[error("unable to read kernel image")]
    ReadKernelImage,
    #[error("unable to read program header")]
    ReadProgramHeader,
    #[error("unable to seek to kernel end")]
    SeekKernelEnd,
    #[error("unable to seek to kernel start")]
    SeekKernelStart,
    #[error("unable to seek to program header")]
    SeekProgramHeader,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// Information about a kernel loaded with the [`load_elf`] function.
pub struct LoadedKernel {
    /// Address range containg the bounds of the loaded program headers.
    /// `address_range.start` is the start of the lowest loaded program header.
    /// `address_range.end` is the end of the highest loaded program header.
    pub address_range: AddressRange,

    /// Size of the kernel image in bytes.
    pub size: u64,

    /// Entry point address of the kernel.
    pub entry: GuestAddress,
}

/// Loads a kernel from a 32-bit ELF image into memory.
///
/// The ELF file will be loaded at the physical address specified by the `p_paddr` fields of its
/// program headers.
///
/// # Arguments
///
/// * `guest_mem` - The guest memory region the kernel is written to.
/// * `kernel_start` - The minimum guest address to allow when loading program headers.
/// * `kernel_image` - Input vmlinux image.
/// * `phys_offset` - An offset in bytes to add to each physical address (`p_paddr`).
pub fn load_elf32<F>(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    kernel_image: &mut F,
    phys_offset: u64,
) -> Result<LoadedKernel>
where
    F: FileReadWriteAtVolatile,
{
    load_elf_for_class(
        guest_mem,
        kernel_start,
        kernel_image,
        phys_offset,
        Some(elf::ELFCLASS32),
    )
}

/// Loads a kernel from a 64-bit ELF image into memory.
///
/// The ELF file will be loaded at the physical address specified by the `p_paddr` fields of its
/// program headers.
///
/// # Arguments
///
/// * `guest_mem` - The guest memory region the kernel is written to.
/// * `kernel_start` - The minimum guest address to allow when loading program headers.
/// * `kernel_image` - Input vmlinux image.
/// * `phys_offset` - An offset in bytes to add to each physical address (`p_paddr`).
pub fn load_elf64<F>(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    kernel_image: &mut F,
    phys_offset: u64,
) -> Result<LoadedKernel>
where
    F: FileReadWriteAtVolatile,
{
    load_elf_for_class(
        guest_mem,
        kernel_start,
        kernel_image,
        phys_offset,
        Some(elf::ELFCLASS64),
    )
}

/// Loads a kernel from a 32-bit or 64-bit ELF image into memory.
///
/// The ELF file will be loaded at the physical address specified by the `p_paddr` fields of its
/// program headers.
///
/// # Arguments
///
/// * `guest_mem` - The guest memory region the kernel is written to.
/// * `kernel_start` - The minimum guest address to allow when loading program headers.
/// * `kernel_image` - Input vmlinux image.
/// * `phys_offset` - An offset in bytes to add to each physical address (`p_paddr`).
pub fn load_elf<F>(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    kernel_image: &mut F,
    phys_offset: u64,
) -> Result<LoadedKernel>
where
    F: FileReadWriteAtVolatile,
{
    load_elf_for_class(guest_mem, kernel_start, kernel_image, phys_offset, None)
}

fn load_elf_for_class<F>(
    guest_mem: &GuestMemory,
    kernel_start: GuestAddress,
    kernel_image: &mut F,
    phys_offset: u64,
    ei_class: Option<u32>,
) -> Result<LoadedKernel>
where
    F: FileReadWriteAtVolatile,
{
    let elf = read_elf(kernel_image, ei_class)?;
    let mut start = None;
    let mut end = 0;

    // Read in each section pointed to by the program headers.
    for phdr in &elf.program_headers {
        if phdr.p_type != elf::PT_LOAD {
            continue;
        }

        let paddr = phdr
            .p_paddr
            .checked_add(phys_offset)
            .ok_or(Error::ProgramHeaderAddressOutOfRange)?;

        if paddr < kernel_start.offset() {
            return Err(Error::ProgramHeaderAddressOutOfRange);
        }

        if start.is_none() {
            start = Some(paddr);
        }

        end = paddr
            .checked_add(phdr.p_memsz)
            .ok_or(Error::InvalidProgramHeaderMemSize)?;

        if phdr.p_filesz == 0 {
            continue;
        }

        let guest_slice = guest_mem
            .get_slice_at_addr(GuestAddress(paddr), phdr.p_filesz as usize)
            .map_err(|_| Error::ReadKernelImage)?;
        kernel_image
            .read_exact_at_volatile(guest_slice, phdr.p_offset)
            .map_err(|_| Error::ReadKernelImage)?;
    }

    // We should have found at least one PT_LOAD program header. If not, `start` will not be set.
    let start = start.ok_or(Error::NoLoadableProgramHeaders)?;

    let size = end
        .checked_sub(start)
        .ok_or(Error::InvalidProgramHeaderSize)?;

    let address_range = AddressRange { start, end };

    // The entry point address must fall within one of the loaded sections.
    // We approximate this by checking whether it within the bounds of the first and last sections.
    let entry = elf
        .file_header
        .e_entry
        .checked_add(phys_offset)
        .ok_or(Error::InvalidEntryPoint)?;
    if !address_range.contains(entry) {
        return Err(Error::InvalidEntryPoint);
    }

    Ok(LoadedKernel {
        address_range,
        size,
        entry: GuestAddress(entry),
    })
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
        return Err(Error::CommandLineOverflow);
    }

    guest_mem
        .write_at_addr(cmdline.to_bytes_with_nul(), guest_addr)
        .map_err(|_| Error::CommandLineCopy)?;

    Ok(())
}

struct Elf64 {
    file_header: elf::Elf64_Ehdr,
    program_headers: Vec<elf::Elf64_Phdr>,
}

/// Reads the headers of an ELF32 or ELF64 object file.  Returns ELF file and program headers,
/// converted to ELF64 format.  If `required_ei_class` is Some and the file's ELF ei_class doesn't
/// match, an Err is returned.
fn read_elf<F>(file: &mut F, required_ei_class: Option<u32>) -> Result<Elf64>
where
    F: FileReadWriteAtVolatile,
{
    // Read the ELF identification (e_ident) block.
    let mut ident = [0u8; 16];
    file.read_exact_at_volatile(VolatileSlice::new(&mut ident), 0)
        .map_err(|_| Error::ReadHeader)?;

    // e_ident checks
    if ident[elf::EI_MAG0 as usize] != elf::ELFMAG0 as u8
        || ident[elf::EI_MAG1 as usize] != elf::ELFMAG1
        || ident[elf::EI_MAG2 as usize] != elf::ELFMAG2
        || ident[elf::EI_MAG3 as usize] != elf::ELFMAG3
    {
        return Err(Error::InvalidMagicNumber);
    }
    if ident[elf::EI_DATA as usize] != elf::ELFDATA2LSB as u8 {
        return Err(Error::BigEndianOnLittle);
    }
    if ident[elf::EI_VERSION as usize] != elf::EV_CURRENT as u8 {
        return Err(Error::InvalidElfVersion);
    }

    let ei_class = ident[elf::EI_CLASS as usize] as u32;
    if let Some(required_ei_class) = required_ei_class {
        if ei_class != required_ei_class {
            return Err(Error::InvalidElfClass);
        }
    }
    match ei_class {
        elf::ELFCLASS32 => read_elf_by_type::<_, elf::Elf32_Ehdr, elf::Elf32_Phdr>(file),
        elf::ELFCLASS64 => read_elf_by_type::<_, elf::Elf64_Ehdr, elf::Elf64_Phdr>(file),
        _ => Err(Error::InvalidElfClass),
    }
}

/// Reads the headers of an ELF32 or ELF64 object file.  Returns ELF file and program headers,
/// converted to ELF64 format.  `FileHeader` and `ProgramHeader` are the ELF32 or ELF64 ehdr/phdr
/// types to read from the file.  Caller should check that `file` is a valid ELF file before calling
/// this function.
fn read_elf_by_type<F, FileHeader, ProgramHeader>(file: &mut F) -> Result<Elf64>
where
    F: FileReadWriteAtVolatile,
    FileHeader: AsBytes + FromBytes + Default + Into<elf::Elf64_Ehdr>,
    ProgramHeader: AsBytes + FromBytes + Clone + Default + Into<elf::Elf64_Phdr>,
{
    let mut ehdr = FileHeader::new_zeroed();
    file.read_exact_at_volatile(VolatileSlice::new(ehdr.as_bytes_mut()), 0)
        .map_err(|_| Error::ReadHeader)?;
    let ehdr: elf::Elf64_Ehdr = ehdr.into();

    if ehdr.e_phentsize as usize != mem::size_of::<ProgramHeader>() {
        return Err(Error::InvalidProgramHeaderSize);
    }
    if (ehdr.e_phoff as usize) < mem::size_of::<FileHeader>() {
        // If the program header is backwards, bail.
        return Err(Error::InvalidProgramHeaderOffset);
    }

    let num_phdrs = ehdr.e_phnum as usize;
    let mut phdrs = vec![ProgramHeader::default(); num_phdrs];
    file.read_exact_at_volatile(VolatileSlice::new(phdrs.as_bytes_mut()), ehdr.e_phoff)
        .map_err(|_| Error::ReadProgramHeader)?;

    Ok(Elf64 {
        file_header: ehdr,
        program_headers: phdrs.into_iter().map(|ph| ph.into()).collect(),
    })
}

impl From<elf::Elf32_Ehdr> for elf::Elf64_Ehdr {
    fn from(ehdr32: elf::Elf32_Ehdr) -> Self {
        elf::Elf64_Ehdr {
            e_ident: ehdr32.e_ident,
            e_type: ehdr32.e_type as elf::Elf64_Half,
            e_machine: ehdr32.e_machine as elf::Elf64_Half,
            e_version: ehdr32.e_version as elf::Elf64_Word,
            e_entry: ehdr32.e_entry as elf::Elf64_Addr,
            e_phoff: ehdr32.e_phoff as elf::Elf64_Off,
            e_shoff: ehdr32.e_shoff as elf::Elf64_Off,
            e_flags: ehdr32.e_flags as elf::Elf64_Word,
            e_ehsize: ehdr32.e_ehsize as elf::Elf64_Half,
            e_phentsize: ehdr32.e_phentsize as elf::Elf64_Half,
            e_phnum: ehdr32.e_phnum as elf::Elf64_Half,
            e_shentsize: ehdr32.e_shentsize as elf::Elf64_Half,
            e_shnum: ehdr32.e_shnum as elf::Elf64_Half,
            e_shstrndx: ehdr32.e_shstrndx as elf::Elf64_Half,
        }
    }
}

impl From<elf::Elf32_Phdr> for elf::Elf64_Phdr {
    fn from(phdr32: elf::Elf32_Phdr) -> Self {
        elf::Elf64_Phdr {
            p_type: phdr32.p_type as elf::Elf64_Word,
            p_flags: phdr32.p_flags as elf::Elf64_Word,
            p_offset: phdr32.p_offset as elf::Elf64_Off,
            p_vaddr: phdr32.p_vaddr as elf::Elf64_Addr,
            p_paddr: phdr32.p_paddr as elf::Elf64_Addr,
            p_filesz: phdr32.p_filesz as elf::Elf64_Xword,
            p_memsz: phdr32.p_memsz as elf::Elf64_Xword,
            p_align: phdr32.p_align as elf::Elf64_Xword,
        }
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;

    use tempfile::tempfile;
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;

    use super::*;

    const MEM_SIZE: u64 = 0x40_0000;

    fn create_guest_mem() -> GuestMemory {
        GuestMemory::new(&[(GuestAddress(0x0), MEM_SIZE)]).unwrap()
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
        assert_eq!(val, b'1');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'2');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'3');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'4');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'\0');
    }

    // Elf32 image that prints hello world on x86.
    fn make_elf32_bin() -> File {
        // test_elf32.bin built on Linux with gcc -m32 -static-pie
        let bytes = include_bytes!("test_elf32.bin");
        make_elf_bin(bytes)
    }

    // Elf64 image that prints hello world on x86_64.
    fn make_elf64_bin() -> File {
        let bytes = include_bytes!("test_elf64.bin");
        make_elf_bin(bytes)
    }

    fn make_elf_bin(elf_bytes: &[u8]) -> File {
        let mut file = tempfile().expect("failed to create tempfile");
        file.write_all(elf_bytes)
            .expect("failed to write elf to shared memory");
        file
    }

    fn mutate_elf_bin(mut f: &File, offset: u64, val: u8) {
        f.seek(SeekFrom::Start(offset))
            .expect("failed to seek file");
        f.write_all(&[val])
            .expect("failed to write mutated value to file");
    }

    #[test]
    fn load_elf32() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut image = make_elf32_bin();
        let kernel = load_elf(&gm, kernel_addr, &mut image, 0).unwrap();
        assert_eq!(kernel.address_range.start, 0);
        assert_eq!(kernel.address_range.end, 0xa_2038);
        assert_eq!(kernel.size, 0xa_2038);
        assert_eq!(kernel.entry, GuestAddress(0x3dc0));
    }

    #[test]
    fn load_elf64() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut image = make_elf64_bin();
        let kernel = load_elf(&gm, kernel_addr, &mut image, 0).expect("failed to load ELF");
        assert_eq!(kernel.address_range.start, 0x20_0000);
        assert_eq!(kernel.address_range.end, 0x20_0035);
        assert_eq!(kernel.size, 0x35);
        assert_eq!(kernel.entry, GuestAddress(0x20_000e));
    }

    #[test]
    fn bad_magic() {
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut bad_image = make_elf64_bin();
        mutate_elf_bin(&bad_image, 0x1, 0x33);
        assert_eq!(
            Err(Error::InvalidMagicNumber),
            load_elf(&gm, kernel_addr, &mut bad_image, 0)
        );
    }

    #[test]
    fn bad_endian() {
        // Only little endian is supported
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x20_0000);
        let mut bad_image = make_elf64_bin();
        mutate_elf_bin(&bad_image, 0x5, 2);
        assert_eq!(
            Err(Error::BigEndianOnLittle),
            load_elf(&gm, kernel_addr, &mut bad_image, 0)
        );
    }

    #[test]
    fn bad_phoff() {
        // program header has to be past the end of the elf header
        let gm = create_guest_mem();
        let kernel_addr = GuestAddress(0x0);
        let mut bad_image = make_elf64_bin();
        mutate_elf_bin(&bad_image, 0x20, 0x10);
        assert_eq!(
            Err(Error::InvalidProgramHeaderOffset),
            load_elf(&gm, kernel_addr, &mut bad_image, 0)
        );
    }

    #[test]
    fn paddr_below_start() {
        let gm = create_guest_mem();
        // test_elf.bin loads a phdr at 0x20_0000, so this will fail due to an out-of-bounds address
        let kernel_addr = GuestAddress(0x30_0000);
        let mut image = make_elf64_bin();
        let res = load_elf(&gm, kernel_addr, &mut image, 0);
        assert_eq!(res, Err(Error::ProgramHeaderAddressOutOfRange));
    }
}
