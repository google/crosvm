// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! x86 architecture gdb debugging support.

use gdbstub_arch::x86::reg::id::X86_64CoreRegId;
use gdbstub_arch::x86::reg::X86SegmentRegs;
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use gdbstub_arch::x86::reg::X87FpuInternalRegs;
use hypervisor::x86_64::Regs;
use hypervisor::x86_64::Sregs;
use hypervisor::VcpuX86_64;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::Error;
use crate::Result;
use crate::X8664arch;

impl<T: VcpuX86_64> arch::GdbOps<T> for X8664arch {
    type Error = Error;

    fn read_registers(vcpu: &T) -> Result<X86_64CoreRegs> {
        // General registers: RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15
        let gregs = vcpu.get_regs().map_err(Error::ReadRegs)?;
        let regs = [
            gregs.rax, gregs.rbx, gregs.rcx, gregs.rdx, gregs.rsi, gregs.rdi, gregs.rbp, gregs.rsp,
            gregs.r8, gregs.r9, gregs.r10, gregs.r11, gregs.r12, gregs.r13, gregs.r14, gregs.r15,
        ];

        // GDB exposes 32-bit eflags instead of 64-bit rflags.
        // https://github.com/bminor/binutils-gdb/blob/master/gdb/features/i386/64bit-core.xml
        let eflags = gregs.rflags as u32;
        let rip = gregs.rip;

        // Segment registers: CS, SS, DS, ES, FS, GS
        let sregs = vcpu.get_sregs().map_err(Error::ReadRegs)?;
        let segments = X86SegmentRegs {
            cs: sregs.cs.selector as u32,
            ss: sregs.ss.selector as u32,
            ds: sregs.ds.selector as u32,
            es: sregs.es.selector as u32,
            fs: sregs.fs.selector as u32,
            gs: sregs.gs.selector as u32,
        };

        // x87 FPU internal state
        // TODO(dverkamp): floating point tag word, instruction pointer, and data pointer
        let fpu = vcpu.get_fpu().map_err(Error::ReadRegs)?;
        let fpu_internal = X87FpuInternalRegs {
            fctrl: u32::from(fpu.fcw),
            fstat: u32::from(fpu.fsw),
            fop: u32::from(fpu.last_opcode),
            ..Default::default()
        };

        let mut regs = X86_64CoreRegs {
            regs,
            eflags,
            rip,
            segments,
            st: Default::default(),
            fpu: fpu_internal,
            xmm: Default::default(),
            mxcsr: fpu.mxcsr,
        };

        // x87 FPU registers: ST0-ST7
        for (dst, src) in regs.st.iter_mut().zip(fpu.fpr.iter()) {
            // `fpr` contains the x87 floating point registers in FXSAVE format.
            // Each element contains an 80-bit floating point value.
            *dst = (*src).into();
        }

        // SSE registers: XMM0-XMM15
        for (dst, src) in regs.xmm.iter_mut().zip(fpu.xmm.iter()) {
            *dst = u128::from_le_bytes(*src);
        }

        Ok(regs)
    }

    fn write_registers(vcpu: &T, regs: &X86_64CoreRegs) -> Result<()> {
        // General purpose registers (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15) + RIP + rflags
        let orig_gregs = vcpu.get_regs().map_err(Error::ReadRegs)?;
        let gregs = Regs {
            rax: regs.regs[0],
            rbx: regs.regs[1],
            rcx: regs.regs[2],
            rdx: regs.regs[3],
            rsi: regs.regs[4],
            rdi: regs.regs[5],
            rbp: regs.regs[6],
            rsp: regs.regs[7],
            r8: regs.regs[8],
            r9: regs.regs[9],
            r10: regs.regs[10],
            r11: regs.regs[11],
            r12: regs.regs[12],
            r13: regs.regs[13],
            r14: regs.regs[14],
            r15: regs.regs[15],
            rip: regs.rip,
            // Update the lower 32 bits of rflags.
            rflags: (orig_gregs.rflags & !(u32::MAX as u64)) | (regs.eflags as u64),
        };
        vcpu.set_regs(&gregs).map_err(Error::WriteRegs)?;

        // Segment registers: CS, SS, DS, ES, FS, GS
        // Since GDB care only selectors, we call get_sregs() first.
        let mut sregs = vcpu.get_sregs().map_err(Error::ReadRegs)?;
        sregs.cs.selector = regs.segments.cs as u16;
        sregs.ss.selector = regs.segments.ss as u16;
        sregs.ds.selector = regs.segments.ds as u16;
        sregs.es.selector = regs.segments.es as u16;
        sregs.fs.selector = regs.segments.fs as u16;
        sregs.gs.selector = regs.segments.gs as u16;

        vcpu.set_sregs(&sregs).map_err(Error::WriteRegs)?;

        // FPU and SSE registers
        let mut fpu = vcpu.get_fpu().map_err(Error::ReadRegs)?;
        fpu.fcw = regs.fpu.fctrl as u16;
        fpu.fsw = regs.fpu.fstat as u16;
        fpu.last_opcode = regs.fpu.fop as u16;
        // TODO(dverkamp): floating point tag word, instruction pointer, and data pointer

        // x87 FPU registers: ST0-ST7
        for (dst, src) in fpu.fpr.iter_mut().zip(regs.st.iter()) {
            *dst = (*src).into();
        }

        // SSE registers: XMM0-XMM15
        for (dst, src) in fpu.xmm.iter_mut().zip(regs.xmm.iter()) {
            dst.copy_from_slice(&src.to_le_bytes());
        }

        vcpu.set_fpu(&fpu).map_err(Error::WriteRegs)?;

        Ok(())
    }

    #[inline]
    fn read_register(_vcpu: &T, _reg: X86_64CoreRegId) -> Result<Vec<u8>> {
        Err(Error::ReadRegIsUnsupported)
    }

    #[inline]
    fn write_register(_vcpu: &T, _reg: X86_64CoreRegId, _buf: &[u8]) -> Result<()> {
        Err(Error::WriteRegIsUnsupported)
    }

    fn read_memory(
        vcpu: &T,
        guest_mem: &GuestMemory,
        vaddr: GuestAddress,
        len: usize,
    ) -> Result<Vec<u8>> {
        let sregs = vcpu.get_sregs().map_err(Error::ReadRegs)?;
        let mut buf = vec![0; len];
        let mut total_read = 0u64;
        // Handle reads across page boundaries.

        while total_read < len as u64 {
            let (paddr, psize) = phys_addr(guest_mem, vaddr.0 + total_read, &sregs)?;
            let read_len = std::cmp::min(len as u64 - total_read, psize - (paddr & (psize - 1)));
            guest_mem
                .get_slice_at_addr(GuestAddress(paddr), read_len as usize)
                .map_err(Error::ReadingGuestMemory)?
                .copy_to(&mut buf[total_read as usize..]);
            total_read += read_len;
        }
        Ok(buf)
    }

    fn write_memory(
        vcpu: &T,
        guest_mem: &GuestMemory,
        vaddr: GuestAddress,
        buf: &[u8],
    ) -> Result<()> {
        let sregs = vcpu.get_sregs().map_err(Error::ReadRegs)?;
        let mut total_written = 0u64;
        // Handle writes across page boundaries.
        while total_written < buf.len() as u64 {
            let (paddr, psize) = phys_addr(guest_mem, vaddr.0 + total_written, &sregs)?;
            let write_len = std::cmp::min(
                buf.len() as u64 - total_written,
                psize - (paddr & (psize - 1)),
            );

            guest_mem
                .write_all_at_addr(
                    &buf[total_written as usize..(total_written as usize + write_len as usize)],
                    GuestAddress(paddr),
                )
                .map_err(Error::WritingGuestMemory)?;
            total_written += write_len;
        }
        Ok(())
    }

    fn enable_singlestep(vcpu: &T) -> Result<()> {
        vcpu.set_guest_debug(&[], true /* enable_singlestep */)
            .map_err(Error::EnableSinglestep)
    }

    fn get_max_hw_breakpoints(_vcpu: &T) -> Result<usize> {
        Ok(4usize)
    }

    fn set_hw_breakpoints(vcpu: &T, breakpoints: &[GuestAddress]) -> Result<()> {
        vcpu.set_guest_debug(breakpoints, false /* enable_singlestep */)
            .map_err(Error::SetHwBreakpoint)
    }
}

// return the translated address and the size of the page it resides in.
fn phys_addr(mem: &GuestMemory, vaddr: u64, sregs: &Sregs) -> Result<(u64, u64)> {
    const CR0_PG_MASK: u64 = 1 << 31;
    const CR4_PAE_MASK: u64 = 1 << 5;
    const CR4_LA57_MASK: u64 = 1 << 12;
    const MSR_EFER_LMA: u64 = 1 << 10;
    // bits 12 through 51 are the address in a PTE.
    const PTE_ADDR_MASK: u64 = ((1 << 52) - 1) & !0x0fff;
    const PAGE_PRESENT: u64 = 0x1;
    const PAGE_PSE_MASK: u64 = 0x1 << 7;

    const PAGE_SIZE_4K: u64 = 4 * 1024;
    const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
    const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

    fn next_pte(mem: &GuestMemory, curr_table_addr: u64, vaddr: u64, level: usize) -> Result<u64> {
        let ent: u64 = mem
            .read_obj_from_addr(GuestAddress(
                (curr_table_addr & PTE_ADDR_MASK) + page_table_offset(vaddr, level),
            ))
            .map_err(|_| Error::TranslatingVirtAddr)?;
        /* TODO - convert to a trace
        println!(
            "level {} vaddr {:x} table-addr {:x} mask {:x} ent {:x} offset {:x}",
            level,
            vaddr,
            curr_table_addr,
            PTE_ADDR_MASK,
            ent,
            page_table_offset(vaddr, level)
        );
        */
        if ent & PAGE_PRESENT == 0 {
            return Err(Error::PageNotPresent);
        }
        Ok(ent)
    }

    // Get the offset in to the page of `vaddr`.
    fn page_offset(vaddr: u64, page_size: u64) -> u64 {
        vaddr & (page_size - 1)
    }

    // Get the offset in to the page table of the given `level` specified by the virtual `address`.
    // `level` is 1 through 5 in x86_64 to handle the five levels of paging.
    fn page_table_offset(addr: u64, level: usize) -> u64 {
        let offset = (level - 1) * 9 + 12;
        ((addr >> offset) & 0x1ff) << 3
    }

    if sregs.cr0 & CR0_PG_MASK == 0 {
        return Ok((vaddr, PAGE_SIZE_4K));
    }

    if sregs.cr4 & CR4_PAE_MASK == 0 {
        return Err(Error::TranslatingVirtAddr);
    }

    if sregs.efer & MSR_EFER_LMA != 0 {
        // TODO - check LA57
        if sregs.cr4 & CR4_LA57_MASK != 0 {
            todo!("handle LA57");
        }
        let p4_ent = next_pte(mem, sregs.cr3, vaddr, 4)?;
        let p3_ent = next_pte(mem, p4_ent, vaddr, 3)?;
        // TODO check if it's a 1G page with the PSE bit in p2_ent
        if p3_ent & PAGE_PSE_MASK != 0 {
            // It's a 1G page with the PSE bit in p3_ent
            let paddr = p3_ent & PTE_ADDR_MASK | page_offset(vaddr, PAGE_SIZE_1G);
            return Ok((paddr, PAGE_SIZE_1G));
        }
        let p2_ent = next_pte(mem, p3_ent, vaddr, 2)?;
        if p2_ent & PAGE_PSE_MASK != 0 {
            // It's a 2M page with the PSE bit in p2_ent
            let paddr = p2_ent & PTE_ADDR_MASK | page_offset(vaddr, PAGE_SIZE_2M);
            return Ok((paddr, PAGE_SIZE_2M));
        }
        let p1_ent = next_pte(mem, p2_ent, vaddr, 1)?;
        let paddr = p1_ent & PTE_ADDR_MASK | page_offset(vaddr, PAGE_SIZE_4K);
        return Ok((paddr, PAGE_SIZE_4K));
    }
    Err(Error::TranslatingVirtAddr)
}
