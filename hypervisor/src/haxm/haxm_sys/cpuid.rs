// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// These cpuid bit definitions come from HAXM here:
// https://github.com/intel/haxm/blob/v7.6.1/core/include/cpuid.h#L97

use bitflags::bitflags;

const fn feature_bit(bit: u32) -> u32 {
    1 << bit
}

/*
 * Intel SDM Vol. 2A: Table 3-10.
 * Feature Information Returned in the ECX Register
 * Features for CPUID with EAX=01h stored in ECX
 */
bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct Feature1Ecx: u32 {
        const SSE3 = feature_bit(0);          /* 0x00000001  Streaming SIMD Extensions 3 */
        const PCLMULQDQ = feature_bit(1);     /* 0x00000002  PCLMULQDQ Instruction */
        const DTES64 = feature_bit(2);        /* 0x00000004  64-bit DS Area */
        const MONITOR = feature_bit(3);       /* 0x00000008  MONITOR/MWAIT Instructions */
        const DS_CPL = feature_bit(4);        /* 0x00000010  CPL Qualified Debug Store */
        const VMX = feature_bit(5);           /* 0x00000020  Virtual Machine Extensions */
        const SMX = feature_bit(6);           /* 0x00000040  Safer Mode Extensions */
        const EIST = feature_bit(7);          /* 0x00000080  Enhanced Intel SpeedStep technology */
        const TM2 = feature_bit(8);           /* 0x00000100  Thermal Monitor 2 */
        const SSSE3 = feature_bit(9);         /* 0x00000200  Supplemental Streaming SIMD Extensions 3 */
        const CNXT_ID = feature_bit(10);      /* 0x00000400  L1 Context ID */
        const SDBG = feature_bit(11);         /* 0x00000800  Silicon Debug Interface */
        const FMA = feature_bit(12);          /* 0x00001000  Fused Multiply-Add  */
        const CMPXCHG16B = feature_bit(13);   /* 0x00002000  CMPXCHG16B Instruction */
        const XTPR_UPDATE = feature_bit(14);  /* 0x00004000  xTPR Update Control */
        const PDCM = feature_bit(15);         /* 0x00008000  Perfmon and Debug Capability */
        const PCID = feature_bit(17);         /* 0x00020000  Process-context identifiers */
        const DCA = feature_bit(18);          /* 0x00040000  Direct cache access for DMA writes */
        const SSE41 = feature_bit(19);        /* 0x00080000  Streaming SIMD Extensions 4.1 */
        const SSE42 = feature_bit(20);        /* 0x00100000  Streaming SIMD Extensions 4.2 */
        const X2APIC = feature_bit(21);       /* 0x00200000  x2APIC support */
        const MOVBE = feature_bit(22);        /* 0x00400000  MOVBE Instruction */
        const POPCNT = feature_bit(23);       /* 0x00800000  POPCNT Instruction */
        const TSC_DEADLINE = feature_bit(24); /* 0x01000000  APIC supports one-shot operation using TSC deadline */
        const AESNI = feature_bit(25);        /* 0x02000000  AESNI Extension */
        const XSAVE = feature_bit(26);        /* 0x04000000  XSAVE/XRSTOR/XSETBV/XGETBV Instructions and XCR0 */
        const OSXSAVE = feature_bit(27);      /* 0x08000000  XSAVE enabled by OS */
        const AVX = feature_bit(28);          /* 0x10000000  Advanced Vector Extensions */
        const F16C = feature_bit(29);         /* 0x20000000  16-bit Floating-Point Instructions */
        const RDRAND = feature_bit(30);       /* 0x40000000  RDRAND Instruction */
        const HYPERVISOR = feature_bit(31);   /* 0x80000000  Hypervisor Running */
    }
}

/*
 * Intel SDM Vol. 2A: Table 3-11.
 * More on Feature Information Returned in the EDX Register
 * Features for CPUID with EAX=01h stored in EDX
 */
bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct Feature1Edx: u32 {
        const FPU = feature_bit(0);    /* 0x00000001  Floating Point Unit On-Chip */
        const VME = feature_bit(1);    /* 0x00000002  Virtual 8086 Mode Enhancements */
        const DE = feature_bit(2);     /* 0x00000004  Debugging Extensions */
        const PSE = feature_bit(3);    /* 0x00000008  Page Size Extension */
        const TSC = feature_bit(4);    /* 0x00000010  Time Stamp Counter */
        const MSR = feature_bit(5);    /* 0x00000020  RDMSR/WRMSR Instructions */
        const PAE = feature_bit(6);    /* 0x00000040  Physical Address Extension */
        const MCE = feature_bit(7);    /* 0x00000080  Machine Check Exception */
        const CX8 = feature_bit(8);    /* 0x00000100  CMPXCHG8B Instruction */
        const APIC = feature_bit(9);   /* 0x00000200  APIC On-Chip */
        const SEP = feature_bit(11);   /* 0x00000800  SYSENTER/SYSEXIT Instructions */
        const MTRR = feature_bit(12);  /* 0x00001000  Memory Type Range Registers */
        const PGE = feature_bit(13);   /* 0x00002000  Page Global Bit */
        const MCA = feature_bit(14);   /* 0x00004000  Machine Check Architecture */
        const CMOV = feature_bit(15);  /* 0x00008000  Conditional Move Instructions */
        const PAT = feature_bit(16);   /* 0x00010000  Page Attribute Table */
        const PSE36 = feature_bit(17); /* 0x00020000  36-Bit Page Size Extension */
        const PSN = feature_bit(18);   /* 0x00040000  Processor Serial Number */
        const CLFSH = feature_bit(19); /* 0x00080000  CLFLUSH Instruction */
        const DS = feature_bit(21);    /* 0x00200000  Debug Store */
        const ACPI = feature_bit(22);  /* 0x00400000  Thermal Monitor and Software Controlled Clock Facilities */
        const MMX = feature_bit(23);   /* 0x00800000  Intel MMX Technology */
        const FXSR = feature_bit(24);  /* 0x01000000  FXSAVE and FXRSTOR Instructions */
        const SSE = feature_bit(25);   /* 0x02000000  Streaming SIMD Extensions */
        const SSE2 = feature_bit(26);  /* 0x04000000  Streaming SIMD Extensions 2 */
        const SS = feature_bit(27);    /* 0x08000000  Self Snoop */
        const HTT = feature_bit(28);   /* 0x10000000  Max APIC IDs reserved field is Valid */
        const TM = feature_bit(29);    /* 0x20000000  Thermal Monitor */
        const PBE = feature_bit(31);   /* 0x80000000  Pending Break Enable */
    }
}
/*
 * Intel SDM Vol. 2A: Table 3-8. Information Returned by CPUID Instruction
 * Extended Function CPUID Information
 * Features for CPUID with EAX=80000001h stored in ECX
 */
bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct Feature80000001Ecx: u32 {
        const LAHF = feature_bit(0);      /* 0x00000001  LAHF/SAHF Instructions */
        const ABM  = feature_bit(5);      /* 0x00000020  Advanced bit manipulation (lzcnt and popcnt) */
        const PREFETCHW = feature_bit(8); /* 0x00000100  PREFETCH/PREFETCHW instructions */
    }
}

/*
 * Intel SDM Vol. 2A: Table 3-8. Information Returned by CPUID Instruction
 * Extended Function CPUID Information
 * Features for CPUID with EAX=80000001h stored in EDX
 */
bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct Feature80000001Edx: u32 {
        const SYSCALL = feature_bit(11); /* 0x00000800  SYSCALL/SYSRET Instructions */
        const NX = feature_bit(20);      /* 0x00100000  No-Execute Bit */
        const PDPE1GB = feature_bit(26); /* 0x04000000  Gibibyte pages */
        const RDTSCP = feature_bit(27);  /* 0x08000000  RDTSCP Instruction */
        const EM64T = feature_bit(29);   /* 0x20000000  Long Mode */
    }
}
