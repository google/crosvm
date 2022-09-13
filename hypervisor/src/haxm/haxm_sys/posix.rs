// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::ioctl_io_nr;
use base::ioctl_ior_nr;
use base::ioctl_iow_nr;
use base::ioctl_iowr_nr;

use super::*;

const HAXIO: u32 = 0;

ioctl_iowr_nr!(HAX_IOCTL_VERSION, HAXIO, 0x20, hax_module_version);
ioctl_iowr_nr!(HAX_IOCTL_CREATE_VM, HAXIO, 0x21, u32);
ioctl_iow_nr!(HAX_IOCTL_DESTROY_VM, HAXIO, 0x22, u32);
ioctl_ior_nr!(HAX_IOCTL_CAPABILITY, HAXIO, 0x23, hax_capabilityinfo);
ioctl_iowr_nr!(HAX_IOCTL_SET_MEMLIMIT, HAXIO, 0x24, hax_set_memlimit);
ioctl_ior_nr!(HAX_VM_IOCTL_VCPU_CREATE_ORIG, HAXIO, 0x80, i32);
ioctl_iowr_nr!(HAX_VM_IOCTL_VCPU_CREATE, HAXIO, 0x80, u32);
ioctl_iowr_nr!(HAX_VM_IOCTL_ALLOC_RAM, HAXIO, 0x81, hax_alloc_ram_info);
ioctl_iowr_nr!(HAX_VM_IOCTL_SET_RAM, HAXIO, 0x82, hax_set_ram_info);
ioctl_ior_nr!(HAX_VM_IOCTL_VCPU_DESTROY, HAXIO, 0x83, u32);
ioctl_iow_nr!(HAX_VM_IOCTL_ADD_RAMBLOCK, HAXIO, 0x85, hax_ramblock_info);
ioctl_iowr_nr!(HAX_VM_IOCTL_SET_RAM2, HAXIO, 0x86, hax_set_ram_info2);
ioctl_iowr_nr!(HAX_VM_IOCTL_PROTECT_RAM, HAXIO, 0x87, hax_protect_ram_info);
ioctl_io_nr!(HAX_VCPU_IOCTL_RUN, HAXIO, 0xc0);
ioctl_iowr_nr!(HAX_VCPU_IOCTL_SET_MSRS, HAXIO, 0xc1, hax_msr_data);
ioctl_iowr_nr!(HAX_VCPU_IOCTL_GET_MSRS, HAXIO, 0xc2, hax_msr_data);
ioctl_iow_nr!(HAX_VCPU_IOCTL_SET_FPU, HAXIO, 0xc3, fx_layout);
ioctl_ior_nr!(HAX_VCPU_IOCTL_GET_FPU, HAXIO, 0xc4, fx_layout);
ioctl_iowr_nr!(HAX_VCPU_IOCTL_SETUP_TUNNEL, HAXIO, 0xc5, hax_tunnel_info);
ioctl_iowr_nr!(HAX_VCPU_IOCTL_INTERRUPT, HAXIO, 0xc6, u32);
ioctl_iowr_nr!(HAX_VCPU_SET_REGS, HAXIO, 0xc7, vcpu_state_t);
ioctl_iowr_nr!(HAX_VCPU_GET_REGS, HAXIO, 0xc8, vcpu_state_t);
ioctl_iow_nr!(
    HAX_VM_IOCTL_NOTIFY_QEMU_VERSION,
    HAXIO,
    0x84,
    hax_qemu_version
);
ioctl_iow_nr!(HAX_IOCTL_VCPU_DEBUG, HAXIO, 0xc9, hax_debug_t);
ioctl_iow_nr!(HAX_VCPU_IOCTL_SET_CPUID, HAXIO, 0xca, &hax_cpuid);
