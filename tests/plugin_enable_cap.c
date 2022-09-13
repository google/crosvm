/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "crosvm.h"

#define KILL_ADDRESS 0x3f9

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#endif

#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif

const uint8_t code[] = {
    // Set a non-zero value for HV_X64_MSR_GUEST_OS_ID
    // to enable hypercalls.

    // mov edx, 0xffffffff
    0x66, 0xba, 0xff, 0xff, 0xff, 0xff,

    // mov eax, 0xffffffff
    0x66, 0xb8, 0xff, 0xff, 0xff, 0xff,

    // mov ecx, 0x40000000 # HV_X64_MSR_GUEST_OS_ID
    0x66, 0xb9, 0x00, 0x00, 0x00, 0x40,

    // wrmsr
    0x0f, 0x30,

    // Establish page at 0x2000 as the hypercall page.

    // mov edx, 0x00000000
    0x66, 0xba, 0x00, 0x00, 0x00, 0x00,

    // mov eax, 0x00002001 # lowest bit is enable bit
    0x66, 0xb8, 0x01, 0x20, 0x00, 0x00,

    // mov ecx, 0x40000001 # HV_X64_MSR_HYPERCALL
    0x66, 0xb9, 0x01, 0x00, 0x00, 0x40,

    // wrmsr
    0x0f, 0x30,

    // We can't test generic hypercalls since they're
    // defined to UD for processors running in real mode.

    // for HV_X64_MSR_CONTROL:
    // edx:eax gets transferred as 'control'

    // mov edx, 0x05060708
    0x66, 0xba, 0x08, 0x07, 0x06, 0x05,

    // mov eax, 0x01020304
    0x66, 0xb8, 0x04, 0x03, 0x02, 0x01,

    // mov ecx, 0x40000080 # HV_X64_MSR_SCONTROL
    0x66, 0xb9, 0x80, 0x00, 0x00, 0x40,

    // wrmsr
    0x0f, 0x30,

    // Establish page at 0x3000 as the evt_page.

    // mov edx, 0x00000000
    0x66, 0xba, 0x00, 0x00, 0x00, 0x00,

    // mov eax, 0x00003000
    0x66, 0xb8, 0x00, 0x30, 0x00, 0x00,

    // mov ecx, 0x40000082 # HV_X64_MSR_SIEFP
    0x66, 0xb9, 0x82, 0x00, 0x00, 0x40,

    // wrmsr
    0x0f, 0x30,

    // Establish page at 0x4000 as the 'msg_page'.

    // mov edx, 0x00000000
    0x66, 0xba, 0x00, 0x00, 0x00, 0x00,

    // mov eax, 0x00004000
    0x66, 0xb8, 0x00, 0x40, 0x00, 0x00,

    // mov ecx, 0x40000083 # HV_X64_MSR_SIMP
    0x66, 0xb9, 0x83, 0x00, 0x00, 0x40,

    // wrmsr
    0x0f, 0x30,

    // Request a kill.

    // mov dx, 0x3f9
    0xba, 0xf9, 0x03,

    // mov al, 0x1
    0xb0, 0x01,

    // out dx, al
    0xee,

    // hlt
    0xf4
};

int check_synic_access(struct crosvm_vcpu* vcpu, struct crosvm_vcpu_event *evt,
                       uint32_t msr, uint64_t control, uint64_t evt_page,
                       uint64_t msg_page, const char *phase) {
    if (evt->kind != CROSVM_VCPU_EVENT_KIND_HYPERV_SYNIC) {
        fprintf(stderr, "Got incorrect exit type before %s: %d\n", phase,
                evt->kind);
        return 1;
    }
    if (evt->hyperv_synic.msr != msr ||
        evt->hyperv_synic._reserved != 0 ||
        evt->hyperv_synic.control != control ||
        evt->hyperv_synic.evt_page != evt_page ||
        evt->hyperv_synic.msg_page != msg_page) {
        fprintf(stderr, "Got unexpected synic message after %s: "
                "0x%x vs 0x%x, 0x%lx vs 0x%lx, 0x%lx vs 0x%lx, "
                "0x%lx vs 0x%lx\n",
                phase, msr, evt->hyperv_synic.msr,
                control, evt->hyperv_synic.control,
                evt_page, evt->hyperv_synic.evt_page,
                msg_page, evt->hyperv_synic.msg_page);
        return 1;
    }

    if (crosvm_vcpu_resume(vcpu) != 0) {
        fprintf(stderr, "Failed to resume after %s\n", phase);
        return 1;
    }

    if (crosvm_vcpu_wait(vcpu, evt) != 0) {
        fprintf(stderr, "Failed to wait after %s\n", phase);
        return 1;
    }
    return 0;
}

int main(int argc, char** argv) {
    struct crosvm* crosvm = NULL;
    uint64_t cap_args[4] = {0};

    int ret = crosvm_connect(&crosvm);
    if (ret) {
        fprintf(stderr, "failed to connect to crosvm: %d\n", ret);
        return 1;
    }

    ret = crosvm_reserve_range(crosvm, CROSVM_ADDRESS_SPACE_IOPORT,
                               KILL_ADDRESS, 1);
    if (ret) {
        fprintf(stderr, "failed to reserve kill port: %d\n", ret);
        return 1;
    }

    // VM mem layout:
    // null page, code page, hypercall page, synic evt_page, synic msg_page
    int mem_size = 0x4000;
    int mem_fd = syscall(SYS_memfd_create, "guest_mem",
                         MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (mem_fd < 0) {
        fprintf(stderr, "failed to create guest memfd: %d\n", errno);
        return 1;
    }
    ret = ftruncate(mem_fd, mem_size);
    if (ret) {
        fprintf(stderr, "failed to set size of guest memory: %d\n", errno);
        return 1;
    }
    uint8_t *mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                        mem_fd, 0x0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "failed to mmap guest memory: %d\n", errno);
        return 1;
    }
    fcntl(mem_fd, F_ADD_SEALS, F_SEAL_SHRINK);
    memcpy(mem, code, sizeof(code));

    // Before MSR verify hypercall page is zero
    int i;
    for (i = 0; i < 5; ++i) {
        if (mem[0x1000 + i]) {
            fprintf(stderr, "Hypercall page isn't zero\n");
            return 1;
        }
    }

    struct crosvm_memory *mem_obj;
    ret = crosvm_create_memory(crosvm, mem_fd, 0x0, mem_size, 0x1000,
                               false, false, &mem_obj);
    if (ret) {
        fprintf(stderr, "failed to create memory in crosvm: %d\n", ret);
        return 1;
    }

    struct crosvm_vcpu* vcpu = NULL;
    ret = crosvm_get_vcpu(crosvm, 0, &vcpu);
    if (ret) {
        fprintf(stderr, "failed to get vcpu #0: %d\n", ret);
        return 1;
    }

    ret = crosvm_start(crosvm);
    if (ret) {
        fprintf(stderr, "failed to start vm: %d\n", ret);
        return 1;
    }

    struct crosvm_vcpu_event evt = {0};
    ret = crosvm_vcpu_wait(vcpu, &evt);
    if (ret) {
        fprintf(stderr, "failed to wait for vm start: %d\n", ret);
        return 1;
    }
    if (evt.kind != CROSVM_VCPU_EVENT_KIND_INIT) {
        fprintf(stderr, "Got unexpected exit type: %d\n", evt.kind);
        return 1;
    }

    ret = crosvm_enable_capability(crosvm, 0, 0, cap_args);
    if (ret != -EINVAL) {
        fprintf(stderr, "Unexpected crosvm_enable_capability result: %d\n",
                ret);
        return 1;
    }

    ret = crosvm_vcpu_enable_capability(vcpu, KVM_CAP_HYPERV_SYNIC, 0,
                                        cap_args);
    if (ret) {
        fprintf(stderr, "crosvm_vcpu_enable_capability() failed: %d\n", ret);
        return 1;
    }

    {
        struct kvm_sregs sregs = {0};
        crosvm_vcpu_get_sregs(vcpu, &sregs);
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        sregs.es.base = 0;
        sregs.es.selector = 0;
        crosvm_vcpu_set_sregs(vcpu, &sregs);

        struct kvm_regs regs = {0};
        crosvm_vcpu_get_regs(vcpu, &regs);
        regs.rip = 0x1000;
        regs.rflags = 2;
        crosvm_vcpu_set_regs(vcpu, &regs);
    }

    if (crosvm_vcpu_resume(vcpu) != 0) {
        fprintf(stderr, "Failed to resume after init\n");
        return 1;
    }

    if (crosvm_vcpu_wait(vcpu, &evt) != 0) {
        fprintf(stderr, "Failed to wait after init\n");
        return 1;
    }
    if (check_synic_access(vcpu, &evt, 0x40000080, 0x506070801020304, 0, 0,
                           "synic msg #1")) {
        return 1;
    }

    // After first MSR verify hypercall page is non-zero
    uint8_t value = 0;
    for (i = 0; i < 5; ++i) {
        value |= mem[0x1000+i];
    }
    if (value == 0) {
        fprintf(stderr, "Hypercall page is still zero\n");
        return 1;
    }

    if (check_synic_access(vcpu, &evt, 0x40000082, 0x506070801020304, 0x3000,
                           0, "synic msg #2")) {
        return 1;
    }

    if (check_synic_access(vcpu, &evt, 0x40000083, 0x506070801020304, 0x3000,
                           0x4000, "synic msg #3")) {
        return 1;
    }

    if (evt.kind != CROSVM_VCPU_EVENT_KIND_IO_ACCESS) {
        fprintf(stderr, "Got incorrect exit type after synic #3: %d\n",
                evt.kind);
        return 1;
    }
    if (evt.io_access.address_space != CROSVM_ADDRESS_SPACE_IOPORT ||
        evt.io_access.address != KILL_ADDRESS ||
        !evt.io_access.is_write ||
        evt.io_access.length != 1 ||
        evt.io_access.data[0] != 1) {
        fprintf(stderr, "Didn't see kill request from VM\n");
        return 1;
    }

    fprintf(stderr, "Saw kill request from VM, exiting\n");

    return 0;
}
