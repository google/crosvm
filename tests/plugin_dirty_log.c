/*
 * Copyright 2017 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "crosvm.h"

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#endif

#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif

#define LOAD_ADDRESS 0x1000
#define SI_ADDRESS 0x8000
#define BL_VALUE 0x12
#define KILL_ADDRESS 0x9000

int g_kill_evt;

void *vcpu_thread(void *arg) {
    struct crosvm_vcpu *vcpu = arg;
    struct crosvm_vcpu_event evt;
    int i = 0;
    while (crosvm_vcpu_wait(vcpu, &evt) == 0) {
        if (evt.kind == CROSVM_VCPU_EVENT_KIND_INIT) {
            struct kvm_sregs sregs;
            crosvm_vcpu_get_sregs(vcpu, &sregs);
            sregs.cs.base = 0;
            sregs.cs.selector = 0;
            sregs.es.base = KILL_ADDRESS;
            sregs.es.selector = 0;
            crosvm_vcpu_set_sregs(vcpu, &sregs);

            struct kvm_regs regs;
            crosvm_vcpu_get_regs(vcpu, &regs);
            regs.rflags = 2;
            regs.rip = LOAD_ADDRESS;
            regs.rbx = BL_VALUE;
            regs.rsi = SI_ADDRESS;
            crosvm_vcpu_set_regs(vcpu, &regs);
        }

        if (evt.kind == CROSVM_VCPU_EVENT_KIND_IO_ACCESS &&
            evt.io_access.address_space == CROSVM_ADDRESS_SPACE_MMIO &&
            evt.io_access.address == KILL_ADDRESS &&
            evt.io_access.is_write &&
            evt.io_access.length == 1 &&
            evt.io_access.data[0] == 1)
        {
            uint64_t dummy = 1;
            write(g_kill_evt, &dummy, sizeof(dummy));
            return NULL;
        }

        crosvm_vcpu_resume(vcpu);
    }

    return NULL;
}

int main(int argc, char** argv) {
    const uint8_t code[] = {
    /*
    0000  881C          mov [si],bl
    0014  26C606000001  mov byte [es:0x0],0x1
    0002  F4            hlt
    */
        0x88, 0x1c, 0x26, 0xc6, 0x06, 0x00, 0x00, 0x01, 0xf4
    };

    struct crosvm *crosvm;
    int ret = crosvm_connect(&crosvm);
    if (ret) {
        fprintf(stderr, "failed to connect to crosvm: %d\n", ret);
        return 1;
    }

    g_kill_evt = crosvm_get_shutdown_eventfd(crosvm);
    if (g_kill_evt < 0) {
        fprintf(stderr, "failed to get kill eventfd: %d\n", g_kill_evt);
        return 1;
    }

    ret = crosvm_reserve_range(crosvm, CROSVM_ADDRESS_SPACE_MMIO, KILL_ADDRESS, 1);
    if (ret) {
        fprintf(stderr, "failed to reserve mmio range: %d\n", ret);
        return 1;
    }

    int mem_size = 0x9000;
    int mem_fd = syscall(SYS_memfd_create, "guest_mem", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (mem_fd < 0) {
        fprintf(stderr, "failed to create guest memfd: %d\n", errno);
        return 1;
    }
    ret = ftruncate(mem_fd, mem_size);
    if (ret) {
        fprintf(stderr, "failed to set size of guest memory: %d\n", errno);
        return 1;
    }
    uint8_t *mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "failed to mmap guest memory: %d\n", errno);
        return 1;
    }
    fcntl(mem_fd, F_ADD_SEALS, F_SEAL_SHRINK);
    memcpy(mem + LOAD_ADDRESS, code, sizeof(code));

    struct crosvm_memory *mem_obj;
    ret = crosvm_create_memory(crosvm, mem_fd, 0, mem_size, 0, false, true, &mem_obj);
    if (ret) {
        fprintf(stderr, "failed to create memory in crosvm: %d\n", ret);
        return 1;
    }

    struct crosvm_vcpu *vcpus[32];
    pthread_t vcpu_threads[32];
    uint32_t vcpu_count;
    for (vcpu_count = 0; vcpu_count < 32; vcpu_count++) {
        ret = crosvm_get_vcpu(crosvm, vcpu_count, &vcpus[vcpu_count]);
        if (ret == -ENOENT)
            break;

        if (ret) {
            fprintf(stderr, "error while getting all vcpus: %d\n", ret);
            return 1;
        }
        pthread_create(&vcpu_threads[vcpu_count], NULL, vcpu_thread, vcpus[vcpu_count]);
    }

    ret = crosvm_start(crosvm);
    if (ret) {
        fprintf(stderr, "failed to tell crosvm to start: %d\n", ret);
        return 1;
    }

    uint64_t dummy;
    read(g_kill_evt, &dummy, 8);

    uint8_t dirty_log[2] = {0};
    ret = crosvm_memory_get_dirty_log(crosvm, mem_obj, dirty_log);
    if (ret) {
        fprintf(stderr, "failed to get dirty log: %d\n", ret);
        return 1;
    }

    if (dirty_log[1] != 0x1) {
        fprintf(stderr, "dirty log does not have expected bits: %x\n", dirty_log[1]);
        return 1;
    }

    uint64_t val = *(uint64_t*)(&mem[SI_ADDRESS]);
    if (val != BL_VALUE) {
        fprintf(stderr, "memory does not have expected value %d\n", val);
        return 1;
    }

    return 0;
}
