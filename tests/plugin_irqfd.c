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
#define STACK_BASE (LOAD_ADDRESS + 0x1000)
#define STACK_SIZE 0x1000
#define SUCCESS_ADDRESS 0x3000
#define KILL_ADDRESS 0x4000

/*
org 0x1000
bits 16

cli

; Set entry 0x0 in the interrupt vector table
mov word [0x0], handle
mov word [0x2], 0x0

sti

; Loop until interrupt is handled
loop:
    cmp byte [si], 0x01
    jne loop

cli

; Signal that we are ready to end
end:
    mov byte [es:0], 0x01
    hlt

; Handle the interrupt by halting
handle:
    mov byte [si], 0x01
    iret
*/
const uint8_t g_code[] = {
      0xfa, 0xc7, 0x06, 0x00, 0x00, 0x1b, 0x10, 0xc7, 0x06, 0x02, 0x00, 0x00,
      0x00, 0xfb, 0x80, 0x3c, 0x01, 0x75, 0xfb, 0xfa, 0x26, 0xc6, 0x06, 0x00,
      0x00, 0x01, 0xf4, 0xc6, 0x04, 0x01, 0xcf
};

struct vcpu_context {
    struct crosvm_vcpu *vcpu;
    int irqeventfd;
    int kill_evt;
};

void *vcpu_thread(void *arg) {
    struct vcpu_context *ctx = arg;
    struct crosvm_vcpu *vcpu = ctx->vcpu;
    struct crosvm_vcpu_event evt;
    uint64_t dummy = 1;
    int i = 0;
    int ret;
    while (crosvm_vcpu_wait(vcpu, &evt) == 0) {
        if (evt.kind == CROSVM_VCPU_EVENT_KIND_INIT) {
            struct kvm_sregs sregs;
            crosvm_vcpu_get_sregs(vcpu, &sregs);
            sregs.cs.base = 0;
            sregs.cs.selector = 0x0;
            sregs.ss.base = 0;
            sregs.ss.selector = 0x0;
            sregs.es.base = KILL_ADDRESS;
            sregs.es.selector = 0x0;
            crosvm_vcpu_set_sregs(vcpu, &sregs);

            struct kvm_regs regs;
            crosvm_vcpu_get_regs(vcpu, &regs);
            regs.rflags = 2;
            regs.rip = LOAD_ADDRESS;
            regs.rsp = STACK_BASE + STACK_SIZE;
            regs.rsi = SUCCESS_ADDRESS;
            crosvm_vcpu_set_regs(vcpu, &regs);

            write(ctx->irqeventfd, &dummy, sizeof(dummy));
        }

        if (evt.kind == CROSVM_VCPU_EVENT_KIND_IO_ACCESS &&
            evt.io_access.address_space == CROSVM_ADDRESS_SPACE_MMIO &&
            evt.io_access.address == KILL_ADDRESS &&
            evt.io_access.is_write &&
            evt.io_access.length == 1 &&
            evt.io_access.data[0] == 1)
        {
            write(ctx->kill_evt, &dummy, sizeof(dummy));
            return NULL;
        }

        crosvm_vcpu_resume(vcpu);
    }

    return NULL;
}

int main(int argc, char** argv) {
    int i;
    uint64_t dummy = 1;
    struct crosvm *crosvm;
    int ret = crosvm_connect(&crosvm);
    if (ret) {
        fprintf(stderr, "failed to connect to crosvm: %d\n", ret);
        return 1;
    }

    int kill_evt = crosvm_get_shutdown_eventfd(crosvm);
    if (kill_evt < 0) {
        fprintf(stderr, "failed to get kill eventfd: %d\n", kill_evt);
        return 1;
    }

    crosvm_reserve_range(crosvm, CROSVM_ADDRESS_SPACE_MMIO, KILL_ADDRESS, 1);

    struct crosvm_irq *irq;
    ret = crosvm_create_irq_event(crosvm, 0, &irq);
    if (ret) {
        fprintf(stderr, "failed to create irq event: %d\n", ret);
        return 1;
    }

    int irqeventfd = crosvm_irq_event_get_fd(irq);

    int mem_size = 0x4000;
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
    memcpy(mem + LOAD_ADDRESS, g_code, sizeof(g_code));

    struct crosvm_memory *mem_obj;
    ret = crosvm_create_memory(crosvm, mem_fd, 0, mem_size, 0, false, false, &mem_obj);
    if (ret) {
        fprintf(stderr, "failed to create memory in crosvm: %d\n", ret);
        return 1;
    }

    struct crosvm_vcpu *vcpus[32];
    struct vcpu_context ctxs[32];
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
        ctxs[vcpu_count].vcpu = vcpus[vcpu_count];
        ctxs[vcpu_count].irqeventfd = irqeventfd;
        ctxs[vcpu_count].kill_evt = kill_evt;
        pthread_create(&vcpu_threads[vcpu_count], NULL, vcpu_thread, &ctxs[vcpu_count]);
    }

    ret = crosvm_start(crosvm);
    if (ret) {
        fprintf(stderr, "failed to tell crosvm to start: %d\n", ret);
        return 1;
    }

    ret = read(kill_evt, &dummy, sizeof(dummy));
    if (ret == -1) {
        fprintf(stderr, "failed to read kill eventfd: %d\n", errno);
        return 1;
    }

    if (mem[SUCCESS_ADDRESS] != 0x01) {
        fprintf(stderr, "interrupt was not handled: 0x%x\n", mem[SUCCESS_ADDRESS]);
        return 1;
    }

    return 0;
}
