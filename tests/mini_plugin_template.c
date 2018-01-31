/*
 * Copyright 2018 The Chromium OS Authors. All rights reserved.
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

#define LOAD_ADDRESS {load_address}

const uint8_t g_assembly_code[] = {{
    {assembly_code}
}};

/* These get defined by the code inserted below. */
int setup_vm(struct crosvm *, void *mem);
int handle_vpcu_init(struct crosvm_vcpu *, struct kvm_regs *, struct kvm_sregs *);
int handle_vpcu_evt(struct crosvm_vcpu *, struct crosvm_vcpu_event evt);
int check_result(struct crosvm *, void *mem);
{src}

struct vcpu_context {{
    struct crosvm_vcpu *vcpu;
}};

void *vcpu_thread(void *arg) {{
    struct vcpu_context *ctx = arg;
    struct crosvm_vcpu *vcpu = ctx->vcpu;
    struct crosvm_vcpu_event evt;
    int ret;
    while (crosvm_vcpu_wait(vcpu, &evt) == 0) {{
        if (evt.kind == CROSVM_VCPU_EVENT_KIND_INIT) {{
            struct kvm_regs regs;
            crosvm_vcpu_get_regs(vcpu, &regs);
            regs.rflags = 2;
            regs.rip = LOAD_ADDRESS;

            struct kvm_sregs sregs;
            crosvm_vcpu_get_sregs(vcpu, &sregs);
            sregs.cs.base = 0;
            sregs.cs.selector = 0;

            handle_vpcu_init(vcpu, &regs, &sregs);
            crosvm_vcpu_set_regs(vcpu, &regs);
            crosvm_vcpu_set_sregs(vcpu, &sregs);
        }} else {{
            ret = handle_vpcu_evt(vcpu, evt);
            if (ret)
                return NULL;
        }}

        crosvm_vcpu_resume(vcpu);
    }}

    return NULL;
}}

int main(int argc, char** argv) {{
    int i;
    uint64_t dummy = 1;
    struct crosvm *crosvm;
    int ret = crosvm_connect(&crosvm);
    if (ret) {{
        fprintf(stderr, "failed to connect to crosvm: %d\n", ret);
        return 1;
    }}

    int kill_evt = crosvm_get_shutdown_eventfd(crosvm);
    if (kill_evt < 0) {{
        fprintf(stderr, "failed to get kill eventfd: %d\n", kill_evt);
        return 1;
    }}

    int mem_size = {mem_size};
    int mem_fd = syscall(SYS_memfd_create, "guest_mem", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (mem_fd < 0) {{
        fprintf(stderr, "failed to create guest memfd: %d\n", errno);
        return 1;
    }}
    ret = ftruncate(mem_fd, mem_size);
    if (ret) {{
        fprintf(stderr, "failed to set size of guest memory: %d\n", errno);
        return 1;
    }}
    uint8_t *mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, 0);
    if (mem == MAP_FAILED) {{
        fprintf(stderr, "failed to mmap guest memory: %d\n", errno);
        return 1;
    }}
    fcntl(mem_fd, F_ADD_SEALS, F_SEAL_SHRINK);
    memcpy(mem + LOAD_ADDRESS, g_assembly_code, sizeof(g_assembly_code));

    struct crosvm_memory *mem_obj;
    ret = crosvm_create_memory(crosvm, mem_fd, 0, mem_size, 0, false, false, &mem_obj);
    if (ret) {{
        fprintf(stderr, "failed to create memory in crosvm: %d\n", ret);
        return 1;
    }}

    ret = setup_vm(crosvm, mem);
    if (ret)
        return ret;

    struct crosvm_vcpu *vcpus[32];
    struct vcpu_context ctxs[32];
    pthread_t vcpu_threads[32];
    uint32_t vcpu_count;
    for (vcpu_count = 0; vcpu_count < 32; vcpu_count++) {{
        ret = crosvm_get_vcpu(crosvm, vcpu_count, &vcpus[vcpu_count]);
        if (ret == -ENOENT)
            break;

        if (ret) {{
            fprintf(stderr, "error while getting all vcpus: %d\n", ret);
            return 1;
        }}
        ctxs[vcpu_count].vcpu = vcpus[vcpu_count];
        pthread_create(&vcpu_threads[vcpu_count], NULL, vcpu_thread, &ctxs[vcpu_count]);
    }}

    ret = crosvm_start(crosvm);
    if (ret) {{
        fprintf(stderr, "failed to tell crosvm to start: %d\n", ret);
        return 1;
    }}

    ret = read(kill_evt, &dummy, sizeof(dummy));
    if (ret == -1) {{
        fprintf(stderr, "failed to read kill eventfd: %d\n", errno);
        return 1;
    }}

    return check_result(crosvm, mem);
}}
