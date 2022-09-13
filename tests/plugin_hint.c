/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <signal.h>
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

#define KILL_ADDRESS   0x3f9
#define HINT_ADDRESS   0x500
#define EAX_HINT_VALUE 0x77

int g_kill_evt;
int got_regs = 0;

void *vcpu_thread(void *arg) {
    struct crosvm_vcpu *vcpu = arg;
    struct crosvm_vcpu_event evt;
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
            regs.rip = 0x1000;
            regs.rax = 2;
            regs.rbx = 7;
            regs.rflags = 2;
            crosvm_vcpu_set_regs(vcpu, &regs);
        }
        if (evt.kind == CROSVM_VCPU_EVENT_KIND_IO_ACCESS) {
            if (evt.io_access.address_space == CROSVM_ADDRESS_SPACE_IOPORT &&
                evt.io_access.address == HINT_ADDRESS &&
                evt.io_access.is_write &&
                evt.io_access.length == 1) {
              struct kvm_regs regs = {0};
              struct kvm_sregs sregs = {0};
              struct kvm_debugregs debugregs = {0};

              /*
               * In a properly running test the following
               * get and set calls will return success despite
               * crosvm being halted.
               */
              if (kill(getppid(), SIGSTOP)) {
                fprintf(stderr, "failed to send stop to crosvm\n");
                exit(1);
              }

              printf("get regs query on crosvm\n");
              if (crosvm_vcpu_get_regs(vcpu, &regs)) {
                /*
                 * The failure mode for this test is that crosvm remains
                 * halted (since the plugin hasn't returned from
                 * crosvm_vcpu_[g|s]et_regs() to resume crosvm) and
                 * the test times out.
                 */
                fprintf(stderr, "failed to query regs on hint port\n");
                exit(1);
              }

              printf("set regs query on crosvm\n");
              if (crosvm_vcpu_set_regs(vcpu, &regs)) {
                fprintf(stderr, "failed to set regs on hint port\n");
                exit(1);
              }

              printf("get sregs query on crosvm\n");
              if (crosvm_vcpu_get_sregs(vcpu, &sregs)) {
                fprintf(stderr, "failed to query sregs on hint port\n");
                exit(1);
              }
              printf("set sregs query on crosvm\n");
              if (crosvm_vcpu_set_sregs(vcpu, &sregs)) {
                fprintf(stderr, "failed to set sregs on hint port\n");
                exit(1);
              }

              printf("get debugregs query on crosvm\n");
              if (crosvm_vcpu_get_debugregs(vcpu, &debugregs)) {
                fprintf(stderr, "failed to query debugregs on hint port\n");
                exit(1);
              }
              printf("set debugregs query on crosvm\n");
              if (crosvm_vcpu_set_debugregs(vcpu, &debugregs)) {
                fprintf(stderr, "failed to set debugregs on hint port\n");
                exit(1);
              }

              got_regs = 1;

              if (kill(getppid(), SIGCONT)) {
                fprintf(stderr, "failed to send continue to crosvm\n");
                exit(1);
              }
            }
            if (evt.io_access.address_space == CROSVM_ADDRESS_SPACE_IOPORT &&
                evt.io_access.address == KILL_ADDRESS &&
                evt.io_access.is_write &&
                evt.io_access.length == 1 &&
                evt.io_access.data[0] == 1)
            {
                uint64_t dummy = 1;
                write(g_kill_evt, &dummy, sizeof(dummy));
                return NULL;
            }
        }

        crosvm_vcpu_resume(vcpu);
    }

    return NULL;
}

int main(int argc, char** argv) {
    const uint8_t code[] = {
    /*
    B007    mov al,0x7
    BA0005  mov dx,0x500
    EE      out dx,al
    BAF903  mov dx,0x3f9
    B001    mov al,0x1
    EE      out dx,al
    F4      hlt
    */
        0xb0, EAX_HINT_VALUE,
        0xba, (HINT_ADDRESS & 0xFF), ((HINT_ADDRESS >> 8) & 0xFF),
        0xee,
        0xba, (KILL_ADDRESS & 0xFF), ((KILL_ADDRESS >> 8) & 0xFF),
        0xb0, 0x01,
        0xee,
        0xf4
    };

    struct crosvm *crosvm;
    int ret = crosvm_connect(&crosvm);
    if (ret) {
        fprintf(stderr, "failed to connect to crosvm: %d\n", ret);
        return 1;
    }

    /*
     * Not strictly necessary, but demonstrates we can have as many connections
     * as we please.
     */
    struct crosvm *extra_crosvm;
    ret = crosvm_new_connection(crosvm, &extra_crosvm);
    if (ret) {
        fprintf(stderr, "failed to make new socket: %d\n", ret);
        return 1;
    }

    /* We needs this eventfd to know when to exit before being killed. */
    g_kill_evt = crosvm_get_shutdown_eventfd(crosvm);
    if (g_kill_evt < 0) {
        fprintf(stderr, "failed to get kill eventfd: %d\n", g_kill_evt);
        return 1;
    }

    ret = crosvm_reserve_range(crosvm, CROSVM_ADDRESS_SPACE_IOPORT,
                               HINT_ADDRESS, 1);
    if (ret) {
        fprintf(stderr, "failed to reserve hint ioport range: %d\n", ret);
        return 1;
    }

    ret = crosvm_reserve_range(crosvm, CROSVM_ADDRESS_SPACE_IOPORT,
                               KILL_ADDRESS, 1);
    if (ret) {
        fprintf(stderr, "failed to reserve kill ioport range: %d\n", ret);
        return 1;
    }

    struct crosvm_hint_detail details = {0};
    details.match_rax = 1;
    details.rax = EAX_HINT_VALUE;
    details.send_sregs = 1;
    details.send_debugregs = 1;

    struct crosvm_hint hint = {0};
    hint.address_space = CROSVM_ADDRESS_SPACE_IOPORT;
    hint.address = HINT_ADDRESS;
    hint.address_flags = CROSVM_HINT_ON_WRITE;
    hint.details_count = 1;
    hint.details = &details;

    ret = crosvm_set_hypercall_hint(crosvm, 1, &hint);
    if (ret) {
        fprintf(stderr, "failed to set hypercall hint: %d\n", ret);
        return 1;
    }

    int mem_size = 0x2000;
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
                        mem_fd, 0x1000);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "failed to mmap guest memory: %d\n", errno);
        return 1;
    }
    fcntl(mem_fd, F_ADD_SEALS, F_SEAL_SHRINK);
    memcpy(mem, code, sizeof(code));

    struct crosvm_memory *mem_obj;
    ret = crosvm_create_memory(crosvm, mem_fd, 0x1000, 0x1000, 0x1000, false,
                               false, &mem_obj);
    if (ret) {
        fprintf(stderr, "failed to create memory in crosvm: %d\n", ret);
        return 1;
    }

    /* get and creat a thread for each vcpu */
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
        pthread_create(&vcpu_threads[vcpu_count], NULL, vcpu_thread,
                       vcpus[vcpu_count]);
    }

    ret = crosvm_start(extra_crosvm);
    if (ret) {
        fprintf(stderr, "failed to tell crosvm to start: %d\n", ret);
        return 1;
    }

    /* Wait for crosvm to request that we exit otherwise we will be killed. */
    uint64_t dummy;
    read(g_kill_evt, &dummy, 8);

    ret = crosvm_destroy_memory(crosvm, &mem_obj);
    if (ret) {
        fprintf(stderr, "failed to destroy memory in crosvm: %d\n", ret);
        return 1;
    }

    ret = crosvm_set_hypercall_hint(crosvm, 0, NULL);
    if (ret) {
        fprintf(stderr, "failed to clear hypercall hint: %d\n", ret);
        return 1;
    }

    ret = crosvm_reserve_range(crosvm, CROSVM_ADDRESS_SPACE_IOPORT,
                               HINT_ADDRESS, 0);
    if (ret) {
        fprintf(stderr, "failed to unreserve hint ioport range: %d\n", ret);
        return 1;
    }

    ret = crosvm_reserve_range(crosvm, CROSVM_ADDRESS_SPACE_IOPORT,
                               KILL_ADDRESS, 0);
    if (ret) {
        fprintf(stderr, "failed to unreserve kill ioport range: %d\n", ret);
        return 1;
    }

    if (!got_regs) {
      fprintf(stderr, "vm ran to completion without reg query\n");
      return 1;
    }

    return 0;
}
