/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crosvm.h"

typedef int (*crosvm_function)(struct crosvm*, uint32_t,
                               struct kvm_cpuid_entry2*, uint32_t*);
typedef int (*vcpu_function)(struct crosvm_vcpu*, uint32_t,
                             struct kvm_cpuid_entry2*, uint32_t*);

// Members of union should only differ by the pointer type of 1st arg.
union cpuid_function {
    crosvm_function crosvm;
    vcpu_function vcpu;
};

int test_cpuid(void* crosvm, union cpuid_function funct, const char* name) {
    struct kvm_cpuid_entry2 cpuids[100];
    int n_entries = 0;
    int ret = funct.crosvm(crosvm, 1, cpuids, &n_entries);
    if (ret >= 0) {
        fprintf(stderr,
                "expected %s to fail with E2BIG\n", name);
        return ret;
    }

    ret = funct.crosvm(crosvm, 100, cpuids, &n_entries);
    if (ret < 0) {
        if (ret != -EINVAL) {
            fprintf(stderr, "unexpected failure of %s: %d\n", name, ret);
        } else {
            fprintf(stderr,
                    "Query of %s failed with EINVAL (may be expected)\n",
                    name, ret);
        }
        return ret;
    }

    if (n_entries <= 1) {
        fprintf(stderr,
                "unexpected number of cpuid entries from %s: %d\n",
                name, n_entries);
        return 1;
    }
    return 0;
}

int main(int argc, char** argv) {
    struct crosvm* crosvm = NULL;
    int ret = crosvm_connect(&crosvm);
    if (ret) {
        fprintf(stderr, "failed to connect to crosvm: %d\n", ret);
        return 1;
    }

    struct crosvm_vcpu* vcpu = NULL;
    ret = crosvm_get_vcpu(crosvm, 0, &vcpu);
    if (ret) {
        fprintf(stderr, "failed to get vcpu #0: %d\n", ret);
        return 1;
    }

    union cpuid_function funct;
    funct.crosvm = crosvm_get_supported_cpuid;
    if (test_cpuid(crosvm, funct, "crosvm_get_supported_cpuid")) {
        return 1;
    }
    funct.crosvm = crosvm_get_emulated_cpuid;
    if (test_cpuid(crosvm, funct, "crosvm_get_emulated_cpuid")) {
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

    funct.vcpu = crosvm_get_hyperv_cpuid;
    ret = test_cpuid(vcpu, funct, "crosvm_get_hyperv_cpuid");
    // Older kernels don't support and return EINVAL, so allow this for now.
    if (ret && ret != -EINVAL) {
        fprintf(stderr, "Ignoring failure of crosvm_get_hyperv_cpuid\n");
        return 1;
    }
    return 0;
}
