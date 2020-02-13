/*
 * Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crosvm.h"

int main(int argc, char** argv) {
    struct crosvm* crosvm = NULL;
    uint64_t cap_args[4] = {0};

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

    return 0;
}
