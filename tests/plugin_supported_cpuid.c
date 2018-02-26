/*
 * Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crosvm.h"

int main(int argc, char** argv) {
    struct crosvm *crosvm;
    int ret = crosvm_connect(&crosvm);
    if (ret) {
        fprintf(stderr, "failed to connect to crosvm: %d\n", ret);
        return 1;
    }

    struct kvm_cpuid_entry2 cpuids[100];
    int n_entries;
    ret = crosvm_get_supported_cpuid(crosvm, 1, cpuids, &n_entries);
    if (ret >= 0) {
        fprintf(stderr,
                "expected crosvm_get_supported_cpuids to fail with E2BIG\n");
        return 1;
    }

    ret = crosvm_get_supported_cpuid(crosvm, 100, cpuids, &n_entries);
    if (ret < 0) {
        fprintf(stderr,
                "unexpected failure of crosvm_get_supported_cpuids: %d\n", ret);
        return 1;
    }

    if (n_entries <= 1) {
        fprintf(stderr,
                "unexpected number of supported cpuid entries: %d\n",
                n_entries);
        return 1;
    }

    ret = crosvm_get_emulated_cpuid(crosvm, 1, cpuids, &n_entries);
    if (ret >= 0) {
        fprintf(stderr,
                "expected crosvm_get_emulated_cpuids to fail with E2BIG\n");
        return 1;
    }

    ret = crosvm_get_emulated_cpuid(crosvm, 100, cpuids, &n_entries);
    if (ret < 0) {
        fprintf(stderr,
                "unexpected failure of crosvm_get_emulated_cpuid: %d\n", ret);
        return 1;
    }

    if (n_entries < 1) {
        fprintf(stderr,
                "unexpected number of emulated cpuid entries: %d\n", n_entries);
        return 1;
    }

    return 0;
}
