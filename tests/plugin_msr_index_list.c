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

    uint32_t msr_indices[256];
    int n_entries;
    ret = crosvm_get_msr_index_list(crosvm, 1, msr_indices, &n_entries);
    if (ret >= 0) {
        fprintf(stderr,
                "expected crosvm_get_msr_index_list to fail with E2BIG\n");
        return 1;
    }


    memset(msr_indices, 0, sizeof(msr_indices));
    ret = crosvm_get_msr_index_list(crosvm, 256, msr_indices, &n_entries);
    if (ret < 0) {
        fprintf(stderr,
                "unexpected failure of crosvm_get_msr_index_list: %d\n", ret);
        return 1;
    }

    if (n_entries <= 1) {
        fprintf(stderr,
                "unexpected number of supported msr entries: %d\n",
                n_entries);
        return 1;
    }

    return 0;
}
