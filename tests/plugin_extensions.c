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

int main(int argc, char** argv) {
    struct crosvm *crosvm;
    int ret = crosvm_connect(&crosvm);
    if (ret) {
        fprintf(stderr, "failed to connect to crosvm: %d\n", ret);
        return 1;
    }

    bool supported;
    ret = crosvm_check_extension(crosvm, KVM_CAP_IRQCHIP, &supported);
    if (ret) {
        fprintf(stderr, "failed to check for KVM extension: %d\n", ret);
        return 1;
    }
    if (!supported) {
        fprintf(stderr, "expected KVM extension to be supported\n");
        return 1;
    }

    // Assume s390 extensions aren't supported because we shouldn't be running on one.
    ret = crosvm_check_extension(crosvm, KVM_CAP_S390_PSW, &supported);
    if (ret) {
        fprintf(stderr, "failed to check for KVM extension: %d\n", ret);
        return 1;
    }
    if (supported) {
        fprintf(stderr, "unexpected KVM extension is supported\n");
        return 1;
    }

    return 0;
}
