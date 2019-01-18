/*
 * Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

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

    struct kvm_pic_state pic_state;
    ret = crosvm_get_pic_state(crosvm, false, &pic_state);
    if (ret < 0) {
        fprintf(stderr, "failed to get initial PIC1 state: %d\n", ret);
        return 1;
    }

    if (pic_state.auto_eoi) {
        fprintf(stderr, "unexpected value of auto_eoi flag\n");
        return 1;
    }

    pic_state.auto_eoi = true;
    ret = crosvm_set_pic_state(crosvm, false, &pic_state);
    if (ret < 0) {
        fprintf(stderr, "failed to update PIC1 state: %d\n", ret);
        return 1;
    }

    ret = crosvm_get_pic_state(crosvm, false, &pic_state);
    if (ret < 0) {
        fprintf(stderr, "failed to get updated PIC1 state: %d\n", ret);
        return 1;
    }

    if (!pic_state.auto_eoi) {
        fprintf(stderr, "unexpected value of auto_eoi flag after update\n");
        return 1;
    }

    // Test retrieving and setting IOAPIC state.
    struct kvm_ioapic_state ioapic_state;
    ret = crosvm_get_ioapic_state(crosvm, &ioapic_state);
    if (ret < 0) {
        fprintf(stderr, "failed to get initial PIC1 state: %d\n", ret);
        return 1;
    }

    fprintf(stderr, "IOAPIC ID: %d\n", ioapic_state.id);

    if (ioapic_state.id != 0) {
        fprintf(stderr, "unexpected value of IOAPIC ID: %d\n", ioapic_state.id);
        return 1;
    }

    ioapic_state.id = 1;
    ret = crosvm_set_ioapic_state(crosvm, &ioapic_state);
    if (ret < 0) {
        fprintf(stderr, "failed to update PIC1 state: %d\n", ret);
        return 1;
    }

    ret = crosvm_get_ioapic_state(crosvm, &ioapic_state);
    if (ret < 0) {
        fprintf(stderr, "failed to get updated PIC1 state: %d\n", ret);
        return 1;
    }

    if (ioapic_state.id != 1) {
        fprintf(stderr, "unexpected value of IOAPIC ID after update: %d\n",
                ioapic_state.id);
        return 1;
    }

    // Test retrieving and setting PIT state.
    struct kvm_pit_state2 pit_state;
    ret = crosvm_get_pit_state(crosvm, &pit_state);
    if (ret < 0) {
        fprintf(stderr, "failed to get initial PIT state: %d\n", ret);
        return 1;
    }

    if (pit_state.flags & KVM_PIT_FLAGS_HPET_LEGACY) {
        fprintf(stderr, "unexpected value of KVM_PIT_FLAGS_HPET_LEGACY flag\n");
        return 1;
    }

    pit_state.flags |= KVM_PIT_FLAGS_HPET_LEGACY;
    ret = crosvm_set_pit_state(crosvm, &pit_state);
    if (ret < 0) {
        fprintf(stderr, "failed to update PIT state: %d\n", ret);
        return 1;
    }

    ret = crosvm_get_pit_state(crosvm, &pit_state);
    if (ret < 0) {
        fprintf(stderr, "failed to get updated PIT state: %d\n", ret);
        return 1;
    }

    if (!(pit_state.flags & KVM_PIT_FLAGS_HPET_LEGACY)) {
        fprintf(stderr,
                "unexpected value of KVM_PIT_FLAGS_HPET_LEGACY after update\n");
        return 1;
    }

    // Test retrieving and setting clock state.
    struct kvm_clock_data clock_data = { .clock = 0, .flags = -1U, };
    ret = crosvm_get_clock(crosvm, &clock_data);
    if (ret < 0) {
        fprintf(stderr, "failed to get initial clock state: %d\n", ret);
        return 1;
    }

    if (clock_data.clock == 0 || clock_data.flags != 0) {
        fprintf(stderr, "invalid clock data returned (%llu, %u)\n",
                clock_data.clock, clock_data.flags);
    }

    clock_data.clock += 10000000;

    ret = crosvm_set_clock(crosvm, &clock_data);
    if (ret < 0) {
        fprintf(stderr, "failed to update clock: %d\n", ret);
        return 1;
    }

    clock_data.flags = -1U;
    ret = crosvm_set_clock(crosvm, &clock_data);
    if (ret >= 0) {
        fprintf(stderr, "unexpected success updating clock\n");
        return 1;
    }

    return 0;
}
