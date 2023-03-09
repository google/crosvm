#!/bin/bash
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Exports env variables to make the e2e_tests use a locally built
# kernel / rootfs.
#
# Note: `source` this file, do not run it if you want it to set the environmens
# variables for you.

ARCH=$(arch)
CARGO_TARGET=$(cargo metadata --no-deps --format-version 1 |
    jq -r ".target_directory")
LOCAL_BZIMAGE=${CARGO_TARGET}/guest_under_test/${ARCH}/bzImage
LOCAL_ROOTFS=${CARGO_TARGET}/guest_under_test/${ARCH}/rootfs

export CROSVM_CARGO_TEST_KERNEL_BINARY="${LOCAL_BZIMAGE}"
export CROSVM_CARGO_TEST_ROOTFS_IMAGE="${LOCAL_ROOTFS}"
