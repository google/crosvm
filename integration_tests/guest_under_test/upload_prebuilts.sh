#!/bin/bash
# Copyright 2020 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Builds and uploads prebuilts to cloud storage.
#
# Note: Only Googlers with access to the crosvm-testing cloud storage bin can
#       upload prebuilts.
#
# See README.md for how to uprev the prebuilt version.

set -e
cd "${0%/*}"

readonly PREBUILT_VERSION="$(cat ./PREBUILT_VERSION)"

# Cloud storage files
readonly GS_BUCKET="gs://chromeos-localmirror/distfiles"
readonly GS_PREFIX="${GS_BUCKET}/crosvm-testing"
readonly REMOTE_BZIMAGE="${GS_PREFIX}-bzimage-$(arch)-${PREBUILT_VERSION}"
readonly REMOTE_ROOTFS="${GS_PREFIX}-rootfs-$(arch)-${PREBUILT_VERSION}"

# Local files
CARGO_TARGET=$(cargo metadata --no-deps --format-version 1 |
    jq -r ".target_directory")
LOCAL_BZIMAGE=${CARGO_TARGET}/guest_under_test/bzImage
LOCAL_ROOTFS=${CARGO_TARGET}/guest_under_test/rootfs

function prebuilts_exist_error() {
    echo "Prebuilts of version ${PREBUILT_VERSION} already exist. See README.md"
    exit 1
}

echo "Checking if prebuilts already exist."
gsutil stat "${REMOTE_BZIMAGE}" && prebuilts_exist_error
gsutil stat "${REMOTE_ROOTFS}" && prebuilts_exist_error

echo "Building rootfs and kernel."
make "${LOCAL_BZIMAGE}" "${LOCAL_ROOTFS}"

echo "Uploading files."
gsutil cp -n -a public-read "${LOCAL_BZIMAGE}" "${REMOTE_BZIMAGE}"
gsutil cp -n -a public-read "${LOCAL_ROOTFS}" "${REMOTE_ROOTFS}"
