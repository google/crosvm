#!/bin/bash
# Copyright 2019 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -ex
cd "${0%/*}"

src_root="$(realpath ..)"

docker run \
    --rm \
    --privileged \
    -e TEST_RUNNER_FLAGS='--format terse' \
    -v /dev/log:/dev/log \
    -v "${src_root}":/platform/crosvm:ro \
    crosvm-base \
    bin/smoke_test

