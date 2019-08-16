#!/bin/bash
# Copyright 2019 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -ex
cd "${0%/*}"

if command -v nvidia-smi >/dev/null 2>&1; then
    export NVIDIA_VERSION="$(nvidia-smi -q | grep "Driver Version" | cut -d':' -f 2 | xargs)"
fi

src_root="$(realpath ..)"

docker build -t crosvm \
    -f Dockerfile.crosvm \
    --build-arg UID \
    --build-arg GID \
    --build-arg NVIDIA_VERSION \
    "$@" \
    "${src_root}"
