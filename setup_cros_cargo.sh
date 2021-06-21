#!/usr/bin/env bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# To build crosvm using cargo against libraries and crates provided by ChromeOS
# use this script to update path references in Cargo.toml.
#
# TODO(b/194323235): Add documentation for ChromeOS developer workflows.

declare -A replacements=(
    ["libcras_stub"]="../../third_party/adhd/cras/client/libcras"
    ["system_api_stub"]="../../platform2/system_api"
    ["third_party/minijail"]="../../aosp/external/minijail"
    ["third_party/vmm_vhost"]="../../third_party/rust-vmm/vhost"
)

for crate in "${!replacements[@]}"; do
    echo "Replacing '${crate}' with '${replacements[$crate]}'"
    sed -i "s|path = \"${crate}|path = \"${replacements[$crate]}|g" \
        Cargo.toml
done

echo "Modified Cargo.toml with new paths. Please do not commit those."
