#!/usr/bin/env bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file
#
# To build crosvm using cargo against libraries and crates provided by ChromeOS
# use this script to update path references in Cargo.toml.
#
# TODO(b/194323235): Add documentation for ChromeOS developer workflows.

sed -i 's|path = "libcras_stub"|path = "../../third_party/adhd/cras/client/libcras"|g' \
    Cargo.toml

echo "Modified Cargo.toml with new paths. Please do not commit those."
