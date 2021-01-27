#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

source "$(dirname $0)/common.sh"

./ci/builder --vm ./run_tests --require-all && \
    ./ci/builder "bin/clippy" && \
    ./ci/builder "bin/fmt --check"
