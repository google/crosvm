#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

source "$(dirname $0)/common.sh"

./ci/run_container.sh crosvm_aarch64_builder --vm "\
    ./run_tests -v --require-all \
        --junit-file=/workspace/logs/cargo_test/sponge_log.xml"
