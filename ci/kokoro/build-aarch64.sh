#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

source "$(dirname $0)/common.sh"

cd "${KOKORO_ARTIFACTS_DIR}/cros/src/platform/crosvm"
./ci/aarch64_builder --vm ./run_tests --require-all
