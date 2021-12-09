#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

source "$(dirname $0)/common.sh"

./tools/dev_container --hermetic ./tools/run_tests --target=vm:aarch64 --arch armhf -v
