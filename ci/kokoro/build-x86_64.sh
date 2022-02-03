#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
source "$(dirname $0)/common.sh"

./tools/dev_container --hermetic bash -c "\
    ./tools/run_tests --target=host -v \
    && ./tools/clippy \
    && ./tools/fmt --check \
    && cargo build --verbose --no-default-features \
    && mdbook build ./docs/book \
    && ./tools/cargo-doc"
