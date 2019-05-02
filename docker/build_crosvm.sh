#!/bin/bash
# Copyright 2019 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -ex
cd "${0%/*}"

src_root="$(realpath ..)"

docker build -t crosvm -f Dockerfile.crosvm --build-arg UID --build-arg GID "${src_root}"
