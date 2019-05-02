#!/bin/bash
# Copyright 2019 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -ex
cd "${0%/*}"

gen_build_args() {
    for arg in $(cat ./checkout_commits.env); do
        echo --build-arg "${arg}"
    done
}

docker build $(gen_build_args) -t crosvm-base .
