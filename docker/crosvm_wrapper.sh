#!/bin/bash
# Copyright 2019 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -ex
cd "${0%/*}"

exec docker run -it --rm \
    --privileged \
    -e DISPLAY=$DISPLAY -e XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR \
    -v /dev/log:/dev/log \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    --volume "$PWD":/wd \
    --workdir /wd \
    crosvm \
    "$@"
