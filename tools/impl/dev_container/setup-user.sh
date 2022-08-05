#!/usr/bin/env bash
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

if [[ $OUTSIDE_GID != $(sudo -u crosvmdev id -g) ]]; then
    groupmod -g "$OUTSIDE_GID" crosvmdev
    chgrp -R crosvmdev /home/crosvmdev
fi
if [[ $OUTSIDE_UID != $(sudo -u crosvmdev id -u) ]]; then
    usermod -u "$OUTSIDE_UID" crosvmdev
fi

# Transitional section to fix CI's cache permission
chmod -R 777 /cache
if [[ -d /workspace/infra/.recipe_deps ]]; then
    chmod -R 777 /workspace/infra/.recipe_deps
fi
