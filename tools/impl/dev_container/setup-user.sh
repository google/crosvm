#!/usr/bin/env bash
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

if [[ $OUTSIDE_GID != $(id -g crosvmdev) || $OUTSIDE_UID != $(id -u crosvmdev) ]]; then
    groupmod -g "$OUTSIDE_GID" crosvmdev
    usermod -u "$OUTSIDE_UID" crosvmdev
    chown -R crosvmdev:crosvmdev /scratch
fi

# Transitional section to fix CI's cache permission
chmod -R 777 /cache
if [[ -d /workspace/infra/.recipe_deps ]]; then
    chmod -R 777 /workspace/infra/.recipe_deps
fi
