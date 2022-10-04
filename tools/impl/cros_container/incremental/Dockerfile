# syntax=docker/dockerfile:1.3-labs
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

FROM gcr.io/crosvm-infra-experimental/crosvm_cros_cloudbuild
ARG BOARD=hatch

USER crosvmdev
WORKDIR /home/crosvmdev/chromiumos

RUN repo sync -j 16 --current-branch

RUN --security=insecure cros_sdk emerge-${BOARD} --update --deep -j$(nproc) crosvm
