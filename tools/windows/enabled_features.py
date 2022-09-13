# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Following lists allow vendors to set/override default features during
# presubmit/continuous builds.

ENABLED_FEATURES = []
BUILD_ONLY_FEATURES = []

BUILD_FEATURES = ENABLED_FEATURES + BUILD_ONLY_FEATURES
