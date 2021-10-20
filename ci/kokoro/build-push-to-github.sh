#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

GITHUB_TOKEN_FILE=$KOKORO_KEYSTORE_DIR/76320_github_token
TOKEN=$(cat $GITHUB_TOKEN_FILE)

cd "${KOKORO_ARTIFACTS_DIR}/git/crosvm"
git push --force --all "https://crosvm-bot:${TOKEN}@github.com/google/crosvm.git"
