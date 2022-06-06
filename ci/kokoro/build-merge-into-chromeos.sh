#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
set -e

# Python script to check for at least version 3.9
VERSION_CHECK="
import sys
sys.exit(sys.version_info.major != 3 or sys.version_info.minor < 9)
"

main() {
    cd "${KOKORO_ARTIFACTS_DIR}/git/crosvm"

    # Ensure we have at least python 3.9. Kokoro does not and requires us to use pyenv to install
    # The required version.
    if ! python3 -c "$VERSION_CHECK"; then
        pyenv install --verbose --skip-existing 3.9.5
        pyenv global 3.9.5
    fi

    # Extra packages required by merge_bot
    if ! pip show argh; then
        pip install argh
    fi

    # Run git cookie auth daemon to pull git http cookies for this GCE instance.
    # Don't do this if a cookie already exists, which allow us to test this script locally.
    if ! git config http.cookiefile; then
        local gcompute_path="${KOKORO_ARTIFACTS_DIR}/gcompute-tools"
        git clone "https://gerrit.googlesource.com/gcompute-tools" "$gcompute_path"
        ${gcompute_path}/git-cookie-authdaemon
    fi

    # Overwrite kokoro default with service account we are actually using to submit code.
    git config user.name "Crosvm Bot"
    git config user.email "crosvm-bot@crosvm-packages.iam.gserviceaccount.com"

    local target_rev=$(git rev-parse HEAD)
    ./tools/chromeos/merge_bot -v update-merges --is-bot "$target_rev"
    ./tools/chromeos/merge_bot -v update-dry-runs --is-bot "$target_rev"
}

main
