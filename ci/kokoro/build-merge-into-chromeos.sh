#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
set -e
cd "${KOKORO_ARTIFACTS_DIR}/git/crosvm"

ORIGIN=https://chromium.googlesource.com/chromiumos/platform/crosvm
RETRIES=3

gerrit_prerequisites() {
    set -e

    # Authenticate to GoB if we don't already have a cookie.
    # This should only happen when running in Kokoro, not locally.
    # See: go/gob-gce
    if [[ -z $(git config http.cookiefile) ]]; then
        git clone https://gerrit.googlesource.com/gcompute-tools \
            "${KOKORO_ARTIFACTS_DIR}/gcompute-tools"
        "${KOKORO_ARTIFACTS_DIR}/gcompute-tools/git-cookie-authdaemon" --no-fork
    fi

    git config user.name "Crosvm Bot"
    git config user.email crosvm-bot@crosvm-packages.iam.gserviceaccount.com

    # We cannot use the original origin that kokoro used, as we no longer have
    # access the GoB host via rpc://.
    git remote remove origin
    git remote add origin ${ORIGIN}
    git fetch -q origin

    # Set up gerrit Change-Id hook.
    mkdir -p .git/hooks
    curl -Lo .git/hooks/commit-msg \
        https://gerrit-review.googlesource.com/tools/hooks/commit-msg
    chmod +x .git/hooks/commit-msg
}

upload() {
    git push origin HEAD:refs/for/chromeos%r=crosvm-uprev@google.com
}

upload_with_retries() {
    # Try uploading to gerrit. Retry due to errors on first upload.
    # See: b/209031134
    for i in $(seq 1 $RETRIES); do
        echo "Push attempt $i"
        if upload; then
            return 0
        fi
    done
    return 1
}

main() {
    set -e
    gerrit_prerequisites

    # Make a copy of the merge script, so we are using the HEAD version to
    # create the merge.
    cp ./tools/chromeos/create_merge "${KOKORO_ARTIFACTS_DIR}/create_merge"

    # Clean possible stray files from previous builds.
    git clean -f -d -x
    git checkout -f

    # Perform merge on a tracking branch.
    git checkout -b chromeos origin/chromeos
    git branch --set-upstream-to origin/chromeos chromeos
    "${KOKORO_ARTIFACTS_DIR}/create_merge"

    upload_with_retries
}
main
