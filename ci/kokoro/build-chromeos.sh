#!/bin/bash
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Note: To simulate this locally, sudo needs to be passwordless for the duration of the build (~1h).
# This could be achieved by refreshing sudo in the background before running ci/simulate.py:
#
#   while true; do sudo -n true; sleep 60; kill -0 "$$" || exit; done 2>/dev/null &
#   ./ci/kokoro/simulate.py ./ci/kokoro/build-chromeos.sh

set -ex

CROS_ROOT="${KOKORO_ARTIFACTS_DIR}/cros"
CROSVM_ROOT="${KOKORO_ARTIFACTS_DIR}/git/crosvm"
DEPOT_TOOLS="${KOKORO_ARTIFACTS_DIR}/depot_tools"

BOARD="amd64-generic"
# TODO: Add other packages tracking the crosvm repo.
PACKAGE_LIST=(
    'chromeos-base/crosvm'
)

setup_depot_tools() {
    git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git \
        "$DEPOT_TOOLS"
    export PATH="${DEPOT_TOOLS}:${PATH}"
}

setup_cros_source() {
    repo init -q -u https://chromium.googlesource.com/chromiumos/manifest \
        -b stable --depth=1 -c -g minilayout,crosvm
    time repo sync -c      # ~5min
    time cros_sdk --create # ~16min
}

setup_crosvm_source() {
    # Pull kokoro's version of crosvm into the cros monorepo
    (
        cd "${CROS_ROOT}/src/platform/crosvm" &&
            git remote add crosvm "$CROSVM_ROOT" &&
            git fetch crosvm &&
            git checkout FETCH_HEAD
    )
    # Uprev ebuild files
    local colon_separated_packages="$(printf '%s:' "${PACKAGE_LIST[@]}")"
    ./chromite/scripts/cros_uprev \
        --package="$colon_separated_packages" \
        --overlay-type=public
}

build_and_test_crosvm() {
    # TODO: We currently build crosvm twice. Once with build_packages, once to run tests.
    # ~20min
    time cros_sdk build_packages --board "$BOARD" implicit-system "${PACKAGE_LIST[@]}"
    # ~6min
    time cros_sdk cros_run_unit_tests --board "$BOARD" --packages "${PACKAGE_LIST[@]}"
}

main() {
    mkdir -p "$CROS_ROOT"
    cd "$CROS_ROOT"

    setup_depot_tools
    setup_cros_source
    setup_crosvm_source
    build_and_test_crosvm
}

main
