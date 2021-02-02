#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

crosvm_root="${KOKORO_ARTIFACTS_DIR}"/git/crosvm

setup_source() {
  if [ -z "${KOKORO_ARTIFACTS_DIR}" ]; then
    echo "This script must be run in kokoro"
    exit 1
  fi

  cd "${KOKORO_ARTIFACTS_DIR}"

  echo ""
  echo "Downloading crosvm dependencies to $(pwd)/cros..."
  mkdir cros
  cd cros

  # repo gets confused by pyenv, make sure we select 3.6.1 as our default
  # version.
  if command -v pyenv >/dev/null; then
    echo "Selecting Python 3.6.1"
    pyenv global 3.6.1
  fi
  curl -s https://storage.googleapis.com/git-repo-downloads/repo >repo
  chmod +x repo
  ./repo init --depth 1 \
    -u https://chromium.googlesource.com/chromiumos/manifest.git \
    --repo-url https://chromium.googlesource.com/external/repo.git \
    -g crosvm || return 1
  ./repo sync -j8 -c -m "${crosvm_root}/ci/kokoro/manifest.xml" || return 1

  # Bind mount source into cros checkout.
  echo ""
  echo "Mounting crosvm source to $(pwd)/src/platform/crosvm..."
  rm -rf src/platform/crosvm && mkdir -p src/platform/crosvm
  if command -v bindfs >/dev/null; then
    bindfs "${crosvm_root}" src/platform/crosvm || return 1
  else
    sudo mount --bind "${crosvm_root}" src/platform/crosvm || return 1
  fi

}

cleanup() {
  if command -v bindfs >/dev/null; then
    fusermount -uz "${KOKORO_ARTIFACTS_DIR}/cros/src/platform/crosvm"
  else
    sudo umount --lazy "${KOKORO_ARTIFACTS_DIR}/cros/src/platform/crosvm"
  fi

  # List files in the logs directory which are uploaded to sponge.
  echo "Build Artifacts:"
  ls "${KOKORO_ARTIFACTS_DIR}/logs"
}

# Setup source when the script is loaded. Clean up on exit.
trap cleanup EXIT
setup_source || {
  echo "Failed to setup_source"
  exit 1
}

# Set logs directory so we can copy them to sponge
export CROSVM_BUILDER_LOGS_DIR="${KOKORO_ARTIFACTS_DIR}/logs"
cd "${KOKORO_ARTIFACTS_DIR}/cros/src/platform/crosvm"
