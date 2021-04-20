#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

crosvm_root="${KOKORO_ARTIFACTS_DIR}"/git/crosvm

# Enable SSH access to the kokoro builder.
# Use the fusion2/ UI to trigger a build and set the DEBUG_SSH_KEY environment
# variable to your public key, that will allow you to connect to the builder
# via SSH.
# Note: Access is restricted to the google corporate network.
# Details: https://yaqs.corp.google.com/eng/q/6628551334035456
if [[ ! -z "${DEBUG_SSH_KEY}" ]]; then
  echo "${DEBUG_SSH_KEY}" >>~/.ssh/authorized_keys
  external_ip=$(
    curl -s -H "Metadata-Flavor: Google"
    http://metadata/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip
  )
  echo "SSH Debug enabled. Connect to: kbuilder@${external_ip}"
fi

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
  ./repo sync -j8 -c || return 1

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
  # Sleep after the build to allow for SSH debugging to continue.
  if [[ ! -z "${DEBUG_SSH_KEY}" ]]; then
    echo "Build done. Blocking for SSH debugging."
    sleep 1h
  fi

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
