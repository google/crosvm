#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

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
  if [ -z "${KOKORO_ARTIFACTS_DIR}/git" ]; then
    echo "This script must be run in kokoro"
    exit 1
  fi

  cd "${KOKORO_ARTIFACTS_DIR}/git/crosvm"
  git submodule update --init
}

cleanup() {
  # Sleep after the build to allow for SSH debugging to continue.
  if [[ ! -z "${DEBUG_SSH_KEY}" ]]; then
    echo "Build done. Blocking for SSH debugging."
    sleep 1h
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
cd "${KOKORO_ARTIFACTS_DIR}/git/crosvm"
