#!/bin/bash
# Copyright 2018 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -ex

main() {
  if [ -z "${KOKORO_ARTIFACTS_DIR}" ]; then
    echo "This script must be run in kokoro"
    exit 1
  fi

  local src_root="${KOKORO_ARTIFACTS_DIR}"/git/crosvm
  local base_image_tarball="${KOKORO_GFILE_DIR}"/crosvm-base.tar.xz
  local base_image="crosvm-base"

  if [[ "$(docker images -q ${base_image} 2> /dev/null)" == "" ]]; then
    docker load -i "${base_image_tarball}"
  fi
  "${src_root}"/docker/wrapped_smoke_test.sh

  return 0
}

main "$@"
