#!/bin/bash
# Copyright 2018 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -ex

main() {
  cd "$(dirname "$0")"

  local kokoro_simulator_root=/tmp/kokoro_simulator
  local src_root="${kokoro_simulator_root}"/git/crosvm
  local base_image_tarball="${kokoro_simulator_root}"/crosvm-base.tar.xz
  local base_image="crosvm-base"

  mkdir -p "${kokoro_simulator_root}"
  if [[ ! -e "${base_image_tarball}" ]]; then
    if [[ "$(docker images -q ${base_image} 2> /dev/null)" == "" ]]; then
      ../docker/build_crosvm_base.sh
    fi
    docker save ${base_image} | xz -T 0 -z >"${base_image_tarball}"
  fi

  if [[ ! -e "${src_root}" ]]; then
    mkdir -p "${kokoro_simulator_root}"/git
    ln -s "$(realpath ../)" "${src_root}"
  fi

  export KOKORO_ARTIFACTS_DIR="${kokoro_simulator_root}"
  export KOKORO_GFILE_DIR="${kokoro_simulator_root}"

  ./build.sh
}

main "$@"
