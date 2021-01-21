#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Runs a crosvm builder. Will use podman if available, falls back to docker.
crosvm_root=$(realpath "$(dirname $0)/..")
cros_root=$(realpath "${crosvm_root}/../../..")
target=$(
    cargo metadata --no-deps --format-version 1 | jq -r ".target_directory"
)

if [ ! -d "${cros_root}/.repo" ]; then
    echo "The CI builder must be run from a cros checkout. See ci/README.md"
    exit 1
fi

# User podman if available for root-less execution. Fall-back to docker.
if which podman >/dev/null; then
    run() {
        # The run.oci.keep_original_groups flag allows us to access devices to
        # which the calling user only has access via a group membership (i.e.
        # /dev/kvm). See: https://github.com/containers/podman/issues/4477
        podman run \
            --runtime /usr/bin/crun \
            --annotation run.oci.keep_original_groups=1 \
            "$@"
    }
else
    run() {
        docker run "$@"
    }
fi

version=$(cat $(dirname $0)/image_tag)
src="${cros_root}/src"
scratch="${target}/ci/$1"
mkdir -p "${scratch}"

echo "Using builder version: ${version}"
echo "Using source directory: ${src}"
echo "Using scratch directory: ${scratch}"
echo ""

run --rm -it \
    --device /dev/kvm \
    --volume /dev/log:/dev/log \
    --volume "${src}":/workspace/src:rw \
    --volume "${scratch}":/workspace/scratch:rw \
    "gcr.io/crosvm-packages/$1:${version}" \
    "${@:2}"
