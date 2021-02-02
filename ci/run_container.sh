#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Runs a crosvm builder. Will use podman if available, falls back to docker.
# Usage:
# run_container.sh builder_name entry point args...
#
# The scratch or logs directory can be enabled by setting the env variables
# CROSVM_BUILDER_SCRATCH_DIR or CROSVM_BUILDER_LOGS_DIR.

crosvm_root=$(realpath "$(dirname $0)/..")
cros_root=$(realpath "${crosvm_root}/../../..")

if [ ! -d "${cros_root}/.repo" ]; then
    echo "The CI builder must be run from a cros checkout. See ci/README.md"
    exit 1
fi

# Parse parameters
builder="$1"
shift

# User podman if available for root-less execution. Fall-back to docker.
if which podman >/dev/null; then
    run() {
        # The run.oci.keep_original_groups flag allows us to access devices to
        # which the calling user only has access via a group membership (i.e.
        # /dev/kvm). See: https://github.com/containers/podman/issues/4477
        podman run \
            --runtime /usr/bin/crun \
            --annotation run.oci.keep_original_groups=1 \
            --security-opt label=disable \
            "$@"
    }
else
    run() {
        docker run "$@"
    }
fi

version=$(cat $(dirname $0)/image_tag)
echo "Using builder: ${builder}:${version}"

src="${cros_root}/src"
echo "Using source directory: ${src} (Available at /workspace/src)"

docker_args=(
    --rm
    --device /dev/kvm
    --volume /dev/log:/dev/log
    --volume "${src}":/workspace/src:rw
)

if [ ! -z "${CROSVM_BUILDER_SCRATCH_DIR}" ]; then
    echo "Using scratch directory: ${CROSVM_BUILDER_SCRATCH_DIR}\
 (Available at /workspace/scratch)"
    mkdir -p "${CROSVM_BUILDER_SCRATCH_DIR}"
    docker_args+=(
        --volume "${CROSVM_BUILDER_SCRATCH_DIR}:/workspace/scratch:rw"
    )
fi

if [ ! -z "${CROSVM_BUILDER_LOGS_DIR}" ]; then
    echo "Using logs directory: ${CROSVM_BUILDER_LOGS_DIR}\
 (Available at /workspace/logs)"
    mkdir -p "${CROSVM_BUILDER_LOGS_DIR}"
    docker_args+=(--volume "${CROSVM_BUILDER_LOGS_DIR}":/workspace/logs:rw)
fi

# Enable interactive mode when running in an interactive terminal.
if [ -t 1 ]; then
    docker_args+=(-it)
fi

echo ""
run ${docker_args[@]} \
    "gcr.io/crosvm-packages/${builder}:${version}" \
    "$@"
