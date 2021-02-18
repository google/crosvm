# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Docker container to build crosvm for the host architecture.

# Build-argument of the image tag of dependencies to use. Set to the same
# version as `ci/image_tag`
ARG TAG

# Stage containing VM data to be used later.
# (COPY --from does not allow the use of ARGs)
FROM gcr.io/crosvm-packages/crosvm_test_vm_amd64:${TAG} as vm

# Main stage
FROM gcr.io/crosvm-packages/crosvm_base:${TAG}

# Install libraries needed to compile crosvm and it's dependencies.
RUN apt-get install --yes --no-install-recommends \
    libcap-dev \
    libdbus-1-dev \
    libdrm-dev \
    libepoxy-dev \
    libssl-dev \
    libwayland-dev \
    qemu-system-x86

RUN apt-get install --yes -t testing --no-install-recommends \
    libdrm-dev \
    libepoxy-dev

# Allow GCC/Rust to find packages and libraries stored on the scratch volume.
ENV LIBRARY_PATH=/workspace/scratch/lib
ENV LD_LIBRARY_PATH=/workspace/scratch/lib
ENV PKG_CONFIG_PATH=/workspace/scratch/lib/pkgconfig

# Include test VM inside this container
COPY --from=vm \
    /workspace/vm/* \
    /workspace/vm/
COPY --from=vm \
    /root/.ssh /root/.ssh

# Setup entrypoint and interactive shell
WORKDIR /workspace/src/platform/crosvm
COPY bashrc /root/.bashrc
COPY entrypoint /workspace
ENTRYPOINT ["/workspace/entrypoint"]
