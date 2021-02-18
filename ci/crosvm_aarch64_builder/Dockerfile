# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Docker container that cross-compiles crosvm for aarch64.

# Build-argument of the image tag of dependencies to use. Set to the same
# version as `ci/image_tag`
ARG TAG

# Stage containing VM data to be used later.
# (COPY --from does not allow the use of ARGs)
FROM gcr.io/crosvm-packages/crosvm_test_vm_arm64:${TAG} as vm

# Main stage
FROM gcr.io/crosvm-packages/crosvm_base:${TAG}

# Add repositories for arm64 packages
RUN dpkg --add-architecture arm64

# Install cross-compilation and VM tooling
RUN apt-get update && apt-get install --yes --no-install-recommends  \
    dpkg-dev \
    g++-aarch64-linux-gnu \
    gcc-aarch64-linux-gnu \
    ipxe-qemu \
    qemu-efi-aarch64 \
    qemu-system-aarch64 \
    qemu-user-static

RUN apt-get install --yes --no-install-recommends -o APT::Immediate-Configure=false \
    libcap-dev:arm64 \
    libdbus-1-dev:arm64 \
    libdrm-dev:arm64 \
    libepoxy-dev:arm64 \
    libssl-dev:arm64 \
    libwayland-dev:arm64

RUN apt-get install --yes -t testing --no-install-recommends  \
    libdrm-dev:arm64 \
    libepoxy-dev:arm64

# Setup rust for cross-compilation
RUN rustup target add aarch64-unknown-linux-gnu
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    CARGO_BUILD_TARGET=aarch64-unknown-linux-gnu \
    PKG_CONFIG=aarch64-linux-gnu-pkg-config \
    PKG_CONFIG_PATH=/workspace/scratch/lib/pkgconfig

# Allow GCC/Rust to find packages and libraries stored on the scratch volume. We
# have to link to a known search path since LIBRARY_PATH is not used by
# cross-compile GCC.
RUN ln -s /workspace/scratch/lib/ /usr/local/lib/aarch64-linux-gnu

# Hack: For some reason the libgcc-10-dev-arm64-cross package does not install
# this link correctly.
RUN cd /usr/aarch64-linux-gnu/lib && ln -s libgcc_s.so.1 libgcc_s.so

# Allow qemu-aarch64-static to find aarch64 libraries
ENV QEMU_LD_PREFIX=/usr/aarch64-linux-gnu

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
