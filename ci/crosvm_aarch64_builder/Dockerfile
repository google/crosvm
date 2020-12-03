# Copyright 2021 The Chromium OS Authors. All rights reserved. Use of this
# source code is governed by a BSD-style license that can be found in the
# LICENSE file..
#
# Docker container that cross-compiles crosvm for aarch64.

FROM gcr.io/crosvm-packages/crosvm_base

# Add repositories for arm64 packages
RUN dpkg --add-architecture arm64

# Install cross-compilation and VM tooling
RUN apt-get update && apt-get install --yes --no-install-recommends  \
    dpkg-dev \
    g++-aarch64-linux-gnu \
    gcc-aarch64-linux-gnu \
    ipxe-qemu \
    openssh-client \
    qemu-system-aarch64 \
    qemu-user-static \
    rsync \
    screen

RUN apt-get install --yes --no-install-recommends -o APT::Immediate-Configure=false \
    libcap-dev:arm64 \
    libdrm-dev:arm64 \
    libepoxy-dev:arm64 \
    libfdt-dev:arm64 \
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
    PKG_CONFIG=aarch64-linux-gnu-pkg-config

# Allow GCC/Rust to find packages and libraries stored on the scratch volume. We
# have to link to a known search path since LIBRARY_PATH is not used by
# cross-compile GCC.
RUN ln -s /workspace/scratch/lib/ /usr/local/lib/aarch64-linux-gnu

# Hack: For some reason the libgcc-10-dev-arm64-cross package does not install
# this link correctly.
RUN cd /usr/aarch64-linux-gnu/lib && ln -s libgcc_s.so.1 libgcc_s.so

# Allow qemu-aarch64-static to find aarch64 libraries
ENV QEMU_LD_PREFIX=/usr/aarch64-linux-gnu

# Setup entrypoint and interactive shell
WORKDIR /workspace/src/platform/crosvm
COPY entrypoint /workspace
COPY bashrc /root/.bashrc
ENTRYPOINT ["/workspace/entrypoint"]
CMD ["bash"]
