# syntax=docker/dockerfile:1.11.1
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Development container for crosvm.
#
# Provides all dependencies specified in tools/deps/* with some additonal
# logic to cache cargo data in CI runs.
#
# Uses the crosvm_dev_base image built by Dockerfile.base
#
# See Makefile for build instructions

# Global arg must be before any build stages
ARG BASE_VERSION

# Build catapult dashboard upload tool in a builder container
FROM docker.io/golang:bullseye AS gobuilder
WORKDIR /root/
RUN git clone https://fuchsia.googlesource.com/infra/infra
WORKDIR /root/infra/cmd/catapult
RUN go build

FROM gcr.io/crosvm-infra/crosvm_dev_base:${BASE_VERSION}

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/workspace/tools:/usr/local/cargo/bin:$PATH

# Install pipx applications globally in /usr/local/bin
ENV PIPX_HOME=/usr/local/pipx \
    PIPX_BIN_DIR=/usr/local/bin

# Use a dedicated target directory so we do not write into the source directory.
RUN mkdir -p /scratch/cargo_target \
    && mkdir /cache

# Prevent the container from writing __pycache__ files into the src.
ENV PYTHONDONTWRITEBYTECODE=1
ENV CARGO_TARGET_DIR=/scratch/cargo_target

# Allow APT to cache packages between docker image builds
RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Add wine64 to PATH, as debian removed alternative entry to wine64
ENV PATH=/usr/lib/wine:$PATH

# Install non-debian dependencies. Debian packages are installed in the base image in Dockefile.base
COPY --chmod=555 \
    tools/deps/install-x86_64-other \
    tools/deps/install-aarch64-other \
    tools/deps/install-armhf-other \
    tools/deps/install-mingw64-other \
    tools/deps/install-riscv64-other \
    rust-toolchain \
    /tools/deps/
RUN cd /tools/deps \
    && ./install-x86_64-other \
    && ./install-aarch64-other \
    && ./install-armhf-other \
    && ./install-mingw64-other \
    && ./install-riscv64-other \
    # We only use the nightly toolchain for rustfmt, remove other parts to save space.
    && rustup component remove --toolchain nightly rust-std \
    && rustup component remove --toolchain nightly cargo

# Install global config.toml for cross-compilation
COPY --chmod=555 .cargo/config.debian.toml /.cargo/config.toml

# Install catapult dashboard upload tool
COPY --from=gobuilder /root/infra/cmd/catapult/catapult /tools/

# Cache CARGO_HOME between container runs in CI.
VOLUME /cache
ENV CROSVM_CACHE_DIR=/cache
ENV CARGO_HOME=/cache/cargo_home

VOLUME /workspace
WORKDIR /workspace
