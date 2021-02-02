# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Base image for crosvm_builder and crosvm_aarch64_builder containing basic
# devleopment environment for building rust.

# TODO(b/177078591): Use debian buster and backports (or manual dpkg downloads)
# of outdated libraries. Sid could blow up on us any day.
FROM debian:buster

# Set timezone so apt-get won't try to prompt
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=US/Pacific

# Add bullseye to sources so we can install some newer versions of packages.
RUN echo 'deb http://deb.debian.org/debian bullseye main' >/etc/apt/sources.list.d/testing.list
RUN echo 'APT::Default-Release "stable";' >/etc/apt/apt.conf.d/99_default_stable

RUN apt-get update && apt-get install --yes --no-install-recommends \
    ca-certificates \
    curl \
    g++ \
    gcc \
    git \
    jq \
    make \
    meson/testing \
    nasm \
    ninja-build \
    openssh-client \
    pkg-config \
    protobuf-compiler \
    python3 \
    python3-setuptools \
    rsync \
    screen \
    sudo

# This is a scratch volume for build files. It can be used to allow incremental
# builds between container runs.
# Note: This volume is optional if incremental builds are not required.
VOLUME /workspace/scratch

# This is where the chromiumos source tree will be mounted
VOLUME /workspace/src

# This is a volume to store additional logs for kokoro builds that are uploaded
# to sponge.
VOLUME /workspace/logs

# Install the current crosvm rust toolchain via rustup.
COPY rust-toolchain ./
RUN curl https://sh.rustup.rs -sSf | sh -s -- \
    -y \
    --profile minimal \
    -c rustfmt,clippy \
    --default-toolchain $(cat rust-toolchain)
ENV PATH="/root/.cargo/bin:${PATH}"

# Point cargo to store data on the scratch volume.
ENV CARGO_TARGET_DIR=/workspace/scratch/cargo_target
ENV CARGO_HOME=/workspace/scratch/cargo_home

# Warms up the cargo registry cache for future cargo runs. Cargo will still
# update the cache using a git pull, but it only needs to download files that
# were changed since this image was built.
RUN cargo install thisiznotarealpackage -q || true

# We are building out of source with a readonly source filesystem. This flag
# tells some build.rs files to not write into the src filesystem.
ENV RUSTFLAGS='--cfg hermetic'

# Environment variables for the run_tests script to enable all tests.
ENV CROSVM_CROS_BUILD=1

# All commands will be executed in the crosvm src directory.
WORKDIR /workspace/src/platform/crosvm
