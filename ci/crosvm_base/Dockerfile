# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Base image for crosvm_builder and crosvm_aarch64_builder containing basic
# devleopment environment for building rust.

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
    clang \
    libclang-dev \
    g++ \
    gcc \
    git \
    jq \
    libasound2-dev \
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
RUN curl https://static.rust-lang.org/rustup/archive/1.24.3/x86_64-unknown-linux-gnu/rustup-init -sSf -o rustup-init \
    && echo "3dc5ef50861ee18657f9db2eeb7392f9c2a6c95c90ab41e45ab4ca71476b4338 rustup-init" | sha256sum --check \
    && chmod +x rustup-init \
    && ./rustup-init -y \
    --profile minimal \
    -c rustfmt,clippy \
    --default-toolchain $(cat rust-toolchain)
ENV PATH="/root/.cargo/bin:${PATH}"

# The bindgen tool is required to build a crosvm dependency.
RUN cargo install bindgen

# The mdbook and mdbook-mermaid tools are used to build the crosvm book.
RUN cargo install mdbook --no-default-features --version "^0.4.10"
RUN cargo install mdbook-mermaid --version "^0.8.3"

# Point cargo to store data on the scratch volume.
ENV CARGO_TARGET_DIR=/workspace/scratch/cargo_target
ENV CARGO_HOME=/workspace/scratch/cargo_home

# We are building out of source with a readonly source filesystem. This flag
# tells some build.rs files to not write into the src filesystem.
ENV RUSTFLAGS='--cfg hermetic'

# Environment variables for the run_tests script to enable all tests.
ENV CROSVM_CROS_BUILD=1

# All commands will be executed in the crosvm src directory.
WORKDIR /workspace/src/crosvm
