# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
ARG RUST_VERSION
FROM docker.io/rust:${RUST_VERSION}-slim-bullseye

# Use a dedicated target directory so we do not write into the source directory.
RUN mkdir -p /scratch/cargo_target
ENV CARGO_TARGET_DIR=/scratch/cargo_target

# Prevent the container from writing root-owned __pycache__ files into the src.
ENV PYTHONDONTWRITEBYTECODE=1

# Add foreign architectures for cross-compilation.
RUN dpkg --add-architecture arm64 \
    && dpkg --add-architecture armhf

# Install dependencies for native builds.
COPY tools/install-deps /tools/
RUN apt-get update \
    && apt-get install --yes sudo \
    && /tools/install-deps \
    # Clear apt cache to save space in layer.
    && rm -rf /var/lib/apt/lists/* \
    # Delete build artifacts from 'cargo install' to save space in layer.
    && rm -rf /scratch/cargo_target/*

# Prepare wine64
RUN ln -sf /usr/bin/wine64-stable /usr/bin/wine64 \
    && wine64 wineboot

# Install cross-compilation dependencies.
COPY tools/install-aarch64-deps tools/install-armhf-deps /tools/

RUN apt-get update \
    && /tools/install-aarch64-deps \
    && /tools/install-armhf-deps \
    # Clear apt cache to save space in layer.
    && rm -rf /var/lib/apt/lists/*

# Prebuild aarch64 VM image for faster startup.
COPY tools/aarch64vm /tools/
COPY /tools/impl/testvm.py /tools/impl/
COPY /tools/impl/testvm/version /tools/impl/testvm/
RUN /tools/aarch64vm build

VOLUME /workspace
WORKDIR /workspace
