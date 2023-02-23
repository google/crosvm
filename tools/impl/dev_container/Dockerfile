# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Development container for crosvm.
#
# Provides all dependencies specified in install-deps with some additonal
# logic to cache cargo data in CI runs.
#
# Note, if you are using docker, you will probably be using "Dockerfile.user".

# Build catapult dashboard upload tool in a builder container
FROM docker.io/golang:bullseye AS gobuilder
WORKDIR /root/
RUN git clone https://fuchsia.googlesource.com/infra/infra
WORKDIR /root/infra/cmd/catapult
RUN go build

FROM docker.io/debian:testing-slim

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# Install pipx applications globally in /usr/local/bin
ENV PIPX_HOME=/usr/local/pipx \
    PIPX_BIN_DIR=/usr/local/bin

# Use a dedicated target directory so we do not write into the source directory.
RUN mkdir -p /scratch/cargo_target \
    && mkdir /cache

# Prevent the container from writing __pycache__ files into the src.
ENV PYTHONDONTWRITEBYTECODE=1
ENV CARGO_TARGET_DIR=/scratch/cargo_target

# Add foreign architectures for cross-compilation.
RUN dpkg --add-architecture arm64 \
    && dpkg --add-architecture armhf

# Allow APT to cache packages between docker image builds
RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Install dependencies (APT and cargo packages are cached between image builds for faster iterative builds).
COPY --chmod=555 tools/install-deps tools/install-aarch64-deps tools/install-armhf-deps tools/install-mingw64-deps tools/setup-wine64 rust-toolchain /tools/
RUN --mount=type=cache,target=/var/cache/apt,sharing=private \
    --mount=type=cache,target=/var/lib/apt,sharing=private \
    --mount=type=cache,target=/scratch/cargo_target,sharing=private \
    cd /tools \
    && apt-get update \
    && apt-get install --yes sudo \
    && ./install-deps \
    && ./install-aarch64-deps \
    && ./install-armhf-deps \
    && ./install-mingw64-deps

# Install an older version of binutils-mingw-w64-x86-64. The latest version is crashing when
# linking crosvm. See b/265995780
RUN wget https://snapshot.debian.org/archive/debian/20230101T091029Z/pool/main/b/binutils-mingw-w64/binutils-mingw-w64-x86-64_2.38.90.20220713-2%2B9%2Bb1_amd64.deb \
    && dpkg -i binutils-mingw-w64-x86-64_2.38.90.20220713-2+9+b1_amd64.deb \
    && rm binutils-mingw-w64-x86-64_2.38.90.20220713-2+9+b1_amd64.deb

# Setup wine for root user
RUN /tools/setup-wine64

# Install global config.toml for cross-compilation
COPY --chmod=555 .cargo/config.debian.toml /.cargo/config.toml

# Install catapult dashboard upload tool
COPY --from=gobuilder /root/infra/cmd/catapult/catapult /tools/

# Prebuild aarch64 VM image for faster startup.
COPY tools/aarch64vm /tools/
COPY /tools/impl/testvm.py /tools/impl/
COPY /tools/impl/testvm/version /tools/impl/testvm/
RUN sudo chmod 755 -R /tools \
    && /tools/aarch64vm build

# Cache CARGO_HOME between container runs in CI.
VOLUME /cache
ENV CARGO_HOME=/cache/cargo_home

VOLUME /workspace
WORKDIR /workspace
