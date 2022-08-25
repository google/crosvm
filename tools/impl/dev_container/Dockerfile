# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
ARG RUST_VERSION
FROM docker.io/rust:${RUST_VERSION}-slim-bullseye

# Use a dedicated target directory so we do not write into the source directory.
RUN mkdir -p /scratch/cargo_target \
    && mkdir /cache

# Prevent the container from writing __pycache__ files into the src.
ENV PYTHONDONTWRITEBYTECODE=1
ENV CARGO_TARGET_DIR=/scratch/cargo_target

# Add foreign architectures for cross-compilation.
RUN dpkg --add-architecture arm64 \
    && dpkg --add-architecture armhf

# Install dependencies.
COPY tools/install-deps tools/install-aarch64-deps tools/install-armhf-deps tools/install-docs-deps /tools/
RUN chmod 755 /tools/install-deps /tools/install-aarch64-deps /tools/install-armhf-deps /tools/install-docs-deps \
    && apt update \
    && apt install --yes sudo \
    && /tools/install-deps \
    && /tools/install-aarch64-deps \
    && /tools/install-armhf-deps \
    && /tools/install-docs-deps \
    # Clear apt cache to save space in layer.
    && rm -rf /var/lib/apt/lists/* \
    # Delete build artifacts from 'cargo install' to save space in layer.
    && rm -rf /scratch/cargo_target/*

# Add a new password-less sudoer user crosvmdev
RUN useradd -ms /bin/bash crosvmdev \
    && usermod -aG sudo crosvmdev \
    && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers \
    # Pass rust envs from rust toolchain image when sudo into new user
    && echo 'Defaults env_keep += "RUSTUP_HOME CARGO_HOME RUST_VERSION CARGO_TARGET_DIR"' >> /etc/sudoers \
    # Allow dependencies and build files to be used and overwritten by user
    && chown -R crosvmdev:crosvmdev /scratch /cache

# Following operations will be run as crosvmdev to ensure correct permission.
USER crosvmdev

# Prepare path to rust toolchain for crosvmdev
RUN echo 'export PATH=/cache/cargo_home/bin:/usr/local/cargo/bin:$PATH' >> /home/crosvmdev/.profile

# Prepare wine64
RUN sudo ln -sf /usr/bin/wine64-stable /usr/bin/wine64 \
    && wine64 wineboot

# Prebuild aarch64 VM image for faster startup.
COPY tools/aarch64vm /tools/
COPY /tools/impl/testvm.py /tools/impl/
COPY /tools/impl/testvm/version /tools/impl/testvm/
RUN sudo chmod 755 /tools/aarch64vm /tools/impl/testvm.py \
    && /tools/aarch64vm build

# Cache CARGO_HOME between container runs in CI.
VOLUME /cache
ENV CARGO_HOME=/cache/cargo_home

VOLUME /workspace
WORKDIR /workspace

# Switch back to root to avoid usermod crosvmdev as crosvmdev
USER root
COPY tools/impl/dev_container/entrypoint.sh tools/impl/dev_container/setup-user.sh /tools/
RUN chmod 755 /tools/entrypoint.sh /tools/setup-user.sh
ENTRYPOINT ["/tools/entrypoint.sh"]
