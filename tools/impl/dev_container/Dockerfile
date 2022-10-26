# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
FROM docker.io/debian:testing-20220822-slim

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

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
COPY tools/install-deps tools/install-aarch64-deps tools/install-armhf-deps tools/install-docs-deps rust-toolchain /tools/
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=cache,target=/scratch/cargo_target,sharing=locked \
    cd /tools \
    && chmod +x * \
    && apt-get update \
    && apt-get install --yes sudo \
    && ./install-deps \
    && ./install-aarch64-deps \
    && ./install-armhf-deps \
    && ./install-docs-deps

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
RUN sudo chmod 755 -R /tools \
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
