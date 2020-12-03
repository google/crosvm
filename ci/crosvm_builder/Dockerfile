# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Docker container to build crosvm for the host architecture.



FROM gcr.io/crosvm-packages/crosvm_base

# Install libraries needed to compile crosvm and it's dependencies.

RUN apt-get install --yes --no-install-recommends \
    libdbus-1-dev \
    libcap-dev \
    libdrm-dev \
    libepoxy-dev \
    libfdt-dev \
    libssl-dev \
    libwayland-dev

RUN apt-get install --yes -t testing --no-install-recommends \
    libdrm-dev \
    libepoxy-dev

# Allow GCC/Rust to find packages and libraries stored on the scratch volume.
ENV LIBRARY_PATH=/workspace/scratch/lib
ENV LD_LIBRARY_PATH=/workspace/scratch/lib
ENV PKG_CONFIG_PATH=/workspace/scratch/lib/pkgconfig

# Setup entrypoint and interactive shell
WORKDIR /workspace/src/platform/crosvm
COPY entrypoint /workspace
COPY bashrc /root/.bashrc
ENTRYPOINT ["/workspace/entrypoint"]
CMD ["bash"]
