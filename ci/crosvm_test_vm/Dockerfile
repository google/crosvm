# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Docker container for VMs that can run crosvm tests. This container is
# primarily an intermediate step and imported into the crosvm_(aarch64)_builder
# containers, but for testing purposes it can be run directly.

# Target architecture of the VM. Either arm64 or amd64.
ARG VM_ARCH

# Build stage which will build the rootfs for our VM
FROM debian:buster as vm_builder
ARG VM_ARCH

RUN apt-get update && apt-get install --yes \
    cloud-image-utils \
    curl \
    expect \
    qemu-system-arm \
    qemu-system-x86 \
    qemu-efi-aarch64

WORKDIR /workspace/vm

RUN curl -sSfL -o rootfs.qcow2 \
    "http://cloud.debian.org/images/cloud/bullseye/daily/20210208-542/debian-11-generic-${VM_ARCH}-daily-20210208-542.qcow2"

# Package `cloud_init_data.yaml` to be loaded during `first_boot.expect`
COPY build/cloud_init_data.yaml ./
RUN cloud-localds -v cloud_init.img cloud_init_data.yaml

# Boot the VM once, to do initialization work so we do not have to do it at
# every launch.
COPY runtime/start_vm.${VM_ARCH} ./start_vm
COPY build/first_boot.expect ./
RUN expect -f first_boot.expect

# Compress and sparsify image after doing all the init work.
RUN qemu-img convert -O qcow2 -c rootfs.qcow2 rootfs.compressed \
    && mv -f rootfs.compressed rootfs.qcow2


# Runtime environment for amd64
FROM debian:buster as runtime_amd64
RUN apt-get update && apt-get install --yes --no-install-recommends \
    qemu-system-x86


# Runtime environment for arm64
FROM debian:buster as runtime_arm64
RUN apt-get update && apt-get install --yes --no-install-recommends \
    ipxe-qemu \
    qemu-system-arm \
    qemu-efi-aarch64


# Select the correct stage as runtime stage
FROM runtime_${VM_ARCH} as runtime
ARG VM_ARCH

RUN apt-get install --yes --no-install-recommends \
    openssh-client

# Copy rootfs into runtime stage
WORKDIR /workspace/vm
COPY --from=vm_builder /workspace/vm/rootfs.qcow2 ./

# Setup SSH profile for `vm`.
RUN mkdir -p ~/.ssh
COPY runtime/ssh /root/.ssh
RUN chmod 0600 /root/.ssh/id_rsa

# Copy utility scripts
COPY runtime/start_vm.${VM_ARCH} ./start_vm

# Automatically start the VM.
ENTRYPOINT [ "/workspace/vm/start_vm" ]
