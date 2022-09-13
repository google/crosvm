# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Builds the kernel and rootfs for the guest used in integration testing.
#
# The main artifacts are:
# target/guest_under_test/bzImage
# target/guest_under_test/rootfs

ARCH ?= $(shell arch)
ifeq ($(ARCH), x86_64)
  KERNEL_ARCH=x86
  KERNEL_CONFIG=arch/x86/configs/chromiumos-container-vm-x86_64_defconfig
  KERNEL_BINARY=bzImage
  DOCKER_ARCH=amd64
  CROSS_COMPILE=
  RUSTFLAGS=
else ifeq ($(ARCH), aarch64)
  KERNEL_ARCH=arm64
  KERNEL_CONFIG=arch/arm64/configs/chromiumos-container-vm-arm64_defconfig
  KERNEL_BINARY=Image
  DOCKER_ARCH=arm64v8
  CROSS_COMPILE=aarch64-linux-gnu-
  RUSTFLAGS="-Clinker=aarch64-linux-gnu-ld"
else
  $(error Only x86_64 or aarch64 are supported)
endif

# Build against the musl toolchain, which will produce a statically linked,
# portable binary that we can run on the alpine linux guest without needing
# libc at runtime
RUST_TARGET ?= $(ARCH)-unknown-linux-musl

# We are building everything in target/guest_under_test
CARGO_TARGET ?= $(shell cargo metadata --no-deps --format-version 1 | \
	jq -r ".target_directory")
TARGET ?= $(CARGO_TARGET)/guest_under_test/$(ARCH)
$(shell mkdir -p $(TARGET))

# Parameteters for building the kernel locally
KERNEL_REPO ?= https://chromium.googlesource.com/chromiumos/third_party/kernel
KERNEL_BRANCH ?= chromeos-4.19

################################################################################
# Main targets

all: $(TARGET)/rootfs $(TARGET)/bzImage

clean:
	rm -rf $(TARGET)

################################################################################
# Build rootfs

dockerfile := $(shell pwd)/Dockerfile

# Build rootfs from Dockerfile and export into squashfs
$(TARGET)/rootfs: $(TARGET)/rootfs-build/delegate
	# Build image from Dockerfile
	docker build -t crosvm_integration_test $(TARGET)/rootfs-build \
		-f $(dockerfile) --build-arg ARCH=$(DOCKER_ARCH)

	# Create container and export into squashfs, and don't forget to clean up
	# the container afterwards.
	set -x; \
		CONTAINER=$$(docker create crosvm_integration_test); \
		docker export $$CONTAINER | tar2sqfs -c gzip -f $@; \
		docker rm $$CONTAINER

# Build and copy delegate binary into rootfs build directory
$(TARGET)/rootfs-build/delegate: delegate.rs
	rustup target add $(RUST_TARGET)
	rustc --edition=2018 delegate.rs --out-dir $(@D) \
		 $(RUSTFLAGS) --target $(RUST_TARGET)

################################################################################
# Build kernel

$(TARGET)/bzImage: $(TARGET)/kernel-source $(TARGET)/kernel-build
	cd $(TARGET)/kernel-source && \
		yes "" | make \
		O=$(TARGET)/kernel-build \
		ARCH=$(KERNEL_ARCH) CROSS_COMPILE=$(CROSS_COMPILE) \
		-j$(shell nproc) $(KERNEL_BINARY)
	cp $(TARGET)/kernel-build/arch/${KERNEL_ARCH}/boot/$(KERNEL_BINARY) $@

$(TARGET)/kernel-build: $(TARGET)/kernel-source
	mkdir -p $@
	cp -f $(TARGET)/kernel-source/$(KERNEL_CONFIG) $@/.config

$(TARGET)/kernel-source:
	rm -rf $@
	git clone --depth 1 --branch $(KERNEL_BRANCH) $(KERNEL_REPO) $@


.PHONY: clean all update-prebuilts
