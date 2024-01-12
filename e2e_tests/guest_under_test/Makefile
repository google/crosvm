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
  KERNEL_BINARY=bzImage
  DOCKER_ARCH=amd64
  CROSS_COMPILE=
  RUSTFLAGS=
else ifeq ($(ARCH), aarch64)
  KERNEL_ARCH=arm64
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
KERNEL_REPO ?= https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
KERNEL_BRANCH ?= linux-6.1.y
KERNEL_SRC_BASE ?= $(TARGET)/kernel-source-$(KERNEL_BRANCH)
KERNEL_SRC_PATCHED ?= $(KERNEL_SRC_BASE)-patched
KERNEL_BUILD ?= $(TARGET)/kernel-build
KERNEL_PATCHES ?= "`readlink -f ./kernel/patches`"

################################################################################
# Main targets

all: $(TARGET)/rootfs $(TARGET)/bzImage

# Clean all local build artifacts, but not downloaded sources.
clean:
	rm -rf $(TARGET)/kernel-build $(TARGET)/rootfs-build $(TARGET)/initramfs-build $(TARGET)/rootfs $(TARGET)/bzImage $(TARGET)/initramfs.cpio.gz

clean-all:
	rm -rf $(TARGET)

x86_64_initramfs: $(TARGET)/initramfs

delegate: $(TARGET)/rootfs-build/delegate

readclock: $(TARGET)/rootfs-build/readclock

################################################################################
# Build rootfs
rootfs : ${TARGET}/rootfs

# Build rootfs from Dockerfile and export into squashfs
$(TARGET)/rootfs: $(TARGET)/rootfs-build/delegate $(TARGET)/rootfs-build/readclock rootfs/Dockerfile
	# Build image from Dockerfile
	DOCKER_BUILDKIT=1 docker build -t crosvm_e2e_test_guest $(TARGET)/rootfs-build \
		-f rootfs/Dockerfile --build-arg ARCH=$(DOCKER_ARCH)
	# Make sure tar2sqfs is available. If not, print a help message.
	tar2sqfs --help > /dev/null || \
		{ \
			echo 'tar2sqfs is not found. To install, run: `sudo apt install -y squashfs-tools-ng` or something equivalent.' ; \
			exit 1 ; \
		}
	# Create container and export into squashfs, and don't forget to clean up
	# the container afterwards.
	set -x && \
		CONTAINER=$$(docker create crosvm_e2e_test_guest) && \
		docker export $$CONTAINER | tar2sqfs -c gzip -f $@ && \
		docker rm $$CONTAINER

# Build and copy delegate binary into rootfs build directory
$(TARGET)/rootfs-build/delegate: rootfs/delegate/Cargo.toml rootfs/delegate/src/main.rs rootfs/delegate/src/wire_format.rs
	rustup target add $(RUST_TARGET)
	CARGO_TARGET_DIR=$(TARGET) RUSTFLAGS=$(RUSTFLAGS) cargo build --target $(RUST_TARGET) --release --manifest-path=rootfs/delegate/Cargo.toml
	mkdir -p $(TARGET)/rootfs-build
	cp $(TARGET)/$(RUST_TARGET)/release/delegate $(TARGET)/rootfs-build/delegate

# Build and copy readclock binary into rootfs build directory
$(TARGET)/rootfs-build/readclock: rootfs/readclock/Cargo.toml rootfs/readclock/src/main.rs rootfs/readclock/src/lib.rs
	rustup target add $(RUST_TARGET)
	CARGO_TARGET_DIR=$(TARGET) RUSTFLAGS=$(RUSTFLAGS) cargo build --target $(RUST_TARGET) --release --manifest-path=rootfs/readclock/Cargo.toml
	mkdir -p $(TARGET)/rootfs-build
	cp $(TARGET)/$(RUST_TARGET)/release/readclock $(TARGET)/rootfs-build/readclock

################################################################################
# Build initramfs

# Build initramfs from Containerfile and package as cpio archive
$(TARGET)/initramfs: $(TARGET)/rootfs-build/delegate initramfs/Containerfile initramfs/init.sh
	-mkdir -p $(TARGET)/initramfs-build
	cp initramfs/init.sh $(TARGET)/initramfs-build/init.sh
	cp $(TARGET)/rootfs-build/delegate $(TARGET)/initramfs-build/delegate
	podman build -t crosvm_e2e_test_guest_initramfs $(TARGET)/initramfs-build -f initramfs/Containerfile
	-mkdir -p $(TARGET)/initramfs-build/cpio-base
	# Create container and export into squashfs, and don't forget to clean up
	# the container afterwards.
	set -x; \
		CONTAINER=$$(podman create crosvm_e2e_test_guest_initramfs); \
		podman export $$CONTAINER | tar -xf - -C $(TARGET)/initramfs-build/cpio-base; \
		podman rm $$CONTAINER; \
		cd $(TARGET)/initramfs-build/cpio-base; \
		find . -print0 | cpio --null --create --verbose --format=newc | gzip --best > $(TARGET)/initramfs.cpio.gz

################################################################################
# Build kernel

kernel: $(TARGET)/bzImage

# Make this target PHONY to make sure everything is up to date with the kernel's make recipe.
# You can use custom kernel source by running:
# make kernel KERNEL_SRC_PATCHED=${PATH_TO_YOUR_KERNEL}
# (Note: you have to manually apply the patches applied in %-patched recipe to pass all the tests.)
.PHONY : $(TARGET)/bzImage
$(TARGET)/bzImage : $(KERNEL_SRC_PATCHED)
	mkdir -p $(KERNEL_BUILD)
	cat kernel/common.config kernel/$(KERNEL_ARCH).config > $(KERNEL_BUILD)/.config
	make -C $(KERNEL_SRC_PATCHED) O=$(KERNEL_BUILD) \
		ARCH=$(KERNEL_ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		-j$(shell nproc)\
		olddefconfig \
		$(KERNEL_BINARY)
	cp $(KERNEL_BUILD)/arch/${KERNEL_ARCH}/boot/$(KERNEL_BINARY) $@

$(KERNEL_SRC_PATCHED): $(KERNEL_SRC_BASE)
	rm -rf $@.tmp ; true # ignore failure
	cp -r $(KERNEL_SRC_BASE) $@.tmp
	git -C $@.tmp am $(KERNEL_PATCHES)/virtio_pvclock.patch
	mv $@.tmp $@

$(KERNEL_SRC_BASE):
	rm -rf $@
	git clone --depth 1 --branch $(KERNEL_BRANCH) $(KERNEL_REPO) $@

.PHONY: clean all update-prebuilts
