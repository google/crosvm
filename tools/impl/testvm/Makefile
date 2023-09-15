# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Builds the base image for test VMs used by ./tools/x86vm and
# ./tools/aarch64vm.
#
# To build and upload a new base image, uprev the version in the `version` file
# and run:
#
#   make ARCH=x86_64 upload
#   make ARCH=aarch64 upload
#
# You need write access to the crosvm-testvm storage bucket which is part of the
# crosvm-packages cloud project.
#
# Note: The locally built image is stored in the same place that testvm.py
# expects. So the image can be tested directly:
#
#   make -C tools/impl/testvm ARCH=x86_64
#   ./tools/x86vm run

CARGO_TARGET=$(shell cargo metadata --no-deps --format-version 1 | \
	jq -r ".target_directory")
TARGET=/tmp/crosvm_tools/$(ARCH)
$(shell mkdir -p $(TARGET))

ifeq ($(ARCH), x86_64)
  DEBIAN_ARCH=amd64
  QEMU_CMD=qemu-system-x86_64 \
		-cpu host \
		-enable-kvm
else ifeq ($(ARCH), aarch64)
  DEBIAN_ARCH=arm64
  QEMU_CMD=qemu-system-aarch64 \
		-cpu cortex-a57 \
		-M virt \
		-bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd
else
  $(error Only x86_64 or aarch64 are supported)
endif

GS_PREFIX=gs://crosvm/testvm
DEBIAN_URL=https://cloud.debian.org/images/cloud/bookworm/daily/20230913-1502/

BASE_IMG_NAME=base-$(ARCH)-$(shell cat version).qcow2
GS_URL=$(GS_PREFIX)/$(BASE_IMG_NAME)
LOCAL_IMAGE=$(TARGET)/$(BASE_IMG_NAME)

all: $(LOCAL_IMAGE)

clean:
	rm -rf $(TARGET)

# Upload images to cloud storage. Do not overwrite existing images, uprev
# `image_version` instead.
upload: $(LOCAL_IMAGE)
	gsutil cp -n $(LOCAL_IMAGE) $(GS_URL)

# Download debian bullseye as base image for the testvm.
$(TARGET)/debian.qcow2:
	wget $(DEBIAN_URL)/debian-12-generic-$(DEBIAN_ARCH)-daily-20230913-1502.qcow2 -O $@.tmp
	qemu-img resize $@.tmp 8G
	mv $@.tmp $@

# The cloud init file contains instructions for how to set up the VM when it's
# first booted.
$(TARGET)/clould_init.img: cloud_init.yaml
	cloud-localds -v $@ $<

# Boot image to run through clould-init process.
# cloud-init will shut down the VM after initialization. Compress the image
# afterwards for distribution.
$(LOCAL_IMAGE): $(TARGET)/clould_init.img $(TARGET)/debian.qcow2
	cp -f $(TARGET)/debian.qcow2 $@
	$(QEMU_CMD) \
		-m 4G -smp 8 \
		-display none \
		-serial stdio \
		-drive file=$@,format=qcow2,index=0,media=disk \
		-drive file=$(TARGET)/clould_init.img,format=raw,index=1,media=disk
	qemu-img convert -O qcow2 -c $@ $@-compressed
	mv -f $@-compressed $@
