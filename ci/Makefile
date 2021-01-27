# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Builds docker images for the crosvm builders.
# Run the `upload` target to upload the images to the container registry
# (provided you are authorized to upload them).
#
# Images are always built with docker (since buildkit is a lot faster than
# podman/buildah). But we do automatically pull images into podman if podman
# is installed.

export DOCKER_BUILDKIT=1

TAG_BASE=gcr.io/crosvm-packages
TAG_VERSION=$(shell cat image_tag)

DOCKER ?= docker

all: crosvm_builder crosvm_aarch64_builder

upload: all
	$(DOCKER) push $(TAG_BASE)/crosvm_base:$(TAG_VERSION)
	$(DOCKER) push $(TAG_BASE)/crosvm_builder:$(TAG_VERSION)
	$(DOCKER) push $(TAG_BASE)/crosvm_aarch64_builder:$(TAG_VERSION)
	$(DOCKER) push $(TAG_BASE)/crosvm_test_vm_amd64:$(TAG_VERSION)
	$(DOCKER) push $(TAG_BASE)/crosvm_test_vm_arm64:$(TAG_VERSION)

crosvm_base:
	cd $@ && $(DOCKER) build -t $(TAG_BASE)/$@:$(TAG_VERSION) .

crosvm_builder: crosvm_base crosvm_test_vm_amd64
	cd $@ && $(DOCKER) build \
		 -t $(TAG_BASE)/$@:$(TAG_VERSION) \
		 --build-arg TAG=$(TAG_VERSION) \
		 .
ifneq (, $(shell command -v podman))
	podman pull docker-daemon:$(TAG_BASE)/$@:$(TAG_VERSION)
endif

crosvm_aarch64_builder: crosvm_base crosvm_test_vm_arm64
	cd $@ && $(DOCKER) build \
		 -t $(TAG_BASE)/$@:$(TAG_VERSION) \
		 --build-arg TAG=$(TAG_VERSION) \
		 .
ifneq (, $(shell command -v podman))
	podman pull docker-daemon:$(TAG_BASE)/$@:$(TAG_VERSION)
endif

crosvm_test_vm_amd64:
	cd crosvm_test_vm && \
		$(DOCKER) build -t $(TAG_BASE)/$@:$(TAG_VERSION) --build-arg VM_ARCH=amd64 .

crosvm_test_vm_arm64:
	cd crosvm_test_vm && \
		$(DOCKER) build -t $(TAG_BASE)/$@:$(TAG_VERSION) --build-arg VM_ARCH=arm64 .

.PHONY: all crosvm_base crosvm_builder crosvm_aarch64_builder
