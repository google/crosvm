# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# To locally build the docker container for usage with dev_container:
#
# 	make -C tools/impl/dev_container crosvm_dev
#
# To upload a new version of the container, uprev the `version` file and run;
#
# 	make -C tools/impl/dev_container upload
#
# You need write permission to the crosvm-packages cloud registry to do so.

export DOCKER_BUILDKIT=1

TAG_BASE=gcr.io/crosvm-packages
VERSION=$(shell cat version)
RUST_VERSION=$(shell cat ../../../rust-toolchain | grep channel | grep -E -o "[0-9\.]+")
BUILD_CONTEXT=$(shell realpath ../../../)

DOCKER ?= docker

all: crosvm_dev

upload: all
	$(DOCKER) push $(TAG_BASE)/crosvm_dev:$(VERSION)

crosvm_dev:
	$(DOCKER) build \
		--build-arg RUST_VERSION=$(RUST_VERSION) \
		-t $(TAG_BASE)/$@:$(VERSION) \
		-f Dockerfile \
		$(BUILD_CONTEXT)

.PHONY: all crosvm_dev upload
