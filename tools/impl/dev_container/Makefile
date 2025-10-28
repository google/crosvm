# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

export DOCKER_BUILDKIT=1

TAG_BASE=gcr.io/crosvm-infra
VERSION=$(shell cat version)
BASE_VERSION=$(shell cat base_version)
BUILD_CONTEXT=$(shell realpath ../../../)

DOCKER ?= podman

crosvm_dev:
	$(DOCKER) pull $(TAG_BASE)/crosvm_dev_base:$(BASE_VERSION)
	$(DOCKER) build \
		-t $(TAG_BASE)/$@:$(VERSION) \
		-f Dockerfile \
		--build-arg BASE_VERSION=$(BASE_VERSION) \
		$(BUILD_CONTEXT)
	$(DOCKER) tag $(TAG_BASE)/$@:$(VERSION) $(TAG_BASE)/$@:latest

upload_dev: crosvm_dev
	$(DOCKER) push $(TAG_BASE)/crosvm_dev:$(VERSION)
	$(DOCKER) push $(TAG_BASE)/crosvm_dev:latest

crosvm_dev_base:
	$(DOCKER) build \
		-t $(TAG_BASE)/$@:$(BASE_VERSION) \
		-f Dockerfile.base \
		$(BUILD_CONTEXT)
	$(DOCKER) tag $(TAG_BASE)/$@:$(BASE_VERSION) $(TAG_BASE)/$@:latest

upload_base: crosvm_dev_base
	$(DOCKER) push $(TAG_BASE)/crosvm_dev_base:$(BASE_VERSION)
	$(DOCKER) push $(TAG_BASE)/crosvm_dev_base:latest

.PHONY: all crosvm_dev crosvm_dev_base upload_dev upload_base
