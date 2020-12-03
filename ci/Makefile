# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file
#
# Builds docker images for the crosvm builders.
# Run the `upload` target to upload the images to the container registry
# (provided you are authorized to upload them).

TAG_BASE=gcr.io/crosvm-packages

ifneq (, $(shell which podman))
DEFAULT_DOCKER=podman
else
DEFAULT_DOCKER=docker
endif
DOCKER ?= $(DEFAULT_DOCKER)

all: crosvm_builder crosvm_aarch64_builder

upload: all
	$(DOCKER) push $(TAG_BASE)/crosvm_base
	$(DOCKER) push $(TAG_BASE)/crosvm_builder
	$(DOCKER) push $(TAG_BASE)/crosvm_aarch64_builder

crosvm_base:
	cd $@ && $(DOCKER) build -t $(TAG_BASE)/$@ .

crosvm_builder: crosvm_base
	cd $@ && $(DOCKER) build -t $(TAG_BASE)/$@ .

crosvm_aarch64_builder: crosvm_base
	cd $@ && $(DOCKER) build -t $(TAG_BASE)/$@ .

.PHONY: all crosvm_base crosvm_builder crosvm_aarch64_builder
