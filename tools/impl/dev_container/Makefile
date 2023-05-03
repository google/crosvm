# Copyright 2021 The ChromiumOS Authors
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
# You need to be a Googler to be able to do so. See go/crosvm/infra for access control and
# authenticate via:
#
#   gcloud auth configure-docker gcr.io

export DOCKER_BUILDKIT=1

TAG_BASE=gcr.io/crosvm-infra
VERSION=$(shell cat version)
BUILD_CONTEXT=$(shell realpath ../../../)

DOCKER ?= podman

all: crosvm_dev

upload: all
	$(DOCKER) push $(TAG_BASE)/crosvm_dev:$(VERSION)
	$(DOCKER) push $(TAG_BASE)/crosvm_dev:latest

crosvm_dev:
	$(DOCKER) build \
		-t $(TAG_BASE)/$@:$(VERSION) \
		-f Dockerfile \
		$(BUILD_CONTEXT)
	$(DOCKER) tag $(TAG_BASE)/$@:$(VERSION) $(TAG_BASE)/$@:latest

.PHONY: all crosvm_dev upload
