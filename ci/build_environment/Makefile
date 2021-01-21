# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This makefile is run by the ./ci/crosvm_* containers to build ChromiumOS
# dependencies required by crosvm.
#
# Setting TARGET_ARCH=aarch64 enables cross-compilation for aarch64.

SRC ?= /workspace/src
BUILD ?= /workspace/scratch/build
LIB ?= /workspace/scratch/lib
TARGET_ARCH ?=

MAKEFILE_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

ifeq ($(TARGET_ARCH),aarch64)
CROSS_COMPILE = aarch64-linux-gnu-
MESON_ARGS = --cross-file $(BUILD)/meson-cross
else
CROSS_COMPILE =
MESON_ARGS =
endif


all: $(LIB) tpm2 minijail minigbm virglrenderer
	ldconfig $(LIB)

clean:
	rm -rf $(BUILD) $(LIB)

# Targets to build the needed chromiumos projects.
#
# These are phony targets so that we can delegate the dirty-check to the
# underlying build system for each library.

tpm2:
	mkdir -p $(BUILD)/tpm2
	$(MAKE) -C $(SRC)/third_party/tpm2 \
		obj=$(BUILD)/tpm2 \
		AR=$(CROSS_COMPILE)ar \
		CC=$(CROSS_COMPILE)gcc \
		OBJCOPY=$(CROSS_COMPILE)objcopy V=1

minijail:
	mkdir -p $(BUILD)/minijail
	$(MAKE) -C $(SRC)/aosp/external/minijail \
		OUT=$(BUILD)/minijail \
		CROSS_COMPILE=$(CROSS_COMPILE)

minigbm:
	mkdir -p $(BUILD)/minigbm
	$(MAKE) -C $(SRC)/platform/minigbm \
		OUT=$(BUILD)/minigbm  \
		CROSS_COMPILE=$(CROSS_COMPILE)

virglrenderer: minigbm $(BUILD)/meson-cross
	meson setup \
		$(BUILD)/virglrenderer \
		$(SRC)/third_party/virglrenderer \
		$(MESON_ARGS)

	CPATH=$(SRC)/platform/minigbm \
		meson compile -C $(BUILD)/virglrenderer


# File needed by meson for cross-compilation.
$(BUILD)/meson-cross:
ifeq ($(TARGET_ARCH),aarch64)
	mkdir -p $(BUILD)
	/usr/share/meson/debcrossgen --arch arm64 -o $@
else
	mkdir -p $(BUILD)
	touch $@
endif

# Sets up the $(LIB) directory with links to the generated binaries in $(BUILD).
$(LIB):
	mkdir -p $(LIB) $(LIB)/pkgconfig

	# tpm2
	ln -sf $(BUILD)/tpm2/libtpm2.a $(LIB)/libtpm2.a
	ln -sf $(MAKEFILE_DIR)/pkgconfig/libtpm2.pc $(LIB)/pkgconfig/

	# minijail
	ln -sf $(BUILD)/minijail/libminijail.so $(LIB)
	ln -sf $(LIB)/libminijail.so $(LIB)/libminijail.so.1
	ln -sf $(MAKEFILE_DIR)/pkgconfig/libminijail.pc $(LIB)/pkgconfig/

	# minigbm
	ln -sf $(BUILD)/minigbm/libminigbm.so.1.0.0 $(LIB)/libgbm.so
	ln -sf $(LIB)/libgbm.so $(LIB)/libgbm.so.1
	ln -sf $(SRC)/platform/minigbm/gbm.pc $(LIB)/pkgconfig/

	# virglrenderer
	ln -sf $(BUILD)/virglrenderer/src/libvirglrenderer.so $(LIB)
	ln -sf $(LIB)/libvirglrenderer.so $(LIB)/libvirglrenderer.so.1
	ln -sf $(BUILD)/virglrenderer/virglrenderer.pc $(LIB)/pkgconfig/

.PHONY: all clean tpm2 minijail sysroot minigbm virglrenderer
