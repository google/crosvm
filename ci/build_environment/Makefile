# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Note: This will be removed in the follow up CL which will add this into
# the container and remove this file.
all: $(LIB) /usr/local/share/meson/cross/aarch64

$(LIB):
	mkdir -p $(LIB)

# Note: This will be removed in the follow up CL which will add this into
# the container and remove this file.
/usr/local/share/meson/cross/aarch64:
ifeq ($(TARGET_ARCH),aarch64)
	mkdir -p /usr/local/share/meson/cross \
		&& /usr/share/meson/debcrossgen --arch arm64 \
			-o /usr/local/share/meson/cross/aarch64
endif
