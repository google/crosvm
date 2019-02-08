// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

// Exported interface to basic qcow functionality to be used from C.

#ifdef __cplusplus
extern "C" {
#endif

// Create a basic, empty qcow2 file that can grow to `virtual_size` at `path`.
int create_qcow_with_size(const char *path, uint64_t virtual_size);

// Attempt to resize the disk image at `path` to `virtual_size` bytes if
// the disk image is currently smaller than the requested size.
int expand_disk_image(const char *path, uint64_t virtual_size);

// Copy the source disk image from `src_fd` into `dst_fd` as a qcow2 image file.
// Returns 0 on success or a negated errno value on failure.
int convert_to_qcow2(int src_fd, int dst_fd);

// Copy the source disk image from `src_fd` into `dst_fd` as a raw image file.
// Returns 0 on success or a negated errno value on failure.
int convert_to_raw(int src_fd, int dst_fd);

#ifdef __cplusplus
};
#endif
