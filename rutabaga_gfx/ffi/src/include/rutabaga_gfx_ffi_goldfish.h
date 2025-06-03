/*
 * Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef RUTABAGA_GFX_FFI_GOLDFISH_H
#define RUTABAGA_GFX_FFI_GOLDFISH_H

#include "rutabaga_gfx_ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t rutabaga_resource_transfer_write_goldfish(struct rutabaga *ptr, uint32_t ctx_id,
                                                  uint32_t resource_id,
                                                  const struct rutabaga_transfer *transfer,
                                                  const struct iovec *iovec);

#ifdef __cplusplus
}
#endif

#endif  /* RUTABAGA_GFX_FFI_GOLDFISH_H */
