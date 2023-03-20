/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(__WIN32__)
struct iovec {
   void *iov_base; /* Starting address */
   size_t iov_len; /* Length in bytes */
};
#else
#include <sys/uio.h>
#endif

#ifndef RUTABAGA_GFX_FFI_H
#define RUTABAGA_GFX_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Versioning
 */
#define RUTABAGA_VERSION_MAJOR 0
#define RUTABAGA_VERSION_MINOR 1
#define RUTABAGA_VERSION_PATCH 1

/**
 * Blob resource creation parameters.
 */
#define RUTABAGA_BLOB_MEM_GUEST 1
#define RUTABAGA_BLOB_MEM_HOST3D 2
#define RUTABAGA_BLOB_MEM_HOST3D_GUEST 3

#define RUTABAGA_BLOB_FLAG_USE_MAPPABLE 1
#define RUTABAGA_BLOB_FLAG_USE_SHAREABLE 2
#define RUTABAGA_BLOB_FLAG_USE_CROSS_DEVICE 4

/**
 * Rutabaga capsets.
 */
#define RUTABAGA_CAPSET_VIRGL 1
#define RUTABAGA_CAPSET_VIRGL2 2
#define RUTABAGA_CAPSET_GFXSTREAM 3
#define RUTABAGA_CAPSET_VENUS 4
#define RUTABAGA_CAPSET_CROSS_DOMAIN 5
#define RUTABAGA_CAPSET_DRM 6

/**
 * Mapped memory caching flags (see virtio_gpu spec)
 */
#define RUTABAGA_MAP_CACHE_CACHED 1
#define RUTABAGA_MAP_CACHE_UNCACHED 2
#define RUTABAGA_MAP_CACHE_WC 3

/**
 * Rutabaga flags for creating fences.
 */
#define RUTABAGA_FLAG_FENCE (1 << 0)
#define RUTABAGA_FLAG_INFO_RING_IDX (1 << 1)

/**
 * Rutabaga channel types
 */
#define RUTABAGA_CHANNEL_TYPE_WAYLAND 1

/**
 * Rutabaga handle types
 */
#define RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD 0x1
#define RUTABAGA_MEM_HANDLE_TYPE_DMABUF 0x2
#define RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_WIN32 0x3
#define RUTABAGA_MEM_HANDLE_TYPE_SHM 0x4

#define RUTABAGA_FENCE_HANDLE_TYPE_OPAQUE_FD 0x10
#define RUTABAGA_FENCE_HANDLE_TYPE_SYNC_FD 0x20
#define RUTABAGA_FENCE_HANDLE_TYPE_OPAQUE_WIN32 0x40

struct rutabaga;

struct rutabaga_fence {
	uint32_t flags;
	uint64_t fence_id;
	uint32_t ctx_id;
	uint32_t ring_idx;
};

struct rutabaga_create_blob {
	uint32_t blob_mem;
	uint32_t blob_flags;
	uint64_t blob_id;
	uint64_t size;
};

struct rutabaga_create_3d {
	uint32_t target;
	uint32_t format;
	uint32_t bind;
	uint32_t width;
	uint32_t height;
	uint32_t depth;
	uint32_t array_size;
	uint32_t last_level;
	uint32_t nr_samples;
	uint32_t flags;
};

struct rutabaga_transfer {
	uint32_t x;
	uint32_t y;
	uint32_t z;
	uint32_t w;
	uint32_t h;
	uint32_t d;
	uint32_t level;
	uint32_t stride;
	uint32_t layer_stride;
	uint64_t offset;
};

struct rutabaga_iovecs {
	struct iovec *iovecs;
	size_t num_iovecs;
};

struct rutabaga_handle {
	int64_t os_handle;
	uint32_t handle_type;
};

struct rutabaga_mapping {
    uint64_t ptr;
    uint64_t size;
};

/**
 * Assumes null-terminated C-string.
 */
struct rutabaga_channel {
	char *channel_name;
	uint32_t channel_type;
};

struct rutabaga_channels {
	struct rutabaga_channel *channels;
	size_t num_channels;
};

/**
 * Throwing an exception inside this callback is not allowed.
 */
typedef void (*write_fence_cb)(uint64_t user_data, struct rutabaga_fence fence_data);

struct rutabaga_builder {
	// Required for correct functioning
	uint64_t user_data;
	uint64_t capset_mask;
	write_fence_cb fence_cb;

	// Optional and platform specific
	struct rutabaga_channels *channels;
};

/**
 * # Safety
 * - If `(*builder).channels` is not null, the caller must ensure `(*channels).channels` points to
 *   a valid array of `struct rutabaga_channel` of size `(*channels).num_channels`.
 * - The `channel_name` field of `struct rutabaga_channel` must be a null-terminated C-string.
 */
int32_t rutabaga_init(const struct rutabaga_builder *builder, struct rutabaga **ptr);

/**
 * # Safety
 * - `ptr` must have been created by `rutabaga_init`.
 */
int32_t rutabaga_finish(struct rutabaga **ptr);

int32_t rutabaga_get_num_capsets(struct rutabaga *ptr, uint32_t *num_capsets);

int32_t rutabaga_get_capset_info(struct rutabaga *ptr, uint32_t capset_index, uint32_t *capset_id,
				 uint32_t *capset_version, uint32_t *capset_size);

/**
 * # Safety
 * - `capset` must point an array of bytes of size `capset_size`.
 */
int32_t rutabaga_get_capset(struct rutabaga *ptr, uint32_t capset_id, uint32_t version,
			    uint8_t *capset, uint32_t capset_size);

/**
 * # Safety
 * - `context_name` must either be NULL or a valid pointer to an array of at least
 *   `context_name_len` bytes encoding a UTF-8 string.
 */
int32_t rutabaga_context_create(struct rutabaga *ptr, uint32_t ctx_id, uint32_t context_init,
				const char *context_name, uint32_t context_name_len);

int32_t rutabaga_context_destroy(struct rutabaga *ptr, uint32_t ctx_id);

int32_t rutabaga_context_attach_resource(struct rutabaga *ptr, uint32_t ctx_id,
					 uint32_t resource_id);

int32_t rutabaga_context_detach_resource(struct rutabaga *ptr, uint32_t ctx_id,
					 uint32_t resource_id);

int32_t rutabaga_resource_create_3d(struct rutabaga *ptr, uint32_t resource_id,
				    const struct rutabaga_create_3d *create_3d);

/**
 * # Safety
 * - If `iovecs` is not null, the caller must ensure `(*iovecs).iovecs` points to a valid array of
 *   iovecs of size `(*iovecs).num_iovecs`.
 * - Each iovec must point to valid memory starting at `iov_base` with length `iov_len`.
 * - Each iovec must valid until the resource's backing is explictly detached or the resource is
 *   is unreferenced.
 */
int32_t rutabaga_resource_attach_backing(struct rutabaga *ptr, uint32_t resource_id,
					 const struct rutabaga_iovecs *iovecs);

int32_t rutabaga_resource_detach_backing(struct rutabaga *ptr, uint32_t resource_id);

/**
 * # Safety
 * - If `iovecs` is not null, the caller must ensure `(*iovecs).iovecs` points to a valid array of
 *   iovecs of size `(*iovecs).num_iovecs`.
 */
int32_t rutabaga_resource_transfer_read(struct rutabaga *ptr, uint32_t ctx_id, uint32_t resource_id,
					const struct rutabaga_transfer *transfer,
					const struct iovec *iovec);

int32_t rutabaga_resource_transfer_write(struct rutabaga *ptr, uint32_t ctx_id,
					 uint32_t resource_id,
					 const struct rutabaga_transfer *transfer);

/**
 * # Safety
 * - If `iovecs` is not null, the caller must ensure `(*iovecs).iovecs` points to a valid array of
 *   iovecs of size `(*iovecs).num_iovecs`.
 * - If `handle` is not null, the caller must ensure it is a valid OS-descriptor.  Ownership is
 *   transfered to rutabaga.
 * - Each iovec must valid until the resource's backing is explictly detached or the resource is
 *   is unreferenced.
 */
int32_t rutabaga_resource_create_blob(struct rutabaga *ptr, uint32_t ctx_id, uint32_t resource_id,
				      const struct rutabaga_create_blob *rutabaga_create_blob,
				      const struct rutabaga_iovecs *iovecs,
				      const struct rutabaga_handle *handle);

int32_t rutabaga_resource_unref(struct rutabaga *ptr, uint32_t resource_id);

/**
 * # Safety
 * Caller owns raw descriptor on success and is responsible for closing it.
 */
int32_t rutabaga_resource_export_blob(struct rutabaga *ptr, uint32_t resource_id,
				      struct rutabaga_handle *handle);

int32_t rutabaga_resource_map(struct rutabaga *ptr, uint32_t resource_id,
                struct rutabaga_mapping *mapping);

int32_t rutabaga_resource_unmap(struct rutabaga *ptr, uint32_t resource_id);

int32_t rutabaga_resource_map_info(struct rutabaga *ptr, uint32_t resource_id, uint32_t *map_info);

/**
 * # Safety
 * - `commands` must point to a contiguous memory region of `size` bytes.
 */
int32_t rutabaga_submit_command(struct rutabaga *ptr, uint32_t ctx_id, uint8_t *commands,
				size_t size);

int32_t rutabaga_create_fence(struct rutabaga *ptr, const struct rutabaga_fence *fence);

#ifdef __cplusplus
}
#endif

#endif
