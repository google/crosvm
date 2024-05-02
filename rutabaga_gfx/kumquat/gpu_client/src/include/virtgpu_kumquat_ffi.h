/*
 * Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef VIRTGPU_KUMQUAT_FFI_H
#define VIRTGPU_KUMQUAT_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

struct virtgpu_kumquat;

struct drm_kumquat_map {
    uint32_t bo_handle;

    // out
    void *ptr;
    uint64_t size;
};

#define VIRTGPU_KUMQUAT_EXECBUF_SYNCOBJ_RESET 0x01
#define VIRTGPU_KUMQUAT_EXECBUF_SYNCOBJ_FLAGS (VIRTGPU_KUMQUAT_EXECBUF_SYNCOBJ_RESET | 0)
struct drm_kumquat_execbuffer_syncobj {
    uint32_t handle;
    uint32_t flags;
    uint64_t point;
};

/* fence_fd is modified on success if VIRTGPU_KUMQUAT_EXECBUF_FENCE_FD_OUT flag is set. */
struct drm_kumquat_execbuffer {
    uint32_t flags;
    uint32_t size;
    uint64_t command; /* void* */
    uint64_t bo_handles;
    uint32_t num_bo_handles;
    int32_t fence_fd;        /* in/out fence fd (see VIRTGPU_KUMQUAT_EXECBUF_FENCE_FD_IN/OUT) */
    uint32_t ring_idx;       /* command ring index (see VIRTGPU_KUMQUAT_EXECBUF_RING_IDX) */
    uint32_t syncobj_stride; /* size of @drm_kumquat_execbuffer_syncobj */
    uint32_t num_in_syncobjs;
    uint32_t num_out_syncobjs;
    uint64_t in_syncobjs;
    uint64_t out_syncobjs;
};

#define VIRTGPU_KUMQUAT_PARAM_3D_FEATURES 1          /* do we have 3D features in the hw */
#define VIRTGPU_KUMQUAT_PARAM_CAPSET_QUERY_FIX 2     /* do we have the capset fix */
#define VIRTGPU_KUMQUAT_PARAM_RESOURCE_BLOB 3        /* DRM_VIRTGPU_RESOURCE_CREATE_BLOB */
#define VIRTGPU_KUMQUAT_PARAM_HOST_VISIBLE 4         /* Host blob resources are mappable */
#define VIRTGPU_KUMQUAT_PARAM_CROSS_DEVICE 5         /* Cross virtio-device resource sharing  */
#define VIRTGPU_KUMQUAT_PARAM_CONTEXT_INIT 6         /* DRM_VIRTGPU_KUMQUAT_CONTEXT_INIT */
#define VIRTGPU_KUMQUAT_PARAM_SUPPORTED_CAPSET_IDs 7 /* Bitmask of supported capability set ids */
#define VIRTGPU_KUMQUAT_PARAM_EXPLICIT_DEBUG_NAME 8  /* Ability to set debug name from userspace */
#define VIRTGPU_KUMQUAT_PARAM_CREATE_GUEST_HANDLE 9

struct drm_kumquat_getparam {
    uint64_t param;
    uint64_t value;
};

struct drm_kumquat_resource_create_3d {
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
    uint32_t bo_handle;
    uint32_t res_handle;
    uint32_t size;
    uint32_t stride;
};

struct drm_kumquat_resource_info {
    uint32_t bo_handle;
    uint32_t res_handle;
    uint32_t size;
    uint32_t blob_mem;
};

struct drm_kumquat_3d_box {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t w;
    uint32_t h;
    uint32_t d;
};

struct drm_kumquat_transfer_to_host {
    uint32_t bo_handle;
    struct drm_kumquat_3d_box box;
    uint32_t level;
    uint32_t offset;
    uint32_t stride;
    uint32_t layer_stride;
};

struct drm_kumquat_transfer_from_host {
    uint32_t bo_handle;
    struct drm_kumquat_3d_box box;
    uint32_t level;
    uint32_t offset;
    uint32_t stride;
    uint32_t layer_stride;
};

struct drm_kumquat_wait {
    uint32_t handle; /* 0 is an invalid handle */
    uint32_t flags;
};

struct drm_kumquat_get_caps {
    uint32_t cap_set_id;
    uint32_t cap_set_ver;
    uint64_t addr;
    uint32_t size;
    uint32_t pad;
};

struct drm_kumquat_resource_create_blob {
#define VIRTGPU_KUMQUAT_MEM_GUEST 0x0001
#define VIRTGPU_KUMQUAT_MEM_HOST3D 0x0002
#define VIRTGPU_KUMQUAT_MEM_HOST3D_GUEST 0x0003

#define VIRTGPU_KUMQUAT_FLAG_USE_MAPPABLE 0x0001
#define VIRTGPU_KUMQUAT_FLAG_USE_SHAREABLE 0x0002
#define VIRTGPU_KUMQUAT_FLAG_USE_CROSS_DEVICE 0x0004
    /* zero is invalid blob_mem */
    uint32_t blob_mem;
    uint32_t blob_flags;
    uint32_t bo_handle;
    uint32_t res_handle;
    uint64_t size;

    /*
     * for 3D contexts with VIRTGPU_KUMQUAT_MEM_HOST3D_GUEST and
     * VIRTGPU_KUMQUAT_MEM_HOST3D otherwise, must be zero.
     */
    uint32_t pad;
    uint32_t cmd_size;
    uint64_t cmd;
    uint64_t blob_id;
};

struct drm_kumquat_resource_unref {
    uint32_t bo_handle;
    uint32_t pad;
};

#define VIRTGPU_KUMQUAT_CONTEXT_PARAM_CAPSET_ID 0x0001
#define VIRTGPU_KUMQUAT_CONTEXT_PARAM_NUM_RINGS 0x0002
#define VIRTGPU_KUMQUAT_CONTEXT_PARAM_POLL_RINGS_MASK 0x0003
#define VIRTGPU_KUMQUAT_CONTEXT_PARAM_DEBUG_NAME 0x0004
struct drm_kumquat_context_set_param {
    uint64_t param;
    uint64_t value;
};

struct drm_kumquat_context_init {
    uint32_t num_params;
    uint32_t pad;

    /* pointer to drm_kumquat_context_set_param array */
    uint64_t ctx_set_params;
};

/*
 * Without VIRTGPU_KUMQUAT_EMULATED_EXPORT, the server side descriptor will
 * be provided.
 *
 * With VIRTGPU_KUMQUAT_EMULATED_EXPORT, a shared memory descriptor embedded
 * with resource will be provided.
 */
#define VIRTGPU_KUMQUAT_EMULATED_EXPORT 0x0001

#define VIRTGPU_KUMQUAT_MEM_HANDLE_TYPE_OPAQUE_FD 0x1
#define VIRTGPU_KUMQUAT_MEM_HANDLE_TYPE_DMABUF 0x2
#define VIRTGPU_KUMQUAT_MEM_HANDLE_TYPE_OPAQUE_WIN32 0x3
#define VIRTGPU_KUMQUAT_MEM_HANDLE_TYPE_SHM 0x4
#define VIRTGPU_KUMQUAT_MEM_HANDLE_TYPE_ZIRCON 0x5

#define VIRTGPU_KUMQUAT_FENCE_HANDLE_TYPE_OPAQUE_FD 0x6
#define VIRTGPU_KUMQUAT_FENCE_HANDLE_TYPE_SYNC_FD 0x7
#define VIRTGPU_KUMQUAT_FENCE_HANDLE_TYPE_OPAQUE_WIN32 0x8
#define VIRTGPU_KUMQUAT_FENCE_HANDLE_TYPE_ZIRCON 0x9
struct drm_kumquat_resource_export {
    uint32_t bo_handle;
    uint32_t flags;
    int64_t os_handle;
    uint32_t handle_type;
};

struct drm_kumquat_resource_import {
    int64_t os_handle;
    uint32_t handle_type;
    uint32_t bo_handle;
    uint32_t res_handle;
    uint64_t size;
};

int32_t virtgpu_kumquat_init(struct virtgpu_kumquat **ptr);

int32_t virtgpu_kumquat_finish(struct virtgpu_kumquat **ptr);

int32_t virtgpu_kumquat_get_param(struct virtgpu_kumquat *ptr, struct drm_kumquat_getparam *cmd);

int32_t virtgpu_kumquat_get_caps(struct virtgpu_kumquat *ptr, struct drm_kumquat_get_caps *cmd);

int32_t virtgpu_kumquat_context_init(struct virtgpu_kumquat *ptr,
                                     struct drm_kumquat_context_init *cmd);

int32_t virtgpu_kumquat_resource_create_3d(struct virtgpu_kumquat *ptr,
                                           struct drm_kumquat_resource_create_3d *cmd);

int32_t virtgpu_kumquat_resource_create_blob(struct virtgpu_kumquat *ptr,
                                             struct drm_kumquat_resource_create_blob *cmd);

int32_t virtgpu_kumquat_resource_unref(struct virtgpu_kumquat *ptr,
                                       struct drm_kumquat_resource_unref *cmd);

int32_t virtgpu_kumquat_resource_map(struct virtgpu_kumquat *ptr, struct drm_kumquat_map *cmd);

int32_t virtgpu_kumquat_resource_unmap(struct virtgpu_kumquat *ptr, uint32_t bo_handle);

int32_t virtgpu_kumquat_transfer_to_host(struct virtgpu_kumquat *ptr,
                                         struct drm_kumquat_transfer_to_host *cmd);

int32_t virtgpu_kumquat_transfer_from_host(struct virtgpu_kumquat *ptr,
                                           struct drm_kumquat_transfer_from_host *cmd);

int32_t virtgpu_kumquat_execbuffer(struct virtgpu_kumquat *ptr, struct drm_kumquat_execbuffer *cmd);

int32_t virtgpu_kumquat_wait(struct virtgpu_kumquat *ptr, struct drm_kumquat_wait *cmd);

// The following commands are more emulated than the rest.
int32_t virtgpu_kumquat_resource_export(struct virtgpu_kumquat *ptr,
                                        struct drm_kumquat_resource_export *cmd);

int32_t virtgpu_kumquat_resource_import(struct virtgpu_kumquat *ptr,
                                        struct drm_kumquat_resource_import *cmd);

int32_t virtgpu_kumquat_snapshot_save(struct virtgpu_kumquat *ptr);

int32_t virtgpu_kumquat_snapshot_restore(struct virtgpu_kumquat *ptr);

#ifdef __cplusplus
}
#endif

#endif
