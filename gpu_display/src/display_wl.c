// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>
#include <memory.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "aura-shell.h"
#include "linux-dmabuf-unstable-v1.h"
#include "viewporter.h"
#include "xdg-shell-unstable-v6.h"
#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include <wayland-client.h>

#define DEFAULT_SCALE 2
#define MAX_BUFFER_COUNT 64

struct dwl_context;

struct interfaces {
	struct dwl_context *context;
	struct wl_compositor *compositor;
	struct wl_subcompositor *subcompositor;
	struct wl_shm *shm;
	struct wl_shell *shell;
	struct wl_seat *seat;
	struct zaura_shell *aura; // optional
	struct zwp_linux_dmabuf_v1 *linux_dmabuf;
	struct zxdg_shell_v6 *xdg_shell;
	struct wp_viewporter *viewporter; // optional
};

struct output {
	struct wl_output *output;
	struct zaura_output *aura_output;
	struct dwl_context *context;
	uint32_t id;
	uint32_t current_scale;
	uint32_t device_scale_factor;
	bool internal;
};

struct dwl_context {
	struct wl_display *display;
	struct interfaces ifaces;
	bool output_added;
	struct output outputs[8];
};

#define outputs_for_each(context, pos, output)                                 \
	for (pos = 0, output = &context->outputs[pos];                         \
	     pos < (sizeof(context->outputs) / sizeof(context->outputs[0]));   \
	     pos++, output = &context->outputs[pos])

struct dwl_dmabuf {
	uint32_t width;
	uint32_t height;
	bool in_use;
	struct wl_buffer *buffer;
};

struct dwl_surface {
	struct dwl_context *context;
	struct wl_surface *surface;
	struct zaura_surface *aura;
	struct zxdg_surface_v6 *xdg;
	struct zxdg_toplevel_v6 *toplevel;
	struct wp_viewport *viewport;
	struct wl_subsurface *subsurface;
	uint32_t width;
	uint32_t height;
	double scale;
	bool close_requested;
	size_t buffer_count;
	uint64_t buffer_use_bit_mask;
	struct wl_buffer *buffers[0];
};

static_assert(sizeof(((struct dwl_surface *)0)->buffer_use_bit_mask) * 8 >=
		  MAX_BUFFER_COUNT,
	      "not enough bits in buffer_use_bit_mask");

static void output_geometry(void *data, struct wl_output *output, int x, int y,
			    int physical_width, int physical_height,
			    int subpixel, const char *make, const char *model,
			    int transform)
{
	(void)data;
	(void)output;
	(void)x;
	(void)y;
	(void)physical_width;
	(void)physical_height;
	(void)subpixel;
	(void)make;
	(void)model;
	(void)transform;
}

static void output_mode(void *data, struct wl_output *output, uint32_t flags,
			int width, int height, int refresh)
{
	(void)data;
	(void)output;
	(void)flags;
	(void)width;
	(void)height;
	(void)refresh;
}

static void output_done(void *data, struct wl_output *output)
{
	(void)data;
	(void)output;
}

static void output_scale(void *data, struct wl_output *wl_output,
			 int32_t scale_factor)
{
	(void)wl_output;
	struct output *output = (struct output *)data;
	struct dwl_context *context = output->context;

	// If the aura interface is available, we prefer the scale factor
	// reported by that.
	if (context->ifaces.aura)
		return;

	output->current_scale = 1000 * scale_factor;
}

static const struct wl_output_listener output_listener = {
    .geometry = output_geometry,
    .mode = output_mode,
    .done = output_done,
    .scale = output_scale};

static void aura_output_scale(void *data, struct zaura_output *aura_output,
			      uint32_t flags, uint32_t scale)
{
	(void)aura_output;
	struct output *output = (struct output *)data;
	if (flags & ZAURA_OUTPUT_SCALE_PROPERTY_CURRENT) {
		output->current_scale = scale;
	}
}

static void aura_output_connection(void *data, struct zaura_output *aura_output,
				   uint32_t connection)
{
	(void)aura_output;
	struct output *output = (struct output *)data;
	output->internal = connection == ZAURA_OUTPUT_CONNECTION_TYPE_INTERNAL;
}

static void aura_output_device_scale_factor(void *data,
					    struct zaura_output *aura_output,
					    uint32_t device_scale_factor)
{
	(void)aura_output;
	struct output *output = (struct output *)data;
	output->device_scale_factor = device_scale_factor;
}

static const struct zaura_output_listener aura_output_listener = {
    .scale = aura_output_scale,
    .connection = aura_output_connection,
    .device_scale_factor = aura_output_device_scale_factor};

static void dwl_context_output_add(struct dwl_context *context,
				   struct wl_output *wl_output, uint32_t id)
{
	size_t i;
	struct output *output;
	outputs_for_each(context, i, output)
	{
		if (output->output == NULL) {
			context->output_added = true;
			output->id = id;
			output->output = wl_output;
			output->context = context;
			output->current_scale = 1000;
			output->device_scale_factor = 1000;
			// This is a fun little hack from reveman. The idea is
			// that the first display will be internal and never get
			// removed.
			output->internal = i == 0;
			wl_output_add_listener(output->output, &output_listener,
					       output);
			return;
		}
	}
}

static void dwl_context_output_remove_destroy(struct dwl_context *context,
					      uint32_t id)
{
	size_t i;
	struct output *output;
	outputs_for_each(context, i, output)
	{
		if (output->id == id) {
			if (output->aura_output)
				zaura_output_destroy(output->aura_output);
			wl_output_destroy(output->output);
			memset(output, 0, sizeof(struct output));
			return;
		}
	}
}

static void dwl_context_output_get_aura(struct dwl_context *context)
{
	if (!context->ifaces.aura)
		return;

	size_t i;
	struct output *output;
	outputs_for_each(context, i, output)
	{
		if (output->output != NULL && output->aura_output == NULL) {
			output->aura_output = zaura_shell_get_aura_output(
			    context->ifaces.aura, output->output);
			zaura_output_add_listener(
			    output->aura_output, &aura_output_listener, output);
		}
	}
}

static void registry_global(void *data, struct wl_registry *registry,
			    uint32_t id, const char *interface,
			    uint32_t version)
{
	(void)version;
	struct interfaces *ifaces = (struct interfaces *)data;
	if (strcmp(interface, "wl_compositor") == 0) {
		ifaces->compositor = (struct wl_compositor *)wl_registry_bind(
		    registry, id, &wl_compositor_interface, 3);
	} else if (strcmp(interface, "wl_subcompositor") == 0) {
		ifaces->subcompositor =
		    (struct wl_subcompositor *)wl_registry_bind(
			registry, id, &wl_subcompositor_interface, 1);
	} else if (strcmp(interface, "wl_shm") == 0) {
		ifaces->shm = (struct wl_shm *)wl_registry_bind(
		    registry, id, &wl_shm_interface, 1);
	} else if (strcmp(interface, "wl_seat") == 0) {
		ifaces->seat = (struct wl_seat *)wl_registry_bind(
		    registry, id, &wl_seat_interface, 5);
	} else if (strcmp(interface, "wl_output") == 0) {
		struct wl_output *output = (struct wl_output *)wl_registry_bind(
		    registry, id, &wl_output_interface, 2);
		dwl_context_output_add(ifaces->context, output, id);
	} else if (strcmp(interface, "zaura_shell") == 0 && version >= 6) {
		ifaces->aura = (struct zaura_shell *)wl_registry_bind(
		    registry, id, &zaura_shell_interface, 6);
	} else if (strcmp(interface, "zwp_linux_dmabuf_v1") == 0) {
		ifaces->linux_dmabuf =
		    (struct zwp_linux_dmabuf_v1 *)wl_registry_bind(
			registry, id, &zwp_linux_dmabuf_v1_interface, 1);
	} else if (strcmp(interface, "zxdg_shell_v6") == 0) {
		ifaces->xdg_shell = (struct zxdg_shell_v6 *)wl_registry_bind(
		    registry, id, &zxdg_shell_v6_interface, 1);
	} else if (strcmp(interface, "wp_viewporter") == 0) {
		ifaces->viewporter = (struct wp_viewporter *)wl_registry_bind(
		    registry, id, &wp_viewporter_interface, 1);
	}
}

static void global_remove(void *data, struct wl_registry *registry, uint32_t id)
{
	(void)registry;

	struct interfaces *ifaces = (struct interfaces *)data;
	// If the ID matches any output, this will remove it. Otherwise, this is
	// a no-op.
	dwl_context_output_remove_destroy(ifaces->context, id);

	if (ifaces->aura &&
	    wl_proxy_get_id((struct wl_proxy *)ifaces->aura) == id) {
		zaura_shell_destroy(ifaces->aura);
		ifaces->aura = NULL;
	}

	// TODO(zachr): deal with the removal of some of the required
	// interfaces.
}

static const struct wl_registry_listener registry_listener = {
    .global = registry_global, .global_remove = global_remove};

static void toplevel_configure(void *data,
			       struct zxdg_toplevel_v6 *zxdg_toplevel_v6,
			       int32_t width, int32_t height,
			       struct wl_array *states)
{
	(void)data;
	(void)zxdg_toplevel_v6;
	(void)width;
	(void)height;
	(void)states;
}

static void toplevel_close(void *data,
			   struct zxdg_toplevel_v6 *zxdg_toplevel_v6)
{
	(void)zxdg_toplevel_v6;
	struct dwl_surface *surface = (struct dwl_surface *)data;
	surface->close_requested = true;
}

static const struct zxdg_toplevel_v6_listener toplevel_listener = {
    .configure = toplevel_configure, .close = toplevel_close};

static void surface_enter(void *data, struct wl_surface *wl_surface,
			  struct wl_output *wl_output)
{
	struct dwl_surface *surface = (struct dwl_surface *)data;

	struct output *output =
	    (struct output *)wl_output_get_user_data(wl_output);

	surface->scale = (output->device_scale_factor / 1000.0) *
			 (output->current_scale / 1000.0);

	if (surface->viewport) {
		wp_viewport_set_destination(
		    surface->viewport, ceil(surface->width / surface->scale),
		    ceil(surface->height / surface->scale));
	} else {
		wl_surface_set_buffer_scale(wl_surface, surface->scale);
	}

	wl_surface_commit(wl_surface);
}

static void surface_leave(void *data, struct wl_surface *wl_surface,
			  struct wl_output *output)
{
	(void)data;
	(void)wl_surface;
	(void)output;
}

static const struct wl_surface_listener surface_listener = {
    .enter = surface_enter, .leave = surface_leave};

struct dwl_context *dwl_context_new()
{
	struct dwl_context *ctx = calloc(1, sizeof(struct dwl_context));
	ctx->ifaces.context = ctx;
	return ctx;
}

void dwl_context_destroy(struct dwl_context **self)
{
	if ((*self)->display)
		wl_display_disconnect((*self)->display);
	free(*self);
	*self = NULL;
}

bool dwl_context_setup(struct dwl_context *self, const char *socket_path)
{
	struct wl_display *display = wl_display_connect(socket_path);
	if (!display) {
		syslog(LOG_ERR, "failed to connect to display");
		return false;
	}
	self->display = display;
	wl_display_set_user_data(display, self);

	struct wl_registry *registry = wl_display_get_registry(display);
	if (!registry) {
		syslog(LOG_ERR, "failed to get registry");
		goto fail;
	}

	struct interfaces *ifaces = &self->ifaces;
	wl_registry_add_listener(registry, &registry_listener, ifaces);
	wl_display_roundtrip(display);
	dwl_context_output_get_aura(self);

	if (!ifaces->shm) {
		syslog(LOG_ERR, "missing interface shm");
		goto fail;
	}
	if (!ifaces->compositor) {
		syslog(LOG_ERR, "missing interface compositor");
		goto fail;
	}
	if (!ifaces->subcompositor) {
		syslog(LOG_ERR, "missing interface subcompositor");
		goto fail;
	}
	if (!ifaces->seat) {
		syslog(LOG_ERR, "missing interface seat");
		goto fail;
	}
	if (!ifaces->linux_dmabuf) {
		syslog(LOG_ERR, "missing interface linux_dmabuf");
		goto fail;
	}
	if (!ifaces->xdg_shell) {
		syslog(LOG_ERR, "missing interface xdg_shell");
		goto fail;
	}

	return true;

fail:
	wl_display_disconnect(display);
	return false;
}

int dwl_context_fd(struct dwl_context *self)
{
	return wl_display_get_fd(self->display);
}

void dwl_context_dispatch(struct dwl_context *self)
{
	wl_display_dispatch(self->display);
	if (self->output_added) {
		self->output_added = false;
		dwl_context_output_get_aura(self);
		wl_display_roundtrip(self->display);
	}
}

static void linux_buffer_created(
    void *data, struct zwp_linux_buffer_params_v1 *zwp_linux_buffer_params_v1,
    struct wl_buffer *buffer)
{
	(void)zwp_linux_buffer_params_v1;
	struct dwl_dmabuf *dmabuf = (struct dwl_dmabuf *)data;
	dmabuf->buffer = buffer;
}

static void linux_buffer_failed(
    void *data, struct zwp_linux_buffer_params_v1 *zwp_linux_buffer_params_v1)
{
	(void)data;
	(void)zwp_linux_buffer_params_v1;
}

static const struct zwp_linux_buffer_params_v1_listener linux_buffer_listener =
    {.created = linux_buffer_created, .failed = linux_buffer_failed};

static void dmabuf_buffer_release(void *data, struct wl_buffer *buffer)
{
	struct dwl_dmabuf *dmabuf = (struct dwl_dmabuf *)data;
	(void)buffer;

	dmabuf->in_use = false;
}

static const struct wl_buffer_listener dmabuf_buffer_listener = {
    .release = dmabuf_buffer_release};

struct dwl_dmabuf *dwl_context_dmabuf_new(struct dwl_context *self, int fd,
					  uint32_t offset, uint32_t stride,
					  uint64_t modifiers, uint32_t width,
					  uint32_t height, uint32_t fourcc)
{
	struct dwl_dmabuf *dmabuf = calloc(1, sizeof(struct dwl_dmabuf));
	if (!dmabuf) {
		syslog(LOG_ERR, "failed to allocate dwl_dmabuf");
		return NULL;
	}
	dmabuf->width = width;
	dmabuf->height = height;

	struct zwp_linux_buffer_params_v1 *params =
	    zwp_linux_dmabuf_v1_create_params(self->ifaces.linux_dmabuf);
	if (!params) {
		syslog(LOG_ERR,
		       "failed to allocate zwp_linux_buffer_params_v1");
		free(dmabuf);
		return NULL;
	}

	zwp_linux_buffer_params_v1_add_listener(params, &linux_buffer_listener,
						dmabuf);
	zwp_linux_buffer_params_v1_add(params, fd, 0 /* plane_idx */, offset,
				       stride, modifiers >> 32,
				       (uint32_t)modifiers);
	zwp_linux_buffer_params_v1_create(params, width, height, fourcc, 0);
	wl_display_roundtrip(self->display);
	zwp_linux_buffer_params_v1_destroy(params);

	if (!dmabuf->buffer) {
		syslog(LOG_ERR, "failed to get wl_buffer for dmabuf");
		free(dmabuf);
		return NULL;
	}

	wl_buffer_add_listener(dmabuf->buffer, &dmabuf_buffer_listener, dmabuf);

	return dmabuf;
}

void dwl_dmabuf_destroy(struct dwl_dmabuf **self)
{
	wl_buffer_destroy((*self)->buffer);
	free(*self);
	*self = NULL;
}

static void surface_buffer_release(void *data, struct wl_buffer *buffer)
{
	struct dwl_surface *surface = (struct dwl_surface *)data;
	(void)buffer;

	size_t i;
	for (i = 0; i < surface->buffer_count; i++) {
		if (buffer == surface->buffers[i]) {
			surface->buffer_use_bit_mask &= ~(1 << i);
			break;
		}
	}
}

static const struct wl_buffer_listener surface_buffer_listener = {
    .release = surface_buffer_release};

struct dwl_surface *dwl_context_surface_new(struct dwl_context *self,
					    struct dwl_surface *parent,
					    int shm_fd, size_t shm_size,
					    size_t buffer_size, uint32_t width,
					    uint32_t height, uint32_t stride)
{
	if (buffer_size == 0)
		return NULL;
	size_t buffer_count = shm_size / buffer_size;
	if (buffer_count == 0)
		return NULL;
	if (buffer_count > MAX_BUFFER_COUNT)
		return NULL;

	struct dwl_surface *disp_surface =
	    calloc(1, sizeof(struct dwl_surface) +
			  sizeof(struct wl_buffer *) * buffer_count);
	if (!disp_surface)
		return NULL;
	disp_surface->context = self;
	disp_surface->width = width;
	disp_surface->height = height;
	disp_surface->scale = DEFAULT_SCALE;
	disp_surface->buffer_count = buffer_count;

	struct wl_region *region = NULL;
	struct wl_shm_pool *shm_pool =
	    wl_shm_create_pool(self->ifaces.shm, shm_fd, shm_size);
	if (!shm_pool) {
		syslog(LOG_ERR, "failed to make shm pool");
		goto fail;
	}

	size_t i;
	for (i = 0; i < buffer_count; i++) {
		struct wl_buffer *buffer = wl_shm_pool_create_buffer(
		    shm_pool, buffer_size * i, width, height, stride,
		    WL_SHM_FORMAT_ARGB8888);
		if (!buffer) {
			syslog(LOG_ERR, "failed to create buffer");
			goto fail;
		}
		disp_surface->buffers[i] = buffer;
	}

	for (i = 0; i < buffer_count; i++)
		wl_buffer_add_listener(disp_surface->buffers[i],
				       &surface_buffer_listener, disp_surface);

	disp_surface->surface =
	    wl_compositor_create_surface(self->ifaces.compositor);
	if (!disp_surface->surface) {
		syslog(LOG_ERR, "failed to make surface");
		goto fail;
	}

	wl_surface_add_listener(disp_surface->surface, &surface_listener,
				disp_surface);

	region = wl_compositor_create_region(self->ifaces.compositor);
	if (!region) {
		syslog(LOG_ERR, "failed to make region");
		goto fail;
	}
	wl_region_add(region, 0, 0, width, height);
	wl_surface_set_opaque_region(disp_surface->surface, region);

	if (!parent) {
		disp_surface->xdg = zxdg_shell_v6_get_xdg_surface(
		    self->ifaces.xdg_shell, disp_surface->surface);
		if (!disp_surface->xdg) {
			syslog(LOG_ERR, "failed to make xdg shell surface");
			goto fail;
		}

		disp_surface->toplevel =
		    zxdg_surface_v6_get_toplevel(disp_surface->xdg);
		if (!disp_surface->toplevel) {
			syslog(LOG_ERR,
			       "failed to make toplevel xdg shell surface");
			goto fail;
		}
		zxdg_toplevel_v6_set_title(disp_surface->toplevel, "crosvm");
		zxdg_toplevel_v6_add_listener(disp_surface->toplevel,
					      &toplevel_listener, disp_surface);

		if (self->ifaces.aura) {
			disp_surface->aura = zaura_shell_get_aura_surface(
			    self->ifaces.aura, disp_surface->surface);
			if (!disp_surface->aura) {
				syslog(LOG_ERR, "failed to make aura surface");
				goto fail;
			}
			zaura_surface_set_frame(
			    disp_surface->aura,
			    ZAURA_SURFACE_FRAME_TYPE_NORMAL);
		}
	} else {
		disp_surface->subsurface = wl_subcompositor_get_subsurface(
		    self->ifaces.subcompositor, disp_surface->surface,
		    parent->surface);
		if (!disp_surface->subsurface) {
			syslog(LOG_ERR, "failed to make subsurface");
			goto fail;
		}
		wl_subsurface_set_desync(disp_surface->subsurface);
	}

	if (self->ifaces.viewporter) {
		disp_surface->viewport = wp_viewporter_get_viewport(
		    self->ifaces.viewporter, disp_surface->surface);
		if (!disp_surface->viewport) {
			syslog(LOG_ERR, "failed to make surface viewport");
			goto fail;
		}
	}

	wl_surface_attach(disp_surface->surface, disp_surface->buffers[0], 0,
			  0);
	wl_surface_damage(disp_surface->surface, 0, 0, width, height);
	wl_region_destroy(region);
	wl_shm_pool_destroy(shm_pool);

	// Needed to get outputs before iterating them.
	wl_display_roundtrip(self->display);

	// Assuming that this surface will enter the internal output initially,
	// trigger a surface enter for that output before doing the first
	// surface commit. THis is to avoid unpleasant artifacts when the
	// surface first appears.
	struct output *output;
	outputs_for_each(self, i, output)
	{
		if (output->internal) {
			surface_enter(disp_surface, disp_surface->surface,
				      output->output);
		}
	}

	wl_surface_commit(disp_surface->surface);
	wl_display_flush(self->display);

	return disp_surface;
fail:
	if (disp_surface->viewport)
		wp_viewport_destroy(disp_surface->viewport);
	if (disp_surface->subsurface)
		wl_subsurface_destroy(disp_surface->subsurface);
	if (disp_surface->toplevel)
		zxdg_toplevel_v6_destroy(disp_surface->toplevel);
	if (disp_surface->xdg)
		zxdg_surface_v6_destroy(disp_surface->xdg);
	if (disp_surface->aura)
		zaura_surface_destroy(disp_surface->aura);
	if (region)
		wl_region_destroy(region);
	if (disp_surface->surface)
		wl_surface_destroy(disp_surface->surface);
	for (i = 0; i < buffer_count; i++)
		if (disp_surface->buffers[i])
			wl_buffer_destroy(disp_surface->buffers[i]);
	if (shm_pool)
		wl_shm_pool_destroy(shm_pool);
	free(disp_surface);
	return NULL;
}

void dwl_surface_destroy(struct dwl_surface **self)
{
	size_t i;
	if ((*self)->viewport)
		wp_viewport_destroy((*self)->viewport);
	if ((*self)->subsurface)
		wl_subsurface_destroy((*self)->subsurface);
	if ((*self)->toplevel)
		zxdg_toplevel_v6_destroy((*self)->toplevel);
	if ((*self)->xdg)
		zxdg_surface_v6_destroy((*self)->xdg);
	if ((*self)->aura)
		zaura_surface_destroy((*self)->aura);
	if ((*self)->surface)
		wl_surface_destroy((*self)->surface);
	for (i = 0; i < (*self)->buffer_count; i++)
		wl_buffer_destroy((*self)->buffers[i]);
	wl_display_flush((*self)->context->display);
	free(*self);
	*self = NULL;
}

void dwl_surface_commit(struct dwl_surface *self)
{
	// It is possible that we are committing frames faster than the
	// compositor can put them on the screen. This may result in dropped
	// frames, but this is acceptable considering there is no good way to
	// apply back pressure to the guest gpu driver right now. The intention
	// of this module is to help bootstrap gpu support, so it does not have
	// to have artifact free rendering.
	wl_surface_commit(self->surface);
	wl_display_flush(self->context->display);
}

bool dwl_surface_buffer_in_use(struct dwl_surface *self, size_t buffer_index)
{
	return (self->buffer_use_bit_mask & (1 << buffer_index)) != 0;
}

void dwl_surface_flip(struct dwl_surface *self, size_t buffer_index)
{
	if (buffer_index >= self->buffer_count)
		return;
	wl_surface_attach(self->surface, self->buffers[buffer_index], 0, 0);
	wl_surface_damage(self->surface, 0, 0, self->width, self->height);
	dwl_surface_commit(self);
	self->buffer_use_bit_mask |= 1 << buffer_index;
}

void dwl_surface_flip_to(struct dwl_surface *self, struct dwl_dmabuf *dmabuf)
{
	if (self->width != dmabuf->width || self->height != dmabuf->height)
		return;
	wl_surface_attach(self->surface, dmabuf->buffer, 0, 0);
	wl_surface_damage(self->surface, 0, 0, self->width, self->height);
	dwl_surface_commit(self);
	dmabuf->in_use = true;
}

bool dwl_surface_close_requested(const struct dwl_surface *self)
{
	return self->close_requested;
}

void dwl_surface_set_position(struct dwl_surface *self, uint32_t x, uint32_t y)
{
	if (self->subsurface) {
		wl_subsurface_set_position(self->subsurface, x / self->scale,
					   y / self->scale);
		wl_surface_commit(self->surface);
		wl_display_flush(self->context->display);
	}
}
