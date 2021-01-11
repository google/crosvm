// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! rutabaga_core: Cross-platform, Rust-based, Vulkan centric GPU virtualization.

use std::collections::BTreeMap as Map;
use std::sync::Arc;

use base::ExternalMapping;
use data_model::VolatileSlice;

#[cfg(feature = "gfxstream")]
use crate::gfxstream::Gfxstream;

use crate::rutabaga_2d::Rutabaga2D;
use crate::rutabaga_utils::*;

#[cfg(feature = "virgl_renderer")]
use crate::virgl_renderer::VirglRenderer;

/// Information required for 2D functionality.
pub struct Rutabaga2DInfo {
    pub width: u32,
    pub height: u32,
    pub host_mem: Vec<u8>,
}

/// A Rutabaga resource, supporting 2D and 3D rutabaga features.  Assumes a single-threaded library.
pub struct RutabagaResource {
    pub resource_id: u32,
    pub handle: Option<Arc<RutabagaHandle>>,
    pub blob: bool,
    pub blob_mem: u32,
    pub blob_flags: u32,
    pub backing_iovecs: Vec<RutabagaIovec>,
    pub resource_2d: Option<Rutabaga2DInfo>,
}

/// A RutabagaComponent is a building block of the Virtual Graphics Interface (VGI).  Each component
/// on it's own is sufficient to virtualize graphics on many Google products.  These components wrap
/// libraries like gfxstream or virglrenderer, and Rutabaga's own 2D and cross-domain prototype
/// functionality.
///
/// Most methods return a `RutabagaResult` that indicate the success, failure, or requested data for
/// the given command.
pub trait RutabagaComponent {
    /// Implementations should return the version and size of the given capset_id.  (0, 0) is
    /// returned by default.
    fn get_capset_info(&self, _capset_id: u32) -> (u32, u32) {
        (0, 0)
    }

    /// Implementations should return the capabilites of given a `capset_id` and `version`.  A
    /// zero-sized array is returned by default.
    fn get_capset(&self, _capset_id: u32, _version: u32) -> Vec<u8> {
        Vec::new()
    }

    /// Implementations should set their internal context to be the reserved context 0.
    fn force_ctx_0(&self) {}

    /// Implementations must create a fence that represents the completion of prior work.  This is
    /// required for synchronization with the guest kernel.
    fn create_fence(&mut self, _fence_data: RutabagaFenceData) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must return the last completed fence_id.
    fn poll(&self) -> u32 {
        0
    }

    /// Implementations must create a resource with the given metadata.  For 2D rutabaga components,
    /// this a system memory allocation.  For 3D components, this is typically a GL texture or
    /// buffer.  Vulkan components should use blob resources instead.
    fn create_3d(
        &self,
        _resource_id: u32,
        _resource_create_3d: ResourceCreate3D,
    ) -> RutabagaResult<RutabagaResource> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must attach `vecs` to the resource.
    fn attach_backing(
        &self,
        _resource_id: u32,
        _vecs: &mut Vec<RutabagaIovec>,
    ) -> RutabagaResult<()> {
        Ok(())
    }

    /// Implementations must detach `vecs` from the resource.
    fn detach_backing(&self, _resource_id: u32) {}

    /// Implementations must release the guest kernel reference on the resource.
    fn unref_resource(&self, _resource_id: u32) {}

    /// Implementations must perform the transfer write operation.  For 2D rutabaga components, this
    /// done via memcpy().  For 3D components, this is typically done via glTexSubImage(..).
    fn transfer_write(
        &self,
        _ctx_id: u32,
        _resource: &mut RutabagaResource,
        _transfer: Transfer3D,
    ) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must perform the transfer read operation.  For 2D rutabaga components, this
    /// done via memcpy().  For 3D components, this is typically done via glReadPixels(..).
    fn transfer_read(
        &self,
        _ctx_id: u32,
        _resource: &mut RutabagaResource,
        _transfer: Transfer3D,
        _buf: Option<VolatileSlice>,
    ) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must create a blob resource on success.  The memory parameters, size, and
    /// usage of the blob resource is given by `resource_create_blob`.
    fn create_blob(
        &mut self,
        _ctx_id: u32,
        _resource_id: u32,
        _resource_create_blob: ResourceCreateBlob,
        _backing_iovecs: Vec<RutabagaIovec>,
    ) -> RutabagaResult<RutabagaResource> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must map the blob resource on success.  This is typically done by
    /// glMapBufferRange(...) or vkMapMemory.
    fn map(&self, _resource_id: u32) -> RutabagaResult<ExternalMapping> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must return information about the mapping on success.
    fn map_info(&self, _resource_id: u32) -> RutabagaResult<u32> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must return accurate 3D metadata on success.
    fn query(&self, _resource_id: u32) -> RutabagaResult<Resource3DMetadata> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must return a RutabagaHandle of the blob resource on success.
    fn export_blob(&self, _resource_id: u32) -> RutabagaResult<Arc<RutabagaHandle>> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must return a RutabagaHandle of the fence on success.
    fn export_fence(&self, _fence_id: u32) -> RutabagaResult<RutabagaHandle> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must create a context for submitting commands.  The command stream of the
    /// context is determined by `context_init`.  For virgl contexts, it is a Gallium/TGSI command
    /// stream.  For gfxstream contexts, it's an autogenerated Vulkan or GLES streams.
    fn create_context(
        &self,
        _ctx_id: u32,
        _context_init: u32,
    ) -> RutabagaResult<Box<dyn RutabagaContext>> {
        Err(RutabagaError::Unsupported)
    }
}

pub trait RutabagaContext {
    /// Implementations must handle the context-specific command stream.
    fn submit_cmd(&mut self, _commands: &mut [u8]) -> RutabagaResult<()>;

    /// Implementations may use `resource` in this context's command stream.
    fn attach(&mut self, _resource: &RutabagaResource);

    /// Implementations must stop using `resource` in this context's command stream.
    fn detach(&mut self, _resource: &RutabagaResource);

    /// Implementations must create a fence on specified `fence_ctx_idx` in `fence_data`.  This
    /// allows for multiple syncrhonizations timelines per RutabagaContext.
    fn context_create_fence(&mut self, _fence_data: RutabagaFenceData) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must return an array of fences that have completed.  This will be used by
    /// the cross-domain context for asynchronous Tx/Rx.
    fn context_poll(&mut self) -> Option<Vec<RutabagaFenceData>> {
        None
    }
}

fn capset_id_to_component_type(capset_id: u32) -> RutabagaResult<RutabagaComponentType> {
    let component_type = match capset_id {
        RUTABAGA_CAPSET_VIRGL => RutabagaComponentType::VirglRenderer,
        RUTABAGA_CAPSET_VIRGL2 => RutabagaComponentType::VirglRenderer,
        RUTABAGA_CAPSET_VENUS => RutabagaComponentType::VirglRenderer,
        RUTABAGA_CAPSET_GFXSTREAM => RutabagaComponentType::Gfxstream,
        RUTABAGA_CAPSET_CROSS_DOMAIN => RutabagaComponentType::CrossDomain,
        _ => return Err(RutabagaError::Unsupported),
    };

    Ok(component_type)
}

fn capset_index_to_component_info(index: u32) -> RutabagaResult<(RutabagaComponentType, u32)> {
    let component_info = match index {
        0 => (RutabagaComponentType::VirglRenderer, RUTABAGA_CAPSET_VIRGL),
        1 => (RutabagaComponentType::VirglRenderer, RUTABAGA_CAPSET_VIRGL2),
        2 => (RutabagaComponentType::Gfxstream, RUTABAGA_CAPSET_GFXSTREAM),
        3 => (RutabagaComponentType::VirglRenderer, RUTABAGA_CAPSET_VENUS),
        4 => (
            RutabagaComponentType::CrossDomain,
            RUTABAGA_CAPSET_CROSS_DOMAIN,
        ),
        _ => return Err(RutabagaError::Unsupported),
    };
    Ok(component_info)
}

/// The global libary handle used to query capability sets, create resources and contexts.
///
/// Currently, Rutabaga only supports one default component.  Many components running at the
/// same time is a stretch goal of Rutabaga GFX.
///
/// Not thread-safe, but can be made so easily.  Making non-Rutabaga, C/C++ components
/// thread-safe is more difficult.
pub struct Rutabaga {
    resources: Map<u32, RutabagaResource>,
    components: Map<RutabagaComponentType, Box<dyn RutabagaComponent>>,
    contexts: Map<u32, Box<dyn RutabagaContext>>,
    default_component: RutabagaComponentType,
}

impl Rutabaga {
    /// Gets the version and size for the capabilty set `index`.
    pub fn get_capset_info(&self, index: u32) -> RutabagaResult<(u32, u32, u32)> {
        let (_component_type, capset_id) = capset_index_to_component_info(index)?;

        // The default workaround is just until context types are fully supported in all
        // Google kernels.  We should really use the component_type.
        let component = self
            .components
            .get(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        let (capset_version, capset_size) = component.get_capset_info(capset_id);
        Ok((capset_id, capset_version, capset_size))
    }

    /// Gets the capability set for the `capset_id` and `version`.
    /// Each capability set is associated with a context type, which is associated
    /// with a rutabaga component.
    pub fn get_capset(&self, capset_id: u32, version: u32) -> RutabagaResult<Vec<u8>> {
        // The default workaround is just until context types are fully supported in all
        // Google kernels.
        let component_type =
            capset_id_to_component_type(capset_id).unwrap_or(self.default_component);

        let component = self
            .components
            .get(&component_type)
            .ok_or(RutabagaError::Unsupported)?;

        Ok(component.get_capset(capset_id, version))
    }

    /// Forces context zero for the default rutabaga component.
    pub fn force_ctx_0(&self) {
        if let Some(component) = self.components.get(&self.default_component) {
            component.force_ctx_0();
        }
    }

    /// Creates a fence with the given `fence_data`.
    /// If the flags include RUTABAGA_FLAG_PARAM_FENCE_CTX_IDX, then the fence is created on a
    /// specific timeline on the specific context.
    pub fn create_fence(&mut self, fence_data: RutabagaFenceData) -> RutabagaResult<()> {
        if fence_data.flags & RUTABAGA_FLAG_INFO_FENCE_CTX_IDX != 0 {
            let ctx = self
                .contexts
                .get_mut(&fence_data.ctx_id)
                .ok_or(RutabagaError::InvalidContextId)?;

            ctx.context_create_fence(fence_data)?;
        } else {
            let component = self
                .components
                .get_mut(&self.default_component)
                .ok_or(RutabagaError::Unsupported)?;

            component.create_fence(fence_data)?;
        }

        Ok(())
    }

    /// Polls all rutabaga components and contexts, and returns a vector of RutabagaFenceData
    /// describing which fences have completed.
    pub fn poll(&mut self) -> Vec<RutabagaFenceData> {
        let mut completed_fences: Vec<RutabagaFenceData> = Vec::new();
        // Poll the default component -- this the global timeline which does not take into account
        // `ctx_id` or `fence_ctx_idx`.  This path exists for OpenGL legacy reasons and 2D mode.
        let component = self
            .components
            .get_mut(&self.default_component)
            .ok_or(0)
            .unwrap();

        let global_fence_id = component.poll();
        completed_fences.push(RutabagaFenceData {
            flags: RUTABAGA_FLAG_FENCE,
            fence_id: global_fence_id as u64,
            ctx_id: 0,
            fence_ctx_idx: 0,
        });

        for ctx in self.contexts.values_mut() {
            if let Some(ref mut ctx_completed_fences) = ctx.context_poll() {
                completed_fences.append(ctx_completed_fences);
            }
        }
        completed_fences
    }

    /// Creates a resource with the `resource_create_3d` metadata.
    pub fn resource_create_3d(
        &mut self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> RutabagaResult<()> {
        let component = self
            .components
            .get_mut(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        if self.resources.contains_key(&resource_id) {
            return Err(RutabagaError::InvalidResourceId);
        }

        let mut resource = component.create_3d(resource_id, resource_create_3d)?;
        resource.handle = component.export_blob(resource_id).ok();

        self.resources.insert(resource_id, resource);
        Ok(())
    }

    /// Attaches `vecs` to the resource.
    pub fn attach_backing(
        &mut self,
        resource_id: u32,
        mut vecs: Vec<RutabagaIovec>,
    ) -> RutabagaResult<()> {
        let component = self
            .components
            .get_mut(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        component.attach_backing(resource_id, &mut vecs)?;
        resource.backing_iovecs = vecs;
        Ok(())
    }

    /// Detaches any previously attached iovecs from the resource.
    pub fn detach_backing(&mut self, resource_id: u32) -> RutabagaResult<()> {
        let component = self
            .components
            .get_mut(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        component.detach_backing(resource_id);
        resource.backing_iovecs.clear();
        Ok(())
    }

    /// Releases guest kernel reference on the resource.
    pub fn unref_resource(&mut self, resource_id: u32) -> RutabagaResult<()> {
        let component = self
            .components
            .get_mut(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        self.resources
            .remove(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        component.unref_resource(resource_id);
        Ok(())
    }

    /// For HOST3D_GUEST resources, copies from the attached iovecs to the host resource.  For
    /// HOST3D resources, this may flush caches, though this feature is unused by guest userspace.
    pub fn transfer_write(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
    ) -> RutabagaResult<()> {
        let component = self
            .components
            .get(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        component.transfer_write(ctx_id, resource, transfer)
    }

    /// 1) If specified, copies to `buf` from the host resource.
    /// 2) Otherwise, for HOST3D_GUEST resources, copies to the attached iovecs from the host
    ///    resource.  For HOST3D resources, this may invalidate caches, though this feature is
    ///    unused by guest userspace.
    pub fn transfer_read(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
        buf: Option<VolatileSlice>,
    ) -> RutabagaResult<()> {
        let component = self
            .components
            .get(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        component.transfer_read(ctx_id, resource, transfer, buf)
    }

    /// Creates a blob resource with the `ctx_id` and `resource_create_blob` metadata.
    /// Associates `iovecs` with the resource, if there are any.
    pub fn resource_create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        iovecs: Vec<RutabagaIovec>,
    ) -> RutabagaResult<()> {
        let component = self
            .components
            .get_mut(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        if self.resources.contains_key(&resource_id) {
            return Err(RutabagaError::InvalidResourceId);
        }

        let mut resource =
            component.create_blob(ctx_id, resource_id, resource_create_blob, iovecs)?;
        resource.handle = component.export_blob(resource_id).ok();

        self.resources.insert(resource_id, resource);
        Ok(())
    }

    /// Returns a memory mapping of the blob resource.
    pub fn map(&self, resource_id: u32) -> RutabagaResult<ExternalMapping> {
        let component = self
            .components
            .get(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        if !self.resources.contains_key(&resource_id) {
            return Err(RutabagaError::InvalidResourceId);
        }

        component.map(resource_id)
    }

    /// Returns the `map_info` of the blob resource. The valid values for `map_info`
    /// are defined in the virtio-gpu spec.
    pub fn map_info(&self, resource_id: u32) -> RutabagaResult<u32> {
        let component = self
            .components
            .get(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        if !self.resources.contains_key(&resource_id) {
            return Err(RutabagaError::InvalidResourceId);
        }

        component.map_info(resource_id)
    }

    /// Returns the 3D metadata associated with the resource, if any.
    pub fn query(&self, resource_id: u32) -> RutabagaResult<Resource3DMetadata> {
        let component = self
            .components
            .get(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        if !self.resources.contains_key(&resource_id) {
            return Err(RutabagaError::InvalidResourceId);
        }

        component.query(resource_id)
    }

    /// Exports a blob resource.  See virtio-gpu spec for blob flag use flags.
    pub fn export_blob(&mut self, resource_id: u32) -> RutabagaResult<RutabagaHandle> {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        // We can inspect blob flags only once guest minigbm is fully transitioned to blob.
        let share_mask = RUTABAGA_BLOB_FLAG_USE_SHAREABLE | RUTABAGA_BLOB_FLAG_USE_CROSS_DEVICE;
        let shareable = (resource.blob_flags & share_mask != 0) || !resource.blob;

        let opt = resource.handle.take();

        match (opt, shareable) {
            (Some(handle), true) => {
                let clone = handle.try_clone()?;
                resource.handle = Some(handle);
                Ok(clone)
            }
            (Some(handle), false) => {
                // Exactly one strong reference in this case.
                let hnd = Arc::try_unwrap(handle).map_err(|_| RutabagaError::Unsupported)?;
                Ok(hnd)
            }
            _ => Err(RutabagaError::Unsupported),
        }
    }

    /// Exports the given fence for import into other processes.
    pub fn export_fence(&self, fence_id: u32) -> RutabagaResult<RutabagaHandle> {
        let component = self
            .components
            .get(&self.default_component)
            .ok_or(RutabagaError::Unsupported)?;

        component.export_fence(fence_id)
    }

    /// Creates a context with the given `ctx_id` and `context_init` variable.
    /// `context_init` is used to determine which rutabaga component creates the context.
    pub fn create_context(&mut self, ctx_id: u32, context_init: u32) -> RutabagaResult<()> {
        // The default workaround is just until context types are fully supported in all
        // Google kernels.
        let capset_id = context_init & RUTABAGA_CONTEXT_INIT_CAPSET_ID_MASK;
        let component_type =
            capset_id_to_component_type(capset_id).unwrap_or(self.default_component);

        let component = self
            .components
            .get_mut(&component_type)
            .ok_or(RutabagaError::Unsupported)?;

        if self.contexts.contains_key(&ctx_id) {
            return Err(RutabagaError::InvalidContextId);
        }

        let ctx = component.create_context(ctx_id, context_init)?;
        self.contexts.insert(ctx_id, ctx);
        Ok(())
    }

    /// Destroys the context given by `ctx_id`.
    pub fn destroy_context(&mut self, ctx_id: u32) -> RutabagaResult<()> {
        self.contexts
            .remove(&ctx_id)
            .ok_or(RutabagaError::InvalidContextId)?;
        Ok(())
    }

    /// Attaches the resource given by `resource_id` to the context given by `ctx_id`.
    pub fn context_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> RutabagaResult<()> {
        let ctx = self
            .contexts
            .get_mut(&ctx_id)
            .ok_or(RutabagaError::InvalidContextId)?;

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        ctx.attach(&resource);
        Ok(())
    }

    /// Detaches the resource given by `resource_id` from the context given by `ctx_id`.
    pub fn context_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> RutabagaResult<()> {
        let ctx = self
            .contexts
            .get_mut(&ctx_id)
            .ok_or(RutabagaError::InvalidContextId)?;

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        ctx.detach(&resource);
        Ok(())
    }

    /// Submits `commands` to the context given by `ctx_id`.
    pub fn submit_command(&mut self, ctx_id: u32, commands: &mut [u8]) -> RutabagaResult<()> {
        let ctx = self
            .contexts
            .get_mut(&ctx_id)
            .ok_or(RutabagaError::InvalidContextId)?;

        ctx.submit_cmd(commands)
    }
}

/// Rutabaga Builder, following the Rust builder pattern.
#[derive(Copy, Clone)]
pub struct RutabagaBuilder {
    display_width: Option<u32>,
    display_height: Option<u32>,
    default_component: RutabagaComponentType,
    virglrenderer_flags: Option<VirglRendererFlags>,
    gfxstream_flags: Option<GfxstreamFlags>,
}

impl RutabagaBuilder {
    /// Create new a RutabagaBuilder.
    pub fn new(default_component: RutabagaComponentType) -> RutabagaBuilder {
        RutabagaBuilder {
            display_width: None,
            display_height: None,
            default_component,
            virglrenderer_flags: None,
            gfxstream_flags: None,
        }
    }

    /// Set display width for the RutabagaBuilder
    pub fn set_display_width(mut self, display_width: u32) -> RutabagaBuilder {
        self.display_width = Some(display_width);
        self
    }

    /// Set display height for the RutabagaBuilder
    pub fn set_display_height(mut self, display_height: u32) -> RutabagaBuilder {
        self.display_height = Some(display_height);
        self
    }

    /// Set virglrenderer flags for the RutabagaBuilder
    pub fn set_virglrenderer_flags(
        mut self,
        virglrenderer_flags: VirglRendererFlags,
    ) -> RutabagaBuilder {
        self.virglrenderer_flags = Some(virglrenderer_flags);
        self
    }

    /// Set gfxstream flags for the RutabagaBuilder
    pub fn set_gfxstream_flags(mut self, gfxstream_flags: GfxstreamFlags) -> RutabagaBuilder {
        self.gfxstream_flags = Some(gfxstream_flags);
        self
    }

    /// Builds Rutabaga and returns a handle to it.
    ///
    /// This should be only called once per every virtual machine instance.  Rutabaga tries to
    /// intialize all 3D components which have been built. In 2D mode, only the 2D component is
    /// initialized.
    pub fn build(self) -> RutabagaResult<Rutabaga> {
        let mut rutabaga_components: Map<RutabagaComponentType, Box<dyn RutabagaComponent>> =
            Default::default();

        if self.default_component == RutabagaComponentType::Rutabaga2D {
            let rutabaga_2d = Rutabaga2D::init()?;
            rutabaga_components.insert(RutabagaComponentType::Rutabaga2D, rutabaga_2d);
        } else {
            #[cfg(feature = "virgl_renderer")]
            {
                let virglrenderer_flags = self
                    .virglrenderer_flags
                    .ok_or(RutabagaError::InvalidRutabagaBuild)?;

                let virgl = VirglRenderer::init(virglrenderer_flags)?;
                rutabaga_components.insert(RutabagaComponentType::VirglRenderer, virgl);
            }

            #[cfg(feature = "gfxstream")]
            {
                let display_width = self
                    .display_width
                    .ok_or(RutabagaError::InvalidRutabagaBuild)?;
                let display_height = self
                    .display_height
                    .ok_or(RutabagaError::InvalidRutabagaBuild)?;

                let gfxstream_flags = self
                    .gfxstream_flags
                    .ok_or(RutabagaError::InvalidRutabagaBuild)?;

                let gfxstream = Gfxstream::init(display_width, display_height, gfxstream_flags)?;
                rutabaga_components.insert(RutabagaComponentType::Gfxstream, gfxstream);
            }
        }

        Ok(Rutabaga {
            components: rutabaga_components,
            resources: Default::default(),
            contexts: Default::default(),
            default_component: self.default_component,
        })
    }
}
