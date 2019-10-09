// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A crate for using hardware acceleration to render virtio-gpu's virgl command streams.

mod command_buffer;
mod generated;

use std::cell::RefCell;
use std::fmt::{self, Display};
use std::fs::File;
use std::marker::PhantomData;
use std::mem::{size_of, transmute};
use std::os::raw::{c_char, c_void};
use std::os::unix::io::FromRawFd;
use std::ptr::null_mut;
use std::rc::Rc;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};

use libc::close;

use data_model::{VolatileMemory, VolatileSlice};
use sys_util::{GuestAddress, GuestMemory};

use crate::generated::p_defines::{
    PIPE_BIND_RENDER_TARGET, PIPE_BIND_SAMPLER_VIEW, PIPE_TEXTURE_1D, PIPE_TEXTURE_2D,
};
use crate::generated::p_format::PIPE_FORMAT_B8G8R8X8_UNORM;
use crate::generated::virglrenderer::*;

pub use crate::command_buffer::CommandBufferBuilder;

/// Arguments used in `Renderer::create_resource`..
pub type ResourceCreateArgs = virgl_renderer_resource_create_args;
/// Some of the information returned from `Resource::export_query`.
pub type Query = virgl_renderer_export_query;

/// An error generated while using this crate.
#[derive(Debug)]
pub enum Error {
    /// Inidcates `Renderer` was already initialized, and only one renderer per process is allowed.
    AlreadyInitialized,
    /// An internal virglrenderer error was returned.
    Virglrenderer(i32),
    /// The EGL driver failed to export an EGLImageKHR as a dmabuf.
    ExportedResourceDmabuf,
    /// The indicated region of guest memory is invalid.
    InvalidIovec,
    /// A command size was submitted that was invalid.
    InvalidCommandSize(usize),
    /// The command is unsupported.
    Unsupported,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            AlreadyInitialized => write!(f, "global gpu renderer was already initailized"),
            Virglrenderer(ret) => write!(f, "virglrenderer failed with error {}", ret),
            ExportedResourceDmabuf => write!(f, "failed to export dmabuf"),
            InvalidIovec => write!(f, "an iovec is outside of guest memory's range"),
            InvalidCommandSize(s) => write!(f, "command buffer submitted with invalid size: {}", s),
            Unsupported => write!(f, "gpu renderer function unsupported"),
        }
    }
}

/// The result of an operation in this crate.
pub type Result<T> = result::Result<T, Error>;

fn ret_to_res(ret: i32) -> Result<()> {
    match ret {
        0 => Ok(()),
        _ => Err(Error::Virglrenderer(ret)),
    }
}

#[derive(Debug)]
#[repr(C)]
struct VirglVec {
    base: *mut c_void,
    len: usize,
}

/// An axis aligned box in 3 dimensional space.
#[derive(Debug)]
#[repr(C)]
pub struct Box3 {
    pub x: u32,
    pub y: u32,
    pub z: u32,
    pub w: u32,
    pub h: u32,
    pub d: u32,
}

impl Box3 {
    /// Constructs a 2 dimensional XY box in 3 dimensional space with unit depth and zero
    /// displacement on the Z axis.
    pub fn new_2d(x: u32, y: u32, w: u32, h: u32) -> Box3 {
        Box3 {
            x,
            y,
            z: 0,
            w,
            h,
            d: 1,
        }
    }

    /// Returns true if this box represents a volume of zero.
    pub fn is_empty(&self) -> bool {
        self.w == 0 || self.h == 0 || self.d == 0
    }
}

struct FenceState {
    latest_fence: u32,
}
impl FenceState {
    pub fn write(&mut self, latest_fence: u32) {
        if latest_fence > self.latest_fence {
            self.latest_fence = latest_fence;
        }
    }
}

struct VirglCookie {
    fence_state: Rc<RefCell<FenceState>>,
}

extern "C" fn write_fence(cookie: *mut c_void, fence: u32) {
    assert!(!cookie.is_null());
    let cookie = unsafe { &*(cookie as *mut VirglCookie) };

    // Track the most recent fence.
    let mut fence_state = cookie.fence_state.borrow_mut();
    fence_state.write(fence);
}

const VIRGL_RENDERER_CALLBACKS: &virgl_renderer_callbacks = &virgl_renderer_callbacks {
    version: 1,
    write_fence: Some(write_fence),
    create_gl_context: None,
    destroy_gl_context: None,
    make_current: None,
    get_drm_fd: None,
};

#[derive(Copy, Clone)]
pub struct RendererFlags(u32);

impl Default for RendererFlags {
    fn default() -> RendererFlags {
        RendererFlags::new()
            .use_egl(true)
            .use_surfaceless(true)
            .use_gles(true)
    }
}

impl RendererFlags {
    pub fn new() -> RendererFlags {
        RendererFlags(0)
    }

    fn set_flag(self, bitmask: u32, set: bool) -> RendererFlags {
        if set {
            RendererFlags(self.0 | bitmask)
        } else {
            RendererFlags(self.0 & (!bitmask))
        }
    }

    pub fn uses_egl(self) -> bool {
        (self.0 & VIRGL_RENDERER_USE_EGL) != 0
    }

    pub fn use_egl(self, v: bool) -> RendererFlags {
        self.set_flag(VIRGL_RENDERER_USE_EGL, v)
    }

    pub fn uses_glx(self) -> bool {
        (self.0 & VIRGL_RENDERER_USE_GLX) != 0
    }

    pub fn use_glx(self, v: bool) -> RendererFlags {
        self.set_flag(VIRGL_RENDERER_USE_GLX, v)
    }

    pub fn uses_surfaceless(self) -> bool {
        (self.0 & VIRGL_RENDERER_USE_SURFACELESS) != 0
    }

    pub fn use_surfaceless(self, v: bool) -> RendererFlags {
        self.set_flag(VIRGL_RENDERER_USE_SURFACELESS, v)
    }

    pub fn uses_gles(self) -> bool {
        (self.0 & VIRGL_RENDERER_USE_GLES) != 0
    }

    pub fn use_gles(self, v: bool) -> RendererFlags {
        self.set_flag(VIRGL_RENDERER_USE_GLES, v)
    }
}

impl From<RendererFlags> for i32 {
    fn from(flags: RendererFlags) -> i32 {
        flags.0 as i32
    }
}

/// The global renderer handle used to query capability sets, and create resources and contexts.
pub struct Renderer {
    no_sync_send: PhantomData<*mut ()>,
    fence_state: Rc<RefCell<FenceState>>,
}

impl Renderer {
    /// Initializes the renderer and returns a handle to it.
    ///
    /// This may only be called once per process. Calls after the first will return an error.
    pub fn init(flags: RendererFlags) -> Result<Renderer> {
        // virglrenderer is a global state backed library that uses thread bound OpenGL contexts.
        // Initialize it only once and use the non-send/non-sync Renderer struct to keep things tied
        // to whichever thread called this function first.
        static INIT_ONCE: AtomicBool = AtomicBool::new(false);
        if INIT_ONCE.compare_and_swap(false, true, Ordering::Acquire) {
            return Err(Error::AlreadyInitialized);
        }

        // Cookie is intentionally never freed because virglrenderer never gets uninitialized.
        // Otherwise, Resource and Context would become invalid because their lifetime is not tied
        // to the Renderer instance. Doing so greatly simplifies the ownership for users of this
        // library.

        let fence_state = Rc::new(RefCell::new(FenceState { latest_fence: 0 }));

        let cookie: *mut VirglCookie = Box::into_raw(Box::new(VirglCookie {
            fence_state: Rc::clone(&fence_state),
        }));

        // Safe because a valid cookie and set of callbacks is used and the result is checked for
        // error.
        let ret = unsafe {
            virgl_renderer_init(
                cookie as *mut c_void,
                flags.into(),
                transmute(VIRGL_RENDERER_CALLBACKS),
            )
        };
        ret_to_res(ret)?;

        Ok(Renderer {
            no_sync_send: PhantomData,
            fence_state,
        })
    }

    /// Gets the version and size for the given capability set ID.
    pub fn get_cap_set_info(&self, id: u32) -> (u32, u32) {
        let mut version = 0;
        let mut size = 0;
        // Safe because virglrenderer is initialized by now and properly size stack variables are
        // used for the pointers.
        unsafe {
            virgl_renderer_get_cap_set(id, &mut version, &mut size);
        }
        (version, size)
    }

    /// Gets the capability set for the given ID and version.
    pub fn get_cap_set(&self, id: u32, version: u32) -> Vec<u8> {
        let (_, max_size) = self.get_cap_set_info(id);
        let mut buf = vec![0u8; max_size as usize];
        // Safe because virglrenderer is initialized by now and the given buffer is sized properly
        // for the given cap id/version.
        unsafe {
            virgl_renderer_fill_caps(id, version, buf.as_mut_ptr() as *mut c_void);
        }
        buf
    }

    /// Creates a rendering context with the given id.
    pub fn create_context(&self, id: u32) -> Result<Context> {
        const CONTEXT_NAME: &[u8] = b"gpu_renderer";
        // Safe because virglrenderer is initialized by now and the context name is statically
        // allocated. The return value is checked before returning a new context.
        let ret = unsafe {
            virgl_renderer_context_create(
                id,
                CONTEXT_NAME.len() as u32,
                CONTEXT_NAME.as_ptr() as *const c_char,
            )
        };
        ret_to_res(ret)?;
        Ok(Context {
            id,
            no_sync_send: PhantomData,
        })
    }

    /// Creates a resource with the given arguments.
    pub fn create_resource(
        &self,
        mut args: virgl_renderer_resource_create_args,
    ) -> Result<Resource> {
        // Safe because virglrenderer is initialized by now, and the return value is checked before
        // returning a new resource. The backing buffers are not supplied with this call.
        let ret = unsafe { virgl_renderer_resource_create(&mut args, null_mut(), 0) };
        ret_to_res(ret)?;
        Ok(Resource {
            id: args.handle,
            backing_iovecs: Vec::new(),
            backing_mem: None,
            no_sync_send: PhantomData,
        })
    }

    /// Helper that creates a simple 2 dimensional resource with basic metadata and usable for
    /// display.
    pub fn create_resource_2d(
        &self,
        id: u32,
        width: u32,
        height: u32,
        format: u32,
    ) -> Result<Resource> {
        self.create_resource(virgl_renderer_resource_create_args {
            handle: id,
            target: PIPE_TEXTURE_2D,
            format,
            width,
            height,
            depth: 1,
            array_size: 1,
            last_level: 0,
            nr_samples: 0,
            bind: PIPE_BIND_RENDER_TARGET,
            flags: 0,
        })
    }

    /// Helper that creates a simple 1 dimensional resource with basic metadata.
    pub fn create_tex_1d(&self, id: u32, width: u32) -> Result<Resource> {
        self.create_resource(virgl_renderer_resource_create_args {
            handle: id,
            target: PIPE_TEXTURE_1D,
            format: PIPE_FORMAT_B8G8R8X8_UNORM,
            width,
            height: 1,
            depth: 1,
            array_size: 1,
            last_level: 0,
            nr_samples: 0,
            bind: PIPE_BIND_SAMPLER_VIEW,
            flags: 0,
        })
    }

    /// Helper that creates a simple 2 dimensional resource with basic metadata and usable as a
    /// texture.
    pub fn create_tex_2d(&self, id: u32, width: u32, height: u32) -> Result<Resource> {
        self.create_resource(virgl_renderer_resource_create_args {
            handle: id,
            target: PIPE_TEXTURE_2D,
            format: PIPE_FORMAT_B8G8R8X8_UNORM,
            width,
            height,
            depth: 1,
            array_size: 1,
            last_level: 0,
            nr_samples: 0,
            bind: PIPE_BIND_SAMPLER_VIEW,
            flags: 0,
        })
    }

    pub fn poll(&self) -> u32 {
        unsafe { virgl_renderer_poll() };
        self.fence_state.borrow().latest_fence
    }

    pub fn create_fence(&mut self, fence_id: u32, ctx_id: u32) -> Result<()> {
        let ret = unsafe { virgl_renderer_create_fence(fence_id as i32, ctx_id) };
        ret_to_res(ret)
    }

    pub fn force_ctx_0(&self) {
        unsafe { virgl_renderer_force_ctx_0() };
    }

    #[allow(unused_variables)]
    pub fn allocation_metadata(&self, request: &[u8], response: &mut Vec<u8>) -> Result<()> {
        #[cfg(feature = "virtio-gpu-next")]
        {
            let ret = unsafe {
                virgl_renderer_allocation_metadata(
                    request.as_ptr() as *const c_void,
                    response.as_mut_ptr() as *mut c_void,
                    request.len() as u32,
                    response.len() as u32,
                )
            };
            ret_to_res(ret)
        }
        #[cfg(not(feature = "virtio-gpu-next"))]
        Err(Error::Unsupported)
    }

    #[allow(unused_variables)]
    pub fn resource_create_v2(
        &self,
        resource_id: u32,
        guest_memory_type: u32,
        guest_caching_type: u32,
        size: u64,
        mem: &GuestMemory,
        iovecs: &[(GuestAddress, usize)],
        args: &[u8],
    ) -> Result<Resource> {
        #[cfg(feature = "virtio-gpu-next")]
        {
            if iovecs
                .iter()
                .any(|&(addr, len)| mem.get_slice(addr.offset(), len as u64).is_err())
            {
                return Err(Error::InvalidIovec);
            }

            let mut vecs = Vec::new();
            for &(addr, len) in iovecs {
                // Unwrap will not panic because we already checked the slices.
                let slice = mem.get_slice(addr.offset(), len as u64).unwrap();
                vecs.push(VirglVec {
                    base: slice.as_ptr() as *mut c_void,
                    len,
                });
            }

            let ret = unsafe {
                virgl_renderer_resource_create_v2(
                    resource_id,
                    guest_memory_type,
                    guest_caching_type,
                    size,
                    vecs.as_ptr() as *const iovec,
                    vecs.len() as u32,
                    args.as_ptr() as *const c_void,
                    args.len() as u32,
                )
            };

            ret_to_res(ret)?;

            Ok(Resource {
                id: resource_id,
                backing_iovecs: vecs,
                backing_mem: None,
                no_sync_send: PhantomData,
            })
        }
        #[cfg(not(feature = "virtio-gpu-next"))]
        Err(Error::Unsupported)
    }
}

/// A context in which resources can be attached/detached and commands can be submitted.
pub struct Context {
    id: u32,
    no_sync_send: PhantomData<*mut ()>,
}

impl Context {
    /// Gets the ID assigned to this context when it was created.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Submits a command stream to this rendering context.
    pub fn submit<T: AsMut<[u8]>>(&mut self, mut buf: T) -> Result<()> {
        let buf = buf.as_mut();
        if buf.len() % size_of::<u32>() != 0 {
            return Err(Error::InvalidCommandSize(buf.len()));
        }
        let dword_count = (buf.len() / size_of::<u32>()) as i32;
        // Safe because the context and buffer are valid and virglrenderer will have been
        // initialized if there are Context instances.
        let ret = unsafe {
            virgl_renderer_submit_cmd(buf.as_mut_ptr() as *mut c_void, self.id as i32, dword_count)
        };
        ret_to_res(ret)
    }

    /// Attaches the given resource to this rendering context.
    pub fn attach(&mut self, res: &Resource) {
        // The context id and resource id must be valid because the respective instances ensure
        // their lifetime.
        unsafe {
            virgl_renderer_ctx_attach_resource(self.id as i32, res.id() as i32);
        }
    }

    /// Detaches a previously attached resource from this rendering context.
    pub fn detach(&mut self, res: &Resource) {
        // The context id and resource id must be valid because the respective instances ensure
        // their lifetime.
        unsafe {
            virgl_renderer_ctx_detach_resource(self.id as i32, res.id() as i32);
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // The context is safe to destroy because nothing else can be referencing it.
        unsafe {
            virgl_renderer_context_destroy(self.id);
        }
    }
}

/// A resource handle used by the renderer.
pub struct Resource {
    id: u32,
    backing_iovecs: Vec<VirglVec>,
    backing_mem: Option<GuestMemory>,
    no_sync_send: PhantomData<*mut ()>,
}

impl Resource {
    /// Gets the ID assigned to this resource when it was created.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Retrieves metadata suitable for export about this resource. If "export_fd" is true,
    /// performs an export of this resource so that it may be imported by other processes.
    fn export_query(&self, export_fd: bool) -> Result<Query> {
        let mut query: Query = Default::default();
        query.hdr.stype = VIRGL_RENDERER_STRUCTURE_TYPE_EXPORT_QUERY;
        query.hdr.stype_version = 0;
        query.hdr.size = size_of::<Query>() as u32;
        query.in_resource_id = self.id;
        query.in_export_fds = if export_fd { 1 } else { 0 };

        // Safe because the image parameters are stack variables of the correct type.
        let ret =
            unsafe { virgl_renderer_execute(&mut query as *mut _ as *mut c_void, query.hdr.size) };

        ret_to_res(ret)?;
        Ok(query)
    }

    /// Returns resource metadata.
    pub fn query(&self) -> Result<Query> {
        self.export_query(false)
    }

    /// Returns resource metadata and exports the associated dma-buf.
    pub fn export(&self) -> Result<(Query, File)> {
        let query = self.export_query(true)?;
        if query.out_num_fds != 1 || query.out_fds[0] < 0 {
            for fd in &query.out_fds {
                if *fd >= 0 {
                    // Safe because the FD was just returned by a successful virglrenderer
                    // call so it must be valid and owned by us.
                    unsafe { close(*fd) };
                }
            }
            return Err(Error::ExportedResourceDmabuf);
        }

        // Safe because the FD was just returned by a successful virglrenderer call so it must
        // be valid and owned by us.
        let dmabuf = unsafe { File::from_raw_fd(query.out_fds[0]) };
        Ok((query, dmabuf))
    }

    /// Attaches a scatter-gather mapping of guest memory to this resource which used for transfers.
    pub fn attach_backing(
        &mut self,
        iovecs: &[(GuestAddress, usize)],
        mem: &GuestMemory,
    ) -> Result<()> {
        if iovecs
            .iter()
            .any(|&(addr, len)| mem.get_slice(addr.offset(), len as u64).is_err())
        {
            return Err(Error::InvalidIovec);
        }
        self.detach_backing();
        self.backing_mem = Some(mem.clone());
        for &(addr, len) in iovecs {
            // Unwrap will not panic because we already checked the slices.
            let slice = mem.get_slice(addr.offset(), len as u64).unwrap();
            self.backing_iovecs.push(VirglVec {
                base: slice.as_ptr() as *mut c_void,
                len,
            });
        }
        // Safe because the backing is into guest memory that we store a reference count for.
        let ret = unsafe {
            virgl_renderer_resource_attach_iov(
                self.id as i32,
                self.backing_iovecs.as_mut_ptr() as *mut iovec,
                self.backing_iovecs.len() as i32,
            )
        };
        let res = ret_to_res(ret);
        if res.is_err() {
            // Not strictly necessary, but it's good to clear out our collection of pointers to
            // memory we don't own or need.
            self.backing_iovecs.clear();
            self.backing_mem = None;
        }
        res
    }

    /// Detaches previously attached scatter-gather memory from this resource.
    pub fn detach_backing(&mut self) {
        // Safe as we don't need the old backing iovecs returned and the reference to the guest
        // memory can be dropped as it will no longer be needed for this resource.
        unsafe {
            virgl_renderer_resource_detach_iov(self.id as i32, null_mut(), null_mut());
        }
        self.backing_iovecs.clear();
        self.backing_mem = None;
    }

    /// Performs a transfer to the given resource from its backing in guest memory.
    pub fn transfer_write(
        &self,
        ctx: Option<&Context>,
        level: u32,
        stride: u32,
        layer_stride: u32,
        mut transfer_box: Box3,
        offset: u64,
    ) -> Result<()> {
        if transfer_box.is_empty() {
            return Ok(());
        }
        // Safe because only stack variables of the appropriate type are used.
        let ret = unsafe {
            virgl_renderer_transfer_write_iov(
                self.id,
                ctx.map(Context::id).unwrap_or(0),
                level as i32,
                stride,
                layer_stride,
                &mut transfer_box as *mut Box3 as *mut virgl_box,
                offset,
                null_mut(),
                0,
            )
        };
        ret_to_res(ret)
    }

    /// Performs a transfer from the given resource to its backing in guest memory.
    pub fn transfer_read(
        &self,
        ctx: Option<&Context>,
        level: u32,
        stride: u32,
        layer_stride: u32,
        mut transfer_box: Box3,
        offset: u64,
    ) -> Result<()> {
        if transfer_box.is_empty() {
            return Ok(());
        }
        // Safe because only stack variables of the appropriate type are used.
        let ret = unsafe {
            virgl_renderer_transfer_read_iov(
                self.id,
                ctx.map(Context::id).unwrap_or(0),
                level,
                stride,
                layer_stride,
                &mut transfer_box as *mut Box3 as *mut virgl_box,
                offset,
                null_mut(),
                0,
            )
        };
        ret_to_res(ret)
    }

    /// Performs a transfer from the given resource to the provided `buf`
    pub fn transfer_read_buf(
        &self,
        ctx: Option<&Context>,
        level: u32,
        stride: u32,
        layer_stride: u32,
        mut transfer_box: Box3,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        if transfer_box.is_empty() {
            return Ok(());
        }
        let mut iov = VirglVec {
            base: buf.as_mut_ptr() as *mut c_void,
            len: buf.len(),
        };
        // Safe because only stack variables of the appropriate type are used, along with a properly
        // sized buffer.
        let ret = unsafe {
            virgl_renderer_transfer_read_iov(
                self.id,
                ctx.map(Context::id).unwrap_or(0),
                level,
                stride,
                layer_stride,
                &mut transfer_box as *mut Box3 as *mut virgl_box,
                offset,
                &mut iov as *mut VirglVec as *mut iovec,
                1,
            )
        };
        ret_to_res(ret)
    }

    /// Reads from this resource to a volatile slice of memory.
    pub fn read_to_volatile(
        &self,
        ctx: Option<&Context>,
        level: u32,
        stride: u32,
        layer_stride: u32,
        mut transfer_box: Box3,
        offset: u64,
        buf: VolatileSlice,
    ) -> Result<()> {
        if transfer_box.is_empty() {
            return Ok(());
        }
        let mut iov = VirglVec {
            base: buf.as_ptr() as *mut c_void,
            len: buf.size() as usize,
        };
        // Safe because only stack variables of the appropriate type are used, along with a properly
        // sized buffer.
        let ret = unsafe {
            virgl_renderer_transfer_read_iov(
                self.id,
                ctx.map(Context::id).unwrap_or(0),
                level,
                stride,
                layer_stride,
                &mut transfer_box as *mut Box3 as *mut virgl_box,
                offset,
                &mut iov as *mut VirglVec as *mut iovec,
                1,
            )
        };
        ret_to_res(ret)
    }
}

impl Drop for Resource {
    fn drop(&mut self) {
        // The resource is safe to unreference destroy because no user of these bindings can still
        // be holding a reference.
        unsafe {
            virgl_renderer_resource_unref(self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::p_defines::PIPE_CLEAR_COLOR0;

    #[test]
    #[ignore]
    // Make sure a simple buffer clear works by using a command stream.
    fn simple_clear() {
        let render =
            Renderer::init(RendererFlags::default()).expect("failed to initialize virglrenderer");
        let mut ctx = render.create_context(1).expect("failed to create context");

        // Create a 50x50 texture with id=2.
        let resource = render
            .create_tex_2d(2, 50, 50)
            .expect("failed to create texture");
        ctx.attach(&resource);

        // Create a command buffer that uses the resource as a render target and clears it.
        const CLEAR_COLOR: [f32; 4] = [0.5, 0.4, 0.3, 0.2];
        let mut cbuf = CommandBufferBuilder::new();
        cbuf.e_create_surface(1, &resource, PIPE_FORMAT_B8G8R8X8_UNORM, 0, 0, 0);
        cbuf.e_set_fb_state(&[1], None);
        cbuf.e_clear(PIPE_CLEAR_COLOR0, CLEAR_COLOR, 0.0, 0);
        ctx.submit(&mut cbuf)
            .expect("failed to submit command buffer to context");

        // Read the result of the rendering into a buffer.
        let mut pix_buf = [0; 50 * 50 * 4];
        resource
            .transfer_read_buf(
                Some(&ctx),
                0,
                50,
                0,
                Box3::new_2d(0, 0, 5, 1),
                0,
                &mut pix_buf[..],
            )
            .expect("failed to read back resource data");

        // Check that the pixels are the color we cleared to. The red and blue channels are switched
        // because the surface was created with the BGR format, but the colors are RGB order in the
        // command stream.
        assert_eq!(pix_buf[0], (256.0 * CLEAR_COLOR[2]) as u8);
        assert_eq!(pix_buf[1], (256.0 * CLEAR_COLOR[1]) as u8);
        assert_eq!(pix_buf[2], (256.0 * CLEAR_COLOR[0]) as u8);
        assert_eq!(pix_buf[3], (256.0 * CLEAR_COLOR[3]) as u8);
    }
}
