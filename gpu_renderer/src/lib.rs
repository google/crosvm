// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A crate for using hardware acceleration to render virtio-gpu's virgl command streams.

mod command_buffer;
mod generated;
mod pipe_format_fourcc;

use std::cell::RefCell;
use std::ffi::CStr;
use std::fmt::{self, Display};
use std::fs::File;
use std::marker::PhantomData;
use std::mem::{size_of, transmute};
use std::ops::Deref;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::os::unix::io::{FromRawFd, RawFd};
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};

use data_model::{VolatileMemory, VolatileSlice};
use sys_util::{GuestAddress, GuestMemory};

use crate::generated::epoxy_egl::{
    EGLAttrib, EGLBoolean, EGLClientBuffer, EGLConfig, EGLContext, EGLDisplay, EGLImageKHR,
    EGLNativeDisplayType, EGLSurface, EGLenum, EGLint, EGLuint64KHR, EGLDEBUGPROCKHR,
    EGL_CONTEXT_CLIENT_VERSION, EGL_DMA_BUF_PLANE0_FD_EXT, EGL_DMA_BUF_PLANE0_OFFSET_EXT,
    EGL_DMA_BUF_PLANE0_PITCH_EXT, EGL_GL_TEXTURE_2D_KHR, EGL_HEIGHT, EGL_LINUX_DMA_BUF_EXT,
    EGL_LINUX_DRM_FOURCC_EXT, EGL_NONE, EGL_OPENGL_ES_API, EGL_SURFACE_TYPE, EGL_WIDTH,
};
use crate::generated::p_defines::{PIPE_BIND_SAMPLER_VIEW, PIPE_TEXTURE_1D, PIPE_TEXTURE_2D};
use crate::generated::p_format::PIPE_FORMAT_B8G8R8X8_UNORM;
use crate::generated::virglrenderer::*;

pub use crate::command_buffer::CommandBufferBuilder;
pub use crate::generated::virglrenderer::{
    virgl_renderer_resource_create_args, virgl_renderer_resource_info, VIRGL_RES_BIND_SCANOUT,
};
pub use crate::pipe_format_fourcc::pipe_format_fourcc as format_fourcc;

/// Arguments used in `Renderer::create_resource`..
pub type ResourceCreateArgs = virgl_renderer_resource_create_args;
/// Information returned from `Resource::get_info`.
pub type ResourceInfo = virgl_renderer_resource_info;

/// An error generated while using this crate.
#[derive(Debug)]
pub enum Error {
    /// Inidcates `Renderer` was already initialized, and only one renderer per process is allowed.
    AlreadyInitialized,
    /// Indicates libeopoxy was unable to load the EGL function with the given name.
    MissingEGLFunction(&'static str),
    /// A call to eglGetDisplay indicated failure.
    EGLGetDisplay,
    /// A call to eglInitialize indicated failure.
    EGLInitialize,
    /// A call to eglChooseConfig indicated failure.
    EGLChooseConfig,
    /// A call to eglBindAPI indicated failure.
    EGLBindAPI,
    /// A call to eglCreateContext indicated failure.
    EGLCreateContext,
    /// A call to eglMakeCurrent indicated failure.
    EGLMakeCurrent,
    /// An internal virglrenderer error was returned.
    Virglrenderer(i32),
    /// An EGLIMageKHR could not be created, indicating a EGL driver error.
    CreateImage,
    /// The EGL driver failed to export an EGLImageKHR as a dmabuf.
    ExportedResourceDmabuf,
    /// The indicated region of guest memory is invalid.
    InvalidIovec,
    /// A command size was submitted that was invalid.
    InvalidCommandSize(usize),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            AlreadyInitialized => write!(f, "global gpu renderer was already initailized"),
            MissingEGLFunction(name) => write!(f, "egl function `{}` was missing", name),
            EGLGetDisplay => write!(f, "call to eglGetDisplay failed"),
            EGLInitialize => write!(f, "call to eglInitialize failed"),
            EGLChooseConfig => write!(f, "call to eglChooseConfig failed"),
            EGLBindAPI => write!(f, "call to eglBindAPI failed"),
            EGLCreateContext => write!(f, "call to eglCreateContext failed"),
            EGLMakeCurrent => write!(f, "call to eglMakeCurrent failed"),
            Virglrenderer(ret) => write!(f, "virglrenderer failed with error {}", ret),
            CreateImage => write!(f, "failed to create EGLImage"),
            ExportedResourceDmabuf => write!(f, "failed to export dmabuf from EGLImageKHR"),
            InvalidIovec => write!(f, "an iovec is outside of guest memory's range"),
            InvalidCommandSize(s) => write!(f, "command buffer submitted with invalid size: {}", s),
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
    pub fn new_2d(x: u32, w: u32, y: u32, h: u32) -> Box3 {
        Box3 {
            x,
            y,
            z: 0,
            w,
            h,
            d: 1,
        }
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

unsafe extern "C" fn error_callback(
    error: c_uint,
    command: *const c_char,
    _: c_int,
    _: *mut c_void,
    _: *mut c_void,
    message: *const c_char,
) {
    eprint!("EGL ERROR {}: {:?}", error, CStr::from_ptr(command));
    if !message.is_null() {
        eprint!(": {:?}", CStr::from_ptr(message));
    }
    eprintln!();
}

#[allow(non_snake_case)]
struct EGLFunctionsInner {
    BindAPI: unsafe extern "C" fn(api: EGLenum) -> EGLBoolean,
    ChooseConfig: unsafe extern "C" fn(
        dpy: EGLDisplay,
        attrib_list: *const EGLint,
        configs: *mut EGLConfig,
        config_size: EGLint,
        num_config: *mut EGLint,
    ) -> EGLBoolean,
    CreateContext: unsafe extern "C" fn(
        dpy: EGLDisplay,
        config: EGLConfig,
        share_context: EGLContext,
        attrib_list: *const EGLint,
    ) -> EGLContext,
    CreateImageKHR: unsafe extern "C" fn(
        dpy: EGLDisplay,
        ctx: EGLContext,
        target: EGLenum,
        buffer: EGLClientBuffer,
        attrib_list: *const EGLint,
    ) -> EGLImageKHR,
    DebugMessageControlKHR:
        unsafe extern "C" fn(callback: EGLDEBUGPROCKHR, attrib_list: *const EGLAttrib) -> EGLint,
    DestroyImageKHR: unsafe extern "C" fn(dpy: EGLDisplay, image: EGLImageKHR) -> EGLBoolean,
    ExportDRMImageMESA: unsafe extern "C" fn(
        dpy: EGLDisplay,
        image: EGLImageKHR,
        fds: *mut ::std::os::raw::c_int,
        strides: *mut EGLint,
        offsets: *mut EGLint,
    ) -> EGLBoolean,
    ExportDMABUFImageQueryMESA: unsafe extern "C" fn(
        dpy: EGLDisplay,
        image: EGLImageKHR,
        fourcc: *mut ::std::os::raw::c_int,
        num_planes: *mut ::std::os::raw::c_int,
        modifiers: *mut EGLuint64KHR,
    ) -> EGLBoolean,
    GetCurrentContext: unsafe extern "C" fn() -> EGLContext,
    GetCurrentDisplay: unsafe extern "C" fn() -> EGLDisplay,
    GetDisplay: unsafe extern "C" fn(display_id: EGLNativeDisplayType) -> EGLDisplay,
    Initialize:
        unsafe extern "C" fn(dpy: EGLDisplay, major: *mut EGLint, minor: *mut EGLint) -> EGLBoolean,
    MakeCurrent: unsafe extern "C" fn(
        dpy: EGLDisplay,
        draw: EGLSurface,
        read: EGLSurface,
        ctx: EGLContext,
    ) -> EGLBoolean,
    no_sync_send: PhantomData<*mut ()>,
}

#[derive(Clone)]
struct EGLFunctions(Rc<EGLFunctionsInner>);

impl EGLFunctions {
    fn new() -> Result<EGLFunctions> {
        use crate::generated::epoxy_egl::{
            epoxy_eglBindAPI, epoxy_eglChooseConfig, epoxy_eglCreateContext,
            epoxy_eglCreateImageKHR, epoxy_eglDebugMessageControlKHR, epoxy_eglDestroyImageKHR,
            epoxy_eglExportDMABUFImageQueryMESA, epoxy_eglExportDRMImageMESA,
            epoxy_eglGetCurrentContext, epoxy_eglGetCurrentDisplay, epoxy_eglGetDisplay,
            epoxy_eglInitialize, epoxy_eglMakeCurrent,
        };
        // This is unsafe because it is reading mutable static variables exported by epoxy. These
        // variables are initialized during the binary's init and never modified again, so it should
        // be safe to read them now.
        unsafe {
            Ok(EGLFunctions(Rc::new(EGLFunctionsInner {
                BindAPI: epoxy_eglBindAPI.ok_or(Error::MissingEGLFunction("eglBindAPI"))?,
                ChooseConfig: epoxy_eglChooseConfig
                    .ok_or(Error::MissingEGLFunction("eglChooseConfig"))?,
                CreateContext: epoxy_eglCreateContext
                    .ok_or(Error::MissingEGLFunction("eglCreateContext"))?,
                CreateImageKHR: epoxy_eglCreateImageKHR
                    .ok_or(Error::MissingEGLFunction("eglCreateImageKHR"))?,
                DebugMessageControlKHR: epoxy_eglDebugMessageControlKHR
                    .ok_or(Error::MissingEGLFunction("eglDebugMessageControlKHR"))?,
                DestroyImageKHR: epoxy_eglDestroyImageKHR
                    .ok_or(Error::MissingEGLFunction("eglDestroyImageKHR"))?,
                ExportDRMImageMESA: epoxy_eglExportDRMImageMESA
                    .ok_or(Error::MissingEGLFunction("eglExportDRMImageMESA"))?,
                ExportDMABUFImageQueryMESA: epoxy_eglExportDMABUFImageQueryMESA
                    .ok_or(Error::MissingEGLFunction("eglExportDMABUFImageQueryMESA"))?,
                GetCurrentContext: epoxy_eglGetCurrentContext
                    .ok_or(Error::MissingEGLFunction("eglGetCurrentContext"))?,
                GetCurrentDisplay: epoxy_eglGetCurrentDisplay
                    .ok_or(Error::MissingEGLFunction("eglGetCurrentDisplay"))?,
                GetDisplay: epoxy_eglGetDisplay
                    .ok_or(Error::MissingEGLFunction("eglGetDisplay"))?,
                Initialize: epoxy_eglInitialize
                    .ok_or(Error::MissingEGLFunction("eglInitialize"))?,
                MakeCurrent: epoxy_eglMakeCurrent
                    .ok_or(Error::MissingEGLFunction("eglMakeCurrent"))?,
                no_sync_send: PhantomData,
            })))
        }
    }
}

impl Deref for EGLFunctions {
    type Target = EGLFunctionsInner;
    fn deref(&self) -> &EGLFunctionsInner {
        self.0.deref()
    }
}

/// The global renderer handle used to query capability sets, and create resources and contexts.
pub struct Renderer {
    no_sync_send: PhantomData<*mut ()>,
    egl_funcs: EGLFunctions,
    display: EGLDisplay,
    fence_state: Rc<RefCell<FenceState>>,
}

impl Renderer {
    /// Initializes the renderer and returns a handle to it.
    ///
    /// This may only be called once per process. Calls after the first will return an error.
    pub fn init() -> Result<Renderer> {
        // virglrenderer is a global state backed library that uses thread bound OpenGL contexts.
        // Initialize it only once and use the non-send/non-sync Renderer struct to keep things tied
        // to whichever thread called this function first.
        static INIT_ONCE: AtomicBool = AtomicBool::new(false);
        if INIT_ONCE.compare_and_swap(false, true, Ordering::Acquire) {
            return Err(Error::AlreadyInitialized);
        }

        let egl_funcs = EGLFunctions::new()?;

        // Safe because only valid callbacks are given and only one thread can execute this
        // function.
        unsafe {
            (egl_funcs.DebugMessageControlKHR)(Some(error_callback), null());
        }

        // Trivially safe.
        let display = unsafe { (egl_funcs.GetDisplay)(null_mut()) };
        if display.is_null() {
            return Err(Error::EGLGetDisplay);
        }

        // Safe because only a valid display is given.
        let ret = unsafe { (egl_funcs.Initialize)(display, null_mut(), null_mut()) };
        if ret == 0 {
            return Err(Error::EGLInitialize);
        }

        let config_attribs = [EGL_SURFACE_TYPE as i32, -1, EGL_NONE as i32];
        let mut egl_config: *mut c_void = null_mut();
        let mut num_configs = 0;
        // Safe because only a valid, initialized display is used, along with validly sized
        // pointers to stack variables.
        let ret = unsafe {
            (egl_funcs.ChooseConfig)(
                display,
                config_attribs.as_ptr(),
                &mut egl_config,
                1,
                &mut num_configs, /* unused but can't be null */
            )
        };
        if ret == 0 {
            return Err(Error::EGLChooseConfig);
        }

        // Cookie is intentionally never freed because virglrenderer never gets uninitialized.
        // Otherwise, Resource and Context would become invalid because their lifetime is not tied
        // to the Renderer instance. Doing so greatly simplifies the ownership for users of this
        // library.

        let fence_state = Rc::new(RefCell::new(FenceState { latest_fence: 0 }));

        let cookie: *mut VirglCookie = Box::into_raw(Box::new(VirglCookie {
            fence_state: Rc::clone(&fence_state),
        }));

        // Safe because EGL was properly initialized before here..
        let ret = unsafe { (egl_funcs.BindAPI)(EGL_OPENGL_ES_API) };
        if ret == 0 {
            return Err(Error::EGLBindAPI);
        }

        let context_attribs = [EGL_CONTEXT_CLIENT_VERSION as i32, 3, EGL_NONE as i32];
        // Safe because a valid display, config, and config_attribs pointer are given.
        let ctx = unsafe {
            (egl_funcs.CreateContext)(display, egl_config, null_mut(), context_attribs.as_ptr())
        };
        if ctx.is_null() {
            return Err(Error::EGLCreateContext);
        }

        // Safe because a valid display and context is used, and the two null surfaces are not
        // used.
        let ret = unsafe { (egl_funcs.MakeCurrent)(display, null_mut(), null_mut(), ctx) };
        if ret == 0 {
            return Err(Error::EGLMakeCurrent);
        }

        // Safe because a valid cookie and set of callbacks is used and the result is checked for
        // error.
        let ret = unsafe {
            virgl_renderer_init(
                cookie as *mut c_void,
                (VIRGL_RENDERER_USE_EGL | VIRGL_RENDERER_USE_SURFACELESS | VIRGL_RENDERER_USE_GLES)
                    as i32,
                transmute(VIRGL_RENDERER_CALLBACKS),
            )
        };
        ret_to_res(ret)?;

        Ok(Renderer {
            no_sync_send: PhantomData,
            egl_funcs,
            display,
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
            egl_funcs: self.egl_funcs.clone(),
            no_sync_send: PhantomData,
        })
    }

    /// Imports a resource from an EGLImage.
    pub fn import_resource(
        &self,
        mut args: virgl_renderer_resource_create_args,
        image: &Image,
    ) -> Result<Resource> {
        let ret = unsafe { virgl_renderer_resource_import_eglimage(&mut args, image.image) };
        ret_to_res(ret)?;
        Ok(Resource {
            id: args.handle,
            backing_iovecs: Vec::new(),
            backing_mem: None,
            egl_funcs: self.egl_funcs.clone(),
            no_sync_send: PhantomData,
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

    /// Helper that creates a simple 2 dimensional resource with basic metadata.
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

    /// Creates an EGLImage from a DMA buffer.
    pub fn image_from_dmabuf(
        &self,
        fourcc: u32,
        width: u32,
        height: u32,
        fd: RawFd,
        offset: u32,
        stride: u32,
    ) -> Result<Image> {
        let mut attrs = [
            EGL_WIDTH as EGLint,
            width as EGLint,
            EGL_HEIGHT as EGLint,
            height as EGLint,
            EGL_LINUX_DRM_FOURCC_EXT as EGLint,
            fourcc as EGLint,
            EGL_DMA_BUF_PLANE0_FD_EXT as EGLint,
            fd as EGLint,
            EGL_DMA_BUF_PLANE0_OFFSET_EXT as EGLint,
            offset as EGLint,
            EGL_DMA_BUF_PLANE0_PITCH_EXT as EGLint,
            stride as EGLint,
            EGL_NONE as EGLint,
        ];

        let image = unsafe {
            (self.egl_funcs.CreateImageKHR)(
                self.display,
                0 as EGLContext,
                EGL_LINUX_DMA_BUF_EXT,
                null_mut() as EGLClientBuffer,
                attrs.as_mut_ptr(),
            )
        };

        if image.is_null() {
            return Err(Error::CreateImage);
        }

        Ok(Image {
            egl_funcs: self.egl_funcs.clone(),
            egl_dpy: self.display,
            image,
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

/// A wrapper of an EGLImage to manage its destruction.
pub struct Image {
    egl_funcs: EGLFunctions,
    egl_dpy: EGLDisplay,
    image: EGLImageKHR,
}

impl Drop for Image {
    fn drop(&mut self) {
        unsafe {
            (self.egl_funcs.DestroyImageKHR)(self.egl_dpy, self.image);
        }
    }
}

/// A DMABUF file descriptor handle and metadata returned from `Resource::export`.
#[derive(Debug)]
pub struct ExportedResource {
    /// The file descriptor that represents the DMABUF kernel object.
    pub dmabuf: File,
    /// The width in pixels of the exported resource.
    pub width: u32,
    /// The height in pixels of the exported resource.
    pub height: u32,
    /// The fourcc identifier for the format of the resource.
    pub fourcc: u32,
    /// Extra modifiers for the format.
    pub modifiers: u64,
    /// The number of bytes between successive rows in the exported resource.
    pub stride: u32,
    /// The number of bytes from the start of the exported resource to the first pixel.
    pub offset: u32,
}

/// A resource handle used by the renderer.
pub struct Resource {
    id: u32,
    backing_iovecs: Vec<VirglVec>,
    backing_mem: Option<GuestMemory>,
    egl_funcs: EGLFunctions,
    no_sync_send: PhantomData<*mut ()>,
}

impl Resource {
    /// Gets the ID assigned to this resource when it was created.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Retrieves metadata about this resource.
    pub fn get_info(&self) -> Result<ResourceInfo> {
        let mut res_info = Default::default();
        let ret = unsafe { virgl_renderer_resource_get_info(self.id as i32, &mut res_info) };
        ret_to_res(ret)?;
        Ok(res_info)
    }

    /// Performs an export of this resource so that it may be imported by other processes.
    pub fn export(&self) -> Result<ExportedResource> {
        let res_info = self.get_info()?;
        let mut fourcc = 0;
        let mut modifiers = 0;
        let mut fd = -1;
        let mut stride = 0;
        let mut offset = 0;
        // Always safe on the same thread with an already initialized virglrenderer.
        unsafe {
            virgl_renderer_force_ctx_0();
        }
        // These are trivially safe and always return successfully because we bind the context in
        // the previous line.
        let egl_dpy: EGLDisplay = unsafe { (self.egl_funcs.GetCurrentDisplay)() };
        let egl_ctx: EGLContext = unsafe { (self.egl_funcs.GetCurrentContext)() };

        // Safe because a valid display, context, and texture ID are given. The attribute list is
        // not needed. The result is checked to ensure the returned image is valid.
        let image = unsafe {
            (self.egl_funcs.CreateImageKHR)(
                egl_dpy,
                egl_ctx,
                EGL_GL_TEXTURE_2D_KHR,
                res_info.tex_id as EGLClientBuffer,
                null(),
            )
        };

        if image.is_null() {
            return Err(Error::CreateImage);
        }

        // Safe because the display and image are valid and each function call is checked for
        // success. The returned image parameters are stored in stack variables of the correct type.
        let export_success = unsafe {
            (self.egl_funcs.ExportDMABUFImageQueryMESA)(
                egl_dpy,
                image,
                &mut fourcc,
                null_mut(),
                &mut modifiers,
            ) != 0
                && (self.egl_funcs.ExportDRMImageMESA)(
                    egl_dpy,
                    image,
                    &mut fd,
                    &mut stride,
                    &mut offset,
                ) != 0
        };

        // Safe because we checked that the image was valid and nobody else owns it. The image does
        // not need to be around for the dmabuf to be valid.
        unsafe {
            (self.egl_funcs.DestroyImageKHR)(egl_dpy, image);
        }

        if !export_success || fd < 0 {
            return Err(Error::ExportedResourceDmabuf);
        }

        // Safe because the FD was just returned by a successful EGL call so it must be valid and
        // owned by us.
        let dmabuf = unsafe { File::from_raw_fd(fd) };
        Ok(ExportedResource {
            dmabuf,
            width: res_info.width,
            height: res_info.height,
            fourcc: fourcc as u32,
            modifiers,
            stride: stride as u32,
            offset: offset as u32,
        })
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
        let render = Renderer::init().expect("failed to initialize virglrenderer");
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
                Box3::new_2d(0, 5, 0, 1),
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
