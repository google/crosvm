// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[path = "generated/xlib.rs"]
#[allow(
    dead_code,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals
)]
mod xlib;

use std::cmp::max;
use std::ffi::c_void;
use std::ffi::CStr;
use std::ffi::CString;
use std::mem::transmute_copy;
use std::mem::zeroed;
use std::os::raw::c_ulong;
use std::ptr::null;
use std::ptr::null_mut;
use std::ptr::NonNull;
use std::rc::Rc;

use base::AsRawDescriptor;
use base::RawDescriptor;
use base::VolatileSlice;
use libc::shmat;
use libc::shmctl;
use libc::shmdt;
use libc::shmget;
use libc::IPC_CREAT;
use libc::IPC_PRIVATE;
use libc::IPC_RMID;
use linux_input_sys::virtio_input_event;

use crate::keycode_converter::KeycodeTranslator;
use crate::keycode_converter::KeycodeTypes;
use crate::DisplayT;
use crate::EventDeviceKind;
use crate::GpuDisplayError;
use crate::GpuDisplayEvents;
use crate::GpuDisplayFramebuffer;
use crate::GpuDisplayResult;
use crate::GpuDisplaySurface;
use crate::SurfaceType;
use crate::SysDisplayT;

const BUFFER_COUNT: usize = 2;

/// A wrapper for XFree that takes any type.
/// SAFETY: It is caller's responsibility to ensure that `t` is valid for the entire duration of the
/// call.
unsafe fn x_free<T>(t: *mut T) {
    xlib::XFree(t as *mut c_void);
}

#[derive(Clone)]
struct XDisplay(Rc<NonNull<xlib::Display>>);
impl Drop for XDisplay {
    fn drop(&mut self) {
        if Rc::strong_count(&self.0) == 1 {
            // TODO(b/315870313): Add safety comment
            #[allow(clippy::undocumented_unsafe_blocks)]
            unsafe {
                xlib::XCloseDisplay(self.as_ptr());
            }
        }
    }
}

impl XDisplay {
    /// Returns a pointer to the X display object.
    fn as_ptr(&self) -> *mut xlib::Display {
        self.0.as_ptr()
    }

    /// Sends any pending commands to the X server.
    fn flush(&self) {
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            xlib::XFlush(self.as_ptr());
        }
    }

    /// Returns true of the XShm extension is supported on this display.
    fn supports_shm(&self) -> bool {
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            xlib::XShmQueryExtension(self.as_ptr()) != 0
        }
    }

    /// Gets the default screen of this display.
    fn default_screen(&self) -> Option<XScreen> {
        Some(XScreen(NonNull::new(
            // TODO(b/315870313): Add safety comment
            #[allow(clippy::undocumented_unsafe_blocks)]
            unsafe {
                xlib::XDefaultScreenOfDisplay(self.as_ptr())
            },
        )?))
    }

    /// Blocks until the next event from the display is received and returns that event.
    ///
    /// Always flush before using this if any X commands where issued.
    fn next_event(&self) -> XEvent {
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            let mut ev = zeroed();
            xlib::XNextEvent(self.as_ptr(), &mut ev);
            ev.into()
        }
    }
}

impl AsRawDescriptor for XDisplay {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            xlib::XConnectionNumber(self.as_ptr())
        }
    }
}

struct XEvent(xlib::XEvent);
impl From<xlib::XEvent> for XEvent {
    fn from(ev: xlib::XEvent) -> XEvent {
        XEvent(ev)
    }
}

impl XEvent {
    fn any(&self) -> xlib::XAnyEvent {
        // All events have the same xany field.
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            self.0.xany
        }
    }

    fn type_(&self) -> u32 {
        // All events have the same type_ field.
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            self.0.type_ as u32
        }
    }

    fn window(&self) -> xlib::Window {
        self.any().window
    }

    // Some of the event types are dynamic so they need to be passed in.
    fn as_enum(&self, shm_complete_type: u32) -> XEventEnum {
        match self.type_() {
            xlib::KeyPress | xlib::KeyRelease => XEventEnum::KeyEvent(
                // TODO(b/315870313): Add safety comment
                #[allow(clippy::undocumented_unsafe_blocks)]
                unsafe {
                    self.0.xkey
                },
            ),
            xlib::ButtonPress => {
                // TODO(b/315870313): Add safety comment
                #[allow(clippy::undocumented_unsafe_blocks)]
                XEventEnum::ButtonEvent {
                    event: unsafe { self.0.xbutton },
                    pressed: true,
                }
            }
            xlib::ButtonRelease => {
                // TODO(b/315870313): Add safety comment
                #[allow(clippy::undocumented_unsafe_blocks)]
                XEventEnum::ButtonEvent {
                    event: unsafe { self.0.xbutton },
                    pressed: false,
                }
            }
            xlib::MotionNotify => XEventEnum::Motion(
                // TODO(b/315870313): Add safety comment
                #[allow(clippy::undocumented_unsafe_blocks)]
                unsafe {
                    self.0.xmotion
                },
            ),
            xlib::Expose => XEventEnum::Expose,
            xlib::ClientMessage => {
                XEventEnum::ClientMessage(
                    // TODO(b/315870313): Add safety comment
                    #[allow(clippy::undocumented_unsafe_blocks)]
                    unsafe {
                        self.0.xclient.data.l[0] as u64
                    },
                )
            }
            t if t == shm_complete_type => {
                // Because XShmCompletionEvent is not part of the XEvent union, simulate a union
                // with transmute_copy. If the shm_complete_type turns out to be bogus, some of the
                // data would be incorrect, but the common event fields would still be valid.
                // TODO(b/315870313): Add safety comment
                #[allow(clippy::undocumented_unsafe_blocks)]
                let ev_completion: xlib::XShmCompletionEvent = unsafe { transmute_copy(&self.0) };
                XEventEnum::ShmCompletionEvent(ev_completion.shmseg)
            }
            _ => XEventEnum::Unhandled,
        }
    }
}

enum XEventEnum {
    KeyEvent(xlib::XKeyEvent),
    ButtonEvent {
        event: xlib::XButtonEvent,
        pressed: bool,
    },
    Motion(xlib::XMotionEvent),
    Expose,
    ClientMessage(u64),
    ShmCompletionEvent(xlib::ShmSeg),
    // We don't care about most kinds of events,
    Unhandled,
}

struct XScreen(NonNull<xlib::Screen>);

impl XScreen {
    fn as_ptr(&self) -> *mut xlib::Screen {
        self.0.as_ptr()
    }

    /// Gets the screen number of this screen.
    fn get_number(&self) -> i32 {
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            xlib::XScreenNumberOfScreen(self.as_ptr())
        }
    }
}

struct Buffer {
    display: XDisplay,
    image: *mut xlib::XImage,
    /// The documentation says XShmSegmentInfo must last at least as long as the XImage, which
    /// probably precludes moving it as well.
    segment_info: Box<xlib::XShmSegmentInfo>,
    size: usize,
    in_use: bool,
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            xlib::XShmDetach(self.display.as_ptr(), self.segment_info.as_mut());
            xlib::XDestroyImage(self.image);
            shmdt(self.segment_info.shmaddr as *const _);
            shmctl(self.segment_info.shmid, IPC_RMID, null_mut());
        }
    }
}

impl Buffer {
    fn as_volatile_slice(&self) -> VolatileSlice {
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            VolatileSlice::from_raw_parts(self.segment_info.shmaddr as *mut _, self.size)
        }
    }

    fn stride(&self) -> usize {
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            (*self.image).bytes_per_line as usize
        }
    }

    fn bytes_per_pixel(&self) -> usize {
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        let bytes_per_pixel = unsafe { (*self.image).bits_per_pixel / 8 };
        bytes_per_pixel as usize
    }
}

// Surfaces here are equivalent to XWindows.
struct XSurface {
    display: XDisplay,
    visual: *mut xlib::Visual,
    depth: u32,
    window: xlib::Window,
    gc: xlib::GC,
    width: u32,
    height: u32,

    // Fields for handling the buffer swap chain.
    buffers: [Option<Buffer>; BUFFER_COUNT],
    buffer_next: usize,
    buffer_completion_type: u32,

    // Fields for handling window close requests
    delete_window_atom: c_ulong,
    close_requested: bool,
}

impl XSurface {
    /// Returns index of the current (on-screen) buffer, or 0 if there are no buffers.
    fn current_buffer(&self) -> usize {
        match self.buffer_next.checked_sub(1) {
            Some(i) => i,
            None => self.buffers.len() - 1,
        }
    }

    /// Draws the indicated buffer onto the screen.
    fn draw_buffer(&mut self, buffer_index: usize) {
        let buffer = match self.buffers.get_mut(buffer_index) {
            Some(Some(b)) => b,
            _ => {
                // If there is no buffer, that means the framebuffer was never set and we should
                // simply blank the window with arbitrary contents.
                // TODO(b/315870313): Add safety comment
                #[allow(clippy::undocumented_unsafe_blocks)]
                unsafe {
                    xlib::XClearWindow(self.display.as_ptr(), self.window);
                }
                return;
            }
        };
        // Mark the buffer as in use. When the XShmCompletionEvent occurs, this will get marked
        // false.
        buffer.in_use = true;
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            xlib::XShmPutImage(
                self.display.as_ptr(),
                self.window,
                self.gc,
                buffer.image,
                0, // src x
                0, // src y
                0, // dst x
                0, // dst y
                self.width,
                self.height,
                true as i32, /* send XShmCompletionEvent event */
            );
            self.display.flush();
        }
    }

    /// Gets the buffer at buffer_index, allocating it if necessary.
    fn lazily_allocate_buffer(&mut self, buffer_index: usize) -> Option<&Buffer> {
        if buffer_index >= self.buffers.len() {
            return None;
        }

        if self.buffers[buffer_index].is_some() {
            return self.buffers[buffer_index].as_ref();
        }
        // The buffer_index is valid and the buffer was never created, so we create it now.
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            // The docs for XShmCreateImage imply that XShmSegmentInfo must be allocated to live at
            // least as long as the XImage, which probably means it can't move either. Use a Box in
            // order to fulfill those requirements.
            let mut segment_info: Box<xlib::XShmSegmentInfo> = Box::new(zeroed());
            let image = xlib::XShmCreateImage(
                self.display.as_ptr(),
                self.visual,
                self.depth,
                xlib::ZPixmap as i32,
                null_mut(),
                segment_info.as_mut(),
                self.width,
                self.height,
            );
            if image.is_null() {
                return None;
            }
            let size = (*image)
                .bytes_per_line
                .checked_mul((*image).height)
                .unwrap();
            segment_info.shmid = shmget(IPC_PRIVATE, size as usize, IPC_CREAT | 0o777);
            if segment_info.shmid == -1 {
                xlib::XDestroyImage(image);
                return None;
            }
            segment_info.shmaddr = shmat(segment_info.shmid, null_mut(), 0) as *mut _;
            if segment_info.shmaddr == (-1isize) as *mut _ {
                xlib::XDestroyImage(image);
                shmctl(segment_info.shmid, IPC_RMID, null_mut());
                return None;
            }
            (*image).data = segment_info.shmaddr;
            segment_info.readOnly = true as i32;
            xlib::XShmAttach(self.display.as_ptr(), segment_info.as_mut());
            self.buffers[buffer_index] = Some(Buffer {
                display: self.display.clone(),
                image,
                segment_info,
                size: size as usize,
                in_use: false,
            });
            self.buffers[buffer_index].as_ref()
        }
    }
}

impl GpuDisplaySurface for XSurface {
    #[allow(clippy::unnecessary_cast)]
    fn surface_descriptor(&self) -> u64 {
        self.window as u64
    }

    fn framebuffer(&mut self) -> Option<GpuDisplayFramebuffer> {
        // Framebuffers are lazily allocated. If the next buffer is not in self.buffers, add it
        // using push_new_buffer and then get its memory.
        let framebuffer = self.lazily_allocate_buffer(self.buffer_next)?;
        let bytes_per_pixel = framebuffer.bytes_per_pixel() as u32;
        Some(GpuDisplayFramebuffer::new(
            framebuffer.as_volatile_slice(),
            framebuffer.stride() as u32,
            bytes_per_pixel,
        ))
    }

    fn next_buffer_in_use(&self) -> bool {
        // Buffers that have not yet been made are not in use, hence unwrap_or(false).
        self.buffers
            .get(self.buffer_next)
            .and_then(|b| Some(b.as_ref()?.in_use))
            .unwrap_or(false)
    }

    fn close_requested(&self) -> bool {
        self.close_requested
    }

    fn flip(&mut self) {
        let current_buffer_index = self.buffer_next;
        self.buffer_next = (self.buffer_next + 1) % self.buffers.len();
        self.draw_buffer(current_buffer_index);
    }

    fn buffer_completion_type(&self) -> u32 {
        self.buffer_completion_type
    }

    fn draw_current_buffer(&mut self) {
        self.draw_buffer(self.current_buffer())
    }

    fn on_client_message(&mut self, client_data: u64) {
        if client_data == self.delete_window_atom {
            self.close_requested = true;
        }
    }

    fn on_shm_completion(&mut self, shm_complete: u64) {
        for buffer in self.buffers.iter_mut().flatten() {
            if buffer.segment_info.shmseg == shm_complete {
                buffer.in_use = false;
            }
        }
    }
}

impl Drop for XSurface {
    fn drop(&mut self) {
        // SAFETY:
        // Safe given it should always be of the correct type.
        unsafe {
            xlib::XFreeGC(self.display.as_ptr(), self.gc);
            xlib::XDestroyWindow(self.display.as_ptr(), self.window);
        }
    }
}

pub struct DisplayX {
    display: XDisplay,
    screen: XScreen,
    visual: *mut xlib::Visual,
    keycode_translator: KeycodeTranslator,
    current_event: Option<XEvent>,
    mt_tracking_id: u16,
}

impl DisplayX {
    pub fn open_display(display: Option<&str>) -> GpuDisplayResult<DisplayX> {
        let display_cstr = match display.map(CString::new) {
            Some(Ok(s)) => Some(s),
            Some(Err(_)) => return Err(GpuDisplayError::InvalidPath),
            None => None,
        };

        let keycode_translator = KeycodeTranslator::new(KeycodeTypes::XkbScancode);

        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            // Open the display
            let display = match NonNull::new(xlib::XOpenDisplay(
                display_cstr
                    .as_ref()
                    .map(|s| CStr::as_ptr(s))
                    .unwrap_or(null()),
            )) {
                Some(display_ptr) => XDisplay(Rc::new(display_ptr)),
                None => return Err(GpuDisplayError::Connect),
            };

            // Check for required extension.
            if !display.supports_shm() {
                return Err(GpuDisplayError::RequiredFeature("xshm extension"));
            }

            let screen = display
                .default_screen()
                .ok_or(GpuDisplayError::Connect)
                .unwrap();
            let screen_number = screen.get_number();

            // Check for and save required visual (24-bit BGR for the default screen).
            let mut visual_info_template = xlib::XVisualInfo {
                visual: null_mut(),
                visualid: 0,
                screen: screen_number,
                depth: 24,
                class: 0,
                red_mask: 0x00ff0000,
                green_mask: 0x0000ff00,
                blue_mask: 0x000000ff,
                colormap_size: 0,
                bits_per_rgb: 0,
            };
            let visual_info = xlib::XGetVisualInfo(
                display.as_ptr(),
                (xlib::VisualScreenMask
                    | xlib::VisualDepthMask
                    | xlib::VisualRedMaskMask
                    | xlib::VisualGreenMaskMask
                    | xlib::VisualBlueMaskMask) as i64,
                &mut visual_info_template,
                &mut 0,
            );
            if visual_info.is_null() {
                return Err(GpuDisplayError::RequiredFeature("no matching visual"));
            }
            let visual = (*visual_info).visual;
            x_free(visual_info);

            Ok(DisplayX {
                display,
                screen,
                visual,
                keycode_translator,
                current_event: None,
                mt_tracking_id: 0,
            })
        }
    }

    pub fn next_tracking_id(&mut self) -> i32 {
        let cur_id: i32 = self.mt_tracking_id as i32;
        self.mt_tracking_id = self.mt_tracking_id.wrapping_add(1);
        cur_id
    }

    pub fn current_tracking_id(&self) -> i32 {
        self.mt_tracking_id as i32
    }
}

impl DisplayT for DisplayX {
    fn pending_events(&self) -> bool {
        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            xlib::XPending(self.display.as_ptr()) != 0
        }
    }

    fn flush(&self) {
        self.display.flush();
    }

    #[allow(clippy::unnecessary_cast)]
    fn next_event(&mut self) -> GpuDisplayResult<u64> {
        let ev = self.display.next_event();
        let descriptor = ev.window() as u64;
        self.current_event = Some(ev);
        Ok(descriptor)
    }

    fn handle_next_event(
        &mut self,
        surface: &mut Box<dyn GpuDisplaySurface>,
    ) -> Option<GpuDisplayEvents> {
        // Should not panic since the common layer only calls this when an event exists.
        let ev = self.current_event.take().unwrap();

        match ev.as_enum(surface.buffer_completion_type()) {
            XEventEnum::KeyEvent(key) => {
                if let Some(linux_keycode) = self.keycode_translator.translate(key.keycode) {
                    let events = vec![virtio_input_event::key(
                        linux_keycode,
                        key.type_ == xlib::KeyPress as i32,
                        false,
                    )];

                    return Some(GpuDisplayEvents {
                        events,
                        device_type: EventDeviceKind::Keyboard,
                    });
                }
            }
            XEventEnum::ButtonEvent {
                event: button_event,
                pressed,
            } => {
                // We only support a single touch from button 1 (left mouse button).
                // TODO(tutankhamen): slot is always 0, because all the input
                // events come from mouse device, i.e. only one touch is possible at a time.
                // Full MT protocol has to be implemented and properly wired later.
                if button_event.button & xlib::Button1 != 0 {
                    // The touch event *must* be first per the Linux input subsystem's guidance.
                    let mut events = vec![virtio_input_event::multitouch_slot(0)];

                    if pressed {
                        events.push(virtio_input_event::multitouch_tracking_id(
                            self.next_tracking_id(),
                        ));
                        events.push(virtio_input_event::multitouch_absolute_x(max(
                            0,
                            button_event.x,
                        )));
                        events.push(virtio_input_event::multitouch_absolute_y(max(
                            0,
                            button_event.y,
                        )));
                    } else {
                        events.push(virtio_input_event::multitouch_tracking_id(-1));
                    }

                    return Some(GpuDisplayEvents {
                        events,
                        device_type: EventDeviceKind::Touchscreen,
                    });
                }
            }
            XEventEnum::Motion(motion) => {
                if motion.state & xlib::Button1Mask != 0 {
                    let events = vec![
                        virtio_input_event::multitouch_slot(0),
                        virtio_input_event::multitouch_tracking_id(self.current_tracking_id()),
                        virtio_input_event::multitouch_absolute_x(max(0, motion.x)),
                        virtio_input_event::multitouch_absolute_y(max(0, motion.y)),
                    ];

                    return Some(GpuDisplayEvents {
                        events,
                        device_type: EventDeviceKind::Touchscreen,
                    });
                }
            }
            XEventEnum::Expose => surface.draw_current_buffer(),
            XEventEnum::ClientMessage(xclient_data) => {
                surface.on_client_message(xclient_data);
                return None;
            }
            XEventEnum::ShmCompletionEvent(shmseg) => {
                surface.on_shm_completion(shmseg);
                return None;
            }
            XEventEnum::Unhandled => return None,
        }

        None
    }

    fn create_surface(
        &mut self,
        parent_surface_id: Option<u32>,
        _surface_id: u32,
        width: u32,
        height: u32,
        _surf_type: SurfaceType,
    ) -> GpuDisplayResult<Box<dyn GpuDisplaySurface>> {
        if parent_surface_id.is_some() {
            return Err(GpuDisplayError::Unsupported);
        }

        // TODO(b/315870313): Add safety comment
        #[allow(clippy::undocumented_unsafe_blocks)]
        unsafe {
            let depth = xlib::XDefaultDepthOfScreen(self.screen.as_ptr()) as u32;

            let black_pixel = xlib::XBlackPixelOfScreen(self.screen.as_ptr());

            let window = xlib::XCreateSimpleWindow(
                self.display.as_ptr(),
                xlib::XRootWindowOfScreen(self.screen.as_ptr()),
                0,
                0,
                width,
                height,
                1,
                black_pixel,
                black_pixel,
            );

            let gc = xlib::XCreateGC(self.display.as_ptr(), window, 0, null_mut());

            // Because the event is from an extension, its type must be calculated dynamically.
            let buffer_completion_type =
                xlib::XShmGetEventBase(self.display.as_ptr()) as u32 + xlib::ShmCompletion;

            // Mark this window as responding to close requests.
            let mut delete_window_atom = xlib::XInternAtom(
                self.display.as_ptr(),
                CStr::from_bytes_with_nul(b"WM_DELETE_WINDOW\0")
                    .unwrap()
                    .as_ptr(),
                0,
            );
            xlib::XSetWMProtocols(self.display.as_ptr(), window, &mut delete_window_atom, 1);

            let size_hints = xlib::XAllocSizeHints();
            (*size_hints).flags = (xlib::PMinSize | xlib::PMaxSize) as i64;
            (*size_hints).max_width = width as i32;
            (*size_hints).min_width = width as i32;
            (*size_hints).max_height = height as i32;
            (*size_hints).min_height = height as i32;
            xlib::XSetWMNormalHints(self.display.as_ptr(), window, size_hints);
            x_free(size_hints);

            // We will use redraw the buffer when we are exposed.
            xlib::XSelectInput(
                self.display.as_ptr(),
                window,
                (xlib::ExposureMask
                    | xlib::KeyPressMask
                    | xlib::KeyReleaseMask
                    | xlib::ButtonPressMask
                    | xlib::ButtonReleaseMask
                    | xlib::PointerMotionMask) as i64,
            );

            xlib::XClearWindow(self.display.as_ptr(), window);
            xlib::XMapRaised(self.display.as_ptr(), window);

            // Flush everything so that the window is visible immediately.
            self.display.flush();

            Ok(Box::new(XSurface {
                display: self.display.clone(),
                visual: self.visual,
                depth,
                window,
                gc,
                width,
                height,
                buffers: Default::default(),
                buffer_next: 0,
                buffer_completion_type,
                delete_window_atom,
                close_requested: false,
            }))
        }
    }
}

impl SysDisplayT for DisplayX {}

impl AsRawDescriptor for DisplayX {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.display.as_raw_descriptor()
    }
}
