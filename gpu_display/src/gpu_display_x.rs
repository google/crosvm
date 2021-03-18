// Copyright 2019 The Chromium OS Authors. All rights reserved.
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

use linux_input_sys::virtio_input_event;
use std::cmp::max;
use std::collections::BTreeMap;
use std::ffi::{c_void, CStr, CString};
use std::mem::{transmute_copy, zeroed};
use std::num::NonZeroU32;
use std::os::raw::c_ulong;
use std::ptr::{null, null_mut, NonNull};
use std::rc::Rc;
use std::time::Duration;

use libc::{shmat, shmctl, shmdt, shmget, IPC_CREAT, IPC_PRIVATE, IPC_RMID};

use crate::{
    keycode_converter::KeycodeTranslator, keycode_converter::KeycodeTypes, DisplayT, EventDevice,
    EventDeviceKind, GpuDisplayError, GpuDisplayFramebuffer,
};

use base::{error, AsRawDescriptor, EventType, PollToken, RawDescriptor, WaitContext};
use data_model::VolatileSlice;

const BUFFER_COUNT: usize = 2;

type ObjectId = NonZeroU32;

/// A wrapper for XFree that takes any type.
unsafe fn x_free<T>(t: *mut T) {
    xlib::XFree(t as *mut c_void);
}

#[derive(Clone)]
struct XDisplay(Rc<NonNull<xlib::Display>>);
impl Drop for XDisplay {
    fn drop(&mut self) {
        if Rc::strong_count(&self.0) == 1 {
            unsafe {
                xlib::XCloseDisplay(self.as_ptr());
            }
        }
    }
}

impl XDisplay {
    fn as_ptr(&self) -> *mut xlib::Display {
        self.0.as_ptr()
    }

    /// Returns true of the XShm extension is supported on this display.
    fn supports_shm(&self) -> bool {
        unsafe { xlib::XShmQueryExtension(self.as_ptr()) != 0 }
    }

    /// Gets the default screen of this display.
    fn default_screen(&self) -> Option<XScreen> {
        Some(XScreen(NonNull::new(unsafe {
            xlib::XDefaultScreenOfDisplay(self.as_ptr())
        })?))
    }

    /// Returns true if there are events that are on the queue.
    fn pending_events(&self) -> bool {
        unsafe { xlib::XPending(self.as_ptr()) != 0 }
    }

    /// Sends any pending commands to the X server.
    fn flush(&self) {
        unsafe {
            xlib::XFlush(self.as_ptr());
        }
    }

    /// Blocks until the next event from the display is received and returns that event.
    ///
    /// Always flush before using this if any X commands where issued.
    fn next_event(&self) -> XEvent {
        unsafe {
            let mut ev = zeroed();
            xlib::XNextEvent(self.as_ptr(), &mut ev);
            ev.into()
        }
    }
}

impl AsRawDescriptor for XDisplay {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        unsafe { xlib::XConnectionNumber(self.as_ptr()) }
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
        unsafe { self.0.xany }
    }

    fn type_(&self) -> u32 {
        // All events have the same type_ field.
        unsafe { self.0.type_ as u32 }
    }

    fn window(&self) -> xlib::Window {
        self.any().window
    }

    // Some of the event types are dynamic so they need to be passed in.
    fn as_enum(&self, shm_complete_type: u32) -> XEventEnum {
        match self.type_() {
            xlib::KeyPress | xlib::KeyRelease => XEventEnum::KeyEvent(unsafe { self.0.xkey }),
            xlib::ButtonPress => XEventEnum::ButtonEvent {
                event: unsafe { self.0.xbutton },
                pressed: true,
            },
            xlib::ButtonRelease => XEventEnum::ButtonEvent {
                event: unsafe { self.0.xbutton },
                pressed: false,
            },
            xlib::MotionNotify => XEventEnum::Motion(unsafe { self.0.xmotion }),
            xlib::Expose => XEventEnum::Expose,
            xlib::ClientMessage => {
                XEventEnum::ClientMessage(unsafe { self.0.xclient.data.l[0] as u64 })
            }
            t if t == shm_complete_type => {
                // Because XShmCompletionEvent is not part of the XEvent union, simulate a union
                // with transmute_copy. If the shm_complete_type turns out to be bogus, some of the
                // data would be incorrect, but the common event fields would still be valid.
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
        unsafe { xlib::XScreenNumberOfScreen(self.as_ptr()) }
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
        unsafe { VolatileSlice::from_raw_parts(self.segment_info.shmaddr as *mut _, self.size) }
    }

    fn stride(&self) -> usize {
        unsafe { (*self.image).bytes_per_line as usize }
    }

    fn bytes_per_pixel(&self) -> usize {
        let bytes_per_pixel = unsafe { (*self.image).bits_per_pixel / 8 };
        bytes_per_pixel as usize
    }
}

// Surfaces here are equivalent to XWindows.
struct Surface {
    display: XDisplay,
    visual: *mut xlib::Visual,
    depth: u32,
    window: xlib::Window,
    gc: xlib::GC,
    width: u32,
    height: u32,
    event_devices: BTreeMap<ObjectId, EventDevice>,
    keycode_translator: KeycodeTranslator,

    // Fields for handling the buffer swap chain.
    buffers: [Option<Buffer>; BUFFER_COUNT],
    buffer_next: usize,
    buffer_completion_type: u32,

    // Fields for handling window close requests
    delete_window_atom: c_ulong,
    close_requested: bool,
}

impl Surface {
    fn create(
        display: XDisplay,
        screen: &XScreen,
        visual: *mut xlib::Visual,
        width: u32,
        height: u32,
    ) -> Surface {
        let keycode_translator = KeycodeTranslator::new(KeycodeTypes::XkbScancode);
        unsafe {
            let depth = xlib::XDefaultDepthOfScreen(screen.as_ptr()) as u32;

            let black_pixel = xlib::XBlackPixelOfScreen(screen.as_ptr());

            let window = xlib::XCreateSimpleWindow(
                display.as_ptr(),
                xlib::XRootWindowOfScreen(screen.as_ptr()),
                0,
                0,
                width,
                height,
                1,
                black_pixel,
                black_pixel,
            );

            let gc = xlib::XCreateGC(display.as_ptr(), window, 0, null_mut());

            // Because the event is from an extension, its type must be calculated dynamically.
            let buffer_completion_type =
                xlib::XShmGetEventBase(display.as_ptr()) as u32 + xlib::ShmCompletion;

            // Mark this window as responding to close requests.
            let mut delete_window_atom = xlib::XInternAtom(
                display.as_ptr(),
                CStr::from_bytes_with_nul(b"WM_DELETE_WINDOW\0")
                    .unwrap()
                    .as_ptr(),
                0,
            );
            xlib::XSetWMProtocols(display.as_ptr(), window, &mut delete_window_atom, 1);

            let size_hints = xlib::XAllocSizeHints();
            (*size_hints).flags = (xlib::PMinSize | xlib::PMaxSize) as i64;
            (*size_hints).max_width = width as i32;
            (*size_hints).min_width = width as i32;
            (*size_hints).max_height = height as i32;
            (*size_hints).min_height = height as i32;
            xlib::XSetWMNormalHints(display.as_ptr(), window, size_hints);
            x_free(size_hints);

            // We will use redraw the buffer when we are exposed.
            xlib::XSelectInput(
                display.as_ptr(),
                window,
                (xlib::ExposureMask
                    | xlib::KeyPressMask
                    | xlib::KeyReleaseMask
                    | xlib::ButtonPressMask
                    | xlib::ButtonReleaseMask
                    | xlib::PointerMotionMask) as i64,
            );

            xlib::XClearWindow(display.as_ptr(), window);
            xlib::XMapRaised(display.as_ptr(), window);

            // Flush everything so that the window is visible immediately.
            display.flush();

            Surface {
                display,
                visual,
                depth,
                window,
                gc,
                width,
                height,
                event_devices: Default::default(),
                keycode_translator,
                buffers: Default::default(),
                buffer_next: 0,
                buffer_completion_type,
                delete_window_atom,
                close_requested: false,
            }
        }
    }

    /// Returns index of the current (on-screen) buffer, or 0 if there are no buffers.
    fn current_buffer(&self) -> usize {
        match self.buffer_next.checked_sub(1) {
            Some(i) => i,
            None => self.buffers.len() - 1,
        }
    }

    fn dispatch_to_event_devices(
        &mut self,
        events: &[virtio_input_event],
        device_type: EventDeviceKind,
    ) {
        for event_device in self.event_devices.values_mut() {
            if event_device.kind() != device_type {
                continue;
            }
            if let Err(e) = event_device.send_report(events.iter().cloned()) {
                error!("error sending events to event device: {}", e);
            }
        }
    }

    fn handle_event(&mut self, ev: XEvent) {
        match ev.as_enum(self.buffer_completion_type) {
            XEventEnum::KeyEvent(key) => {
                if let Some(linux_keycode) = self.keycode_translator.translate(key.keycode) {
                    let events = &[virtio_input_event::key(
                        linux_keycode,
                        key.type_ == xlib::KeyPress as i32,
                    )];
                    self.dispatch_to_event_devices(events, EventDeviceKind::Keyboard);
                }
            }
            XEventEnum::ButtonEvent {
                event: button_event,
                pressed,
            } => {
                // We only support a single touch from button 1 (left mouse button).
                if button_event.button & xlib::Button1 != 0 {
                    // The touch event *must* be first per the Linux input subsystem's guidance.
                    let events = &[
                        virtio_input_event::touch(pressed),
                        virtio_input_event::absolute_x(max(0, button_event.x)),
                        virtio_input_event::absolute_y(max(0, button_event.y)),
                    ];
                    self.dispatch_to_event_devices(events, EventDeviceKind::Touchscreen);
                }
            }
            XEventEnum::Motion(motion) => {
                if motion.state & xlib::Button1Mask != 0 {
                    let events = &[
                        virtio_input_event::touch(true),
                        virtio_input_event::absolute_x(max(0, motion.x)),
                        virtio_input_event::absolute_y(max(0, motion.y)),
                    ];
                    self.dispatch_to_event_devices(events, EventDeviceKind::Touchscreen);
                }
            }
            XEventEnum::Expose => self.draw_buffer(self.current_buffer()),
            XEventEnum::ClientMessage(xclient_data) => {
                if xclient_data == self.delete_window_atom {
                    self.close_requested = true;
                }
            }
            XEventEnum::ShmCompletionEvent(shmseg) => {
                // Find the buffer associated with this event and mark it as not in use.
                for buffer_opt in self.buffers.iter_mut() {
                    if let Some(buffer) = buffer_opt {
                        if buffer.segment_info.shmseg == shmseg {
                            buffer.in_use = false;
                        }
                    }
                }
            }
            XEventEnum::Unhandled => {}
        }
    }

    /// Draws the indicated buffer onto the screen.
    fn draw_buffer(&mut self, buffer_index: usize) {
        let buffer = match self.buffers.get_mut(buffer_index) {
            Some(Some(b)) => b,
            _ => {
                // If there is no buffer, that means the framebuffer was never set and we should
                // simply blank the window with arbitrary contents.
                unsafe {
                    xlib::XClearWindow(self.display.as_ptr(), self.window);
                }
                return;
            }
        };
        // Mark the buffer as in use. When the XShmCompletionEvent occurs, this will get marked
        // false.
        buffer.in_use = true;
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

    /// Gets the next framebuffer, allocating if necessary.
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

    /// True if the next buffer is in use because of an XShmPutImage call.
    fn next_buffer_in_use(&self) -> bool {
        // Buffers that have not yet been made are not in use, hence unwrap_or(false).
        self.buffers
            .get(self.buffer_next)
            .and_then(|b| Some(b.as_ref()?.in_use))
            .unwrap_or(false)
    }

    /// Puts the next buffer onto the screen and sets the next buffer in the swap chain.
    fn flip(&mut self) {
        let current_buffer_index = self.buffer_next;
        self.buffer_next = (self.buffer_next + 1) % self.buffers.len();
        self.draw_buffer(current_buffer_index);
    }
}

impl Drop for Surface {
    fn drop(&mut self) {
        // Safe given it should always be of the correct type.
        unsafe {
            xlib::XFreeGC(self.display.as_ptr(), self.gc);
            xlib::XDestroyWindow(self.display.as_ptr(), self.window);
        }
    }
}

#[derive(PollToken)]
enum DisplayXPollToken {
    Display,
    EventDevice { event_device_id: u32 },
}

pub struct DisplayX {
    wait_ctx: WaitContext<DisplayXPollToken>,
    display: XDisplay,
    screen: XScreen,
    visual: *mut xlib::Visual,
    next_id: ObjectId,
    surfaces: BTreeMap<ObjectId, Surface>,
    event_devices: BTreeMap<ObjectId, EventDevice>,
}

impl DisplayX {
    pub fn open_display(display: Option<&str>) -> Result<DisplayX, GpuDisplayError> {
        let wait_ctx = WaitContext::new().map_err(|_| GpuDisplayError::Allocate)?;

        let display_cstr = match display.map(CString::new) {
            Some(Ok(s)) => Some(s),
            Some(Err(_)) => return Err(GpuDisplayError::InvalidPath),
            None => None,
        };

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

            wait_ctx
                .add(&display, DisplayXPollToken::Display)
                .map_err(|_| GpuDisplayError::Allocate)?;

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
                wait_ctx,
                display,
                screen,
                visual,
                next_id: ObjectId::new(1).unwrap(),
                surfaces: Default::default(),
                event_devices: Default::default(),
            })
        }
    }

    fn surface_ref(&self, surface_id: u32) -> Option<&Surface> {
        ObjectId::new(surface_id).and_then(move |id| self.surfaces.get(&id))
    }

    fn surface_mut(&mut self, surface_id: u32) -> Option<&mut Surface> {
        ObjectId::new(surface_id).and_then(move |id| self.surfaces.get_mut(&id))
    }

    fn event_device(&self, event_device_id: u32) -> Option<&EventDevice> {
        ObjectId::new(event_device_id).and_then(move |id| self.event_devices.get(&id))
    }

    fn event_device_mut(&mut self, event_device_id: u32) -> Option<&mut EventDevice> {
        ObjectId::new(event_device_id).and_then(move |id| self.event_devices.get_mut(&id))
    }

    fn handle_event(&mut self, ev: XEvent) {
        let window = ev.window();
        for surface in self.surfaces.values_mut() {
            if surface.window != window {
                continue;
            }
            surface.handle_event(ev);
            return;
        }
    }

    fn dispatch_display_events(&mut self) {
        loop {
            self.display.flush();
            if !self.display.pending_events() {
                break;
            }
            let ev = self.display.next_event();
            self.handle_event(ev);
        }
    }

    fn handle_event_device(&mut self, event_device_id: u32) {
        if let Some(event_device) = self.event_device(event_device_id) {
            // TODO(zachr): decode the event and forward to the device.
            let _ = event_device.recv_event_encoded();
        }
    }

    fn handle_poll_ctx(&mut self) -> base::Result<()> {
        let wait_events = self.wait_ctx.wait_timeout(Duration::default())?;
        for wait_event in wait_events.iter().filter(|e| e.is_writable) {
            if let DisplayXPollToken::EventDevice { event_device_id } = wait_event.token {
                if let Some(event_device) = self.event_device_mut(event_device_id) {
                    if !event_device.flush_buffered_events()? {
                        continue;
                    }
                }
                // Although this looks exactly like the previous if-block, we need to reborrow self
                // as immutable in order to make use of self.wait_ctx.
                if let Some(event_device) = self.event_device(event_device_id) {
                    self.wait_ctx.modify(
                        event_device,
                        EventType::Read,
                        DisplayXPollToken::EventDevice { event_device_id },
                    )?;
                }
            }
        }

        for wait_event in wait_events.iter().filter(|e| e.is_readable) {
            match wait_event.token {
                DisplayXPollToken::Display => self.dispatch_display_events(),
                DisplayXPollToken::EventDevice { event_device_id } => {
                    self.handle_event_device(event_device_id)
                }
            }
        }

        Ok(())
    }
}

impl DisplayT for DisplayX {
    fn dispatch_events(&mut self) {
        if let Err(e) = self.handle_poll_ctx() {
            error!("failed to dispatch events: {}", e);
        }
    }

    fn create_surface(
        &mut self,
        parent_surface_id: Option<u32>,
        width: u32,
        height: u32,
    ) -> Result<u32, GpuDisplayError> {
        if parent_surface_id.is_some() {
            return Err(GpuDisplayError::Unsupported);
        }

        let new_surface = Surface::create(
            self.display.clone(),
            &self.screen,
            self.visual,
            width,
            height,
        );
        let new_surface_id = self.next_id;
        self.surfaces.insert(new_surface_id, new_surface);
        self.next_id = ObjectId::new(self.next_id.get() + 1).unwrap();

        Ok(new_surface_id.get())
    }

    fn release_surface(&mut self, surface_id: u32) {
        if let Some(mut surface) =
            ObjectId::new(surface_id).and_then(|id| self.surfaces.remove(&id))
        {
            self.event_devices.append(&mut surface.event_devices);
        }
    }

    fn framebuffer(&mut self, surface_id: u32) -> Option<GpuDisplayFramebuffer> {
        self.surface_mut(surface_id).and_then(|s| s.framebuffer())
    }

    fn next_buffer_in_use(&self, surface_id: u32) -> bool {
        self.surface_ref(surface_id)
            .map(|s| s.next_buffer_in_use())
            .unwrap_or(false)
    }

    fn flip(&mut self, surface_id: u32) {
        if let Some(surface) = self.surface_mut(surface_id) {
            surface.flip()
        }
    }

    fn close_requested(&self, surface_id: u32) -> bool {
        self.surface_ref(surface_id)
            .map(|s| s.close_requested)
            .unwrap_or(true)
    }

    #[allow(unused_variables)]
    fn import_dmabuf(
        &mut self,
        fd: RawDescriptor,
        offset: u32,
        stride: u32,
        modifiers: u64,
        width: u32,
        height: u32,
        fourcc: u32,
    ) -> Result<u32, GpuDisplayError> {
        Err(GpuDisplayError::Unsupported)
    }
    #[allow(unused_variables)]
    fn release_import(&mut self, import_id: u32) {
        // unsupported
    }
    #[allow(unused_variables)]
    fn commit(&mut self, surface_id: u32) {
        // unsupported
    }
    #[allow(unused_variables)]
    fn flip_to(&mut self, surface_id: u32, import_id: u32) {
        // unsupported
    }
    #[allow(unused_variables)]
    fn set_position(&mut self, surface_id: u32, x: u32, y: u32) {
        // unsupported
    }

    fn import_event_device(&mut self, event_device: EventDevice) -> Result<u32, GpuDisplayError> {
        let new_event_device_id = self.next_id;

        self.wait_ctx
            .add(
                &event_device,
                DisplayXPollToken::EventDevice {
                    event_device_id: new_event_device_id.get(),
                },
            )
            .map_err(|_| GpuDisplayError::Allocate)?;

        self.event_devices.insert(new_event_device_id, event_device);
        self.next_id = ObjectId::new(self.next_id.get() + 1).unwrap();

        Ok(new_event_device_id.get())
    }

    fn release_event_device(&mut self, event_device_id: u32) {
        ObjectId::new(event_device_id).and_then(|id| self.event_devices.remove(&id));
    }

    fn attach_event_device(&mut self, surface_id: u32, event_device_id: u32) {
        let event_device_id = match ObjectId::new(event_device_id) {
            Some(id) => id,
            None => return,
        };
        let surface_id = match ObjectId::new(surface_id) {
            Some(id) => id,
            None => return,
        };
        let surface = self.surfaces.get_mut(&surface_id).unwrap();
        let event_device = self.event_devices.remove(&event_device_id).unwrap();
        surface.event_devices.insert(event_device_id, event_device);
    }
}

impl AsRawDescriptor for DisplayX {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.wait_ctx.as_raw_descriptor()
    }
}
