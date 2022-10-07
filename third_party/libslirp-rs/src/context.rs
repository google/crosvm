// Documentation for code maintainers:
//
// Closure pointers as *c_void
// -----------------
// This file interfaces with Slirp's callbacks extensively. As part of that, it passes Rust closures
// to callbacks as opaque data, and those closures are executed during a call into Slirp; in other
// words, the sequence of events looks like this:
//    1. Rust creates a closure C.
//    2. Rust calls Slirp and gives it callback CB (a Rust func.), and opaque data that contains C.
//    3. (0...n times) CB runs and unpacks C from the opaque data.
//          a. CB calls C.
//    4. The call from #2 completes.
// Closures are represented as trait objects, and trait object references are wide/fat pointers
// (2x machine pointer size) that contain pointers to the closure's struct & its vtable. Since wide
// pointers are obviously too large to fit into a *mut c_void (this is the opaque data), we cannot
// pass them directly. Luckily, wide pointers themselves are simple sized data structures, so we can
// pass a reference to the wide pointer as a *mut c_void; in other words, the way to pass a closure
// is to cast &mut &mut some_closure into a *mut c_void. We can then unpack this easily and call
// the closure.
//
// Why is CallbackHandler involved in the outbound (guest -> host) packet path?
// ----------------------------------------------------------------------------
// In short, ownership. Since the CallbackHandler is responsible for writing to the guest, it must
// own the connection/stream that is attached to the guest. Because CallbackHandler owns the
// connection, it would be significantly complicated to have any other entity read from the
// connection.
//
// Safety assumptions
// ------------------
// Most statements explaining the safety of unsafe code depend on libslirp behaving in a safe
// & expected manner. Given that libslirp is has experienced CVEs related to safety problems,
// these statements should be taken with a grain of salt. Consumers of this library are STRONGLY
// RECOMMENDED to run this code in a separate process with strong sandboxing.

// Some bindings of the libslirp API are used, but we want to keep them for completeness
#![allow(dead_code)]

use std::ffi::CStr;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::ops;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::slice;
use std::str;

use base::error;
use base::RawDescriptor;
use libslirp_sys::*;

use crate::Error;
use crate::Result;

/// An instance of libslirp is represented by a Context, which provides methods that consumers use
/// to interact with Slirp. The Context is also where consumers register their CallbackHandler,
/// which provides required functions to libslirp, and allows libslirp to communicate back to the
/// consumer. The Context is intended to be used from an event loop which handles polling for IO
/// from the guest and host (see `Context.pollfds_fill`, `Context.pollfds_poll`, and
/// `Context.handle_guest_input`).
///
/// Example data flow for an outbound packet:
/// 1. Context `ctx` created with CallbackHandler `h`. An event loop (henceforth the slirp loop) is
///    started, which polls for packets from the guest, and from the outside world (sockets).
/// 2. Guest emits an ethernet frame. The consumer makes this frame available through their
///    implementation of `h.read_from_guest`.
/// 3. The slirp loop is notified there is a packet from the guest, and invokes
///    `ctx.handle_guest_input`. `ctx.handle_guest_input` reads all currently available packets
///    using `h.read_from_guest` & returns back to the slirp loop.
///
/// Example data flow for an inbound packet:
/// 1. Same as above.
/// 2. An ethernet frame arrives to the host, and gets demuxed by the host kernel into one of the
///    host sockets opened by libslirp.
/// 3. The slirp loop receives a notification that data has arrived on one of the libslirp sockets,
///    and invokes `ctx.pollfds_poll` to notify libslirp.
///    a. libslirp calls into `h.send_packet` to deliver the packet to the consumer.
pub struct Context<H> {
    slirp: *mut Slirp,
    callbacks: SlirpCb,
    callback_handler: H,
}

impl<H> Drop for Context<H> {
    fn drop(&mut self) {
        // Safe because self.context is guaranteed to be valid or null upon construction.
        if !self.slirp.is_null() {
            unsafe {
                slirp_cleanup(self.slirp);
            }
        }
    }
}

/// `CallbackHandler` is the safe Rust interface for the Slirp callbacks. Consumers of Slirp MUST
/// implement this interface to handle the required callbacks from Slirp.
///
/// ## Notes about timers
/// To send NDP router advertisements on IPv6, libslirp uses a timer. If IPv6 support is not
/// needed, the timer callbacks can be left unimplemented.
///
/// Example data flow for timer creation/modification (`timer_new`/`timer_mod`/`timer_free`):
/// 1. libslirp calls into `timer_new` to request a new timer. `timer_new` creates some entity to
///    represent the timer and boxes it. A pointer to that boxed entity is returned to libslirp,
///    and is how libslirp will refer to the timer in the future.
/// 2. The timer's expire time can be changed when timer_mod is called by libslirp. A pointer to the
///    boxed timer is passed in by libslirp.
/// 3. The implementor of `CallbackHandler` is responsible for ensuring that the timer's callback as
///    provided in `timer_new` is invoked at/after the `expire_time`.
/// 4. libslirp will free timers using `timer_free` when `slirp_cleanup` runs.
///
/// libslirp never does anything with the timer pointer beyond passing it to/from the the functions
/// in `CallbackHandler`.
pub trait CallbackHandler {
    type Timer;

    /// Returns a timestamp in nanoseconds relative to the moment that this instance of libslirp
    /// started running.
    fn clock_get_ns(&mut self) -> i64;

    fn send_packet(&mut self, buf: &[u8]) -> io::Result<usize>;

    /// Gets an iterator of timers (as raw descriptors) so they can be awaited with a suitable
    /// polling function as part of libslirp's main consumer loop.
    fn get_timers<'a>(&'a self) -> Box<dyn Iterator<Item = &RawDescriptor> + 'a>;

    /// Runs the handler function for a specific timer.
    fn execute_timer(&mut self, timer: RawDescriptor);

    // Normally in crosvm we refer to FDs as descriptors, because FDs are platform specific;
    // however, this interface is very close to the libslirp FFI, and libslirp follows the Linux
    // philosophy of everything is an FD. Since even Windows refers to FDs in WSAPoll, keeping FD
    // as a concept here helps keep terminology consistent between crosvm code interfacing with
    // libslirp, and libslirp itself.
    fn register_poll_fd(&mut self, fd: i32);
    fn unregister_poll_fd(&mut self, fd: i32);

    fn guest_error(&mut self, msg: &str);

    fn notify(&mut self);

    fn timer_new(&mut self, callback: Box<dyn FnMut()>) -> Box<Self::Timer>;

    /// Sets a timer to expire in expire_time_ms - (clock_get_ns() (as ms).
    fn timer_mod(&mut self, timer: &mut Self::Timer, expire_time: i64);

    fn timer_free(&mut self, timer: Box<Self::Timer>);

    fn begin_read_from_guest(&mut self) -> io::Result<()>;

    fn end_read_from_guest(&mut self) -> io::Result<&[u8]>;
}

extern "C" fn write_handler_callback(buf: *const c_void, len: usize, opaque: *mut c_void) -> isize {
    // Safe because we pass in opaque as exactly this type.
    let closure = unsafe { &mut *(opaque as *mut &mut dyn FnMut(&[u8]) -> isize) };

    // Safe because libslirp provides us with a valid buffer & that buffer's length.
    let slice = unsafe { slice::from_raw_parts(buf as *const u8, len) };

    closure(slice)
}

extern "C" fn read_handler_callback(buf: *mut c_void, len: usize, opaque: *mut c_void) -> isize {
    // Safe because we pass in opaque as exactly this type.
    let closure = unsafe { &mut *(opaque as *mut &mut dyn FnMut(&mut [u8]) -> isize) };

    // Safe because libslirp provides us with a valid buffer & that buffer's length.
    let slice = unsafe { slice::from_raw_parts_mut(buf as *mut u8, len) };

    closure(slice)
}

/// Represents poll events in libslirp's format (e.g. `struct pollfd.[r]events`).
#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct PollEvents(usize);

impl PollEvents {
    pub fn empty() -> Self {
        PollEvents(0)
    }
    pub fn poll_in() -> Self {
        PollEvents(SLIRP_POLL_IN as usize)
    }
    pub fn poll_out() -> Self {
        PollEvents(SLIRP_POLL_OUT as usize)
    }
    pub fn poll_pri() -> Self {
        PollEvents(SLIRP_POLL_PRI as usize)
    }
    pub fn poll_err() -> Self {
        PollEvents(SLIRP_POLL_ERR as usize)
    }
    pub fn poll_hup() -> Self {
        PollEvents(SLIRP_POLL_HUP as usize)
    }
    pub fn contains<T: Into<Self>>(&self, other: T) -> bool {
        let other = other.into();
        (*self & other) == other
    }
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
    pub fn has_in(&self) -> bool {
        self.contains(PollEvents::poll_in())
    }
    pub fn has_out(&self) -> bool {
        self.contains(PollEvents::poll_out())
    }
    pub fn has_pri(&self) -> bool {
        self.contains(PollEvents::poll_pri())
    }
    pub fn has_err(&self) -> bool {
        self.contains(PollEvents::poll_err())
    }
    pub fn has_hup(&self) -> bool {
        self.contains(PollEvents::poll_hup())
    }
}

impl<T: Into<PollEvents>> ops::BitAnd<T> for PollEvents {
    type Output = PollEvents;

    fn bitand(self, other: T) -> PollEvents {
        PollEvents(self.0 & other.into().0)
    }
}

impl<T: Into<PollEvents>> ops::BitOr<T> for PollEvents {
    type Output = PollEvents;

    fn bitor(self, other: T) -> PollEvents {
        PollEvents(self.0 | other.into().0)
    }
}

impl<T: Into<PollEvents>> ops::BitOrAssign<T> for PollEvents {
    fn bitor_assign(&mut self, other: T) {
        self.0 |= other.into().0;
    }
}

impl fmt::Debug for PollEvents {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut one = false;
        let flags = [
            (PollEvents(SLIRP_POLL_IN as usize), "IN"),
            (PollEvents(SLIRP_POLL_OUT as usize), "OUT"),
            (PollEvents(SLIRP_POLL_PRI as usize), "PRI"),
            (PollEvents(SLIRP_POLL_ERR as usize), "ERR"),
            (PollEvents(SLIRP_POLL_HUP as usize), "HUP"),
        ];

        for &(flag, msg) in &flags {
            if self.contains(flag) {
                if one {
                    write!(fmt, " | ")?
                }
                write!(fmt, "{}", msg)?;

                one = true
            }
        }

        if !one {
            fmt.write_str("(empty)")?;
        }

        Ok(())
    }
}

extern "C" fn add_poll_handler_callback(fd: c_int, events: c_int, opaque: *mut c_void) -> c_int {
    // Safe because we pass in opaque as exactly this type.
    let closure = unsafe { &mut *(opaque as *mut &mut dyn FnMut(i32, PollEvents) -> i32) };

    closure(fd, PollEvents(events as usize))
}

extern "C" fn get_revents_handler_callback(idx: c_int, opaque: *mut c_void) -> c_int {
    // Safe because we pass in opaque as exactly this type.
    let closure = unsafe { &mut *(opaque as *mut &mut dyn FnMut(i32) -> PollEvents) };

    closure(idx).0 as c_int
}

/// Inbound packets from libslirp are delivered to this handler, which passes them on to the
/// Context's CallbackHandler for forwarding to the guest.
extern "C" fn send_packet_handler<H: CallbackHandler>(
    buf: *const c_void,
    len: usize,
    opaque: *mut c_void,
) -> isize {
    // Safe because libslirp gives us a valid buffer & that buffer's length.
    let slice = unsafe { slice::from_raw_parts(buf as *const u8, len) };

    // Safe because we pass in opaque as exactly this type when constructing the Slirp object.
    let res = unsafe {
        (*(opaque as *mut Context<H>))
            .callback_handler
            .send_packet(slice)
    };

    match res {
        Ok(res) => res as isize,
        Err(e) => {
            error!("send_packet error: {}", e);
            -1
        }
    }
}

extern "C" fn guest_error_handler<H: CallbackHandler>(msg: *const c_char, opaque: *mut c_void) {
    // Safe because libslirp gives us a valid C string representing the error message.
    let msg = str::from_utf8(unsafe { CStr::from_ptr(msg) }.to_bytes()).unwrap_or("");

    // Safe because we pass in opaque as exactly this type when constructing the Slirp object.
    unsafe {
        (*(opaque as *mut Context<H>))
            .callback_handler
            .guest_error(msg)
    }
}

extern "C" fn clock_get_ns_handler<H: CallbackHandler>(opaque: *mut c_void) -> i64 {
    // Safe because we pass in opaque as exactly this type when constructing the Slirp object.
    unsafe {
        (*(opaque as *mut Context<H>))
            .callback_handler
            .clock_get_ns()
    }
}

extern "C" fn timer_new_handler<H: CallbackHandler>(
    cb: SlirpTimerCb,
    cb_opaque: *mut c_void,
    opaque: *mut c_void,
) -> *mut c_void {
    let callback = Box::new(move || {
        if let Some(cb) = cb {
            // Safe because libslirp gives us a valid callback function to call.
            unsafe {
                cb(cb_opaque);
            }
        }
    });

    // Safe because we pass in opaque as exactly this type when constructing the Slirp object.
    let timer = unsafe {
        (*(opaque as *mut Context<H>))
            .callback_handler
            .timer_new(callback)
    };

    Box::into_raw(timer) as *mut c_void
}

extern "C" fn timer_free_handler<H: CallbackHandler>(timer: *mut c_void, opaque: *mut c_void) {
    // Safe because we pass in opaque as exactly this type when constructing the Slirp object.
    // Also, timer was created by us as exactly the type we unpack into.
    unsafe {
        let timer = Box::from_raw(timer as *mut H::Timer);
        (*(opaque as *mut Context<H>))
            .callback_handler
            .timer_free(timer);
    }
}

extern "C" fn timer_mod_handler<H: CallbackHandler>(
    timer: *mut c_void,
    expire_time: i64,
    opaque: *mut c_void,
) {
    // Safe because:
    // 1. We pass in opaque as exactly this type when constructing the Slirp object.
    // 2. timer was created by us as exactly the type we unpack into
    // 3. libslirp is responsible for freeing timer, so forgetting about it is safe.
    unsafe {
        let mut timer = Box::from_raw(timer as *mut H::Timer);
        (*(opaque as *mut Context<H>))
            .callback_handler
            .timer_mod(&mut timer, expire_time);
        Box::into_raw(timer);
    }
}

extern "C" fn register_poll_fd_handler<H: CallbackHandler>(fd: c_int, opaque: *mut c_void) {
    // Safe because we pass in opaque as exactly this type when constructing the Slirp object.
    unsafe {
        (*(opaque as *mut Context<H>))
            .callback_handler
            .register_poll_fd(fd)
    }
}

extern "C" fn unregister_poll_fd_handler<H: CallbackHandler>(fd: c_int, opaque: *mut c_void) {
    // Safe because we pass in opaque as exactly this type when constructing the Slirp object.
    unsafe {
        (*(opaque as *mut Context<H>))
            .callback_handler
            .unregister_poll_fd(fd)
    }
}

extern "C" fn notify_handler<H: CallbackHandler>(opaque: *mut c_void) {
    // Safe because we pass in opaque as exactly this type when constructing the Slirp object.
    unsafe { (*(opaque as *mut Context<H>)).callback_handler.notify() }
}

impl<H: CallbackHandler> Context<H> {
    /// Create a new instance of the libslirp context.
    ///
    /// The parameters which are prefixed by "host" refer to the system on which libslirp runs;
    /// for example, host_v4_address is the IP address of the host system that the guest will be
    /// able to connect to.
    ///
    /// `host_v[4|6]_address` maps to the host's local loopback interface.
    /// `dns_server_` options configure the DNS server provided on the virtual network by libslirp.
    pub fn new(
        disable_access_to_host: bool,
        ipv4_enabled: bool,
        virtual_network_v4_address: Ipv4Addr,
        virtual_network_v4_mask: Ipv4Addr,
        host_v4_address: Ipv4Addr,
        ipv6_enabled: bool,
        virtual_network_v6_address: Ipv6Addr,
        virtual_network_v6_prefix_len: u8,
        host_v6_address: Ipv6Addr,
        host_hostname: Option<String>,
        dhcp_start_addr: Ipv4Addr,
        dns_server_v4_addr: Ipv4Addr,
        dns_server_v6_addr: Ipv6Addr,
        virtual_network_dns_search_domains: Vec<String>,
        dns_server_domain_name: Option<String>,
        callback_handler: H,
    ) -> Result<Box<Context<H>>> {
        let mut ret = Box::new(Context {
            slirp: std::ptr::null_mut(),
            callbacks: SlirpCb {
                send_packet: Some(send_packet_handler::<H>),
                guest_error: Some(guest_error_handler::<H>),
                clock_get_ns: Some(clock_get_ns_handler::<H>),
                timer_new: Some(timer_new_handler::<H>),
                timer_free: Some(timer_free_handler::<H>),
                timer_mod: Some(timer_mod_handler::<H>),
                register_poll_fd: Some(register_poll_fd_handler::<H>),
                unregister_poll_fd: Some(unregister_poll_fd_handler::<H>),
                notify: Some(notify_handler::<H>),
            },
            callback_handler,
        });

        let cstr_dns_search: Vec<_> = virtual_network_dns_search_domains
            .iter()
            .map(|arg| CString::new(arg.clone().into_bytes()).unwrap())
            .collect();
        let mut p_dns_search: Vec<_> = cstr_dns_search.iter().map(|arg| arg.as_ptr()).collect();
        p_dns_search.push(std::ptr::null());

        let host_hostname = host_hostname.and_then(|s| CString::new(s).ok());
        let dns_server_domain_name = dns_server_domain_name.and_then(|s| CString::new(s).ok());
        let rust_context_ptr = &*ret as *const _ as *mut _;

        let as_ptr = |p: &Option<CString>| p.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());

        let slirp_config = SlirpConfig {
            version: 1,
            restricted: 0,
            disable_dhcp: false,
            in_enabled: ipv4_enabled,
            vnetwork: virtual_network_v4_address.into(),
            vnetmask: virtual_network_v4_mask.into(),
            vhost: host_v4_address.into(),
            in6_enabled: ipv6_enabled,
            vprefix_addr6: virtual_network_v6_address.into(),
            vprefix_len: virtual_network_v6_prefix_len,
            vhost6: host_v6_address.into(),
            vhostname: as_ptr(&host_hostname),
            tftp_server_name: std::ptr::null(),
            tftp_path: std::ptr::null(),
            bootfile: std::ptr::null(),
            vdhcp_start: dhcp_start_addr.into(),
            vnameserver: dns_server_v4_addr.into(),
            vnameserver6: dns_server_v6_addr.into(),
            vdnssearch: p_dns_search.as_ptr() as *mut *const _,
            vdomainname: as_ptr(&dns_server_domain_name),
            if_mtu: 0,
            if_mru: 0,
            disable_host_loopback: disable_access_to_host,
            enable_emu: false,
            outbound_addr: std::ptr::null(),
            outbound_addr6: std::ptr::null(),
            disable_dns: false,
        };

        // Safe because we pass valid pointers (or null as appropriate) as parameters and we check
        // that the return value is valid.
        let slirp = unsafe {
            slirp_new(
                &slirp_config,
                &ret.callbacks,
                // This value is passed to callbacks as opaque data, which allows those callbacks
                // to get access to the Context struct. It allows them to invoke the appropriate
                // methods on the CallbackHandler to notify it about new packets, get data about
                // sockets that are ready for reading, etc.
                rust_context_ptr,
            )
        };
        assert!(!slirp.is_null());
        match ret.callback_handler.begin_read_from_guest() {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                return Err(Error::BrokenPipe(e));
            }
            Err(e) => {
                return Err(Error::OverlappedError(e));
            }
            _ => {}
        }
        ret.slirp = slirp;
        Ok(ret)
    }

    /// Reads from the guest & injects into Slirp. This method reads until an error is encountered
    /// or io::ErrorKind::WouldBlock is returned by the callback_handler's read_from_guest.
    pub fn handle_guest_input(&mut self) -> Result<()> {
        loop {
            match self.callback_handler.end_read_from_guest() {
                Ok(ethernet_frame) => unsafe {
                    // Safe because the buffer (ethernet_frame) is valid & libslirp is provided
                    // with the data's underlying length.
                    slirp_input(
                        self.slirp,
                        ethernet_frame.as_ptr(),
                        ethernet_frame.len() as i32,
                    );
                },
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    error!("error reading packet from guest: {}", e);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No packets are available. Yield back to the Slirp loop.
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    return Err(Error::BrokenPipe(e));
                }
                Err(_) => {
                    match self.callback_handler.begin_read_from_guest() {
                        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                            return Err(Error::BrokenPipe(e));
                        }
                        Err(e) => {
                            return Err(Error::OverlappedError(e));
                        }
                        _ => {}
                    }
                    break;
                }
            }
            match self.callback_handler.begin_read_from_guest() {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    return Err(Error::BrokenPipe(e));
                }
                Err(e) => {
                    return Err(Error::OverlappedError(e));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn connection_info(&mut self) -> &str {
        str::from_utf8(unsafe { CStr::from_ptr(slirp_connection_info(self.slirp)) }.to_bytes())
            .unwrap_or("")
    }

    /// Requests libslirp provide the set of sockets & events that should be polled for. These
    /// sockets are provided to you by 0..n calls to `add_poll_cb`. `add_poll_cb` must return an
    /// integer (henceforth the socket reference) which libslirp can use to later request the
    /// revents that came from polling on that socket.
    ///
    /// The `timeout` value expresses how long (in ms) the consumer intends to wait (at most) when
    /// it invokes the polling function. libslirp will overwrite this with the time that the
    /// consumer should wait.
    pub fn pollfds_fill<F>(&mut self, timeout: &mut u32, mut add_poll_cb: F)
    where
        F: FnMut(i32, PollEvents) -> i32,
    {
        let cb = &mut (&mut add_poll_cb as &mut dyn FnMut(i32, PollEvents) -> i32);
        // Safe because cb is only used while slirp_pollfds_fill is running, and self.slirp is
        // guaranteed to be valid.
        unsafe {
            slirp_pollfds_fill(
                self.slirp,
                timeout,
                Some(add_poll_handler_callback),
                cb as *mut _ as *mut c_void,
            );
        }
    }

    /// Informs libslirp that polling has returned with some events on sockets that libslirp said
    /// should be polled for when you called `pollfds_fill`. You provide the results of polling by
    /// supplying `get_revents_cb`, which returns the `PollEvents` for each provided socket
    /// reference. libslirp will call that function 0..n times to gather results from the polling
    /// operation.
    pub fn pollfds_poll<F>(&mut self, error: bool, mut get_revents_cb: F)
    where
        F: FnMut(i32) -> PollEvents,
    {
        let cb = &mut (&mut get_revents_cb as &mut dyn FnMut(i32) -> PollEvents);

        // Safe because cb is only used while slirp_pollfds_poll is running, and self.slirp is
        // guaranteed to be valid.
        unsafe {
            slirp_pollfds_poll(
                self.slirp,
                error as i32,
                Some(get_revents_handler_callback),
                cb as *mut _ as *mut c_void,
            );
        }
    }

    pub fn state_save<F>(&mut self, mut write_cb: F)
    where
        F: FnMut(&[u8]) -> isize,
    {
        // Safe because cb is only used while state_save is running, and self.slirp is
        // guaranteed to be valid.
        let cb = &mut (&mut write_cb as &mut dyn FnMut(&[u8]) -> isize);
        unsafe {
            slirp_state_save(
                self.slirp,
                Some(write_handler_callback),
                cb as *mut _ as *mut c_void,
            );
        }
    }

    pub fn state_load<F>(&mut self, version_id: i32, mut read_cb: F) -> i32
    where
        F: FnMut(&mut [u8]) -> isize,
    {
        // Safe because cb is only used while state_load is running, and self.slirp is
        // guaranteed to be valid. While this function may fail, interpretation of the error code
        // is the responsibility of the caller.
        //
        // TODO(nkgold): if state_load becomes used by crosvm, interpretation of the error code
        // should occur here.
        let cb = &mut (&mut read_cb as &mut dyn FnMut(&mut [u8]) -> isize);
        unsafe {
            slirp_state_load(
                self.slirp,
                version_id,
                Some(read_handler_callback),
                cb as *mut _ as *mut c_void,
            )
        }
    }

    pub fn get_timers<'a>(&'a self) -> Box<dyn Iterator<Item = &RawDescriptor> + 'a> {
        self.callback_handler.get_timers()
    }

    pub fn execute_timer(&mut self, timer: RawDescriptor) {
        self.callback_handler.execute_timer(timer)
    }
}
