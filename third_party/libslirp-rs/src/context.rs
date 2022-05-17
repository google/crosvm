use libslirp_sys::*;
use std::io::{Read, Write};

#[cfg(feature = "structopt")]
use crate::Opt;
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::rc::Rc;
use std::{fmt, mem, ops, slice, str};

pub struct Context<H> {
    pub inner: Box<Inner<H>>,
}

pub struct Inner<H> {
    pub context: *mut Slirp,
    callbacks: SlirpCb,
    handler: H,
}

impl<H> Drop for Context<H> {
    fn drop(&mut self) {
        unsafe {
            slirp_cleanup(self.inner.context);
        }
    }
}

//unsafe impl<H: Send> Send for Inner<H> {}

pub trait Handler {
    type Timer;

    fn clock_get_ns(&mut self) -> i64;

    fn send_packet(&mut self, buf: &[u8]) -> io::Result<usize>;

    fn register_poll_fd(&mut self, fd: RawFd);

    fn unregister_poll_fd(&mut self, fd: RawFd);

    fn guest_error(&mut self, msg: &str);

    fn notify(&mut self);

    fn timer_new(&mut self, func: Box<dyn FnMut()>) -> Box<Self::Timer>;

    fn timer_mod(&mut self, timer: &mut Box<Self::Timer>, expire_time: i64);

    fn timer_free(&mut self, timer: Box<Self::Timer>);
}

impl<T: Handler> Handler for Rc<RefCell<T>> {
    type Timer = T::Timer;

    fn clock_get_ns(&mut self) -> i64 {
        self.borrow_mut().clock_get_ns()
    }

    fn send_packet(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.borrow_mut().send_packet(buf)
    }

    fn register_poll_fd(&mut self, fd: RawFd) {
        self.borrow_mut().register_poll_fd(fd);
    }

    fn unregister_poll_fd(&mut self, fd: RawFd) {
        self.borrow_mut().unregister_poll_fd(fd);
    }

    fn guest_error(&mut self, msg: &str) {
        self.borrow_mut().guest_error(msg);
    }

    fn notify(&mut self) {
        self.borrow_mut().notify();
    }

    fn timer_new(&mut self, func: Box<dyn FnMut()>) -> Box<Self::Timer> {
        self.borrow_mut().timer_new(func)
    }

    fn timer_mod(&mut self, timer: &mut Box<Self::Timer>, expire_time: i64) {
        self.borrow_mut().timer_mod(timer, expire_time)
    }

    fn timer_free(&mut self, timer: Box<Self::Timer>) {
        self.borrow_mut().timer_free(timer)
    }
}

extern "C" fn write_handler_cl(buf: *const c_void, len: usize, opaque: *mut c_void) -> isize {
    let closure: &mut &mut dyn FnMut(&[u8]) -> isize = unsafe { mem::transmute(opaque) };
    let slice = unsafe { slice::from_raw_parts(buf as *const u8, len) };

    closure(slice)
}

extern "C" fn read_handler_cl(buf: *mut c_void, len: usize, opaque: *mut c_void) -> isize {
    let closure: &mut &mut dyn FnMut(&mut [u8]) -> isize = unsafe { mem::transmute(opaque) };
    let slice = unsafe { slice::from_raw_parts_mut(buf as *mut u8, len) };

    closure(slice)
}

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

extern "C" fn add_poll_handler_cl(fd: c_int, events: c_int, opaque: *mut c_void) -> c_int {
    let closure: &mut &mut dyn FnMut(RawFd, PollEvents) -> i32 = unsafe { mem::transmute(opaque) };

    closure(fd, PollEvents(events as usize))
}

extern "C" fn get_revents_handler_cl(idx: c_int, opaque: *mut c_void) -> c_int {
    let closure: &mut &mut dyn FnMut(i32) -> PollEvents = unsafe { mem::transmute(opaque) };

    closure(idx).0 as c_int
}

extern "C" fn send_packet_handler<H: Handler>(
    buf: *const c_void,
    len: usize,
    opaque: *mut c_void,
) -> isize {
    let slice = unsafe { slice::from_raw_parts(buf as *const u8, len) };
    let res = unsafe { (*(opaque as *mut Inner<H>)).handler.send_packet(slice) };
    if res.is_ok() {
        res.unwrap() as isize
    } else {
        eprintln!("send_packet error: {}", res.unwrap_err());
        -1
    }
}

extern "C" fn guest_error_handler<H: Handler>(msg: *const c_char, opaque: *mut c_void) {
    let msg = str::from_utf8(unsafe { CStr::from_ptr(msg) }.to_bytes()).unwrap_or("");
    unsafe { (*(opaque as *mut Inner<H>)).handler.guest_error(msg) }
}

extern "C" fn clock_get_ns_handler<H: Handler>(opaque: *mut c_void) -> i64 {
    unsafe { (*(opaque as *mut Inner<H>)).handler.clock_get_ns() }
}

extern "C" fn timer_new_handler<H: Handler>(
    cb: SlirpTimerCb,
    cb_opaque: *mut c_void,
    opaque: *mut c_void,
) -> *mut c_void {
    let func = Box::new(move || {
        if let Some(cb) = cb {
            unsafe {
                cb(cb_opaque);
            }
        }
    });
    let timer = unsafe { (*(opaque as *mut Inner<H>)).handler.timer_new(func) };
    Box::into_raw(timer) as *mut c_void
}

extern "C" fn timer_free_handler<H: Handler>(timer: *mut c_void, opaque: *mut c_void) {
    unsafe {
        let timer = Box::from_raw(timer as *mut H::Timer);
        (*(opaque as *mut Inner<H>)).handler.timer_free(timer);
    }
}

extern "C" fn timer_mod_handler<H: Handler>(
    timer: *mut c_void,
    expire_time: i64,
    opaque: *mut c_void,
) {
    unsafe {
        let mut timer = Box::from_raw(timer as *mut H::Timer);
        (*(opaque as *mut Inner<H>))
            .handler
            .timer_mod(&mut timer, expire_time);
        Box::into_raw(timer);
    }
}

extern "C" fn register_poll_fd_handler<H: Handler>(fd: c_int, opaque: *mut c_void) {
    unsafe { (*(opaque as *mut Inner<H>)).handler.register_poll_fd(fd) }
}

extern "C" fn unregister_poll_fd_handler<H: Handler>(fd: c_int, opaque: *mut c_void) {
    unsafe { (*(opaque as *mut Inner<H>)).handler.unregister_poll_fd(fd) }
}

extern "C" fn notify_handler<H: Handler>(opaque: *mut c_void) {
    unsafe { (*(opaque as *mut Inner<H>)).handler.notify() }
}

impl<H: Handler> Context<H> {
    #[cfg(feature = "structopt")]
    pub fn new_with_opt(opt: &Opt, handler: H) -> Self {
        let cstr_vdns: Vec<_> = opt
            .dns_suffixes
            .iter()
            .map(|arg| CString::new(arg.clone().into_bytes()).unwrap())
            .collect();
        let mut p_vdns: Vec<_> = cstr_vdns.iter().map(|arg| arg.as_ptr()).collect();
        p_vdns.push(std::ptr::null());

        let as_ptr = |p: &Option<CString>| p.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());

        let tftp_path = opt
            .tftp
            .root
            .as_ref()
            .and_then(|s| CString::new(s.to_string_lossy().into_owned()).ok());
        let vhostname = opt.hostname.clone().and_then(|s| CString::new(s).ok());
        let tftp_server_name = opt.tftp.name.clone().and_then(|s| CString::new(s).ok());
        let tftp_bootfile = opt.tftp.bootfile.clone().and_then(|s| CString::new(s).ok());
        let vdomainname = opt.domainname.clone().and_then(|s| CString::new(s).ok());

        let config = SlirpConfig {
            version: 2,
            restricted: opt.restrict as i32,
            in_enabled: !opt.ipv4.disable,
            vnetwork: opt.ipv4.net.ip().into(),
            vnetmask: opt.ipv4.net.mask().into(),
            vhost: opt.ipv4.host.into(),
            in6_enabled: !opt.ipv6.disable,
            vprefix_addr6: opt.ipv6.net6.ip().into(),
            vprefix_len: opt.ipv6.net6.prefix(),
            vhost6: opt.ipv6.host.into(),
            vhostname: as_ptr(&vhostname),
            tftp_server_name: as_ptr(&tftp_server_name),
            tftp_path: as_ptr(&tftp_path),
            bootfile: as_ptr(&tftp_bootfile),
            vdhcp_start: opt.ipv4.dhcp_start.into(),
            vnameserver: opt.ipv4.dns.into(),
            vnameserver6: opt.ipv6.dns.into(),
            vdnssearch: p_vdns.as_ptr() as *mut *const _,
            vdomainname: as_ptr(&vdomainname),
            if_mtu: opt.mtu,
            if_mru: opt.mtu,
            disable_host_loopback: opt.disable_host_loopback,
            enable_emu: false,
            outbound_addr: std::ptr::null(),
            outbound_addr6: std::ptr::null(),
            disable_dns: false,
        };

        Self::new_with_config(&config, handler)
    }

    pub fn new_with_config(config: &SlirpConfig, handler: H) -> Self {
        let mut ret = Context {
            inner: Box::new(Inner {
                context: std::ptr::null_mut(),
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
                handler,
            }),
        };

        let ptr = &*ret.inner as *const _ as *mut _;
        ret.inner.context = unsafe { slirp_new(config as *const _, &ret.inner.callbacks, ptr) };

        assert!(!ret.inner.context.is_null());
        ret
    }

    pub fn new(
        restricted: bool,
        ipv4_enabled: bool,
        vnetwork: Ipv4Addr,
        vnetmask: Ipv4Addr,
        vhost: Ipv4Addr,
        ipv6_enabled: bool,
        vprefix_addr6: Ipv6Addr,
        vprefix_len: u8,
        vhost6: Ipv6Addr,
        vhostname: Option<String>,
        tftp_server_name: Option<String>,
        tftp_path: Option<PathBuf>,
        tftp_bootfile: Option<String>,
        vdhcp_start: Ipv4Addr,
        vnameserver: Ipv4Addr,
        vnameserver6: Ipv6Addr,
        vdnssearch: Vec<String>,
        vdomainname: Option<String>,
        handler: H,
    ) -> Self {
        let mut ret = Context {
            inner: Box::new(Inner {
                context: std::ptr::null_mut(),
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
                handler,
            }),
        };

        let cstr_vdns: Vec<_> = vdnssearch
            .iter()
            .map(|arg| CString::new(arg.clone().into_bytes()).unwrap())
            .collect();
        let mut p_vdns: Vec<_> = cstr_vdns.iter().map(|arg| arg.as_ptr()).collect();
        p_vdns.push(std::ptr::null());

        let as_ptr = |p: &Option<CString>| p.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());

        let tftp_path = tftp_path.and_then(|s| CString::new(s.to_string_lossy().into_owned()).ok());
        let vhostname = vhostname.and_then(|s| CString::new(s).ok());
        let tftp_server_name = tftp_server_name.and_then(|s| CString::new(s).ok());
        let tftp_bootfile = tftp_bootfile.and_then(|s| CString::new(s).ok());
        let vdomainname = vdomainname.and_then(|s| CString::new(s).ok());

        let ptr = &*ret.inner as *const _ as *mut _;
        ret.inner.context = unsafe {
            slirp_init(
                restricted as i32,
                ipv4_enabled,
                vnetwork.into(),
                vnetmask.into(),
                vhost.into(),
                ipv6_enabled,
                vprefix_addr6.into(),
                vprefix_len,
                vhost6.into(),
                as_ptr(&vhostname),
                as_ptr(&tftp_server_name),
                as_ptr(&tftp_path),
                as_ptr(&tftp_bootfile),
                vdhcp_start.into(),
                vnameserver.into(),
                vnameserver6.into(),
                p_vdns.as_ptr() as *mut *const _,
                as_ptr(&vdomainname),
                &ret.inner.callbacks,
                ptr,
            )
        };

        assert!(!ret.inner.context.is_null());
        ret
    }

    pub fn input(&self, buf: &[u8]) {
        unsafe {
            slirp_input(self.inner.context, buf.as_ptr(), buf.len() as i32);
        }
    }

    pub fn connection_info(&self) -> &str {
        str::from_utf8(
            unsafe { CStr::from_ptr(slirp_connection_info(self.inner.context)) }.to_bytes(),
        )
        .unwrap_or("")
    }

    pub fn pollfds_fill<F>(&self, timeout: &mut u32, mut add_poll_cb: F)
    where
        F: FnMut(RawFd, PollEvents) -> i32,
    {
        let mut cb: &mut dyn FnMut(RawFd, PollEvents) -> i32 = &mut add_poll_cb;
        let cb = &mut cb;

        unsafe {
            slirp_pollfds_fill(
                self.inner.context,
                timeout,
                Some(add_poll_handler_cl),
                cb as *mut _ as *mut c_void,
            );
        }
    }

    pub fn pollfds_poll<F>(&self, error: bool, mut get_revents_cb: F)
    where
        F: FnMut(i32) -> PollEvents,
    {
        let mut cb: &mut dyn FnMut(i32) -> PollEvents = &mut get_revents_cb;
        let cb = &mut cb;

        unsafe {
            slirp_pollfds_poll(
                self.inner.context,
                error as i32,
                Some(get_revents_handler_cl),
                cb as *mut _ as *mut c_void,
            );
        }
    }

    pub fn state_save<F>(&self, mut write_cb: F)
    where
        F: FnMut(&[u8]) -> isize,
    {
        let mut cb: &mut dyn FnMut(&[u8]) -> isize = &mut write_cb;
        let cb = &mut cb;

        unsafe {
            slirp_state_save(
                self.inner.context,
                Some(write_handler_cl),
                cb as *mut _ as *mut c_void,
            );
        }
    }

    pub fn state_write<F: Write>(&self, writer: &mut F) -> std::io::Result<usize> {
        let mut res = Ok(0);
        self.state_save(|buf| match writer.write(buf) {
            Ok(n) => {
                res = Ok(*res.as_ref().unwrap() + n);
                n as isize
            }
            Err(e) => {
                res = Err(e);
                -1
            }
        });
        res
    }

    pub fn state_get(&self) -> std::io::Result<Vec<u8>> {
        let mut state = vec![];
        self.state_write(&mut state)?;
        Ok(state)
    }

    pub fn state_load<F>(&self, version_id: i32, mut read_cb: F)
    where
        F: FnMut(&mut [u8]) -> isize,
    {
        let mut cb: &mut dyn FnMut(&mut [u8]) -> isize = &mut read_cb;
        let cb = &mut cb;

        unsafe {
            slirp_state_load(
                self.inner.context,
                version_id,
                Some(read_handler_cl),
                cb as *mut _ as *mut c_void,
            );
        }
    }

    pub fn state_read<R: Read>(&self, version_id: i32, reader: &mut R) -> std::io::Result<usize> {
        let mut res = Ok(0);
        self.state_load(version_id, |buf| match reader.read(buf) {
            Ok(n) => {
                res = Ok(*res.as_ref().unwrap() + n);
                n as isize
            }
            Err(e) => {
                res = Err(e);
                -1
            }
        });
        res
    }
}
