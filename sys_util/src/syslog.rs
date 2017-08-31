// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Facilities for sending log message to syslog.
//!
//! Every function exported by this module is thread-safe. Each function will silently fail until
//! `syslog::init()` is called and returns `Ok`.
//!
//! # Examples
//!
//! ```
//! #[macro_use] extern crate sys_util;
//!
//! use sys_util::syslog;
//!
//! fn main() {
//!     if let Err(e) = syslog::init() {
//!         println!("failed to initiailize syslog: {:?}", e);
//!         return;
//!     }
//!     warn!("this is your {} warning", "final");
//!     error!("something went horribly wrong: {:?}", "out of RAMs");
//! }
//! ```

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{Write, Cursor, ErrorKind, stderr};
use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::result;
use std::str::from_utf8;
use std::sync::{Mutex, MutexGuard, Once, ONCE_INIT};

use libc::{tm, time, time_t, localtime_r, gethostname, c_char};

use getpid;

const SYSLOG_PATH: &'static str = "/dev/log";

/// The priority (i.e. severity) of a syslog message.
///
/// See syslog man pages for information on their semantics.
#[derive(Copy, Clone, Debug)]
pub enum Priority {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Priority::Emergency => write!(f, "{}", "EMERGENCY"),
            &Priority::Alert => write!(f, "{}", "ALERT"),
            &Priority::Critical => write!(f, "{}", "CRITICAL"),
            &Priority::Error => write!(f, "{}", "ERROR"),
            &Priority::Warning => write!(f, "{}", "WARNING"),
            &Priority::Notice => write!(f, "{}", "NOTICE"),
            &Priority::Info => write!(f, "{}", "INFO"),
            &Priority::Debug => write!(f, "{}", "DEBUG"),
        }
    }
}

/// The facility of a syslog message.
///
/// See syslog man pages for information on their semantics.
pub enum Facility {
    Kernel = 0,
    User = 1 << 3,
    Mail = 2 << 3,
    Daemon = 3 << 3,
    Auth = 4 << 3,
    Syslog = 5 << 3,
    Lpr = 6 << 3,
    News = 7 << 3,
    Uucp = 8 << 3,
    Local0 = 16 << 3,
    Local1 = 17 << 3,
    Local2 = 18 << 3,
    Local3 = 19 << 3,
    Local4 = 20 << 3,
    Local5 = 21 << 3,
    Local6 = 22 << 3,
    Local7 = 23 << 3,
}

/// Errors returned by `syslog::init()`.
#[derive(Debug)]
pub enum Error {
    /// Initialization has previously failed and can not be retried.
    Poisoned,
    /// Error while creating socket.
    Socket(io::Error),
    /// Error while attempting to connect socket.
    Connect(io::Error),
}

fn get_hostname() -> Result<String, ()> {
    let mut hostname: [u8; 256] = [b'\0'; 256];
    // Safe because we give a valid pointer to a buffer of the indicated length and check for the
    // result.
    let ret = unsafe { gethostname(hostname.as_mut_ptr() as *mut c_char, hostname.len()) };
    if ret == -1 {
        return Err(());
    }

    let len = hostname.iter().position(|&v| v == b'\0').ok_or(())?;

    Ok(from_utf8(&hostname[..len]).map_err(|_| ())?.to_string())
}

fn get_proc_name() -> Option<String> {
    env::args_os()
        .next()
        .map(PathBuf::from)
        .and_then(|s| s.file_name().map(OsStr::to_os_string))
        .map(OsString::into_string)
        .and_then(Result::ok)
}

struct State {
    stderr: bool,
    socket: UnixDatagram,
    file: Option<File>,
    hostname: Option<String>,
    proc_name: Option<String>,
}

impl State {
    fn new() -> Result<State, Error> {
        let s = UnixDatagram::unbound().map_err(Error::Socket)?;
        s.connect(SYSLOG_PATH).map_err(Error::Connect)?;
        Ok(State {
               stderr: true,
               socket: s,
               file: None,
               hostname: get_hostname().ok(),
               proc_name: get_proc_name(),
           })
    }
}

static STATE_ONCE: Once = ONCE_INIT;
static mut STATE: *const Mutex<State> = 0 as *const _;

fn new_mutex_ptr<T>(inner: T) -> *const Mutex<T> {
    Box::into_raw(Box::new(Mutex::new(inner)))
}

/// Initialize the syslog connection and internal variables.
///
/// This should only be called once per process, but it is safe to do so from multiple threads more
/// than once. Every call made after the first will have no effect besides return `Ok` or `Err`
/// appropriately.
pub fn init() -> result::Result<(), Error> {
    let mut err = Error::Poisoned;
    STATE_ONCE.call_once(|| match State::new() {
                             // Safe because STATE mutation is guarded by `Once`.
                             Ok(state) => unsafe { STATE = new_mutex_ptr(state) },
                             Err(e) => err = e,
                         });

    if unsafe { STATE.is_null() } {
        Err(err)
    } else {
        Ok(())
    }
}

fn lock() -> Result<MutexGuard<'static, State>, ()> {
    // Safe because we assume that STATE is always in either a valid or NULL state.
    let state_ptr = unsafe { STATE };
    if state_ptr.is_null() {
        return Err(());
    }
    // Safe because STATE only mutates once and we checked for NULL.
    let state = unsafe { &*state_ptr };
    state.lock().map_err(|_| ())
}

// Attempts to lock and retrieve the state. Returns from the function silently on failure.
macro_rules! lock {
    () => (
        match lock() {
            Ok(s) => s,
            _ => return,
        };
    )
}

/// Replaces the hostname reported in each syslog message.
///
/// The default hostname is whatever `gethostname()` returned when `syslog::init()` was first
/// called.
///
/// Does nothing if syslog was never initialized.
pub fn set_hostname<T: Into<String>>(hostname: T) {
    let mut state = lock!();
    state.hostname = Some(hostname.into());
}

/// Replaces the process name reported in each syslog message.
///
/// The default process name is the _file name_ of `argv[0]`. For example, if this program was
/// invoked as
///
/// ```bash
/// $ path/to/app --delete everything
/// ```
///
/// the default process name would be _app_.
///
/// Does nothing if syslog was never initialized.
pub fn set_proc_name<T: Into<String>>(proc_name: T) {
    let mut state = lock!();
    state.proc_name = Some(proc_name.into());
}

/// Replaces the optional `File` to echo log messages to.
///
/// The default behavior is to not echo to a file. Passing `None` to this function restores that
/// behavior.
///
/// Does nothing if syslog was never initialized.
///
/// # Arguments
/// * `file` - `Some(file)` to echo to `file`, `None` to disable echoing to the file previously passed to `echo_file`.
pub fn echo_file(file: Option<File>) {
    let mut state = lock!();
    state.file = file;
}

/// Enables or disables echoing log messages to the `std::io::stderr()`.
///
/// The default behavior is **enabled**.
///
/// Does nothing if syslog was never initialized.
///
/// # Arguments
/// * `enable` - `true` to enable echoing to stderr, `false` to disable echoing to stderr.
pub fn echo_stderr(enable: bool) {
    let mut state = lock!();
    state.stderr = enable;
}

/// Retrieves the file descriptors owned by the global syslogger.
///
/// Does nothing if syslog was never initialized. If their are any file descriptors, they will be
/// pushed into `fds`.
///
/// Note that the `stderr` file descriptor is never added, as it is not owned by syslog.
pub fn get_fds(fds: &mut Vec<RawFd>) {
    let state = lock!();
    fds.push(state.socket.as_raw_fd());
    fds.extend(state.file.iter().map(|f| f.as_raw_fd()));
}

/// Should only be called after `init()` was called.
fn send_buf(socket: &UnixDatagram, buf: &[u8]) {
    const SEND_RETRY: usize = 2;

    for _ in 0..SEND_RETRY {
        match socket.send(&buf[..]) {
            Ok(_) => break,
            Err(e) => {
                match e.kind() {
                    ErrorKind::ConnectionRefused |
                    ErrorKind::ConnectionReset |
                    ErrorKind::ConnectionAborted |
                    ErrorKind::NotConnected => {
                        let res = socket.connect(SYSLOG_PATH);
                        if res.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn get_localtime() -> tm {
    unsafe {
        // Safe because tm is just a struct of plain data.
        let mut tm: tm = mem::zeroed();
        let mut now: time_t = 0;
        // Safe because we give time a valid pointer and can never fail.
        time(&mut now as *mut _);
        // Safe because we give localtime_r valid pointers and can never fail.
        localtime_r(&now, &mut tm as *mut _);
        tm
    }
}

/// Records a log message with the given details.
///
/// Note that this will fail silently if syslog was not initialized.
///
/// # Arguments
/// * `pri` - The `Priority` (i.e. severity) of the log message.
/// * `fac` - The `Facility` of the log message. Usually `Facility::User` should be used.
/// * `file_name` - Name of the file that generated the log.
/// * `line` - Line number within `file_name` that generated the log.
/// * `args` - The log's message to record, in the form of `format_args!()`  return value
///
/// # Examples
///
/// ```
/// # #[macro_use] extern crate sys_util;
/// # use sys_util::syslog;
/// # fn main() {
/// #   if let Err(e) = syslog::init() {
/// #       println!("failed to initiailize syslog: {:?}", e);
/// #       return;
/// #   }
/// syslog::log(syslog::Priority::Error,
///             syslog::Facility::User,
///             file!(),
///             line!(),
///             format_args!("hello syslog"));
/// # }
/// ```
pub fn log(pri: Priority, fac: Facility, file_name: &str, line: u32, args: fmt::Arguments) {
    const MONTHS: [&'static str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                                        "Sep", "Oct", "Nov", "Dec"];

    let mut state = lock!();
    let tm = get_localtime();
    let prifac = (pri as u8) | (fac as u8);
    let mut buf = [0u8; 1024];
    let (res, len) = {
        let mut buf_cursor = Cursor::new(&mut buf[..]);
        (write!(&mut buf_cursor,
                "<{}>{} {:02} {:02}:{:02}:{:02} {} {}[{}]: [{}:{}] {}",
                prifac,
                MONTHS[tm.tm_mon as usize],
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec,
                state
                    .hostname
                    .as_ref()
                    .map(|s| s.as_ref())
                    .unwrap_or("-"),
                state
                    .proc_name
                    .as_ref()
                    .map(|s| s.as_ref())
                    .unwrap_or("-"),
                getpid(),
                file_name,
                line,
                args),
         buf_cursor.position() as usize)
    };

    if res.is_ok() {
        send_buf(&state.socket, &buf[..len]);
    }

    let (res, len) = {
        let mut buf_cursor = Cursor::new(&mut buf[..]);
        (write!(&mut buf_cursor,
                "[{}:{}:{}] {}\n",
                pri,
                file_name,
                line,
                args),
         buf_cursor.position() as usize)
    };
    if res.is_ok() {
        if let Some(ref mut file) = state.file {
            let _ = file.write_all(&buf[..len]);
        }
        if state.stderr {
            let _ = stderr().write_all(&buf[..len]);
        }
    }
}

/// A macro for logging at an arbitrary priority level.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! log {
    ($pri:expr, $($args:tt)+) => ({
        $crate::syslog::log($pri, $crate::syslog::Facility::User, file!(), line!(), format_args!($($args)+))
    })
}

/// A macro for logging an error.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! error {
    ($($args:tt)+) => (log!($crate::syslog::Priority::Error, $($args)*))
}

/// A macro for logging a warning.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! warn {
    ($($args:tt)+) => (log!($crate::syslog::Priority::Warning, $($args)*))
}

/// A macro for logging info.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! info {
    ($($args:tt)+) => (log!($crate::syslog::Priority::Info, $($args)*))
}

/// A macro for logging debug information.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! debug {
    ($($args:tt)+) => (log!($crate::syslog::Priority::Debug, $($args)*))
}

#[cfg(test)]
mod tests {
    use super::*;

    use libc::{shm_unlink, shm_open, O_RDWR, O_CREAT, O_EXCL};

    use std::os::unix::io::FromRawFd;
    use std::ffi::CStr;
    use std::io::{Read, Seek, SeekFrom};

    #[test]
    fn init_syslog() {
        init().unwrap();
    }

    #[test]
    fn fds() {
        init().unwrap();
        let mut fds = Vec::new();
        get_fds(&mut fds);
        assert!(fds.len() >= 1);
        for fd in fds {
            assert!(fd >= 0);

        }
    }

    #[test]
    fn syslog_log() {
        init().unwrap();
        log(Priority::Error,
            Facility::User,
            file!(),
            line!(),
            format_args!("hello syslog"));
    }

    #[test]
    fn proc_name() {
        init().unwrap();
        log(Priority::Error,
            Facility::User,
            file!(),
            line!(),
            format_args!("before proc name"));
        set_proc_name("sys_util-test");
        log(Priority::Error,
            Facility::User,
            file!(),
            line!(),
            format_args!("after proc name"));
    }

    #[test]
    fn syslog_file() {
        init().unwrap();
        let shm_name = CStr::from_bytes_with_nul(b"/crosvm_shm\0").unwrap();
        let mut file = unsafe {
            shm_unlink(shm_name.as_ptr());
            let fd = shm_open(shm_name.as_ptr(), O_RDWR | O_CREAT | O_EXCL, 0666);
            assert!(fd >= 0, "error creating shared memory;");
            File::from_raw_fd(fd)
        };

        let syslog_file = file.try_clone()
            .expect("error cloning shared memory file");
        echo_file(Some(syslog_file));

        const TEST_STR: &'static str = "hello shared memory file";
        log(Priority::Error,
            Facility::User,
            file!(),
            line!(),
            format_args!("{}", TEST_STR));

        file.seek(SeekFrom::Start(0))
            .expect("error seeking shared memory file");
        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .expect("error reading shared memory file");
        assert!(buf.contains(TEST_STR));
    }

    #[test]
    fn macros() {
        init().unwrap();
        error!("this is an error {}", 3);
        warn!("this is a warning {}", "uh oh");
        info!("this is info {}", true);
        debug!("this is debug info {:?}", Some("helpful stuff"));
    }
}
