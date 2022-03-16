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
//! use sys_util::{error, syslog, warn};
//!
//! if let Err(e) = syslog::init() {
//!     println!("failed to initiailize syslog: {}", e);
//!     return;
//! }
//! warn!("this is your {} warning", "final");
//! error!("something went horribly wrong: {}", "out of RAMs");
//! ```

use super::{target_os::syslog::PlatformSyslog, RawDescriptor};
use std::{
    env,
    ffi::{OsStr, OsString},
    fmt::{
        Display, {self},
    },
    fs::File,
    io,
    io::{stderr, Cursor, Write},
    os::unix::io::{AsRawFd, RawFd},
    path::PathBuf,
    sync::{MutexGuard, Once},
};

use remain::sorted;
use sync::Mutex;
use thiserror::Error as ThisError;

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

impl Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Priority::*;

        let string = match self {
            Emergency => "EMERGENCY",
            Alert => "ALERT",
            Critical => "CRITICAL",
            Error => "ERROR",
            Warning => "WARNING",
            Notice => "NOTICE",
            Info => "INFO",
            Debug => "DEBUG",
        };

        write!(f, "{}", string)
    }
}

/// The facility of a syslog message.
///
/// See syslog man pages for information on their semantics.
#[derive(Copy, Clone)]
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
#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// Error while attempting to connect socket.
    #[error("failed to connect socket: {0}")]
    Connect(io::Error),
    /// There was an error using `open` to get the lowest file descriptor.
    #[error("failed to get lowest file descriptor: {0}")]
    GetLowestFd(io::Error),
    /// The guess of libc's file descriptor for the syslog connection was invalid.
    #[error("guess of fd for syslog connection was invalid")]
    InvalidFd,
    /// Initialization was never attempted.
    #[error("initialization was never attempted")]
    NeverInitialized,
    /// Initialization has previously failed and can not be retried.
    #[error("initialization previously failed and cannot be retried")]
    Poisoned,
    /// Error while creating socket.
    #[error("failed to create socket: {0}")]
    Socket(io::Error),
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
    file: Option<File>,
    proc_name: Option<String>,
    syslog: PlatformSyslog,
}

impl State {
    fn new() -> Result<State, Error> {
        Ok(State {
            stderr: true,
            file: None,
            proc_name: get_proc_name(),
            syslog: PlatformSyslog::new()?,
        })
    }
}

static STATE_ONCE: Once = Once::new();
static mut STATE: *const Mutex<State> = 0 as *const _;

fn new_mutex_ptr<T>(inner: T) -> *const Mutex<T> {
    Box::into_raw(Box::new(Mutex::new(inner)))
}

/// Initialize the syslog connection and internal variables.
///
/// This should only be called once per process before any other threads have been spawned or any
/// signal handlers have been registered. Every call made after the first will have no effect
/// besides return `Ok` or `Err` appropriately.
pub fn init() -> Result<(), Error> {
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

fn lock() -> Result<MutexGuard<'static, State>, Error> {
    // Safe because we assume that STATE is always in either a valid or NULL state.
    let state_ptr = unsafe { STATE };
    if state_ptr.is_null() {
        return Err(Error::NeverInitialized);
    }
    // Safe because STATE only mutates once and we checked for NULL.
    let state = unsafe { &*state_ptr };
    let guard = state.lock();
    Ok(guard)
}

// Attempts to lock and retrieve the state. Returns from the function silently on failure.
macro_rules! lock {
    () => {
        match lock() {
            Ok(s) => s,
            _ => return,
        }
    };
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

pub(crate) trait Syslog {
    fn new() -> Result<Self, Error>
    where
        Self: Sized;

    /// Enables or disables echoing log messages to the syslog.
    ///
    /// The default behavior is **enabled**.
    ///
    /// If `enable` goes from `true` to `false`, the syslog connection is closed. The connection is
    /// reopened if `enable` is set to `true` after it became `false`.
    ///
    /// Returns an error if syslog was never initialized or the syslog connection failed to be
    /// established.
    ///
    /// # Arguments
    /// * `enable` - `true` to enable echoing to syslog, `false` to disable echoing to syslog.
    fn enable(&mut self, enable: bool) -> Result<(), Error>;

    fn log(
        &self,
        proc_name: Option<&str>,
        pri: Priority,
        fac: Facility,
        file_line: Option<(&str, u32)>,
        args: fmt::Arguments,
    );

    fn push_fds(&self, fds: &mut Vec<RawFd>);
}

/// Enables or disables echoing log messages to the syslog.
///
/// The default behavior is **enabled**.
///
/// If `enable` goes from `true` to `false`, the syslog connection is closed. The connection is
/// reopened if `enable` is set to `true` after it became `false`.
///
/// Returns an error if syslog was never initialized or the syslog connection failed to be
/// established.
///
/// # Arguments
/// * `enable` - `true` to enable echoing to syslog, `false` to disable echoing to syslog.
pub fn echo_syslog(enable: bool) -> Result<(), Error> {
    let state_ptr = unsafe { STATE };
    if state_ptr.is_null() {
        return Err(Error::NeverInitialized);
    }
    let mut state = lock().map_err(|_| Error::Poisoned)?;

    state.syslog.enable(enable)
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
pub fn push_fds(fds: &mut Vec<RawFd>) {
    let state = lock!();
    state.syslog.push_fds(fds);
    fds.extend(state.file.iter().map(|f| f.as_raw_fd()));
}

/// Does the same as push_fds, but using the RawDescriptorType
pub fn push_descriptors(descriptors: &mut Vec<RawDescriptor>) {
    push_fds(descriptors)
}

/// Records a log message with the given details.
///
/// Note that this will fail silently if syslog was not initialized.
///
/// # Arguments
/// * `pri` - The `Priority` (i.e. severity) of the log message.
/// * `fac` - The `Facility` of the log message. Usually `Facility::User` should be used.
/// * `file_line` - Optional tuple of the name of the file that generated the
///                 log and the line number within that file.
/// * `args` - The log's message to record, in the form of `format_args!()`  return value
///
/// # Examples
///
/// ```
/// # use sys_util::syslog;
/// # if let Err(e) = syslog::init() {
/// #     println!("failed to initiailize syslog: {}", e);
/// #     return;
/// # }
/// syslog::log(syslog::Priority::Error,
///             syslog::Facility::User,
///             Some((file!(), line!())),
///             format_args!("hello syslog"));
/// ```
pub fn log(pri: Priority, fac: Facility, file_line: Option<(&str, u32)>, args: fmt::Arguments) {
    let mut state = lock!();
    let mut buf = [0u8; 1024];

    state.syslog.log(
        state.proc_name.as_ref().map(|s| s.as_ref()),
        pri,
        fac,
        file_line,
        args,
    );

    let res = {
        let mut buf_cursor = Cursor::new(&mut buf[..]);
        if let Some((file_name, line)) = &file_line {
            write!(&mut buf_cursor, "[{}:{}:{}] ", pri, file_name, line)
        } else {
            Ok(())
        }
        .and_then(|()| writeln!(&mut buf_cursor, "{}", args))
        .map(|()| buf_cursor.position() as usize)
    };
    if let Ok(len) = &res {
        if let Some(file) = &mut state.file {
            let _ = file.write_all(&buf[..*len]);
        }
        if state.stderr {
            let _ = stderr().write_all(&buf[..*len]);
        }
    }
}

/// A macro for logging at an arbitrary priority level.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! log {
    ($pri:expr, $($args:tt)+) => ({
        $crate::syslog::log($pri, $crate::syslog::Facility::User, Some((file!(), line!())), format_args!($($args)+))
    })
}

/// A macro for logging an error.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! error {
    ($($args:tt)+) => ($crate::log!($crate::syslog::Priority::Error, $($args)*))
}

/// A macro for logging a warning.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! warn {
    ($($args:tt)+) => ($crate::log!($crate::syslog::Priority::Warning, $($args)*))
}

/// A macro for logging info.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! info {
    ($($args:tt)+) => ($crate::log!($crate::syslog::Priority::Info, $($args)*))
}

/// A macro for logging debug information.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! debug {
    ($($args:tt)+) => ($crate::log!($crate::syslog::Priority::Debug, $($args)*))
}

// Struct that implements io::Write to be used for writing directly to the syslog
pub struct Syslogger {
    buf: String,
    priority: Priority,
    facility: Facility,
}

impl Syslogger {
    pub fn new(p: Priority, f: Facility) -> Syslogger {
        Syslogger {
            buf: String::new(),
            priority: p,
            facility: f,
        }
    }
}

impl io::Write for Syslogger {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let parsed_str = String::from_utf8_lossy(buf);
        self.buf.push_str(&parsed_str);

        if let Some(last_newline_idx) = self.buf.rfind('\n') {
            for line in self.buf[..last_newline_idx].lines() {
                log(self.priority, self.facility, None, format_args!("{}", line));
            }

            self.buf.drain(..=last_newline_idx);
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use libc::{shm_open, shm_unlink, O_CREAT, O_EXCL, O_RDWR};

    use std::{
        ffi::CStr,
        io::{Read, Seek, SeekFrom},
        os::unix::io::FromRawFd,
    };

    #[test]
    fn init_syslog() {
        init().unwrap();
    }

    #[test]
    fn fds() {
        init().unwrap();
        let mut fds = Vec::new();
        push_fds(&mut fds);
        assert!(!fds.is_empty());
        for fd in fds {
            assert!(fd >= 0);
        }
    }

    #[test]
    fn syslog_log() {
        init().unwrap();
        log(
            Priority::Error,
            Facility::User,
            Some((file!(), line!())),
            format_args!("hello syslog"),
        );
    }

    #[test]
    fn proc_name() {
        init().unwrap();
        log(
            Priority::Error,
            Facility::User,
            Some((file!(), line!())),
            format_args!("before proc name"),
        );
        set_proc_name("sys_util-test");
        log(
            Priority::Error,
            Facility::User,
            Some((file!(), line!())),
            format_args!("after proc name"),
        );
    }

    #[test]
    fn syslog_file() {
        init().unwrap();
        let shm_name = CStr::from_bytes_with_nul(b"/crosvm_shm\0").unwrap();
        let mut file = unsafe {
            shm_unlink(shm_name.as_ptr());
            let fd = shm_open(shm_name.as_ptr(), O_RDWR | O_CREAT | O_EXCL, 0o666);
            assert!(fd >= 0, "error creating shared memory;");
            shm_unlink(shm_name.as_ptr());
            File::from_raw_fd(fd)
        };

        let syslog_file = file.try_clone().expect("error cloning shared memory file");
        echo_file(Some(syslog_file));

        const TEST_STR: &str = "hello shared memory file";
        log(
            Priority::Error,
            Facility::User,
            Some((file!(), line!())),
            format_args!("{}", TEST_STR),
        );

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

    #[test]
    fn syslogger_char() {
        init().unwrap();
        let mut syslogger = Syslogger::new(Priority::Info, Facility::Daemon);

        let string = "Writing chars to syslog";
        for c in string.chars() {
            syslogger.write_all(&[c as u8]).expect("error writing char");
        }

        syslogger
            .write_all(&[b'\n'])
            .expect("error writing newline char");
    }

    #[test]
    fn syslogger_line() {
        init().unwrap();
        let mut syslogger = Syslogger::new(Priority::Info, Facility::Daemon);

        let s = "Writing string to syslog\n";
        syslogger
            .write_all(s.as_bytes())
            .expect("error writing string");
    }

    #[test]
    fn syslogger_partial() {
        init().unwrap();
        let mut syslogger = Syslogger::new(Priority::Info, Facility::Daemon);

        let s = "Writing partial string";
        // Should not log because there is no newline character
        syslogger
            .write_all(s.as_bytes())
            .expect("error writing string");
    }
}
