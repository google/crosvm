// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Facilities for sending log message to syslog.
//!
//! Every function exported by this module is thread-safe. Each function will silently fail until
//! `syslog::init()` is called and returns `Ok`.
//!
//! This implements and sets logger up for logging facade exposed by the [`log`
//! crate][log-crate-url].
//!
//! # Examples
//!
//! ```
//! use log::{error, warn};
//! use base::syslog;
//!
//! if let Err(e) = syslog::init() {
//!     println!("failed to initiailize syslog: {}", e);
//!     return;
//! }
//! warn!("this is your {} warning", "final");
//! error!("something went horribly wrong: {}", "out of RAMs");
//! ```
//!
//! ```
//! use log::{error, warn};
//! use base::syslog::{init_with, LogConfig, fmt};
//! use std::io::Write;
//!
//! let mut cfg = LogConfig::default();
//! cfg.pipe_formatter = Some(|buf, rec| {
//!     let mut level_style = buf.style();
//!     level_style.set_color(fmt::Color::Green);
//!     let mut style = buf.style();
//!     style.set_color(fmt::Color::Red).set_bold(true);
//!     writeln!(buf, "{}:{}", level_style.value(rec.level()), style.value(rec.args()))
//! });
//! cfg.stderr = true;
//! cfg.filter = "info,base=debug,base::syslog=error,serial_console=false";
//!
//! init_with(cfg).unwrap();
//! error!("something went horribly wrong: {}", "out of RAMs");
//!
//!
//! ```
//!
//!
//! [log-crate-url]: https://docs.rs/log/

use std::fmt::Display;
use std::io;
use std::io::Write;
use std::sync::MutexGuard;

use chrono::Local;
pub use env_logger::fmt;
pub use env_logger::{self};
pub use log::*;
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use thiserror::Error as ThisError;

use crate::platform::syslog::PlatformSyslog;
use crate::platform::RawDescriptor;

/// The priority (i.e. severity) of a syslog message.
///
/// See syslog man pages for information on their semantics.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) enum Priority {
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
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

impl From<log::Level> for Priority {
    fn from(level: log::Level) -> Self {
        match level {
            log::Level::Error => Priority::Error,
            log::Level::Warn => Priority::Warning,
            log::Level::Info => Priority::Info,
            log::Level::Debug => Priority::Debug,
            log::Level::Trace => Priority::Debug,
        }
    }
}

pub const FORMATTER_NONE: Option<fn(&mut fmt::Formatter, &log::Record<'_>) -> std::io::Result<()>> =
    None;

impl TryFrom<&str> for Priority {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, <Self as TryFrom<&str>>::Error> {
        match value {
            "0" | "EMERGENCY" => Ok(Priority::Emergency),
            "1" | "ALERT" => Ok(Priority::Alert),
            "2" | "CRITICAL" => Ok(Priority::Critical),
            "3" | "ERROR" => Ok(Priority::Error),
            "4" | "WARNING" => Ok(Priority::Warning),
            "5" | "NOTICE" => Ok(Priority::Notice),
            "6" | "INFO" => Ok(Priority::Info),
            "7" | "DEBUG" => Ok(Priority::Debug),
            _ => Err("Priority can only be parsed from 0-7 and given variant names"),
        }
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

pub(crate) trait Syslog {
    fn new(
        proc_name: String,
        facility: Facility,
    ) -> Result<(Option<Box<dyn Log + Send>>, Option<RawDescriptor>), Error>;
}

pub struct State {
    /// Record filter
    filter: env_logger::filter::Filter,
    /// All the loggers we have
    loggers: Vec<Box<dyn Log + Send>>,
    /// Raw Descriptors to preserve
    descriptors: Vec<RawDescriptor>,
    /// True if we have just been initialized with safe startup defaults (stderr logging), false
    /// after detailed initialization has occurred.
    early_init: bool,
}

/// The logger that is provided to the `log` crate. Wraps our State struct so that we can
/// reconfigure logging sinks on the fly.
struct LoggingFacade {}

impl Log for LoggingFacade {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        STATE.lock().enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        STATE.lock().log(record)
    }

    fn flush(&self) {
        STATE.lock().flush()
    }
}

pub struct LogConfig<'a, F: 'static>
where
    F: Fn(&mut fmt::Formatter, &log::Record<'_>) -> std::io::Result<()> + Sync + Send,
{
    /// A filter for log messages. Please see
    /// module level documentation and [`env_logger` crate](https://docs.rs/env_logger)
    ///
    /// Example: `off`, `trace`, `trace,crosvm=error,base::syslog=debug`
    pub filter: &'a str,
    /// If set to true will duplicate output to stderr
    pub stderr: bool,
    /// If specified will output to given Sink
    pub pipe: Option<Box<dyn io::Write + Send>>,
    /// descriptor to preserve on forks (intended to be used with pipe)
    pub pipe_fd: Option<RawDescriptor>,
    /// A formatter to use with the pipe. (Syslog has hardcoded format)
    /// see module level documentation and [`env_logger` crate](https://docs.rs/env_logger)
    pub pipe_formatter: Option<F>,
    /// TAG to use for syslog output
    pub proc_name: String,
    /// Enable/disable platform's "syslog"
    pub syslog: bool,
    /// Facility to use for syslog output
    pub syslog_facility: Facility,
}

impl<'a> Default
    for LogConfig<'a, fn(&mut fmt::Formatter, &log::Record<'_>) -> std::io::Result<()>>
{
    fn default() -> Self {
        Self {
            filter: "info",
            stderr: true,
            pipe: None,
            proc_name: String::from("crosvm"),
            syslog: true,
            syslog_facility: Facility::User,
            pipe_formatter: FORMATTER_NONE,
            pipe_fd: None,
        }
    }
}

impl State {
    pub fn new<F: 'static>(cfg: LogConfig<'_, F>) -> Result<Self, Error>
    where
        F: Fn(&mut fmt::Formatter, &log::Record<'_>) -> std::io::Result<()> + Sync + Send,
    {
        let mut loggers: Vec<Box<dyn Log + Send>> = vec![];
        let mut descriptors = vec![];
        let mut builder = env_logger::filter::Builder::new();
        builder.parse(cfg.filter);
        let filter = builder.build();

        let create_formatted_builder = || {
            let mut builder = env_logger::Builder::new();

            // Output log lines w/ local ISO 8601 timestamps.
            builder.format(|buf, record| {
                writeln!(
                    buf,
                    "[{} {:5} {}] {}",
                    Local::now().format("%Y-%m-%dT%H:%M:%S%.9f%:z"),
                    record.level(),
                    record.module_path().unwrap_or("<missing module path>"),
                    record.args()
                )
            });
            builder
        };

        if cfg.stderr {
            let mut builder = create_formatted_builder();
            builder.filter_level(log::LevelFilter::Trace);
            builder.target(env_logger::Target::Stderr);
            loggers.push(Box::new(builder.build()));
        }

        if let Some(fd) = cfg.pipe_fd {
            descriptors.push(fd);
        }

        if let Some(file) = cfg.pipe {
            let mut builder = create_formatted_builder();
            builder.filter_level(log::LevelFilter::Trace);
            builder.target(env_logger::Target::Pipe(Box::new(file)));
            // https://github.com/env-logger-rs/env_logger/issues/208
            builder.is_test(true);

            if let Some(format) = cfg.pipe_formatter {
                builder.format(format);
            }
            loggers.push(Box::new(builder.build()));
        }

        if cfg.syslog {
            match PlatformSyslog::new(cfg.proc_name, cfg.syslog_facility) {
                Ok((mut logger, fd)) => {
                    if let Some(fd) = fd {
                        descriptors.push(fd);
                    }
                    if let Some(logger) = logger.take() {
                        loggers.push(logger);
                    }
                }
                Err(e) => {
                    // The default log configuration used in early_init() enables syslog, so we
                    // don't want to terminate the program if syslog can't be initialized. Warn the
                    // user but continue running.
                    eprintln!("syslog init failed: {}", e);
                }
            }
        }

        Ok(State {
            filter,
            loggers,
            descriptors,
            early_init: false,
        })
    }
}

static STATE: Lazy<Mutex<State>> = Lazy::new(|| {
    let mut state = State::new(LogConfig::default()).expect("failed to configure minimal logging");
    state.early_init = true;
    Mutex::new(state)
});
static LOGGING_FACADE: LoggingFacade = LoggingFacade {};
static EARLY_INIT_CALLED: OnceCell<()> = OnceCell::new();

/// Initialize the syslog connection and internal variables.
///
/// This should only be called once per process before any other threads have been spawned or any
/// signal handlers have been registered. Every call made after the first will panic.
///
/// Use `init_with_filter` to initialize with filtering
pub fn init() -> Result<(), Error> {
    init_with(Default::default())
}

/// Initialize the syslog connection and internal variables.
///
/// This should only be called once per process before any other threads have been spawned or any
/// signal handlers have been registered. Every call made after the first will
/// panic.
///
/// Arguments:
/// * filter: See <https://docs.rs/env_logger/0.9/env_logger/index.html> for example filter
///     specifications
/// * stderr: If set will output to stderr (in addition)
/// * file:  If set will output to this file (in addition)
/// * proc_name: proc name for Syslog implementation
/// * syslog_facility: syslog facility
/// * file_formatter: custom formatter for file output. See env_logger docs
pub fn init_with<F: 'static>(cfg: LogConfig<'_, F>) -> Result<(), Error>
where
    F: Fn(&mut fmt::Formatter, &log::Record<'_>) -> std::io::Result<()> + Sync + Send,
{
    let mut state = STATE.lock();
    if !state.early_init {
        panic!("double-init of the logging system is not permitted.");
    }
    *state = State::new(cfg)?;

    // This has no effect if the logging facade was already set.
    apply_logging_state(&LOGGING_FACADE);

    Ok(())
}

/// Performs early (as in, moment of process start) logging initialization. Any logging prior to
/// this call will be SILENTLY discarded. Calling more than once per process will panic.
pub fn early_init() {
    let mut first_init = false;
    let _ = EARLY_INIT_CALLED
        .get_or_try_init(|| -> Result<(), ()> {
            first_init = true;
            Ok(())
        })
        .unwrap();
    if first_init {
        apply_logging_state(&LOGGING_FACADE);
    } else {
        panic!("double early init of the logging system is not permitted.");
    }
}

/// Test only function that ensures logging has been configured. Since tests
/// share module state, we need a way to make sure it has been initialized
/// with *some* configuration.
#[cfg(test)]
pub(crate) fn ensure_inited() -> Result<(), Error> {
    let mut first_init = false;
    let _ = EARLY_INIT_CALLED
        .get_or_try_init(|| -> Result<(), ()> {
            first_init = true;
            Ok(())
        })
        .unwrap();
    if first_init {
        apply_logging_state(&LOGGING_FACADE);
    }
    Ok(())
}

fn apply_logging_state(facade: &'static LoggingFacade) {
    let _ = log::set_logger(facade);
    log::set_max_level(log::LevelFilter::Trace);
}

/// Retrieves the file descriptors owned by the global syslogger.
///
/// Does nothing if syslog was never initialized. If their are any file descriptors, they will be
/// pushed into `fds`.
///
/// Note that the `stderr` file descriptor is never added, as it is not owned by syslog.
pub fn push_descriptors(fds: &mut Vec<RawDescriptor>) {
    let state = STATE.lock();
    fds.extend(state.descriptors.iter());
}

impl Log for State {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.filter.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if self.filter.matches(record) {
            for logger in self.loggers.iter() {
                logger.log(record)
            }
        }
    }

    fn flush(&self) {
        for logger in self.loggers.iter() {
            logger.flush()
        }
    }
}

// Struct that implements io::Write to be used for writing directly to the syslog
pub struct Syslogger<'a> {
    buf: String,
    level: log::Level,
    get_state_fn: Box<dyn Fn() -> MutexGuard<'a, State> + Send + 'a>,
}

impl<'a> Syslogger<'a> {
    pub fn new(level: log::Level) -> Syslogger<'a> {
        Syslogger {
            buf: String::new(),
            level,
            get_state_fn: Box::new(|| STATE.lock()),
        }
    }
    #[cfg(test)]
    fn from_state<F: 'a + Fn() -> MutexGuard<'a, State> + Send>(
        level: log::Level,
        get_state_fn: F,
    ) -> Syslogger<'a> {
        Syslogger {
            buf: String::new(),
            level,
            get_state_fn: Box::new(get_state_fn),
        }
    }
}

impl<'a> io::Write for Syslogger<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let state = (self.get_state_fn)();
        let parsed_str = String::from_utf8_lossy(buf);
        self.buf.push_str(&parsed_str);

        if let Some(last_newline_idx) = self.buf.rfind('\n') {
            for line in self.buf[..last_newline_idx].lines() {
                // Match is to explicitly limit lifetime of args
                // https://github.com/rust-lang/rust/issues/92698
                // https://github.com/rust-lang/rust/issues/15023
                #[allow(clippy::match_single_binding)]
                match format_args!("{}", line) {
                    args => {
                        let mut record_builder = log::Record::builder();
                        record_builder.level(self.level);
                        record_builder.target("syslogger");
                        record_builder.args(args);
                        let record = record_builder.build();
                        state.log(&record);
                    }
                }
            }

            self.buf.drain(..=last_newline_idx);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        STATE.lock().flush();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use std::io::Write;

    use super::*;

    impl Default for State {
        fn default() -> Self {
            Self::new(Default::default()).unwrap()
        }
    }

    use std::sync::Arc;
    #[derive(Clone)]
    struct MockWrite {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl MockWrite {
        fn new() -> Self {
            Self {
                buffer: Arc::new(Mutex::new(vec![])),
            }
        }

        fn into_inner(self) -> Vec<u8> {
            Arc::try_unwrap(self.buffer).unwrap().into_inner()
        }
    }

    impl Write for MockWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer.lock().write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn syslog_log() {
        let state = State::default();
        state.log(
            &log::RecordBuilder::new()
                .level(Level::Error)
                .file(Some(file!()))
                .line(Some(line!()))
                .args(format_args!("hello syslog"))
                .build(),
        );
    }

    #[test]
    fn proc_name() {
        let state = State::new(LogConfig {
            proc_name: String::from("syslog-test"),
            ..Default::default()
        })
        .unwrap();
        state.log(
            &log::RecordBuilder::new()
                .level(Level::Error)
                .file(Some(file!()))
                .line(Some(line!()))
                .args(format_args!("hello syslog"))
                .build(),
        );
    }

    #[test]
    fn macros() {
        ensure_inited().unwrap();
        log::error!("this is an error {}", 3);
        log::warn!("this is a warning {}", "uh oh");
        log::info!("this is info {}", true);
        log::debug!("this is debug info {:?}", Some("helpful stuff"));
    }

    fn pipe_formatter(buf: &mut fmt::Formatter, record: &Record<'_>) -> io::Result<()> {
        writeln!(buf, "{}", record.args())
    }

    #[test]
    fn syslogger_char() {
        let output = MockWrite::new();
        let mut cfg = LogConfig::default();
        cfg.pipe_formatter = Some(pipe_formatter);
        cfg.pipe = Some(Box::new(output.clone()));
        let state = Mutex::new(State::new(cfg).unwrap());

        let mut syslogger = Syslogger::from_state(Level::Info, || state.lock());

        let string = "chars";
        for c in string.chars() {
            syslogger.write_all(&[c as u8]).expect("error writing char");
        }

        syslogger
            .write_all(&[b'\n'])
            .expect("error writing newline char");

        std::mem::drop(syslogger);
        std::mem::drop(state);
        assert_eq!(
            format!("{}\n", string),
            String::from_utf8_lossy(&output.into_inner()[..])
        );
    }

    #[test]
    fn syslogger_line() {
        let output = MockWrite::new();
        let mut cfg = LogConfig::default();
        cfg.pipe_formatter = Some(pipe_formatter);
        cfg.pipe = Some(Box::new(output.clone()));
        let state = Mutex::new(State::new(cfg).unwrap());

        let mut syslogger = Syslogger::from_state(Level::Info, || state.lock());

        let s = "Writing string to syslog\n";
        syslogger
            .write_all(s.as_bytes())
            .expect("error writing string");

        std::mem::drop(syslogger);
        std::mem::drop(state);
        assert_eq!(s, String::from_utf8_lossy(&output.into_inner()[..]));
    }

    #[test]
    fn syslogger_partial() {
        let output = MockWrite::new();
        let state = Mutex::new(
            State::new(LogConfig {
                pipe: Some(Box::new(output.clone())),
                ..Default::default()
            })
            .unwrap(),
        );

        let mut syslogger = Syslogger::from_state(Level::Info, || state.lock());

        let s = "Writing partial string";
        // Should not log because there is no newline character
        syslogger
            .write_all(s.as_bytes())
            .expect("error writing string");

        std::mem::drop(syslogger);
        std::mem::drop(state);
        assert_eq!(Vec::<u8>::new(), output.into_inner());
    }

    #[test]
    fn log_priority_try_from_number() {
        assert_eq!("0".try_into(), Ok(Priority::Emergency));
        assert!(Priority::try_from("100").is_err());
    }

    #[test]
    fn log_priority_try_from_words() {
        assert_eq!("EMERGENCY".try_into(), Ok(Priority::Emergency));
        assert!(Priority::try_from("_EMERGENCY").is_err());
    }

    #[test]
    fn log_should_always_be_enabled_for_level_show_all() {
        let state = State::new(LogConfig {
            filter: "trace",
            ..Default::default()
        })
        .unwrap();

        assert!(state.enabled(
            log::RecordBuilder::new()
                .level(Level::Debug)
                .build()
                .metadata(),
        ));
    }

    #[test]
    fn log_should_always_be_disabled_for_level_silent() {
        let state = State::new(LogConfig {
            filter: "off",
            ..Default::default()
        })
        .unwrap();

        assert!(!state.enabled(
            log::RecordBuilder::new()
                .level(Level::Debug)
                .build()
                .metadata(),
        ));
    }

    #[test]
    fn log_should_be_enabled_if_filter_level_has_a_lower_or_equal_priority() {
        let state = State::new(LogConfig {
            filter: "info",
            ..Default::default()
        })
        .unwrap();

        assert!(state.enabled(
            log::RecordBuilder::new()
                .level(Level::Info)
                .build()
                .metadata(),
        ));
        assert!(state.enabled(
            log::RecordBuilder::new()
                .level(Level::Warn)
                .build()
                .metadata(),
        ));
    }

    #[test]
    fn log_should_be_disabled_if_filter_level_has_a_higher_priority() {
        let state = State::new(LogConfig {
            filter: "info",
            ..Default::default()
        })
        .unwrap();

        assert!(!state.enabled(
            log::RecordBuilder::new()
                .level(Level::Debug)
                .build()
                .metadata(),
        ));
    }

    #[test]
    fn path_overides_should_apply_to_logs() {
        let state = State::new(LogConfig {
            filter: "info,test=debug",
            ..Default::default()
        })
        .unwrap();

        assert!(!state.enabled(
            log::RecordBuilder::new()
                .level(Level::Debug)
                .build()
                .metadata(),
        ));
        assert!(state.enabled(
            log::RecordBuilder::new()
                .level(Level::Debug)
                .target("test")
                .build()
                .metadata(),
        ));
    }

    #[test]
    fn longest_path_prefix_match_should_apply_if_multiple_filters_match() {
        let state = State::new(LogConfig {
            filter: "info,test=debug,test::silence=off",
            ..Default::default()
        })
        .unwrap();

        assert!(!state.enabled(
            log::RecordBuilder::new()
                .level(Level::Debug)
                .build()
                .metadata(),
        ));

        assert!(state.enabled(
            log::RecordBuilder::new()
                .level(Level::Debug)
                .target("test")
                .build()
                .metadata(),
        ));
        assert!(!state.enabled(
            log::RecordBuilder::new()
                .level(Level::Error)
                .target("test::silence")
                .build()
                .metadata(),
        ));
    }
}
