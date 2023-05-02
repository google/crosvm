// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(clippy::field_reassign_with_default)]

use std::io;
use std::io::Write;
use std::sync::Arc;

use base::syslog::test_only_ensure_inited;
use base::syslog::LogConfig;
use base::syslog::Priority;
use base::syslog::State;
use base::syslog::Syslogger;
use env_logger::fmt;
use log::Level;
use log::Log;
use log::Record;
use sync::Mutex;

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
    test_only_ensure_inited().unwrap();
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

    let mut syslogger = Syslogger::test_only_from_state(Level::Info, || state.lock());

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

    let mut syslogger = Syslogger::test_only_from_state(Level::Info, || state.lock());

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

    let mut syslogger = Syslogger::test_only_from_state(Level::Info, || state.lock());

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
