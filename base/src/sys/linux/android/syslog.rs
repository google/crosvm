// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of the Syslog trait as a wrapper around Android's logging library, liblog.

extern crate android_log_sys;

use std::ffi::CString;
use std::ffi::NulError;
use std::mem::size_of;

use android_log_sys::__android_log_is_loggable;
use android_log_sys::__android_log_message;
use android_log_sys::__android_log_write_log_message;
use android_log_sys::log_id_t;
use android_log_sys::LogPriority;

use crate::syslog::Error;
use crate::syslog::Facility;
use crate::syslog::Level;
use crate::syslog::Log;
use crate::syslog::Syslog;
use crate::RawDescriptor;

pub struct PlatformSyslog {
    proc_name: String,
}

impl Syslog for PlatformSyslog {
    fn new(
        proc_name: String,
        facility: Facility,
    ) -> Result<(Option<Box<dyn Log + Send>>, Option<RawDescriptor>), Error> {
        Ok((Some(Box::new(Self { proc_name })), None))
    }
}

impl Log for PlatformSyslog {
    fn log(&self, record: &log::Record) {
        let priority = match record.level() {
            Level::Error => LogPriority::ERROR,
            Level::Warn => LogPriority::WARN,
            Level::Info => LogPriority::INFO,
            Level::Debug => LogPriority::VERBOSE,
            Level::Trace => LogPriority::VERBOSE,
        };
        let message = std::fmt::format(*record.args());
        let _ = android_log(
            log_id_t::SYSTEM,
            priority,
            &self.proc_name,
            record.file(),
            record.line(),
            &message,
        );
    }

    fn enabled(&self, metadata: &log::Metadata) -> bool {
        true
    }

    fn flush(&self) {}
}

/// Send a log message to the Android logger (logd, by default) if it is currently configured to be
/// loggable based on the priority and tag.
///
/// # Arguments
/// * `priority` - The Android log priority. Used to determine whether the message is loggable.
/// * `tag` - A tag to indicate where the log comes from.
/// * `file` - The name of the file from where the message is being logged, if available.
/// * `line` - The line number from where the message is being logged, if available.
/// * `message` - The message to log.
fn android_log(
    buffer_id: log_id_t,
    priority: LogPriority,
    tag: &str,
    file: Option<&str>,
    line: Option<u32>,
    message: &str,
) -> Result<(), NulError> {
    let tag = CString::new(tag)?;
    let default_pri = LogPriority::VERBOSE;
    if unsafe { __android_log_is_loggable(priority as i32, tag.as_ptr(), default_pri as i32) } != 0
    {
        let c_file_name = match file {
            Some(file_name) => CString::new(file_name)?.as_ptr(),
            None => std::ptr::null(),
        };
        let line = line.unwrap_or(0);
        let message = CString::new(message)?;
        let mut log_message = __android_log_message {
            struct_size: size_of::<__android_log_message>(),
            buffer_id: buffer_id as i32,
            priority: priority as i32,
            tag: tag.as_ptr(),
            file: c_file_name,
            line,
            message: message.as_ptr(),
        };
        unsafe { __android_log_write_log_message(&mut log_message) };
    }
    Ok(())
}
