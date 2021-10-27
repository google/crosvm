// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of the Syslog trait as a wrapper around Android's logging library, liblog.

extern crate android_log_sys;

use crate::syslog::{Error, Facility, Priority, Syslog};
use android_log_sys::{
    __android_log_is_loggable, __android_log_message, __android_log_write_log_message, log_id_t,
    LogPriority,
};
use std::ffi::{CString, NulError};
use std::fmt;
use std::mem::size_of;
use std::os::unix::io::RawFd;

pub struct PlatformSyslog {
    enabled: bool,
}

impl Syslog for PlatformSyslog {
    fn new() -> Result<Self, Error> {
        Ok(Self { enabled: true })
    }

    fn enable(&mut self, enable: bool) -> Result<(), Error> {
        self.enabled = enable;
        Ok(())
    }

    fn push_fds(&self, _fds: &mut Vec<RawFd>) {}

    fn log(
        &self,
        proc_name: Option<&str>,
        pri: Priority,
        _fac: Facility,
        file_line: Option<(&str, u32)>,
        args: fmt::Arguments,
    ) {
        let priority = match pri {
            Priority::Emergency => LogPriority::ERROR,
            Priority::Alert => LogPriority::ERROR,
            Priority::Critical => LogPriority::ERROR,
            Priority::Error => LogPriority::ERROR,
            Priority::Warning => LogPriority::WARN,
            Priority::Notice => LogPriority::INFO,
            Priority::Info => LogPriority::DEBUG,
            Priority::Debug => LogPriority::VERBOSE,
        };
        let tag = proc_name.unwrap_or("crosvm");
        let message = std::fmt::format(args);
        let _ = android_log(
            log_id_t::SYSTEM,
            priority,
            tag,
            file_line.map(|(file, _)| file),
            file_line.map(|(_, line)| line),
            &message,
        );
    }
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
