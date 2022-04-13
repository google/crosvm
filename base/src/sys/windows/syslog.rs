// Copyright 2022 The Chromium OS Authors. All rights reserved.
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
//! use base::syslog::{error, self, warn};
//!
//! if let Err(e) = syslog::init() {
//!     println!("failed to initiailize syslog: {}", e);
//!     return;
//! }
//! warn!("this is your {} warning", "final");
//! error!("something went horribly wrong: {}", "out of RAMs");
//! ```

pub use super::win::syslog::PlatformSyslog;

// TODO(b/223733375): Enable ignored flaky tests.
#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::{io::Read, os::windows::io::FromRawHandle};

    use log::*;
    use regex::Regex;

    use super::super::{BlockingMode, FramingMode, StreamChannel};
    use crate::descriptor::AsRawDescriptor;
    use crate::syslog::*;

    #[test]
    fn syslogger_verify_line_written() {
        init().unwrap();
        clear_path_log_levels();
        let (mut reader, writer) =
            StreamChannel::pair(BlockingMode::Blocking, FramingMode::Byte).unwrap();

        // Safe because writer is guaranteed to exist, and we forget the StreamChannel that used
        // to own the StreamChannel.
        let writer_file = unsafe { File::from_raw_handle(writer.as_raw_descriptor()) };
        std::mem::forget(writer);

        echo_file(Some(writer_file));
        error!("Test message.");

        // Ensure the message we wrote actually was written to the supplied "file" (which is
        // really a named pipe here).
        let mut buf: [u8; 1024] = [0; 1024];
        let bytes_read = reader.read(&mut buf).unwrap();
        assert!(bytes_read > 0);
        let log_msg = String::from_utf8(buf.to_vec()).unwrap();
        let re = Regex::new(r"^\[.+:ERROR:.+:[0-9]+\] Test message.").unwrap();
        assert!(re.is_match(&log_msg));
    }

    #[test]
    fn syslogger_log_level_filter() {
        init().unwrap();
        clear_path_log_levels();
        set_log_level(Priority::Error);

        let (mut reader, writer) =
            StreamChannel::pair(BlockingMode::Blocking, FramingMode::Byte).unwrap();

        // Safe because writer is guaranteed to exist, and we forget the StreamChannel that used
        // to own the StreamChannel.
        let writer_file = unsafe { File::from_raw_handle(writer.as_raw_descriptor()) };
        std::mem::forget(writer);

        echo_file(Some(writer_file));
        error!("Test message.");
        debug!("Test message.");

        add_path_log_level(file!(), Priority::Debug);
        debug!("Test with file filter.");

        set_log_level(PriorityFilter::ShowAll);

        // Ensure the message we wrote actually was written to the supplied "file" (which is
        // really a named pipe here).
        let mut buf: [u8; 1024] = [0; 1024];
        let bytes_read = reader.read(&mut buf).unwrap();
        assert!(bytes_read > 0);
        let log_msg = String::from_utf8(buf.to_vec()).unwrap();
        let re_error = Regex::new(r"(?m)^\[.*ERROR:.+:[0-9]+\] Test message.").unwrap();
        let re_debug = Regex::new(r"(?m)^\[.*DEBUG:.+:[0-9]+\] Test message.").unwrap();
        let filter_debug =
            Regex::new(r"(?m)^\[.*DEBUG:.+:[0-9]+\] Test with file filter.").unwrap();
        assert!(re_error.is_match(&log_msg));
        assert!(!re_debug.is_match(&log_msg));
        assert!(filter_debug.is_match(&log_msg));
    }
}
