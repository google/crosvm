// Copyright 2022 The ChromiumOS Authors
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
//! use base::{error, self, warn};
//!
//! if let Err(e) = base::syslog::init() {
//!     println!("failed to initiailize syslog: {}", e);
//!     return;
//! }
//! warn!("this is your {} warning", "final");
//! error!("something went horribly wrong: {}", "out of RAMs");
//! ```

use crate::syslog::Error;
use crate::syslog::Facility;
use crate::syslog::Log;
use crate::syslog::Syslog;
use crate::RawDescriptor;

// SAFETY:
// On windows RawDescriptor is !Sync + !Send, but also on windows we don't do anything with them
unsafe impl Sync for crate::syslog::State {}
// SAFETY: See comments for impl Sync
unsafe impl Send for crate::syslog::State {}

pub struct PlatformSyslog {}

impl Syslog for PlatformSyslog {
    fn new(
        _proc_name: String,
        _facility: Facility,
    ) -> Result<(Option<Box<dyn Log + Send>>, Option<RawDescriptor>), Error> {
        Ok((None, None))
    }
}
