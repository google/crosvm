// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]
//! This file contains values specified in spec.
//! SPC-3: <https://www.t10.org/cgi-bin/ac.pl?t=f&f=spc3r23.pdf>
//! SAM-5: <https://www.t10.org/cgi-bin/ac.pl?t=f&f=sam5r21.pdf>

// SAM status code
/// Indicates that sense data has been delivered in the buffer.
pub const CHECK_CONDITION: u8 = 0x02;

// SENSE KEYS
/// Indicates an error that may have been caused by a flaw in the medium or an error in the
/// recorded data.
pub const MEDIUM_ERROR: u8 = 0x03;
