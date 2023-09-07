// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]
//! This file contains values specified in spec.
//! SPC-3: <https://www.t10.org/cgi-bin/ac.pl?t=f&f=spc3r23.pdf>
//! SAM-5: <https://www.t10.org/cgi-bin/ac.pl?t=f&f=sam5r21.pdf>

// SCSI opcodes
/// Opcode for INQUIRY command.
pub const INQUIRY: u8 = 0x12;

// SAM status code
/// Indicates the completion of the command without error.
pub const GOOD: u8 = 0x00;
/// Indicates that sense data has been delivered in the buffer.
pub const CHECK_CONDITION: u8 = 0x02;

// Device Types
/// Indicates the id of disk type.
pub const TYPE_DISK: u8 = 0x00;

// SENSE KEYS
/// Indicates an error that may have been caused by a flaw in the medium or an error in the
/// recorded data.
pub const MEDIUM_ERROR: u8 = 0x03;
/// Indicates an illegal request.
pub const ILLEGAL_REQUEST: u8 = 0x05;
