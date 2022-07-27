// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::IntegrityLevel;
use crate::JobLevel;
use crate::Semantics;
use crate::SubSystem;
use crate::TokenLevel;
use crate::JOB_OBJECT_UILIMIT_READCLIPBOARD;
use crate::JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

/// Policy struct for describing how a sandbox `TargetPolicy` should be
/// constructed for a particular process.
pub struct Policy {
    pub initial_token_level: TokenLevel,
    pub lockdown_token_level: TokenLevel,
    pub integrity_level: IntegrityLevel,
    pub delayed_integrity_level: IntegrityLevel,
    pub job_level: JobLevel,
    pub ui_exceptions: u32,
    pub alternate_desktop: bool,
    pub alternate_winstation: bool,
    pub exceptions: Vec<Rule>,
    pub dll_blocklist: Vec<String>,
}

/// Rule struct describing a sandbox rule that should be added to the
/// `TargetPolicy`.
pub struct Rule {
    pub subsystem: SubSystem,
    pub semantics: Semantics,
    pub pattern: String,
}

/// Policy for the main emulator process.
pub const MAIN: Policy = Policy {
    // Token levels and integrity levels needed for access to hypervisor APIs.
    initial_token_level: TokenLevel::USER_RESTRICTED_SAME_ACCESS,
    lockdown_token_level: TokenLevel::USER_RESTRICTED_NON_ADMIN,
    integrity_level: IntegrityLevel::INTEGRITY_LEVEL_MEDIUM,
    // Needed for access to audio APIs.
    delayed_integrity_level: IntegrityLevel::INTEGRITY_LEVEL_LOW,
    // Needed for access to UI APIs.
    job_level: JobLevel::JOB_LIMITED_USER,
    ui_exceptions: JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    // Needed to display window on main desktop.
    alternate_desktop: false,
    alternate_winstation: false,
    exceptions: vec![],
    dll_blocklist: vec![],
};

/// Policy for the metrics process.
pub const METRICS: Policy = Policy {
    // Needed for access to WinINet.
    initial_token_level: TokenLevel::USER_NON_ADMIN,
    lockdown_token_level: TokenLevel::USER_NON_ADMIN,
    integrity_level: IntegrityLevel::INTEGRITY_LEVEL_LOW,
    delayed_integrity_level: IntegrityLevel::INTEGRITY_LEVEL_LOW,
    job_level: JobLevel::JOB_LOCKDOWN,
    ui_exceptions: 0,
    alternate_desktop: true,
    alternate_winstation: true,
    exceptions: vec![],
    dll_blocklist: vec![],
};

/// Policy for a block device process.
pub const BLOCK: Policy = Policy {
    initial_token_level: TokenLevel::USER_RESTRICTED_NON_ADMIN,
    lockdown_token_level: TokenLevel::USER_LOCKDOWN,
    // INTEGRITY_LEVEL_MEDIUM needed to open disk file.
    integrity_level: IntegrityLevel::INTEGRITY_LEVEL_MEDIUM,
    delayed_integrity_level: IntegrityLevel::INTEGRITY_LEVEL_UNTRUSTED,
    job_level: JobLevel::JOB_LOCKDOWN,
    ui_exceptions: 0,
    alternate_desktop: true,
    alternate_winstation: true,
    exceptions: vec![],
    dll_blocklist: vec![],
};

/// Policy for the network process.
pub const NET: Policy = Policy {
    // Needed to connect to crash handler.
    initial_token_level: TokenLevel::USER_INTERACTIVE,
    lockdown_token_level: TokenLevel::USER_LOCKDOWN,
    // Process won't start below this level as loading ntdll will fail.
    integrity_level: IntegrityLevel::INTEGRITY_LEVEL_LOW,
    delayed_integrity_level: IntegrityLevel::INTEGRITY_LEVEL_UNTRUSTED,
    job_level: JobLevel::JOB_LOCKDOWN,
    ui_exceptions: 0,
    alternate_desktop: true,
    alternate_winstation: true,
    exceptions: vec![],
    dll_blocklist: vec![],
};

/// Policy for the slirp process.
pub const SLIRP: Policy = Policy {
    // Needed to connect to crash handler.
    initial_token_level: TokenLevel::USER_INTERACTIVE,
    // Needed for access to winsock.
    lockdown_token_level: TokenLevel::USER_LIMITED,
    // Needed for access to winsock.
    integrity_level: IntegrityLevel::INTEGRITY_LEVEL_LOW,
    delayed_integrity_level: IntegrityLevel::INTEGRITY_LEVEL_UNTRUSTED,
    job_level: JobLevel::JOB_LOCKDOWN,
    ui_exceptions: 0,
    alternate_desktop: true,
    alternate_winstation: true,
    exceptions: vec![],
    dll_blocklist: vec![],
};
