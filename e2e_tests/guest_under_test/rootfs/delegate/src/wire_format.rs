// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum HostToGuestMessage {
    RunCommand { command: String },
    Exit,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum ExitStatus {
    Code(i32),
    Signal(i32),
    None,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProgramExit {
    pub stdout: String,
    pub stderr: String,
    pub exit_status: ExitStatus,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum GuestToHostMessage {
    ProgramExit(ProgramExit),
    Ready,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DelegateMessage {
    HostToGuest(HostToGuestMessage),
    GuestToHost(GuestToHostMessage),
}

impl DelegateMessage {
    pub fn assume_host_to_guest(self) -> HostToGuestMessage {
        match self {
            DelegateMessage::HostToGuest(msg) => msg,
            _ => panic!("Expected HostToGuestMessage"),
        }
    }

    #[allow(unused)]
    pub fn assume_guest_to_host(self) -> GuestToHostMessage {
        match self {
            DelegateMessage::GuestToHost(msg) => msg,
            _ => panic!("Expected GuestToHostMessage"),
        }
    }
}
