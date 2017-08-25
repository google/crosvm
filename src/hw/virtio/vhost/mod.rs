// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements vhost-based virtio devices.

use std;

use net_util::Error as TapError;
use sys_util::Error as SysError;
use vhost::Error as VhostError;

mod net;
mod worker;

pub use self::net::Net;

#[derive(Debug)]
pub enum Error {
    /// Creating kill eventfd failed.
    CreateKillEventFd(SysError),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(SysError),
    /// Error while polling for events.
    PollError(SysError),
    /// Open tap device failed.
    TapOpen(TapError),
    /// Setting tap IP failed.
    TapSetIp(TapError),
    /// Setting tap netmask failed.
    TapSetNetmask(TapError),
    /// Setting tap interface offload flags failed.
    TapSetOffload(TapError),
    /// Setting vnet header size failed.
    TapSetVnetHdrSize(TapError),
    /// Enabling tap interface failed.
    TapEnable(TapError),
    /// Failed to open vhost device.
    VhostOpen(VhostError),
    /// Set owner failed.
    VhostSetOwner(VhostError),
    /// Get features failed.
    VhostGetFeatures(VhostError),
    /// Set features failed.
    VhostSetFeatures(VhostError),
    /// Set mem table failed.
    VhostSetMemTable(VhostError),
    /// Set vring num failed.
    VhostSetVringNum(VhostError),
    /// Set vring addr failed.
    VhostSetVringAddr(VhostError),
    /// Set vring base failed.
    VhostSetVringBase(VhostError),
    /// Set vring call failed.
    VhostSetVringCall(VhostError),
    /// Set vring kick failed.
    VhostSetVringKick(VhostError),
    /// Net set backend failed.
    VhostNetSetBackend(VhostError),
    /// Failed to create vhost eventfd.
    VhostIrqCreate(SysError),
    /// Failed to read vhost eventfd.
    VhostIrqRead(SysError),
}

pub type Result<T> = std::result::Result<T, Error>;
