// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements vhost-based virtio devices.

use std;
use std::fmt::{self, Display};

use net_util::Error as TapError;
use sys_util::Error as SysError;
use vhost::Error as VhostError;

mod net;
mod vsock;
mod worker;

pub use self::net::Net;
pub use self::vsock::Vsock;

#[derive(Debug)]
pub enum Error {
    /// Creating kill eventfd failed.
    CreateKillEventFd(SysError),
    /// Creating poll context failed.
    CreatePollContext(SysError),
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
    /// Setting tap mac address failed.
    TapSetMacAddress(TapError),
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
    /// Failed to set CID for guest.
    VhostVsockSetCid(VhostError),
    /// Failed to start vhost-vsock driver.
    VhostVsockStart(VhostError),
    /// Failed to create vhost eventfd.
    VhostIrqCreate(SysError),
    /// Failed to read vhost eventfd.
    VhostIrqRead(SysError),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            CreateKillEventFd(e) => write!(f, "failed to create kill eventfd: {}", e),
            CreatePollContext(e) => write!(f, "failed to create poll context: {}", e),
            CloneKillEventFd(e) => write!(f, "failed to clone kill eventfd: {}", e),
            PollError(e) => write!(f, "failed polling for events: {}", e),
            TapOpen(e) => write!(f, "failed to open tap device: {}", e),
            TapSetIp(e) => write!(f, "failed to set tap IP: {}", e),
            TapSetNetmask(e) => write!(f, "failed to set tap netmask: {}", e),
            TapSetMacAddress(e) => write!(f, "failed to set tap mac address: {}", e),
            TapSetOffload(e) => write!(f, "failed to set tap interface offload flags: {}", e),
            TapSetVnetHdrSize(e) => write!(f, "failed to set vnet header size: {}", e),
            TapEnable(e) => write!(f, "failed to enable tap interface: {}", e),
            VhostOpen(e) => write!(f, "failed to open vhost device: {}", e),
            VhostSetOwner(e) => write!(f, "failed to set owner: {}", e),
            VhostGetFeatures(e) => write!(f, "failed to get features: {}", e),
            VhostSetFeatures(e) => write!(f, "failed to set features: {}", e),
            VhostSetMemTable(e) => write!(f, "failed to set mem table: {}", e),
            VhostSetVringNum(e) => write!(f, "failed to set vring num: {}", e),
            VhostSetVringAddr(e) => write!(f, "failed to set vring addr: {}", e),
            VhostSetVringBase(e) => write!(f, "failed to set vring base: {}", e),
            VhostSetVringCall(e) => write!(f, "failed to set vring call: {}", e),
            VhostSetVringKick(e) => write!(f, "failed to set vring kick: {}", e),
            VhostNetSetBackend(e) => write!(f, "net set backend failed: {}", e),
            VhostVsockSetCid(e) => write!(f, "failed to set CID for guest: {}", e),
            VhostVsockStart(e) => write!(f, "failed to start vhost-vsock driver: {}", e),
            VhostIrqCreate(e) => write!(f, "failed to create vhost eventfd: {}", e),
            VhostIrqRead(e) => write!(f, "failed to read vhost eventfd: {}", e),
        }
    }
}
