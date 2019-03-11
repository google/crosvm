// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements vhost-based virtio devices.

use std;
use std::fmt::{self, Display};

use net_util::Error as TapError;
use remain::sorted;
use sys_util::Error as SysError;
use vhost::Error as VhostError;

mod net;
mod vsock;
mod worker;

pub use self::net::Net;
pub use self::vsock::Vsock;

#[sorted]
#[derive(Debug)]
pub enum Error {
    /// Cloning kill eventfd failed.
    CloneKillEventFd(SysError),
    /// Creating kill eventfd failed.
    CreateKillEventFd(SysError),
    /// Creating poll context failed.
    CreatePollContext(SysError),
    /// Error while polling for events.
    PollError(SysError),
    /// Enabling tap interface failed.
    TapEnable(TapError),
    /// Open tap device failed.
    TapOpen(TapError),
    /// Setting tap IP failed.
    TapSetIp(TapError),
    /// Setting tap mac address failed.
    TapSetMacAddress(TapError),
    /// Setting tap netmask failed.
    TapSetNetmask(TapError),
    /// Setting tap interface offload flags failed.
    TapSetOffload(TapError),
    /// Setting vnet header size failed.
    TapSetVnetHdrSize(TapError),
    /// Get features failed.
    VhostGetFeatures(VhostError),
    /// Failed to create vhost eventfd.
    VhostIrqCreate(SysError),
    /// Failed to read vhost eventfd.
    VhostIrqRead(SysError),
    /// Net set backend failed.
    VhostNetSetBackend(VhostError),
    /// Failed to open vhost device.
    VhostOpen(VhostError),
    /// Set features failed.
    VhostSetFeatures(VhostError),
    /// Set mem table failed.
    VhostSetMemTable(VhostError),
    /// Set owner failed.
    VhostSetOwner(VhostError),
    /// Set vring addr failed.
    VhostSetVringAddr(VhostError),
    /// Set vring base failed.
    VhostSetVringBase(VhostError),
    /// Set vring call failed.
    VhostSetVringCall(VhostError),
    /// Set vring kick failed.
    VhostSetVringKick(VhostError),
    /// Set vring num failed.
    VhostSetVringNum(VhostError),
    /// Failed to set CID for guest.
    VhostVsockSetCid(VhostError),
    /// Failed to start vhost-vsock driver.
    VhostVsockStart(VhostError),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            CloneKillEventFd(e) => write!(f, "failed to clone kill eventfd: {}", e),
            CreateKillEventFd(e) => write!(f, "failed to create kill eventfd: {}", e),
            CreatePollContext(e) => write!(f, "failed to create poll context: {}", e),
            PollError(e) => write!(f, "failed polling for events: {}", e),
            TapEnable(e) => write!(f, "failed to enable tap interface: {}", e),
            TapOpen(e) => write!(f, "failed to open tap device: {}", e),
            TapSetIp(e) => write!(f, "failed to set tap IP: {}", e),
            TapSetMacAddress(e) => write!(f, "failed to set tap mac address: {}", e),
            TapSetNetmask(e) => write!(f, "failed to set tap netmask: {}", e),
            TapSetOffload(e) => write!(f, "failed to set tap interface offload flags: {}", e),
            TapSetVnetHdrSize(e) => write!(f, "failed to set vnet header size: {}", e),
            VhostGetFeatures(e) => write!(f, "failed to get features: {}", e),
            VhostIrqCreate(e) => write!(f, "failed to create vhost eventfd: {}", e),
            VhostIrqRead(e) => write!(f, "failed to read vhost eventfd: {}", e),
            VhostNetSetBackend(e) => write!(f, "net set backend failed: {}", e),
            VhostOpen(e) => write!(f, "failed to open vhost device: {}", e),
            VhostSetFeatures(e) => write!(f, "failed to set features: {}", e),
            VhostSetMemTable(e) => write!(f, "failed to set mem table: {}", e),
            VhostSetOwner(e) => write!(f, "failed to set owner: {}", e),
            VhostSetVringAddr(e) => write!(f, "failed to set vring addr: {}", e),
            VhostSetVringBase(e) => write!(f, "failed to set vring base: {}", e),
            VhostSetVringCall(e) => write!(f, "failed to set vring call: {}", e),
            VhostSetVringKick(e) => write!(f, "failed to set vring kick: {}", e),
            VhostSetVringNum(e) => write!(f, "failed to set vring num: {}", e),
            VhostVsockSetCid(e) => write!(f, "failed to set CID for guest: {}", e),
            VhostVsockStart(e) => write!(f, "failed to start vhost-vsock driver: {}", e),
        }
    }
}
