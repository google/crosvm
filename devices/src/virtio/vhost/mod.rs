// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements vhost-based virtio devices.

use anyhow::anyhow;
use anyhow::Context;
use base::Error as SysError;
use base::TubeError;
use data_model::zerocopy_from_mut_slice;
use net_util::Error as TapError;
use remain::sorted;
use thiserror::Error;
#[cfg(unix)]
use vhost::Error as VhostError;
use vmm_vhost::message::MasterReq;
use vmm_vhost::message::Req;
use vmm_vhost::message::VhostUserMsgHeader;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;

mod control_socket;
pub mod user;

pub use self::control_socket::*;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod net;
        pub mod vsock;
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        pub mod scmi;
        mod worker;

        pub use self::net::Net;
        pub use self::vsock::Vsock;
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        pub use self::scmi::Scmi;
    } else if #[cfg(windows)] {}
}

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// Cloning kill event failed.
    #[error("failed to clone kill event: {0}")]
    CloneKillEvent(SysError),
    /// Creating kill event failed.
    #[error("failed to create kill event: {0}")]
    CreateKillEvent(SysError),
    /// Creating tube failed.
    #[error("failed to create tube: {0}")]
    CreateTube(TubeError),
    /// Creating wait context failed.
    #[error("failed to create poll context: {0}")]
    CreateWaitContext(SysError),
    /// Enabling tap interface failed.
    #[error("failed to enable tap interface: {0}")]
    TapEnable(TapError),
    /// Open tap device failed.
    #[error("failed to open tap device: {0}")]
    TapOpen(TapError),
    /// Setting tap IP failed.
    #[error("failed to set tap IP: {0}")]
    TapSetIp(TapError),
    /// Setting tap mac address failed.
    #[error("failed to set tap mac address: {0}")]
    TapSetMacAddress(TapError),
    /// Setting tap netmask failed.
    #[error("failed to set tap netmask: {0}")]
    TapSetNetmask(TapError),
    /// Setting tap interface offload flags failed.
    #[error("failed to set tap interface offload flags: {0}")]
    TapSetOffload(TapError),
    /// Setting vnet header size failed.
    #[error("failed to set vnet header size: {0}")]
    TapSetVnetHdrSize(TapError),
    /// Get features failed.
    #[cfg(unix)]
    #[error("failed to get features: {0}")]
    VhostGetFeatures(VhostError),
    /// Vhost IOTLB required but not supported.
    #[error("Vhost IOTLB required but not supported")]
    VhostIotlbUnsupported,
    /// Failed to create vhost event.
    #[error("failed to create vhost event: {0}")]
    VhostIrqCreate(SysError),
    /// Failed to read vhost event.
    #[error("failed to read vhost event: {0}")]
    VhostIrqRead(SysError),
    /// Net set backend failed.
    #[cfg(unix)]
    #[error("net set backend failed: {0}")]
    VhostNetSetBackend(VhostError),
    /// Failed to open vhost device.
    #[cfg(unix)]
    #[error("failed to open vhost device: {0}")]
    VhostOpen(VhostError),
    /// Set features failed.
    #[cfg(unix)]
    #[error("failed to set features: {0}")]
    VhostSetFeatures(VhostError),
    /// Set mem table failed.
    #[cfg(unix)]
    #[error("failed to set mem table: {0}")]
    VhostSetMemTable(VhostError),
    /// Set owner failed.
    #[cfg(unix)]
    #[error("failed to set owner: {0}")]
    VhostSetOwner(VhostError),
    /// Set vring addr failed.
    #[cfg(unix)]
    #[error("failed to set vring addr: {0}")]
    VhostSetVringAddr(VhostError),
    /// Set vring base failed.
    #[cfg(unix)]
    #[error("failed to set vring base: {0}")]
    VhostSetVringBase(VhostError),
    /// Set vring call failed.
    #[cfg(unix)]
    #[error("failed to set vring call: {0}")]
    VhostSetVringCall(VhostError),
    /// Set vring kick failed.
    #[cfg(unix)]
    #[error("failed to set vring kick: {0}")]
    VhostSetVringKick(VhostError),
    /// Set vring num failed.
    #[cfg(unix)]
    #[error("failed to set vring num: {0}")]
    VhostSetVringNum(VhostError),
    /// Failed to set CID for guest.
    #[cfg(unix)]
    #[error("failed to set CID for guest: {0}")]
    VhostVsockSetCid(VhostError),
    /// Failed to start vhost-vsock driver.
    #[cfg(unix)]
    #[error("failed to start vhost-vsock driver: {0}")]
    VhostVsockStart(VhostError),
    #[error("queue missing vring base")]
    VringBaseMissing,
    /// Error while waiting for events.
    #[error("failed waiting for events: {0}")]
    WaitError(SysError),
}

pub type Result<T> = std::result::Result<T, Error>;

pub const HEADER_LEN: usize = std::mem::size_of::<VhostUserMsgHeader<MasterReq>>();

pub fn vhost_header_from_bytes<R: Req>(bytes: &[u8]) -> Option<&VhostUserMsgHeader<R>> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    // This can't fail because we already checked the size and because packed alignment is 1.
    Some(
        LayoutVerified::<_, VhostUserMsgHeader<R>>::new(&bytes[0..HEADER_LEN])
            .unwrap()
            .into_ref(),
    )
}

pub fn vhost_body_from_message_bytes<T: FromBytes + AsBytes>(
    bytes: &mut [u8],
) -> anyhow::Result<&mut T> {
    let body_len = std::mem::size_of::<T>();
    let hdr = vhost_header_from_bytes::<MasterReq>(bytes).context("failed to parse header")?;

    if body_len != hdr.get_size() as usize || bytes.len() != body_len + HEADER_LEN {
        return Err(anyhow!(
            "parse error: body_len={} hdr_size={} msg_size={}",
            body_len,
            hdr.get_size(),
            bytes.len()
        ));
    }

    // We already checked the size. This can only fail due to alignment, but all valid
    // message types are packed (i.e. alignment=1).
    Ok(zerocopy_from_mut_slice(&mut bytes[HEADER_LEN..]).expect("bad alignment"))
}
