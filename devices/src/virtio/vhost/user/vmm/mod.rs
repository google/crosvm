// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod block;
mod console;
mod fs;
mod gpu;
mod handler;
mod mac80211_hwsim;
mod net;
mod snd;
mod video;
mod virtio_device;
mod vsock;
mod wl;

use remain::sorted;
use thiserror::Error as ThisError;
use virtio_device::QueueSizes;
pub use virtio_device::VhostUserVirtioDevice;
use vm_memory::GuestMemoryError;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::Error as VhostError;

pub use self::handler::VhostUserHandler;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub type Connection = std::os::unix::net::UnixStream;
    } else if #[cfg(windows)] {
        pub type Connection = base::Tube;
    }
}

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// Failed to copy config to a buffer.
    #[error("failed to copy config to a buffer: {0}")]
    CopyConfig(std::io::Error),
    /// Failed to create backend request handler
    #[error("could not create backend req handler: {0}")]
    CreateBackendReqHandler(VhostError),
    /// Failed to create `base::Event`.
    #[error("failed to create Event: {0}")]
    CreateEvent(base::Error),
    /// Failed to get config.
    #[error("failed to get config: {0}")]
    GetConfig(VhostError),
    /// Failed to get features.
    #[error("failed to get features: {0}")]
    GetFeatures(VhostError),
    /// Failed to get host address.
    #[error("failed to get host address: {0}")]
    GetHostAddress(GuestMemoryError),
    /// Failed to get protocol features.
    #[error("failed to get protocol features: {0}")]
    GetProtocolFeatures(VhostError),
    /// Failed to get number of queues.
    #[error("failed to get number of queues: {0}")]
    GetQueueNum(VhostError),
    /// Failed to get vring base offset.
    #[error("failed to get vring base offset: {0}")]
    GetVringBase(VhostError),
    /// Invalid config length is given.
    #[error("invalid config length is given: {0}")]
    InvalidConfigLen(usize),
    /// Invalid config offset is given.
    #[error("invalid config offset is given: {0}")]
    InvalidConfigOffset(u64),
    /// MSI-X config is unavailable.
    #[error("MSI-X config is unavailable")]
    MsixConfigUnavailable,
    /// MSI-X irqfd is unavailable.
    #[error("MSI-X irqfd is unavailable")]
    MsixIrqfdUnavailable,
    #[error("protocol feature is not negotiated: {0:?}")]
    ProtocolFeatureNotNegoiated(VhostUserProtocolFeatures),
    /// Failed to reset owner.
    #[error("failed to reset owner: {0}")]
    ResetOwner(VhostError),
    /// Failed to restore.
    #[error("failed to restore: {0}")]
    Restore(VhostError),
    /// Failed to convert serde Value to a slice.
    #[error("failed to convert a serde Value to slice {0}")]
    SerdeValueToSlice(serde_json::Error),
    /// Failed to set config.
    #[error("failed to set config: {0}")]
    SetConfig(VhostError),
    /// Failed to set device request channel.
    #[error("failed to set device request channel: {0}")]
    SetDeviceRequestChannel(VhostError),
    /// Failed to set features.
    #[error("failed to set features: {0}")]
    SetFeatures(VhostError),
    /// Failed to set memory map regions.
    #[error("failed to set memory map regions: {0}")]
    SetMemTable(VhostError),
    /// Failed to set owner.
    #[error("failed to set owner: {0}")]
    SetOwner(VhostError),
    /// Failed to set protocol features.
    #[error("failed to set protocol features: {0}")]
    SetProtocolFeatures(VhostError),
    /// Failed to set vring address.
    #[error("failed to set vring address: {0}")]
    SetVringAddr(VhostError),
    /// Failed to set vring base offset.
    #[error("failed to set vring base offset: {0}")]
    SetVringBase(VhostError),
    /// Failed to set eventfd to signal used vring buffers.
    #[error("failed to set eventfd to signal used vring buffers: {0}")]
    SetVringCall(VhostError),
    /// Failed to enable or disable vring.
    #[error("failed to enable or disable vring: {0}")]
    SetVringEnable(VhostError),
    /// Failed to set eventfd for adding buffers to vring.
    #[error("failed to set eventfd for adding buffers to vring: {0}")]
    SetVringKick(VhostError),
    /// Failed to set the size of the queue.
    #[error("failed to set the size of the queue: {0}")]
    SetVringNum(VhostError),
    /// Error getting the shmem regions.
    #[error("failed to enumerate shmem regions {0}")]
    ShmemRegions(VhostError),
    /// Failed to sleep the device.
    #[error("failed to sleep the device {0}")]
    Sleep(VhostError),
    /// Failed to convert a slice to a serde Value.
    #[error("Failed to convert a slice to a serde Value: {0}")]
    SliceToSerdeValue(serde_json::Error),
    /// Failed to snapshot.
    #[error("failed to snapshot: {0}")]
    Snapshot(VhostError),
    /// Failed to connect socket.
    #[error("failed to connect socket: {0}")]
    SocketConnect(std::io::Error),
    /// Failed to create Master from a UDS path.
    #[error("failed to connect to device socket while creating instance: {0}")]
    SocketConnectOnMasterCreate(VhostError),
    /// Failed to spawn worker thread.
    #[error("failed to spawn worker: {0}")]
    SpawnWorker(std::io::Error),
    /// The tag for the Fs device was too long to fit in the config space.
    #[error("tag is too long: {len} > {max}")]
    TagTooLong { len: usize, max: usize },
    /// Too many shmem regions.
    #[error("too many shmem regions: {0} > 1")]
    TooManyShmemRegions(usize),
    /// failed to wake the vhost user device.
    #[error("failed to wake the vhost user device.")]
    Wake(VhostError),
    /// failed to wake the worker.
    #[error("failed to wake the worker.")]
    WakeWorker,
}

pub type Result<T> = std::result::Result<T, Error>;
