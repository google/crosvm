// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Virtio Vhost Backend Drivers
//!
//! Virtio devices use virtqueues to transport data efficiently. The first generation of virtqueue
//! is a set of three different single-producer, single-consumer ring structures designed to store
//! generic scatter-gather I/O. The virtio specification 1.1 introduces an alternative compact
//! virtqueue layout named "Packed Virtqueue", which is more friendly to memory cache system and
//! hardware implemented virtio devices. The packed virtqueue uses read-write memory, that means
//! the memory will be both read and written by both host and guest. The new Packed Virtqueue is
//! preferred for performance.
//!
//! Vhost is a mechanism to improve performance of Virtio devices by delegate data plane operations
//! to dedicated IO service processes. Only the configuration, I/O submission notification, and I/O
//! completion interruption are piped through the hypervisor.
//! It uses the same virtqueue layout as Virtio to allow Vhost devices to be mapped directly to
//! Virtio devices. This allows a Vhost device to be accessed directly by a guest OS inside a
//! hypervisor process with an existing Virtio (PCI) driver.
//!
//! The initial vhost implementation is a part of the Linux kernel and uses ioctl interface to
//! communicate with userspace applications. Dedicated kernel worker threads are created to handle
//! IO requests from the guest.
//!
//! Later Vhost-user protocol is introduced to complement the ioctl interface used to control the
//! vhost implementation in the Linux kernel. It implements the control plane needed to establish
//! virtqueues sharing with a user space process on the same host. It uses communication over a
//! Unix domain socket to share file descriptors in the ancillary data of the message.
//! The protocol defines 2 sides of the communication, master and slave. Master is the application
//! that shares its virtqueues. Slave is the consumer of the virtqueues. Master and slave can be
//! either a client (i.e. connecting) or server (listening) in the socket communication.

#![deny(missing_docs)]

#[cfg_attr(feature = "vhost-user", macro_use)]
extern crate bitflags;
#[cfg_attr(feature = "vhost-kern", macro_use)]
extern crate sys_util;

mod backend;
pub use backend::*;

#[cfg(feature = "vhost-kern")]
pub mod vhost_kern;
#[cfg(feature = "vhost-user")]
pub mod vhost_user;
#[cfg(feature = "vhost-vsock")]
pub mod vsock;

/// Error codes for vhost operations
#[derive(Debug)]
pub enum Error {
    /// Invalid operations.
    InvalidOperation,
    /// Invalid guest memory.
    InvalidGuestMemory,
    /// Invalid guest memory region.
    InvalidGuestMemoryRegion,
    /// Invalid queue.
    InvalidQueue,
    /// Invalid descriptor table address.
    DescriptorTableAddress,
    /// Invalid used address.
    UsedAddress,
    /// Invalid available address.
    AvailAddress,
    /// Invalid log address.
    LogAddress,
    #[cfg(feature = "vhost-kern")]
    /// Error opening the vhost backend driver.
    VhostOpen(std::io::Error),
    #[cfg(feature = "vhost-kern")]
    /// Error while running ioctl.
    IoctlError(std::io::Error),
    /// Error from IO subsystem.
    IOError(std::io::Error),
    #[cfg(feature = "vhost-user")]
    /// Error from the vhost-user subsystem.
    VhostUserProtocol(vhost_user::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidOperation => write!(f, "invalid vhost operations"),
            Error::InvalidGuestMemory => write!(f, "invalid guest memory object"),
            Error::InvalidGuestMemoryRegion => write!(f, "invalid guest memory region"),
            Error::InvalidQueue => write!(f, "invalid virtqueue"),
            Error::DescriptorTableAddress => {
                write!(f, "invalid virtqueue descriptor table address")
            }
            Error::UsedAddress => write!(f, "invalid virtqueue used table address"),
            Error::AvailAddress => write!(f, "invalid virtqueue available table address"),
            Error::LogAddress => write!(f, "invalid virtqueue log address"),
            Error::IOError(e) => write!(f, "IO error: {}", e),
            #[cfg(feature = "vhost-kern")]
            Error::VhostOpen(e) => write!(f, "failure in opening vhost file: {}", e),
            #[cfg(feature = "vhost-kern")]
            Error::IoctlError(e) => write!(f, "failure in vhost ioctl: {}", e),
            #[cfg(feature = "vhost-user")]
            Error::VhostUserProtocol(e) => write!(f, "vhost-user: {}", e),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(feature = "vhost-user")]
impl std::convert::From<vhost_user::Error> for Error {
    fn from(err: vhost_user::Error) -> Self {
        Error::VhostUserProtocol(err)
    }
}

/// Result of vhost operations
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error() {
        assert_eq!(
            format!("{}", Error::AvailAddress),
            "invalid virtqueue available table address"
        );
        assert_eq!(
            format!("{}", Error::InvalidOperation),
            "invalid vhost operations"
        );
        assert_eq!(
            format!("{}", Error::InvalidGuestMemory),
            "invalid guest memory object"
        );
        assert_eq!(
            format!("{}", Error::InvalidGuestMemoryRegion),
            "invalid guest memory region"
        );
        assert_eq!(format!("{}", Error::InvalidQueue), "invalid virtqueue");
        assert_eq!(
            format!("{}", Error::DescriptorTableAddress),
            "invalid virtqueue descriptor table address"
        );
        assert_eq!(
            format!("{}", Error::UsedAddress),
            "invalid virtqueue used table address"
        );
        assert_eq!(
            format!("{}", Error::LogAddress),
            "invalid virtqueue log address"
        );

        assert_eq!(format!("{:?}", Error::AvailAddress), "AvailAddress");
    }

    #[cfg(feature = "vhost-user")]
    #[test]
    fn test_convert_from_vhost_user_error() {
        let e: Error = vhost_user::Error::OversizedMsg.into();

        assert_eq!(format!("{}", e), "vhost-user: oversized message");
    }
}
