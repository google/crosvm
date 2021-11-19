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

mod backend;
pub use backend::*;

#[cfg(feature = "vhost-user")]
pub mod vhost_user;
pub use vhost_user::Error;

/// Result of vhost-user operations
pub type Result<T> = std::result::Result<T, Error>;
