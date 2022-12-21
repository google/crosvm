// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::pin::Pin;
use std::str::FromStr;
use std::sync::Mutex;

use anyhow::bail;
use anyhow::Context;
use base::AsRawDescriptor;
use base::RawDescriptor;
use cros_async::AsyncWrapper;
use cros_async::Executor;
use futures::Future;
use futures::FutureExt;
use vmm_vhost::connection::socket::Listener as SocketListener;
use vmm_vhost::connection::vfio::Device;
use vmm_vhost::connection::vfio::Listener as VfioListener;
use vmm_vhost::connection::Endpoint;
use vmm_vhost::connection::Listener;
use vmm_vhost::message::MasterReq;
use vmm_vhost::SlaveListener;
use vmm_vhost::VhostUserSlaveReqHandler;

use crate::virtio::vhost::user::device::handler::sys::unix::run_handler;
use crate::virtio::vhost::user::device::handler::sys::unix::VvuOps;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;
use crate::virtio::vhost::user::device::vvu::pci::VvuPciDevice;
use crate::virtio::vhost::user::device::vvu::VvuDevice;
use crate::virtio::VirtioDeviceType;
use crate::PciAddress;

//// On Unix we can listen to either a socket or a vhost-user device.
pub enum VhostUserListener {
    Socket(SocketListener),
    // We use a box here to avoid clippy warning about large size difference between variants.
    Vvu(Box<VfioListener<VvuDevice>>, VvuOps),
}

impl VhostUserListener {
    /// Creates a new regular vhost-user listener, listening on `path`.
    ///
    /// `keep_rds` can be specified to retrieve the raw descriptors that must be preserved for this
    /// listener to keep working after forking.
    pub fn new_socket(
        path: &str,
        keep_rds: Option<&mut Vec<RawDescriptor>>,
    ) -> anyhow::Result<Self> {
        let listener = SocketListener::new(path, true)?;
        if let Some(rds) = keep_rds {
            rds.push(listener.as_raw_descriptor());
        }

        Ok(VhostUserListener::Socket(listener))
    }

    /// Creates a new VVU listener operating on device `pci_addr`. `max_num_queues` is the maximum
    /// number of virtio queues the device could use.
    ///
    /// `keep_rds` can be specified to retrieve the raw descriptors that must be preserved for this
    /// listener to keep working after forking.
    pub fn new_vvu(
        pci_addr: PciAddress,
        max_num_queues: usize,
        mut keep_rds: Option<&mut Vec<RawDescriptor>>,
    ) -> anyhow::Result<Self> {
        let mut pci_device = VvuPciDevice::new_from_address(pci_addr, max_num_queues)?;
        if let Some(rds) = &mut keep_rds {
            rds.extend(pci_device.irqs.iter().map(|e| e.as_raw_descriptor()));
            rds.extend(
                pci_device
                    .notification_evts
                    .iter()
                    .map(|e| e.as_raw_descriptor()),
            );
            rds.push(pci_device.vfio_dev.device_file().as_raw_descriptor());
        }

        // We create the ops now because they need the PCI device for building, and we won't have
        // access to it anymore after creating the listener.
        let ops = VvuOps::new(&mut pci_device);

        let device = VvuDevice::new(pci_device);
        if let Some(rds) = &mut keep_rds {
            rds.push(device.event().as_raw_descriptor());
        }

        let listener = VfioListener::new(device)?;
        Ok(VhostUserListener::Vvu(Box::new(listener), ops))
    }

    /// Helper for the `device` command, which separates the socket and vfio arguments.
    ///
    /// `socket` is a path to a socket to listen to.
    /// `vfio` is a PCI address to a VVU device.
    ///
    /// Exactly one of `socket` or `vvu` must be provided, or an error is returned.
    ///
    /// `keep_rds` can be specified to retrieve the raw descriptors that must be preserved for this
    /// listener to keep working after forking.
    pub fn new_from_socket_or_vfio(
        socket: &Option<String>,
        vfio: &Option<String>,
        max_num_queues: usize,
        keep_rds: Option<&mut Vec<RawDescriptor>>,
    ) -> anyhow::Result<Self> {
        match (socket, vfio) {
            (Some(socket), None) => Ok(Self::new_socket(socket, keep_rds)?),
            (None, Some(vfio)) => Ok(Self::new_vvu(
                PciAddress::from_str(vfio)?,
                max_num_queues,
                keep_rds,
            )?),
            _ => bail!("exactly one of `--socket` or `--vfio` is required"),
        }
    }

    /// Returns the virtio transport type that will be used for the vhost string `path`.
    pub fn get_virtio_transport_type(path: &str) -> VirtioDeviceType {
        match PciAddress::from_str(path) {
            Ok(_) => VirtioDeviceType::Vvu,
            Err(_) => VirtioDeviceType::VhostUser,
        }
    }
}

/// Attaches to an already bound socket via `listener` and handles incoming messages from the
/// VMM, which are dispatched to the device backend via the `VhostUserBackend` trait methods.
async fn run_with_handler<L, H>(listener: L, handler: H, ex: &Executor) -> anyhow::Result<()>
where
    L::Endpoint: Endpoint<MasterReq> + AsRawDescriptor,
    L: Listener + AsRawDescriptor,
    H: VhostUserSlaveReqHandler,
{
    let mut listener = SlaveListener::<L, _>::new(listener, handler)?;
    listener.set_nonblocking(true)?;

    loop {
        // If the listener is not ready on the first call to `accept` and returns `None`, we
        // temporarily convert it into an async I/O source and yield until it signals there is
        // input data awaiting, before trying again.
        match listener
            .accept()
            .context("failed to accept an incoming connection")?
        {
            Some(req_handler) => return run_handler(req_handler, ex).await,
            None => {
                // Nobody is on the other end yet, wait until we get a connection.
                let async_waiter = ex
                    .async_from_local(AsyncWrapper::new(listener))
                    .context("failed to create async waiter")?;
                async_waiter.wait_readable().await?;

                // Retrieve the listener back so we can use it again.
                listener = async_waiter.into_source().into_inner();
            }
        }
    }
}
impl VhostUserListenerTrait for VhostUserListener {
    /// Infers whether `path` is a PCI address or a socket path, and create the appropriate type
    /// of listener.
    ///
    /// `keep_rds` can be specified to retrieve the raw descriptors that must be preserved for this
    /// listener to keep working after forking.
    fn new(
        path: &str,
        max_num_queues: usize,
        keep_rds: Option<&mut Vec<RawDescriptor>>,
    ) -> anyhow::Result<Self> {
        // If the argument can be parsed as a PCI address, use VVU - otherwise assume it is a path
        // to a socket.
        Ok(match PciAddress::from_str(path) {
            Ok(addr) => Self::new_vvu(addr, max_num_queues, keep_rds)?,
            Err(_) => Self::new_socket(path, keep_rds)?,
        })
    }

    fn run_backend<'e>(
        self,
        backend: Box<dyn VhostUserBackend>,
        ex: &'e Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'e>> {
        match self {
            VhostUserListener::Socket(listener) => {
                let handler = DeviceRequestHandler::new(backend);
                run_with_handler(listener, Mutex::new(handler), ex).boxed_local()
            }
            VhostUserListener::Vvu(listener, ops) => {
                let handler = DeviceRequestHandler::new_with_ops(backend, Box::new(ops));
                run_with_handler(*listener, Mutex::new(handler), ex).boxed_local()
            }
        }
    }

    fn take_parent_process_resources(&mut self) -> Option<Box<dyn std::any::Any>> {
        if let VhostUserListener::Socket(listener) = self {
            listener.take_resources_for_parent()
        } else {
            None
        }
    }
}
