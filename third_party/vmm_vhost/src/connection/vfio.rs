// Copyright 2021 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structs for VFIO listener and endpoint.

use std::convert::From;
use std::fs::File;
use std::io::{IoSlice, IoSliceMut};
use std::marker::PhantomData;
use std::os::unix::io::RawFd;
use std::path::Path;

use base::{AsRawDescriptor, Event, RawDescriptor};
use remain::sorted;
use thiserror::Error as ThisError;

use super::{Error, Result};
use crate::connection::{Endpoint as EndpointTrait, Listener as ListenerTrait, Req};

/// Errors for `Device::recv_into_bufs()`.
#[sorted]
#[derive(Debug, ThisError)]
pub enum RecvIntoBufsError {
    /// Connection is closed.
    #[error("connection is closed")]
    Disconnect,
    /// Fatal error while receiving data.
    #[error("failed to receive data via VFIO: {0:#}")]
    Fatal(anyhow::Error),
}

impl From<RecvIntoBufsError> for Error {
    fn from(e: RecvIntoBufsError) -> Self {
        match e {
            RecvIntoBufsError::Disconnect => Error::Disconnect,
            RecvIntoBufsError::Fatal(e) => Error::VfioDeviceError(e),
        }
    }
}

/// VFIO device which can be used as virtio-vhost-user device backend.
pub trait Device {
    /// This event must be read before handle_request() is called.
    fn event(&self) -> &Event;

    /// Starts VFIO device.
    fn start(&mut self) -> std::result::Result<(), anyhow::Error>;

    /// Sends data in the given slice of slices.
    fn send_bufs(
        &mut self,
        iovs: &[IoSlice],
        fds: Option<&[RawFd]>,
    ) -> std::result::Result<usize, anyhow::Error>;

    /// Receives data into the given slice of slices and returns the size of the received data.
    fn recv_into_bufs(
        &mut self,
        iovs: &mut [IoSliceMut],
    ) -> std::result::Result<usize, RecvIntoBufsError>;
}

/// Listener for accepting incoming connections from virtio-vhost-user device through VFIO.
pub struct Listener<D: Device> {
    // device will be dropped when Listener::accept() is called.
    device: Option<D>,
}

impl<D: Device> Listener<D> {
    /// Creates a VFIO listener.
    pub fn new(device: D) -> Result<Self> {
        Ok(Self {
            device: Some(device),
        })
    }
}

impl<D: Device> ListenerTrait for Listener<D> {
    type Connection = D;

    fn accept(&mut self) -> Result<Option<Self::Connection>> {
        let mut device = self
            .device
            .take()
            .expect("Listener isn't initialized correctly");
        device.start().map_err(Error::VfioDeviceError)?;
        Ok(Some(device))
    }

    fn set_nonblocking(&self, _block: bool) -> Result<()> {
        unimplemented!("set_nonblocking");
    }
}

/// Endpoint for vhost-user connection through VFIO.
pub struct Endpoint<R: Req, D: Device> {
    device: D,
    _r: PhantomData<R>,
}

impl<R: Req, D: Device> EndpointTrait<R> for Endpoint<R, D> {
    type Listener = Listener<D>;

    /// Create an endpoint from a stream object.
    fn from_connection(device: D) -> Self {
        Self {
            device,
            _r: PhantomData,
        }
    }

    fn connect<P: AsRef<Path>>(_path: P) -> Result<Self> {
        // TODO: remove this method from Endpoint trait?
        panic!("VfioEndpoint cannot create a connection from path");
    }

    fn send_iovec(&mut self, iovs: &[IoSlice], fds: Option<&[RawFd]>) -> Result<usize> {
        self.device
            .send_bufs(iovs, fds)
            .map_err(Error::VfioDeviceError)
    }

    fn recv_into_bufs(
        &mut self,
        bufs: &mut [IoSliceMut],
        _allow_fd: bool, /* ignore, as VFIO doesn't receive FDs */
    ) -> Result<(usize, Option<Vec<File>>)> {
        let size = self
            .device
            .recv_into_bufs(bufs)
            .map_err::<Error, _>(From::<RecvIntoBufsError>::from)?;

        // VFIO backend doesn't receive any files.
        Ok((size, None))
    }
}

impl<R: Req, D: Device> AsRawDescriptor for Endpoint<R, D> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.device.event().as_raw_descriptor()
    }
}
