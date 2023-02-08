// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;
use std::os::unix::prelude::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::open_file;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use data_model::Le64;
use serde::Deserialize;
use vhost::Vhost;
use vhost::Vsock as VhostVsockHandle;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;

use super::worker::Worker;
use super::Error;
use super::Result;
use crate::virtio::copy_config;
use crate::virtio::device_constants::vsock::NUM_QUEUES;
use crate::virtio::device_constants::vsock::QUEUE_SIZES;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;
use crate::Suspendable;
use base::WorkerThread;

static VHOST_VSOCK_DEFAULT_PATH: &str = "/dev/vhost-vsock";

fn default_vsock_path() -> PathBuf {
    PathBuf::from(VHOST_VSOCK_DEFAULT_PATH)
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VhostVsockConfig {
    #[serde(default = "default_vsock_path")]
    pub device: PathBuf,
    pub cid: u64,
}

impl VhostVsockConfig {
    /// Create a new configuration. If `vhost_device` is `None`, the default vhost-vsock device
    /// path will be used.
    pub fn new<P: AsRef<Path>>(cid: u64, vhost_device: Option<P>) -> Self {
        Self {
            cid,
            device: vhost_device
                .map(|p| PathBuf::from(p.as_ref()))
                .unwrap_or_else(|| PathBuf::from(VHOST_VSOCK_DEFAULT_PATH)),
        }
    }
}

pub struct Vsock {
    worker_thread: Option<WorkerThread<()>>,
    vhost_handle: Option<VhostVsockHandle>,
    cid: u64,
    interrupts: Option<Vec<Event>>,
    avail_features: u64,
    acked_features: u64,
}

impl Vsock {
    /// Create a new virtio-vsock device with the given VM cid.
    pub fn new(base_features: u64, vhost_config: &VhostVsockConfig) -> anyhow::Result<Vsock> {
        let device_file = open_file(
            &vhost_config.device,
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK),
        )
        .with_context(|| {
            format!(
                "failed to open virtual socket device {}",
                vhost_config.device.display(),
            )
        })?;

        let handle = VhostVsockHandle::new(device_file);

        let avail_features = base_features;

        let mut interrupts = Vec::new();
        for _ in 0..NUM_QUEUES {
            interrupts.push(Event::new().map_err(Error::VhostIrqCreate)?);
        }

        Ok(Vsock {
            worker_thread: None,
            vhost_handle: Some(handle),
            cid: vhost_config.cid,
            interrupts: Some(interrupts),
            avail_features,
            acked_features: 0,
        })
    }

    pub fn new_for_testing(cid: u64, features: u64) -> Vsock {
        Vsock {
            worker_thread: None,
            vhost_handle: None,
            cid,
            interrupts: None,
            avail_features: features,
            acked_features: 0,
        }
    }

    pub fn acked_features(&self) -> u64 {
        self.acked_features
    }
}

impl VirtioDevice for Vsock {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = Vec::new();

        if let Some(handle) = &self.vhost_handle {
            keep_rds.push(handle.as_raw_descriptor());
        }

        if let Some(interrupt) = &self.interrupts {
            for vhost_int in interrupt.iter() {
                keep_rds.push(vhost_int.as_raw_descriptor());
            }
        }

        keep_rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Vsock
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let cid = Le64::from(self.cid);
        copy_config(data, 0, cid.as_bytes(), offset);
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("vsock: virtio-vsock got unknown feature ack: {:x}", v);

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<(Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() != NUM_QUEUES {
            return Err(anyhow!(
                "net: expected {} queues, got {}",
                NUM_QUEUES,
                queues.len()
            ));
        }

        let vhost_handle = self.vhost_handle.take().context("missing vhost_handle")?;
        let interrupts = self.interrupts.take().context("missing interrupts")?;
        let acked_features = self.acked_features;
        let cid = self.cid;
        // The third vq is an event-only vq that is not handled by the vhost
        // subsystem (but still needs to exist).  Split it off here.
        let _event_queue = queues.remove(2);
        let mut worker = Worker::new(
            queues,
            vhost_handle,
            interrupts,
            interrupt,
            acked_features,
            None,
            self.supports_iommu(),
        );
        let activate_vqs = |handle: &VhostVsockHandle| -> Result<()> {
            handle.set_cid(cid).map_err(Error::VhostVsockSetCid)?;
            handle.start().map_err(Error::VhostVsockStart)?;
            Ok(())
        };
        worker
            .init(mem, QUEUE_SIZES, activate_vqs)
            .context("vsock worker init exited with error")?;

        self.worker_thread = Some(WorkerThread::start("vhost_vsock", move |kill_evt| {
            let cleanup_vqs = |_handle: &VhostVsockHandle| -> Result<()> { Ok(()) };
            let result = worker.run(cleanup_vqs, kill_evt);
            if let Err(e) = result {
                error!("vsock worker thread exited with error: {:?}", e);
            }
        }));

        Ok(())
    }

    fn on_device_sandboxed(&mut self) {
        // ignore the error but to log the error. We don't need to do
        // anything here because when activate, the other vhost set up
        // will be failed to stop the activate thread.
        if let Some(vhost_handle) = &self.vhost_handle {
            match vhost_handle.set_owner() {
                Ok(_) => {}
                Err(e) => error!("{}: failed to set owner: {:?}", self.debug_label(), e),
            }
        }
    }
}

impl Suspendable for Vsock {}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::result::Result;

    use serde_keyvalue::*;

    use super::*;

    #[test]
    fn ack_features() {
        let cid = 5;
        let features: u64 = (1 << 20) | (1 << 49) | (1 << 2) | (1 << 19);
        let mut acked_features: u64 = 0;
        let mut unavailable_features: u64 = 0;

        let mut vsock = Vsock::new_for_testing(cid, features);
        assert_eq!(acked_features, vsock.acked_features());

        acked_features |= 1 << 2;
        vsock.ack_features(acked_features);
        assert_eq!(acked_features, vsock.acked_features());

        acked_features |= 1 << 49;
        vsock.ack_features(acked_features);
        assert_eq!(acked_features, vsock.acked_features());

        acked_features |= 1 << 60;
        unavailable_features |= 1 << 60;
        vsock.ack_features(acked_features);
        assert_eq!(
            acked_features & !unavailable_features,
            vsock.acked_features()
        );

        acked_features |= 1 << 1;
        unavailable_features |= 1 << 1;
        vsock.ack_features(acked_features);
        assert_eq!(
            acked_features & !unavailable_features,
            vsock.acked_features()
        );
    }

    #[test]
    fn read_config() {
        let cid = 0xfca9a559fdcb9756;
        let vsock = Vsock::new_for_testing(cid, 0);

        let mut buf = [0u8; 8];
        vsock.read_config(0, &mut buf);
        assert_eq!(cid, u64::from_le_bytes(buf));

        vsock.read_config(0, &mut buf[..4]);
        assert_eq!(
            (cid & 0xffffffff) as u32,
            u32::from_le_bytes(buf[..4].try_into().unwrap())
        );

        vsock.read_config(4, &mut buf[..4]);
        assert_eq!(
            (cid >> 32) as u32,
            u32::from_le_bytes(buf[..4].try_into().unwrap())
        );

        let data: [u8; 8] = [8, 226, 5, 46, 159, 59, 89, 77];
        buf.copy_from_slice(&data);

        vsock.read_config(12, &mut buf);
        assert_eq!(&buf, &data);
    }

    #[test]
    fn features() {
        let cid = 5;
        let features: u64 = 0xfc195ae8db88cff9;

        let vsock = Vsock::new_for_testing(cid, features);
        assert_eq!(features, vsock.features());
    }

    fn from_vsock_arg(options: &str) -> Result<VhostVsockConfig, ParseError> {
        from_key_values(options)
    }

    #[test]
    fn params_from_key_values() {
        // Path device
        let params = from_vsock_arg("device=/some/path,cid=56").unwrap();
        assert_eq!(
            params,
            VhostVsockConfig {
                device: "/some/path".into(),
                cid: 56,
            }
        );
        // No key for path device
        let params = from_vsock_arg("/some/path,cid=56").unwrap();
        assert_eq!(
            params,
            VhostVsockConfig {
                device: "/some/path".into(),
                cid: 56,
            }
        );
        // Default device
        let params = from_vsock_arg("cid=56").unwrap();
        assert_eq!(
            params,
            VhostVsockConfig {
                device: VHOST_VSOCK_DEFAULT_PATH.into(),
                cid: 56,
            }
        );

        // No argument
        assert_eq!(
            from_vsock_arg("").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("missing field `cid`".into()),
                pos: 0
            }
        );
        // Missing cid
        assert_eq!(
            from_vsock_arg("device=42").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("missing field `cid`".into()),
                pos: 0,
            }
        );
        // Cid passed twice
        assert_eq!(
            from_vsock_arg("cid=42,cid=56").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("duplicate field `cid`".into()),
                pos: 0,
            }
        );
        // Device passed twice
        assert_eq!(
            from_vsock_arg("cid=56,device=42,device=/some/path").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("duplicate field `device`".into()),
                pos: 0,
            }
        );
        // Invalid argument
        assert_eq!(
            from_vsock_arg("invalid=foo").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError(
                    "unknown field `invalid`, expected `device` or `cid`".into()
                ),
                pos: 0,
            }
        );
    }
}
