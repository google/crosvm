// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod sys;

use std::rc::Rc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use base::error;
use base::warn;
use base::Event;
use cros_async::sync::RwLock as AsyncRwLock;
use cros_async::AsyncTube;
use cros_async::Executor;
use cros_async::ExecutorKind;
use cros_async::TaskHandle;
use futures::channel::mpsc;
use futures::channel::oneshot;
use sync::Mutex;
pub use sys::start_device as run_block_device;
pub use sys::Options;
use vm_memory::GuestMemory;
use vmm_vhost::message::*;
use vmm_vhost::VhostUserSlaveReqHandler;
use zerocopy::AsBytes;

use crate::virtio;
use crate::virtio::block::asynchronous::run_worker;
use crate::virtio::block::asynchronous::BlockAsync;
use crate::virtio::block::asynchronous::ConfigChangeSignal;
use crate::virtio::block::asynchronous::WorkerCmd;
use crate::virtio::block::DiskState;
use crate::virtio::copy_config;
use crate::virtio::vhost::user::device::handler::sys::Doorbell;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::handler::Error as DeviceError;
use crate::virtio::vhost::user::device::handler::VhostBackendReqConnection;
use crate::virtio::vhost::user::device::handler::VhostBackendReqConnectionState;
use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::device::handler::VhostUserPlatformOps;
use crate::virtio::vhost::user::device::VhostUserDevice;

const NUM_QUEUES: u16 = 16;

struct BlockBackend {
    ex: Executor,
    disk_state: Rc<AsyncRwLock<DiskState>>,
    disk_size: Arc<AtomicU64>,
    block_size: u32,
    seg_max: u32,
    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
    backend_req_conn: Arc<Mutex<VhostBackendReqConnectionState>>,
    control_tube: Option<base::Tube>,
    worker: Option<Worker>,
}

struct Worker {
    worker_task: TaskHandle<Option<base::Tube>>,
    worker_tx: mpsc::UnboundedSender<WorkerCmd<Doorbell>>,
    kill_evt: Event,
}

impl BlockBackend {
    fn start_worker(&mut self) {
        if self.worker.is_some() {
            return;
        }

        let async_tube = self
            .control_tube
            .take()
            .map(|t| AsyncTube::new(&self.ex, t))
            .transpose()
            .expect("failed to create async tube");
        let kill_evt = Event::new().expect("failed to create kill_evt");
        let (worker_tx, worker_rx) = mpsc::unbounded();
        let worker_task = self.ex.spawn_local({
            let ex = self.ex.clone();
            let disk_state = self.disk_state.clone();
            let backend_req_conn = self.backend_req_conn.clone();
            let kill_evt = kill_evt.try_clone().expect("failed to clone event");
            async move {
                let result = run_worker(
                    &ex,
                    ConfigChangeSignal::VhostUserBackendRequest(backend_req_conn),
                    &disk_state,
                    &async_tube,
                    worker_rx,
                    kill_evt,
                    // Use a do-nothing future for irq resampling because vhost-user handles that
                    // elsewhere.
                    std::future::pending(),
                )
                .await;
                if let Err(e) = result {
                    error!("run_worker failed: {}", e);
                }
                async_tube.map(base::Tube::from)
            }
        });

        self.worker = Some(Worker {
            worker_task,
            worker_tx,
            kill_evt,
        });
    }
}

impl VhostUserDevice for BlockAsync {
    fn max_queue_num(&self) -> usize {
        NUM_QUEUES as usize
    }

    fn into_req_handler(
        mut self: Box<Self>,
        ops: Box<dyn VhostUserPlatformOps>,
        ex: &Executor,
    ) -> anyhow::Result<Box<dyn VhostUserSlaveReqHandler>> {
        let avail_features =
            self.avail_features | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let disk_image = match self.disk_image.take() {
            Some(disk_image) => disk_image,
            None => bail!("cannot create a vhost-user backend from an empty disk image"),
        };
        let async_image = disk_image.to_async_disk(ex)?;

        let disk_state = Rc::new(AsyncRwLock::new(DiskState::new(
            async_image,
            Arc::clone(&self.disk_size),
            self.read_only,
            self.sparse,
            self.id,
        )));

        let backend_req_conn = Arc::new(Mutex::new(VhostBackendReqConnectionState::NoConnection));

        let mut backend = BlockBackend {
            ex: ex.clone(),
            disk_state,
            disk_size: Arc::clone(&self.disk_size),
            block_size: self.block_size,
            seg_max: self.seg_max,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            backend_req_conn,
            control_tube: self.control_tube,
            worker: None,
        };
        backend.start_worker();

        let handler = DeviceRequestHandler::new(Box::new(backend), ops);
        Ok(Box::new(std::sync::Mutex::new(handler)))
    }

    fn executor_kind(&self) -> Option<ExecutorKind> {
        Some(self.executor_kind)
    }
}

impl VhostUserBackend for BlockBackend {
    fn max_queue_num(&self) -> usize {
        NUM_QUEUES as usize
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) -> anyhow::Result<()> {
        let unrequested_features = value & !self.avail_features;
        if unrequested_features != 0 {
            bail!("invalid features are given: {:#x}", unrequested_features);
        }

        self.acked_features |= value;

        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::SLAVE_REQ
    }

    fn ack_protocol_features(&mut self, features: u64) -> anyhow::Result<()> {
        let features = VhostUserProtocolFeatures::from_bits(features)
            .ok_or_else(|| anyhow!("invalid protocol features are given: {:#x}", features))?;
        let supported = self.protocol_features();
        self.acked_protocol_features = features & supported;
        Ok(())
    }

    fn acked_protocol_features(&self) -> u64 {
        self.acked_protocol_features.bits()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config_space = {
            let disk_size = self.disk_size.load(Ordering::Relaxed);
            BlockAsync::build_config_space(disk_size, self.seg_max, self.block_size, NUM_QUEUES)
        };
        copy_config(data, 0, config_space.as_bytes(), offset);
    }

    fn reset(&mut self) {
        panic!("Unsupported call to reset");
    }

    fn start_queue(
        &mut self,
        idx: usize,
        queue: virtio::Queue,
        mem: GuestMemory,
        doorbell: Doorbell,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        self.worker
            .as_ref()
            .expect("worker not started")
            .worker_tx
            .unbounded_send(WorkerCmd::StartQueue {
                index: idx,
                queue,
                kick_evt,
                interrupt: doorbell,
                mem,
            })
            .unwrap_or_else(|_| panic!("worker channel closed early"));
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<virtio::Queue> {
        let (response_tx, response_rx) = oneshot::channel();
        self.worker
            .as_ref()
            .expect("worker not started")
            .worker_tx
            .unbounded_send(WorkerCmd::StopQueue {
                index: idx,
                response_tx,
            })
            .unwrap_or_else(|_| panic!("worker channel closed early"));
        self.ex
            .run_until(async {
                response_rx
                    .await
                    .expect("response_rx closed early")
                    .ok_or(anyhow::Error::new(DeviceError::WorkerNotFound))
            })
            .expect("run_until failed")
    }

    fn set_backend_req_connection(&mut self, conn: VhostBackendReqConnection) {
        let mut backend_req_conn = self.backend_req_conn.lock();

        if let VhostBackendReqConnectionState::Connected(_) = &*backend_req_conn {
            warn!("Backend Request Connection already established. Overwriting");
        }

        *backend_req_conn = VhostBackendReqConnectionState::Connected(conn);
    }

    fn stop_non_queue_workers(&mut self) -> anyhow::Result<()> {
        // TODO: this also stops all queues as a byproduct which is fine given how it is currently
        // used but might be unexpected so i should at least tweak the trait docs to mention it
        if let Some(worker) = self.worker.take() {
            worker.kill_evt.signal().unwrap();
            self.control_tube = self
                .ex
                .run_until(worker.worker_task)
                .expect("run_until failed");
        }

        Ok(())
    }
}
