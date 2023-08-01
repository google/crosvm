// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod sys;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use base::error;
use base::warn;
use base::Tube;
use cros_async::EventAsync;
use cros_async::Executor;
use futures::future::AbortHandle;
use futures::future::Abortable;
use sync::Mutex;
pub use sys::run_gpu_device;
pub use sys::Options;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserVirtioFeatures;

use crate::virtio::gpu;
use crate::virtio::gpu::QueueReader;
use crate::virtio::vhost::user::device::handler::Error as DeviceError;
use crate::virtio::vhost::user::device::handler::VhostBackendReqConnection;
use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::device::handler::WorkerState;
use crate::virtio::DescriptorChain;
use crate::virtio::Gpu;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::SharedMemoryMapper;
use crate::virtio::SharedMemoryRegion;
use crate::virtio::VirtioDevice;

const MAX_QUEUE_NUM: usize = gpu::QUEUE_SIZES.len();

#[derive(Clone)]
struct SharedReader {
    queue: Arc<Mutex<Queue>>,
    doorbell: Interrupt,
}

impl gpu::QueueReader for SharedReader {
    fn pop(&self) -> Option<DescriptorChain> {
        self.queue.lock().pop()
    }

    fn add_used(&self, desc_chain: DescriptorChain, len: u32) {
        self.queue.lock().add_used(desc_chain, len)
    }

    fn signal_used(&self) {
        self.queue.lock().trigger_interrupt(&self.doorbell);
    }
}

async fn run_ctrl_queue(
    reader: SharedReader,
    mem: GuestMemory,
    kick_evt: EventAsync,
    state: Rc<RefCell<gpu::Frontend>>,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for ctrl queue: {}", e);
            break;
        }

        let mut state = state.borrow_mut();
        let needs_interrupt = state.process_queue(&mem, &reader);

        if needs_interrupt {
            reader.signal_used();
        }
    }
}

struct GpuBackend {
    ex: Executor,
    gpu: Rc<RefCell<Gpu>>,
    resource_bridges: Arc<Mutex<Vec<Tube>>>,
    acked_protocol_features: u64,
    state: Option<Rc<RefCell<gpu::Frontend>>>,
    fence_state: Arc<Mutex<gpu::FenceState>>,
    queue_workers: [Option<WorkerState<Arc<Mutex<Queue>>, ()>>; MAX_QUEUE_NUM],
    platform_workers: Rc<RefCell<Vec<AbortHandle>>>,
    shmem_mapper: Arc<Mutex<Option<Box<dyn SharedMemoryMapper>>>>,
}

impl VhostUserBackend for GpuBackend {
    fn max_queue_num(&self) -> usize {
        MAX_QUEUE_NUM
    }

    fn features(&self) -> u64 {
        self.gpu.borrow().features() | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn ack_features(&mut self, value: u64) -> anyhow::Result<()> {
        self.gpu.borrow_mut().ack_features(value);
        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.features()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::SLAVE_REQ
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::SHARED_MEMORY_REGIONS
    }

    fn ack_protocol_features(&mut self, features: u64) -> anyhow::Result<()> {
        let unrequested_features = features & !self.protocol_features().bits();
        if unrequested_features != 0 {
            bail!("Unexpected protocol features: {:#x}", unrequested_features);
        }

        self.acked_protocol_features |= features;
        Ok(())
    }

    fn acked_protocol_features(&self) -> u64 {
        self.acked_protocol_features
    }

    fn read_config(&self, offset: u64, dst: &mut [u8]) {
        self.gpu.borrow().read_config(offset, dst)
    }

    fn write_config(&self, offset: u64, data: &[u8]) {
        self.gpu.borrow_mut().write_config(offset, data)
    }

    fn start_queue(
        &mut self,
        idx: usize,
        queue: Queue,
        mem: GuestMemory,
        doorbell: Interrupt,
    ) -> anyhow::Result<()> {
        if self.queue_workers[idx].is_some() {
            warn!("Starting new queue handler without stopping old handler");
            self.stop_queue(idx)?;
        }

        match idx {
            // ctrl queue.
            0 => {}
            // We don't currently handle the cursor queue.
            1 => return Ok(()),
            _ => bail!("attempted to start unknown queue: {}", idx),
        }

        let kick_evt = queue
            .event()
            .try_clone()
            .context("failed to clone queue event")?;
        let kick_evt = EventAsync::new(kick_evt, &self.ex)
            .context("failed to create EventAsync for kick_evt")?;

        let queue = Arc::new(Mutex::new(queue));
        let reader = SharedReader {
            queue: queue.clone(),
            doorbell,
        };

        let state = if let Some(s) = self.state.as_ref() {
            s.clone()
        } else {
            let fence_handler_resources =
                Arc::new(Mutex::new(Some(gpu::FenceHandlerActivationResources {
                    mem: mem.clone(),
                    ctrl_queue: reader.clone(),
                })));
            let fence_handler =
                gpu::create_fence_handler(fence_handler_resources, self.fence_state.clone());

            let state = Rc::new(RefCell::new(
                self.gpu
                    .borrow_mut()
                    .initialize_frontend(
                        self.fence_state.clone(),
                        fence_handler,
                        Arc::clone(&self.shmem_mapper),
                    )
                    .ok_or_else(|| anyhow!("failed to initialize gpu frontend"))?,
            ));
            self.state = Some(state.clone());
            state
        };

        // Start handling platform-specific workers.
        self.start_platform_workers()?;

        // Start handling the control queue.
        let (handle, registration) = AbortHandle::new_pair();
        let queue_task = self.ex.spawn_local(Abortable::new(
            run_ctrl_queue(reader, mem, kick_evt, state),
            registration,
        ));

        self.queue_workers[idx] = Some(WorkerState {
            abort_handle: handle,
            queue_task,
            queue,
        });
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<Queue> {
        if let Some(worker) = self.queue_workers.get_mut(idx).and_then(Option::take) {
            worker.abort_handle.abort();

            // Wait for queue_task to be aborted.
            let _ = self.ex.run_until(worker.queue_task);

            // Valid as the GPU device has a single Queue, so clearing the state here is ok.
            self.state = None;

            let queue = match Arc::try_unwrap(worker.queue) {
                Ok(queue_mutex) => queue_mutex.into_inner(),
                Err(_) => panic!("failed to recover queue from worker"),
            };

            Ok(queue)
        } else {
            Err(anyhow::Error::new(DeviceError::WorkerNotFound))
        }
    }

    fn stop_non_queue_workers(&mut self) -> anyhow::Result<()> {
        for handle in self.platform_workers.borrow_mut().drain(..) {
            handle.abort();
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.stop_non_queue_workers()
            .expect("Failed to stop platform workers.");

        for queue_num in 0..self.max_queue_num() {
            // The cursor queue is never used, so we should check if the queue is set before
            // stopping.
            if self.queue_workers[queue_num].is_some() {
                if let Err(e) = self.stop_queue(queue_num) {
                    error!("Failed to stop_queue during reset: {}", e);
                }
            }
        }
    }

    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
        self.gpu.borrow().get_shared_memory_region()
    }

    fn set_backend_req_connection(&mut self, mut conn: VhostBackendReqConnection) {
        let mut opt = self.shmem_mapper.lock();

        if opt.replace(conn.take_shmem_mapper().unwrap()).is_some() {
            warn!("connection already established. overwriting");
        }
    }

    fn snapshot(&self) -> anyhow::Result<Vec<u8>> {
        // TODO(b/289431114): Snapshot more fields if needed. Right now we just need a bare bones
        // snapshot of the GPU to create a POC.
        serde_json::to_vec(&serde_json::Value::Null)
            .context("Failed to serialize Null in the GPU device")
    }

    fn restore(&mut self, data: Vec<u8>) -> anyhow::Result<()> {
        let data =
            serde_json::to_value(data).context("Failed to deserialize NULL in the GPU device")?;
        anyhow::ensure!(
            data == serde_json::Value::Null,
            "unexpected snapshot data: should be null, got {}",
            data
        );
        Ok(())
    }
}

impl Drop for GpuBackend {
    fn drop(&mut self) {
        // Workers are detached and will leak unless they are aborted. Aborting marks the
        // Abortable task, then wakes it up. This means the executor should be asked to continue
        // running for one more step after the backend is destroyed.
        self.reset();
    }
}
