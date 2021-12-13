// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::cmp::{max, min};
use std::fs::OpenOptions;
use std::rc::Rc;
use std::sync::{atomic::AtomicU64, atomic::Ordering, Arc};

use anyhow::{anyhow, bail, Context};
use argh::FromArgs;
use futures::future::{AbortHandle, Abortable};
use once_cell::sync::OnceCell;
use sync::Mutex;
use vmm_vhost::message::*;

use base::{error, iov_max, warn, Event, Timer};
use cros_async::{sync::Mutex as AsyncMutex, EventAsync, Executor, TimerAsync};
use data_model::DataInit;
use disk::create_async_disk_file;
use hypervisor::ProtectionType;
use vm_memory::GuestMemory;

use crate::virtio::block::asynchronous::{flush_disk, process_one_chain};
use crate::virtio::block::*;
use crate::virtio::vhost::user::device::handler::{
    CallEvent, DeviceRequestHandler, VhostUserBackend,
};
use crate::virtio::{self, base_features, copy_config, Queue};

static BLOCK_EXECUTOR: OnceCell<Executor> = OnceCell::new();

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: u16 = 16;

pub(crate) struct BlockBackend {
    ex_cell: OnceCell<Executor>,
    disk_state: Rc<AsyncMutex<DiskState>>,
    disk_size: Arc<AtomicU64>,
    block_size: u32,
    seg_max: u32,
    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
    flush_timer: Rc<RefCell<TimerAsync>>,
    flush_timer_armed: Rc<RefCell<bool>>,
    workers: [Option<AbortHandle>; Self::MAX_QUEUE_NUM],
}

impl BlockBackend {
    /// Creates a new block backend.
    ///
    /// * `ex_cell`: `OnceCell` that must be initialized with an executor which is used in this device thread.
    /// * `filename`: Name of the disk image file.
    /// * `options`: Vector of file options.
    ///   - `read-only`
    pub(crate) fn new(
        ex_cell: OnceCell<Executor>,
        filename: &str,
        options: Vec<&str>,
    ) -> anyhow::Result<Self> {
        let read_only = options.contains(&"read-only");
        let sparse = false;
        let block_size = 512;
        let f = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .create(false)
            .open(filename)
            .context("Failed to open disk file")?;
        let disk_image = create_async_disk_file(f).context("Failed to create async file")?;

        let base_features = base_features(ProtectionType::Unprotected);

        if block_size % SECTOR_SIZE as u32 != 0 {
            bail!(
                "Block size {} is not a multiple of {}.",
                block_size,
                SECTOR_SIZE,
            );
        }
        let disk_size = disk_image.get_len()?;
        if disk_size % block_size as u64 != 0 {
            warn!(
                "Disk size {} is not a multiple of block size {}; \
                 the remainder will not be visible to the guest.",
                disk_size, block_size,
            );
        }

        let avail_features = build_avail_features(base_features, read_only, sparse, true)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let seg_max = min(max(iov_max(), 1), u32::max_value() as usize) as u32;

        // Since we do not currently support indirect descriptors, the maximum
        // number of segments must be smaller than the queue size.
        // In addition, the request header and status each consume a descriptor.
        let seg_max = min(seg_max, u32::from(QUEUE_SIZE) - 2);

        let ex = ex_cell.get().context("Executor not initialized")?;

        let async_image = disk_image.to_async_disk(ex)?;

        let disk_size = Arc::new(AtomicU64::new(disk_size));

        let disk_state = Rc::new(AsyncMutex::new(DiskState::new(
            async_image,
            Arc::clone(&disk_size),
            read_only,
            sparse,
            None, // id: Option<BlockId>,
        )));

        let timer = Timer::new().context("Failed to create a timer")?;
        let flush_timer_write = Rc::new(RefCell::new(
            TimerAsync::new(
                // Call try_clone() to share the same underlying FD with the `flush_disk` task.
                timer.0.try_clone().context("Failed to clone flush_timer")?,
                ex,
            )
            .context("Failed to create an async timer")?,
        ));
        // Create a separate TimerAsync with the same backing kernel timer. This allows the
        // `flush_disk` task to borrow its copy waiting for events while the queue handlers can
        // still borrow their copy momentarily to set timeouts.
        // Call try_clone() to share the same underlying FD with the `flush_disk` task.
        let flush_timer_read = timer
            .0
            .try_clone()
            .context("Failed to clone flush_timer")
            .and_then(|t| TimerAsync::new(t, ex).context("Failed to create an async timer"))?;
        let flush_timer_armed = Rc::new(RefCell::new(false));
        ex.spawn_local(flush_disk(
            Rc::clone(&disk_state),
            flush_timer_read,
            Rc::clone(&flush_timer_armed),
        ))
        .detach();

        Ok(BlockBackend {
            ex_cell,
            disk_state,
            disk_size,
            block_size,
            seg_max,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            flush_timer: flush_timer_write,
            flush_timer_armed,
            workers: Default::default(),
        })
    }
}

impl VhostUserBackend for BlockBackend {
    const MAX_QUEUE_NUM: usize = NUM_QUEUES as usize;
    const MAX_VRING_LEN: u16 = QUEUE_SIZE;

    type Doorbell = CallEvent;
    type Error = anyhow::Error;

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
        VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::MQ
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
            build_config_space(disk_size, self.seg_max, self.block_size, NUM_QUEUES)
        };
        copy_config(data, 0, config_space.as_slice(), offset);
    }

    fn reset(&mut self) {
        panic!("Unsupported call to reset");
    }

    fn start_queue(
        &mut self,
        idx: usize,
        mut queue: virtio::Queue,
        mem: GuestMemory,
        call_evt: Arc<Mutex<CallEvent>>,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            warn!("Starting new queue handler without stopping old handler");
            handle.abort();
        }

        // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
        queue.ack_features(self.acked_features);

        // Safe because the executor is initialized in main() below.
        let ex = self.ex_cell.get().expect("Executor not initialized");

        let kick_evt =
            EventAsync::new(kick_evt.0, ex).context("failed to create EventAsync for kick_evt")?;
        let (handle, registration) = AbortHandle::new_pair();

        let disk_state = Rc::clone(&self.disk_state);
        let timer = Rc::clone(&self.flush_timer);
        let timer_armed = Rc::clone(&self.flush_timer_armed);
        ex.spawn_local(Abortable::new(
            handle_queue(
                mem,
                disk_state,
                Rc::new(RefCell::new(queue)),
                kick_evt,
                call_evt,
                timer,
                timer_armed,
            ),
            registration,
        ))
        .detach();

        self.workers[idx] = Some(handle);
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            handle.abort();
        }
    }
}

// There is one async task running `handle_queue` per virtio queue in use.
// Receives messages from the guest and queues a task to complete the operations with the async
// executor.
async fn handle_queue(
    mem: GuestMemory,
    disk_state: Rc<AsyncMutex<DiskState>>,
    queue: Rc<RefCell<Queue>>,
    evt: EventAsync,
    interrupt: Arc<Mutex<CallEvent>>,
    flush_timer: Rc<RefCell<TimerAsync>>,
    flush_timer_armed: Rc<RefCell<bool>>,
) {
    loop {
        if let Err(e) = evt.next_val().await {
            error!("Failed to read the next queue event: {}", e);
            continue;
        }
        // Safe because the executor is initialized in main() below.
        let ex = BLOCK_EXECUTOR.get().expect("Executor not initialized");
        while let Some(descriptor_chain) = queue.borrow_mut().pop(&mem) {
            let queue = Rc::clone(&queue);
            let disk_state = Rc::clone(&disk_state);
            let mem = mem.clone();
            let interrupt = Arc::clone(&interrupt);
            let flush_timer = Rc::clone(&flush_timer);
            let flush_timer_armed = Rc::clone(&flush_timer_armed);
            ex.spawn_local(async move {
                process_one_chain(
                    queue,
                    descriptor_chain,
                    disk_state,
                    mem,
                    &interrupt,
                    flush_timer,
                    flush_timer_armed,
                )
                .await
            })
            .detach();
        }
    }
}

#[derive(FromArgs)]
#[argh(description = "")]
struct Options {
    #[argh(
        option,
        description = "path and options of the disk file.",
        arg_name = "PATH<:read-only>"
    )]
    file: String,
    #[argh(option, description = "path to a socket", arg_name = "PATH")]
    socket: String,
}

/// Starts a vhost-user block device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_block_device(program_name: &str, args: &[&str]) -> anyhow::Result<()> {
    let opts = match Options::from_args(&[program_name], args) {
        Ok(opts) => opts,
        Err(e) => {
            if e.status.is_err() {
                bail!(e.output);
            } else {
                println!("{}", e.output);
            }
            return Ok(());
        }
    };

    let ex = Executor::new().context("failed to create executor")?;
    BLOCK_EXECUTOR
        .set(ex.clone())
        .map_err(|_| anyhow!("failed to set executor"))?;

    let mut fileopts = opts.file.split(":").collect::<Vec<_>>();
    let filename = fileopts.remove(0);

    let block = BlockBackend::new(BLOCK_EXECUTOR.clone(), filename, fileopts)?;
    let handler = DeviceRequestHandler::new(block);

    if let Err(e) = ex.run_until(handler.run(opts.socket, &ex)) {
        bail!("error occurred: {}", e);
    }

    Ok(())
}
