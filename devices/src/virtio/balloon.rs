// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use base::{self, error, info, warn, EventFd, PollContext, PollToken};
use data_model::{DataInit, Le16, Le32, Le64};
use msg_socket::{MsgReceiver, MsgSender};
use vm_control::{
    BalloonControlCommand, BalloonControlResponseSocket, BalloonControlResult, BalloonStats,
};
use vm_memory::{GuestAddress, GuestMemory};

use super::{
    copy_config, Interrupt, Queue, Reader, VirtioDevice, TYPE_BALLOON, VIRTIO_F_VERSION_1,
};

#[derive(Debug)]
pub enum BalloonError {
    /// Request to adjust memory size can't provide the number of pages requested.
    NotEnoughPages,
    /// Failure wriitng the config notification event.
    WritingConfigEvent(base::Error),
}
pub type Result<T> = std::result::Result<T, BalloonError>;

impl Display for BalloonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::BalloonError::*;

        match self {
            NotEnoughPages => write!(f, "not enough pages"),
            WritingConfigEvent(e) => write!(f, "failed to write config event: {}", e),
        }
    }
}

// Balloon has three virt IO queues: Inflate, Deflate, and Stats.
const QUEUE_SIZE: u16 = 128;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE];

const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;

// The feature bitmap for virtio balloon
const VIRTIO_BALLOON_F_MUST_TELL_HOST: u32 = 0; // Tell before reclaiming pages
const VIRTIO_BALLOON_F_STATS_VQ: u32 = 1; // Stats reporting enabled
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2; // Deflate balloon on OOM

// virtio_balloon_config is the ballon device configuration space defined by the virtio spec.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct virtio_balloon_config {
    num_pages: Le32,
    actual: Le32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_balloon_config {}

// BalloonConfig is modified by the worker and read from the device thread.
#[derive(Default)]
struct BalloonConfig {
    num_pages: AtomicUsize,
    actual_pages: AtomicUsize,
}

// The constants defining stats types in virtio_baloon_stat
const VIRTIO_BALLOON_S_SWAP_IN: u16 = 0;
const VIRTIO_BALLOON_S_SWAP_OUT: u16 = 1;
const VIRTIO_BALLOON_S_MAJFLT: u16 = 2;
const VIRTIO_BALLOON_S_MINFLT: u16 = 3;
const VIRTIO_BALLOON_S_MEMFREE: u16 = 4;
const VIRTIO_BALLOON_S_MEMTOT: u16 = 5;
const VIRTIO_BALLOON_S_AVAIL: u16 = 6;
const VIRTIO_BALLOON_S_CACHES: u16 = 7;
const VIRTIO_BALLOON_S_HTLB_PGALLOC: u16 = 8;
const VIRTIO_BALLOON_S_HTLB_PGFAIL: u16 = 9;

// BalloonStat is used to deserialize stats from the stats_queue.
#[derive(Copy, Clone)]
#[repr(C, packed)]
struct BalloonStat {
    tag: Le16,
    val: Le64,
}
// Safe because it only has data.
unsafe impl DataInit for BalloonStat {}

impl BalloonStat {
    fn update_stats(&self, stats: &mut BalloonStats) {
        let val = Some(self.val.to_native());
        match self.tag.to_native() {
            VIRTIO_BALLOON_S_SWAP_IN => stats.swap_in = val,
            VIRTIO_BALLOON_S_SWAP_OUT => stats.swap_out = val,
            VIRTIO_BALLOON_S_MAJFLT => stats.major_faults = val,
            VIRTIO_BALLOON_S_MINFLT => stats.minor_faults = val,
            VIRTIO_BALLOON_S_MEMFREE => stats.free_memory = val,
            VIRTIO_BALLOON_S_MEMTOT => stats.total_memory = val,
            VIRTIO_BALLOON_S_AVAIL => stats.available_memory = val,
            VIRTIO_BALLOON_S_CACHES => stats.disk_caches = val,
            VIRTIO_BALLOON_S_HTLB_PGALLOC => stats.hugetlb_allocations = val,
            VIRTIO_BALLOON_S_HTLB_PGFAIL => stats.hugetlb_failures = val,
            _ => (),
        }
    }
}

struct Worker {
    interrupt: Interrupt,
    mem: GuestMemory,
    inflate_queue: Queue,
    deflate_queue: Queue,
    stats_queue: Queue,
    stats_desc_index: Option<u16>,
    config: Arc<BalloonConfig>,
    command_socket: BalloonControlResponseSocket,
}

impl Worker {
    fn process_inflate_deflate(&mut self, inflate: bool) -> bool {
        let queue = if inflate {
            &mut self.inflate_queue
        } else {
            &mut self.deflate_queue
        };

        let mut needs_interrupt = false;
        while let Some(avail_desc) = queue.pop(&self.mem) {
            let index = avail_desc.index;

            if inflate {
                let mut reader = match Reader::new(&self.mem, avail_desc) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("balloon: failed to create reader: {}", e);
                        queue.add_used(&self.mem, index, 0);
                        needs_interrupt = true;
                        continue;
                    }
                };
                for res in reader.iter::<Le32>() {
                    let pfn = match res {
                        Ok(pfn) => pfn,
                        Err(e) => {
                            error!("error while reading unused pages: {}", e);
                            break;
                        }
                    };
                    let guest_address =
                        GuestAddress((u64::from(pfn.to_native())) << VIRTIO_BALLOON_PFN_SHIFT);
                    if self
                        .mem
                        .remove_range(guest_address, 1 << VIRTIO_BALLOON_PFN_SHIFT)
                        .is_err()
                    {
                        warn!("Marking pages unused failed; addr={}", guest_address);
                        continue;
                    }
                }
            }
            queue.add_used(&self.mem, index, 0);
            needs_interrupt = true;
        }

        needs_interrupt
    }

    fn process_stats(&mut self) {
        let queue = &mut self.stats_queue;
        while let Some(stats_desc) = queue.pop(&self.mem) {
            if let Some(prev_desc) = self.stats_desc_index {
                // We shouldn't ever have an extra buffer if the driver follows
                // the protocol, but return it if we find one.
                warn!("balloon: driver is not compliant, more than one stats buffer received");
                queue.add_used(&self.mem, prev_desc, 0);
            }
            self.stats_desc_index = Some(stats_desc.index);
            let mut reader = match Reader::new(&self.mem, stats_desc) {
                Ok(r) => r,
                Err(e) => {
                    error!("balloon: failed to create reader: {}", e);
                    continue;
                }
            };
            let mut stats: BalloonStats = Default::default();
            for res in reader.iter::<BalloonStat>() {
                match res {
                    Ok(stat) => stat.update_stats(&mut stats),
                    Err(e) => {
                        error!("error while reading stats: {}", e);
                        break;
                    }
                };
            }
            let actual_pages = self.config.actual_pages.load(Ordering::Relaxed) as u64;
            let result = BalloonControlResult::Stats {
                balloon_actual: actual_pages << VIRTIO_BALLOON_PFN_SHIFT,
                stats,
            };
            if let Err(e) = self.command_socket.send(&result) {
                warn!("failed to send stats result: {}", e);
            }
        }
    }

    fn request_stats(&mut self) {
        if let Some(index) = self.stats_desc_index.take() {
            self.stats_queue.add_used(&self.mem, index, 0);
            self.interrupt.signal_used_queue(self.stats_queue.vector);
        }
    }

    fn run(&mut self, mut queue_evts: Vec<EventFd>, kill_evt: EventFd) {
        #[derive(PartialEq, PollToken)]
        enum Token {
            Inflate,
            Deflate,
            Stats,
            CommandSocket,
            InterruptResample,
            Kill,
        }

        let inflate_queue_evt = queue_evts.remove(0);
        let deflate_queue_evt = queue_evts.remove(0);
        let stats_queue_evt = queue_evts.remove(0);

        let poll_ctx: PollContext<Token> = match PollContext::build_with(&[
            (&inflate_queue_evt, Token::Inflate),
            (&deflate_queue_evt, Token::Deflate),
            (&stats_queue_evt, Token::Stats),
            (&self.command_socket, Token::CommandSocket),
            (self.interrupt.get_resample_evt(), Token::InterruptResample),
            (&kill_evt, Token::Kill),
        ]) {
            Ok(pc) => pc,
            Err(e) => {
                error!("failed creating PollContext: {}", e);
                return;
            }
        };

        'poll: loop {
            let events = match poll_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };

            let mut needs_interrupt_inflate = false;
            let mut needs_interrupt_deflate = false;
            for event in events.iter_readable() {
                match event.token() {
                    Token::Inflate => {
                        if let Err(e) = inflate_queue_evt.read() {
                            error!("failed reading inflate queue EventFd: {}", e);
                            break 'poll;
                        }
                        needs_interrupt_inflate |= self.process_inflate_deflate(true);
                    }
                    Token::Deflate => {
                        if let Err(e) = deflate_queue_evt.read() {
                            error!("failed reading deflate queue EventFd: {}", e);
                            break 'poll;
                        }
                        needs_interrupt_deflate |= self.process_inflate_deflate(false);
                    }
                    Token::Stats => {
                        if let Err(e) = stats_queue_evt.read() {
                            error!("failed reading stats queue EventFd: {}", e);
                            break 'poll;
                        }
                        self.process_stats();
                    }
                    Token::CommandSocket => {
                        if let Ok(req) = self.command_socket.recv() {
                            match req {
                                BalloonControlCommand::Adjust { num_bytes } => {
                                    let num_pages =
                                        (num_bytes >> VIRTIO_BALLOON_PFN_SHIFT) as usize;
                                    info!("ballon config changed to consume {} pages", num_pages);

                                    self.config.num_pages.store(num_pages, Ordering::Relaxed);
                                    self.interrupt.signal_config_changed();
                                }
                                BalloonControlCommand::Stats => {
                                    self.request_stats();
                                }
                            };
                        }
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => break 'poll,
                }
            }
            for event in events.iter_hungup() {
                if event.token() == Token::CommandSocket && !event.readable() {
                    // If this call fails, the command socket was already removed from the
                    // PollContext.
                    let _ = poll_ctx.delete(&self.command_socket);
                }
            }

            if needs_interrupt_inflate {
                self.interrupt.signal_used_queue(self.inflate_queue.vector);
            }

            if needs_interrupt_deflate {
                self.interrupt.signal_used_queue(self.deflate_queue.vector);
            }
        }
    }
}

/// Virtio device for memory balloon inflation/deflation.
pub struct Balloon {
    command_socket: Option<BalloonControlResponseSocket>,
    config: Arc<BalloonConfig>,
    features: u64,
    kill_evt: Option<EventFd>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
}

impl Balloon {
    /// Create a new virtio balloon device.
    pub fn new(command_socket: BalloonControlResponseSocket) -> Result<Balloon> {
        Ok(Balloon {
            command_socket: Some(command_socket),
            config: Arc::new(BalloonConfig {
                num_pages: AtomicUsize::new(0),
                actual_pages: AtomicUsize::new(0),
            }),
            kill_evt: None,
            worker_thread: None,
            features: 1 << VIRTIO_BALLOON_F_MUST_TELL_HOST
                | 1 << VIRTIO_BALLOON_F_STATS_VQ
                | 1 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM
                | 1 << VIRTIO_F_VERSION_1,
        })
    }

    fn get_config(&self) -> virtio_balloon_config {
        let num_pages = self.config.num_pages.load(Ordering::Relaxed) as u32;
        let actual_pages = self.config.actual_pages.load(Ordering::Relaxed) as u32;
        virtio_balloon_config {
            num_pages: num_pages.into(),
            actual: actual_pages.into(),
        }
    }
}

impl Drop for Balloon {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do with a failure.
            let _ = kill_evt.write(1);
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

impl VirtioDevice for Balloon {
    fn keep_fds(&self) -> Vec<RawFd> {
        vec![self.command_socket.as_ref().unwrap().as_raw_fd()]
    }

    fn device_type(&self) -> u32 {
        TYPE_BALLOON
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.get_config().as_slice(), offset);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let mut config = self.get_config();
        copy_config(config.as_mut_slice(), offset, data, 0);
        self.config
            .actual_pages
            .store(config.actual.to_native() as usize, Ordering::Relaxed);
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, value: u64) {
        self.features &= value;
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != QUEUE_SIZES.len() || queue_evts.len() != QUEUE_SIZES.len() {
            return;
        }

        let (self_kill_evt, kill_evt) = match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed to create kill EventFd pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let config = self.config.clone();
        let command_socket = self.command_socket.take().unwrap();
        let worker_result = thread::Builder::new()
            .name("virtio_balloon".to_string())
            .spawn(move || {
                let mut worker = Worker {
                    interrupt,
                    mem,
                    inflate_queue: queues.remove(0),
                    deflate_queue: queues.remove(0),
                    stats_queue: queues.remove(0),
                    stats_desc_index: None,
                    command_socket,
                    config,
                };
                worker.run(queue_evts, kill_evt);
                worker
            });

        match worker_result {
            Err(e) => {
                error!("failed to spawn virtio_balloon worker: {}", e);
            }
            Ok(join_handle) => {
                self.worker_thread = Some(join_handle);
            }
        }
    }

    fn reset(&mut self) -> bool {
        if let Some(kill_evt) = self.kill_evt.take() {
            if kill_evt.write(1).is_err() {
                error!("{}: failed to notify the kill event", self.debug_label());
                return false;
            }
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            match worker_thread.join() {
                Err(_) => {
                    error!("{}: failed to get back resources", self.debug_label());
                    return false;
                }
                Ok(worker) => {
                    self.command_socket = Some(worker.command_socket);
                    return true;
                }
            }
        }
        false
    }
}
