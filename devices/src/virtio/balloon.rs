// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod sys;

use std::collections::VecDeque;
use std::sync::Arc;
use std::thread;

use anyhow::anyhow;
use anyhow::Context;
use balloon_control::BalloonStats;
use balloon_control::BalloonTubeCommand;
use balloon_control::BalloonTubeResult;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::Tube;
use cros_async::block_on;
use cros_async::select8;
use cros_async::sync::Mutex as AsyncMutex;
use cros_async::AsyncTube;
use cros_async::EventAsync;
use cros_async::Executor;
use data_model::DataInit;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use futures::channel::mpsc;
use futures::pin_mut;
use futures::FutureExt;
use futures::StreamExt;
use remain::sorted;
use thiserror::Error as ThisError;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use super::async_utils;
use super::copy_config;
use super::descriptor_utils;
use super::DescriptorChain;
use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::Reader;
use super::SignalableInterrupt;
use super::VirtioDevice;
use crate::Suspendable;
use crate::UnpinRequest;
use crate::UnpinResponse;

#[sorted]
#[derive(ThisError, Debug)]
pub enum BalloonError {
    /// Failed an async await
    #[error("failed async await: {0}")]
    AsyncAwait(cros_async::AsyncError),
    /// Failed to create async message receiver.
    #[error("failed to create async message receiver: {0}")]
    CreatingMessageReceiver(base::TubeError),
    /// Failed to receive command message.
    #[error("failed to receive command message: {0}")]
    ReceivingCommand(base::TubeError),
    /// Failed to send command response.
    #[error("failed to send command response: {0}")]
    SendResponse(base::TubeError),
    /// Failed to write config event.
    #[error("failed to write config event: {0}")]
    WritingConfigEvent(base::Error),
}
pub type Result<T> = std::result::Result<T, BalloonError>;

// Balloon implements four virt IO queues: Inflate, Deflate, Stats, Event.
const QUEUE_SIZE: u16 = 128;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE];

const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;
const VIRTIO_BALLOON_PF_SIZE: u64 = 1 << VIRTIO_BALLOON_PFN_SHIFT;

// The feature bitmap for virtio balloon
const VIRTIO_BALLOON_F_MUST_TELL_HOST: u32 = 0; // Tell before reclaiming pages
const VIRTIO_BALLOON_F_STATS_VQ: u32 = 1; // Stats reporting enabled
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2; // Deflate balloon on OOM
const VIRTIO_BALLOON_F_PAGE_REPORTING: u32 = 5; // Page reporting virtqueue

#[derive(Copy, Clone)]
#[repr(u32)]
// Balloon virtqueues
pub enum BalloonFeatures {
    // Page Reporting enabled
    PageReporting = VIRTIO_BALLOON_F_PAGE_REPORTING,
}

// These feature bits are part of the proposal:
//  https://lists.oasis-open.org/archives/virtio-comment/202201/msg00139.html
const VIRTIO_BALLOON_F_RESPONSIVE_DEVICE: u32 = 6; // Device actively watching guest memory
const VIRTIO_BALLOON_F_EVENTS_VQ: u32 = 7; // Event vq is enabled

// virtio_balloon_config is the balloon device configuration space defined by the virtio spec.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct virtio_balloon_config {
    num_pages: Le32,
    actual: Le32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_balloon_config {}

// BalloonState is shared by the worker and device thread.
#[derive(Default)]
struct BalloonState {
    num_pages: u32,
    actual_pages: u32,
    // Flag indicating that the balloon is in the process of a failable update. This
    // is set by an Adjust command that has allow_failure set, and is cleared when the
    // Adjusted success/failure response is sent.
    failable_update: bool,
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
const VIRTIO_BALLOON_S_NONSTANDARD_SHMEM: u16 = 65534;
const VIRTIO_BALLOON_S_NONSTANDARD_UNEVICTABLE: u16 = 65535;

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
            VIRTIO_BALLOON_S_NONSTANDARD_SHMEM => stats.shared_memory = val,
            VIRTIO_BALLOON_S_NONSTANDARD_UNEVICTABLE => stats.unevictable_memory = val,
            _ => (),
        }
    }
}

const VIRTIO_BALLOON_EVENT_PRESSURE: u32 = 1;
const VIRTIO_BALLOON_EVENT_PUFF_FAILURE: u32 = 2;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct virtio_balloon_event_header {
    evt_type: Le32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_balloon_event_header {}

fn invoke_desc_handler<F>(ranges: Vec<(u64, u64)>, desc_handler: &mut F)
where
    F: FnMut(GuestAddress, u64),
{
    for range in ranges {
        desc_handler(GuestAddress(range.0), range.1);
    }
}

// Release a list of guest memory ranges back to the host system.
// Unpin requests for each inflate range will be sent via `release_memory_tube`
// if provided, and then `desc_handler` will be called for each inflate range.
fn release_ranges<F>(
    release_memory_tube: &Option<Tube>,
    inflate_ranges: Vec<(u64, u64)>,
    desc_handler: &mut F,
) -> descriptor_utils::Result<()>
where
    F: FnMut(GuestAddress, u64),
{
    if let Some(tube) = release_memory_tube {
        let unpin_ranges = inflate_ranges
            .iter()
            .map(|v| {
                (
                    v.0 >> VIRTIO_BALLOON_PFN_SHIFT,
                    v.1 / VIRTIO_BALLOON_PF_SIZE,
                )
            })
            .collect();
        let req = UnpinRequest {
            ranges: unpin_ranges,
        };
        if let Err(e) = tube.send(&req) {
            error!("failed to send unpin request: {}", e);
        } else {
            match tube.recv() {
                Ok(resp) => match resp {
                    UnpinResponse::Success => invoke_desc_handler(inflate_ranges, desc_handler),
                    UnpinResponse::Failed => error!("failed to handle unpin request"),
                },
                Err(e) => error!("failed to handle get unpin response: {}", e),
            }
        }
    } else {
        invoke_desc_handler(inflate_ranges, desc_handler);
    }

    Ok(())
}

// Processes one message's list of addresses.
fn handle_address_chain<F>(
    release_memory_tube: &Option<Tube>,
    avail_desc: DescriptorChain,
    mem: &GuestMemory,
    desc_handler: &mut F,
) -> descriptor_utils::Result<()>
where
    F: FnMut(GuestAddress, u64),
{
    // In a long-running system, there is no reason to expect that
    // a significant number of freed pages are consecutive. However,
    // batching is relatively simple and can result in significant
    // gains in a newly booted system, so it's worth attempting.
    let mut range_start = 0;
    let mut range_size = 0;
    let mut reader = Reader::new(mem.clone(), avail_desc)?;
    let mut inflate_ranges: Vec<(u64, u64)> = Vec::new();
    for res in reader.iter::<Le32>() {
        let pfn = match res {
            Ok(pfn) => pfn,
            Err(e) => {
                error!("error while reading unused pages: {}", e);
                break;
            }
        };
        let guest_address = (u64::from(pfn.to_native())) << VIRTIO_BALLOON_PFN_SHIFT;
        if range_start + range_size == guest_address {
            range_size += VIRTIO_BALLOON_PF_SIZE;
        } else if range_start == guest_address + VIRTIO_BALLOON_PF_SIZE {
            range_start = guest_address;
            range_size += VIRTIO_BALLOON_PF_SIZE;
        } else {
            // Discontinuity, so flush the previous range. Note range_size
            // will be 0 on the first iteration, so skip that.
            if range_size != 0 {
                inflate_ranges.push((range_start, range_size));
            }
            range_start = guest_address;
            range_size = VIRTIO_BALLOON_PF_SIZE;
        }
    }
    if range_size != 0 {
        inflate_ranges.push((range_start, range_size));
    }

    release_ranges(release_memory_tube, inflate_ranges, desc_handler)
}

// Async task that handles the main balloon inflate and deflate queues.
async fn handle_queue<F>(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    release_memory_tube: &Option<Tube>,
    interrupt: Interrupt,
    mut desc_handler: F,
) where
    F: FnMut(GuestAddress, u64),
{
    loop {
        let avail_desc = match queue.next_async(mem, &mut queue_event).await {
            Err(e) => {
                error!("Failed to read descriptor {}", e);
                return;
            }
            Ok(d) => d,
        };
        let index = avail_desc.index;
        if let Err(e) =
            handle_address_chain(release_memory_tube, avail_desc, mem, &mut desc_handler)
        {
            error!("balloon: failed to process inflate addresses: {}", e);
        }
        queue.add_used(mem, index, 0);
        queue.trigger_interrupt(mem, &interrupt);
    }
}

// Processes one page-reporting descriptor.
fn handle_reported_buffer<F>(
    release_memory_tube: &Option<Tube>,
    avail_desc: DescriptorChain,
    desc_handler: &mut F,
) -> descriptor_utils::Result<()>
where
    F: FnMut(GuestAddress, u64),
{
    let mut reported_ranges: Vec<(u64, u64)> = Vec::new();
    let regions = avail_desc.into_iter();
    for desc in regions {
        let (desc_regions, _exported) = desc.into_mem_regions();
        for r in desc_regions {
            reported_ranges.push((r.gpa.offset(), r.len));
        }
    }

    release_ranges(release_memory_tube, reported_ranges, desc_handler)
}

// Async task that handles the page reporting queue.
async fn handle_reporting_queue<F>(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    release_memory_tube: &Option<Tube>,
    interrupt: Interrupt,
    mut desc_handler: F,
) where
    F: FnMut(GuestAddress, u64),
{
    loop {
        let avail_desc = match queue.next_async(mem, &mut queue_event).await {
            Err(e) => {
                error!("Failed to read descriptor {}", e);
                return;
            }
            Ok(d) => d,
        };
        let index = avail_desc.index;
        if let Err(e) = handle_reported_buffer(release_memory_tube, avail_desc, &mut desc_handler) {
            error!("balloon: failed to process reported buffer: {}", e);
        }
        queue.add_used(mem, index, 0);
        queue.trigger_interrupt(mem, &interrupt);
    }
}

fn parse_balloon_stats(reader: &mut Reader) -> BalloonStats {
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
    stats
}

// Async task that handles the stats queue. Note that the cadence of this is driven by requests for
// balloon stats from the control pipe.
// The guests queues an initial buffer on boot, which is read and then this future will block until
// signaled from the command socket that stats should be collected again.
async fn handle_stats_queue(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    mut stats_rx: mpsc::Receiver<u64>,
    command_tube: &AsyncTube,
    state: Arc<AsyncMutex<BalloonState>>,
    interrupt: Interrupt,
) {
    // Consume the first stats buffer sent from the guest at startup. It was not
    // requested by anyone, and the stats are stale.
    let mut index = match queue.next_async(mem, &mut queue_event).await {
        Err(e) => {
            error!("Failed to read descriptor {}", e);
            return;
        }
        Ok(d) => d.index,
    };
    loop {
        // Wait for a request to read the stats.
        let id = match stats_rx.next().await {
            Some(id) => id,
            None => {
                error!("stats signal tube was closed");
                break;
            }
        };

        // Request a new stats_desc to the guest.
        queue.add_used(mem, index, 0);
        queue.trigger_interrupt(mem, &interrupt);

        let stats_desc = match queue.next_async(mem, &mut queue_event).await {
            Err(e) => {
                error!("Failed to read descriptor {}", e);
                return;
            }
            Ok(d) => d,
        };
        index = stats_desc.index;
        let mut reader = match Reader::new(mem.clone(), stats_desc) {
            Ok(r) => r,
            Err(e) => {
                error!("balloon: failed to CREATE Reader: {}", e);
                continue;
            }
        };
        let stats = parse_balloon_stats(&mut reader);

        let actual_pages = state.lock().await.actual_pages as u64;
        let result = BalloonTubeResult::Stats {
            balloon_actual: actual_pages << VIRTIO_BALLOON_PFN_SHIFT,
            stats,
            id,
        };
        let send_result = command_tube.send(result).await;
        if let Err(e) = send_result {
            error!("failed to send stats result: {}", e);
        }
    }
}

async fn handle_event(
    state: Arc<AsyncMutex<BalloonState>>,
    interrupt: Interrupt,
    r: &mut Reader,
    command_tube: &AsyncTube,
) -> Result<()> {
    match r.read_obj::<virtio_balloon_event_header>() {
        Ok(hdr) => match hdr.evt_type.to_native() {
            VIRTIO_BALLOON_EVENT_PRESSURE => {
                // TODO(b/213962590): See how this can be integrated this into memory rebalancing
            }
            VIRTIO_BALLOON_EVENT_PUFF_FAILURE => {
                let mut state = state.lock().await;
                if state.failable_update {
                    state.num_pages = state.actual_pages;
                    interrupt.signal_config_changed();

                    state.failable_update = false;
                    return sys::send_adjusted_response_async(command_tube, state.actual_pages)
                        .await
                        .map_err(BalloonError::SendResponse);
                }
            }
            _ => {
                warn!("Unknown event {}", hdr.evt_type.to_native());
            }
        },
        Err(e) => error!("Failed to parse event header {:?}", e),
    }
    Ok(())
}

// Async task that handles the events queue.
async fn handle_events_queue(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    state: Arc<AsyncMutex<BalloonState>>,
    interrupt: Interrupt,
    command_tube: &AsyncTube,
) -> Result<()> {
    loop {
        let avail_desc = queue
            .next_async(mem, &mut queue_event)
            .await
            .map_err(BalloonError::AsyncAwait)?;
        let index = avail_desc.index;
        match Reader::new(mem.clone(), avail_desc) {
            Ok(mut r) => {
                handle_event(state.clone(), interrupt.clone(), &mut r, command_tube).await?
            }
            Err(e) => error!("balloon: failed to CREATE Reader: {}", e),
        };

        queue.add_used(mem, index, 0);
        queue.trigger_interrupt(mem, &interrupt);
    }
}

// Async task that handles the command socket. The command socket handles messages from the host
// requesting that the guest balloon be adjusted or to report guest memory statistics.
async fn handle_command_tube(
    command_tube: &AsyncTube,
    interrupt: Interrupt,
    state: Arc<AsyncMutex<BalloonState>>,
    mut stats_tx: mpsc::Sender<u64>,
) -> Result<()> {
    loop {
        match command_tube.next().await {
            Ok(command) => match command {
                BalloonTubeCommand::Adjust {
                    num_bytes,
                    allow_failure,
                } => {
                    let num_pages = (num_bytes >> VIRTIO_BALLOON_PFN_SHIFT) as u32;
                    let mut state = state.lock().await;

                    state.num_pages = num_pages;
                    interrupt.signal_config_changed();

                    if allow_failure {
                        if num_pages == state.actual_pages {
                            sys::send_adjusted_response(command_tube, num_pages)
                                .map_err(BalloonError::SendResponse)?;
                        } else {
                            state.failable_update = true;
                        }
                    }
                }
                BalloonTubeCommand::Stats { id } => {
                    if let Err(e) = stats_tx.try_send(id) {
                        error!("failed to signal the stat handler: {}", e);
                    }
                }
            },
            Err(e) => {
                return Err(BalloonError::ReceivingCommand(e));
            }
        }
    }
}

// The main worker thread. Initialized the asynchronous worker tasks and passes them to the executor
// to be processed.
fn run_worker(
    queue_evts: Vec<Event>,
    queues: Vec<Queue>,
    command_tube: Tube,
    #[cfg(windows)] dynamic_mapping_tube: Tube,
    release_memory_tube: Option<Tube>,
    interrupt: Interrupt,
    kill_evt: Event,
    mem: GuestMemory,
    state: Arc<AsyncMutex<BalloonState>>,
    acked_features: u64,
) -> Option<Tube> {
    let ex = Executor::new().unwrap();
    let command_tube = AsyncTube::new(&ex, command_tube).unwrap();

    let mut queue_evts: VecDeque<EventAsync> = queue_evts
        .into_iter()
        .map(|e| EventAsync::new(e, &ex).expect("failed to create async event"))
        .collect();
    let mut queues = VecDeque::from(queues);

    // We need a block to release all references to command_tube at the end before returning it.
    {
        // The first queue is used for inflate messages
        let inflate = handle_queue(
            &mem,
            queues.pop_front().unwrap(),
            queue_evts.pop_front().unwrap(),
            &release_memory_tube,
            interrupt.clone(),
            |guest_address, len| {
                sys::free_memory(
                    &guest_address,
                    len,
                    #[cfg(windows)]
                    &dynamic_mapping_tube,
                    #[cfg(unix)]
                    &mem,
                )
            },
        );
        pin_mut!(inflate);

        // The second queue is used for deflate messages
        let deflate = handle_queue(
            &mem,
            queues.pop_front().unwrap(),
            queue_evts.pop_front().unwrap(),
            &None,
            interrupt.clone(),
            |guest_address, len| {
                sys::reclaim_memory(
                    &guest_address,
                    len,
                    #[cfg(windows)]
                    &dynamic_mapping_tube,
                )
            },
        );
        pin_mut!(deflate);

        // The next queue is used for stats messages if VIRTIO_BALLOON_F_STATS_VQ is negotiated.
        // The message type is the id of the stats request, so we can detect if there are any stale
        // stats results that were queued during an error condition.
        let (stats_tx, stats_rx) = mpsc::channel::<u64>(1);
        let stats = if (acked_features & (1 << VIRTIO_BALLOON_F_STATS_VQ)) != 0 {
            handle_stats_queue(
                &mem,
                queues.pop_front().unwrap(),
                queue_evts.pop_front().unwrap(),
                stats_rx,
                &command_tube,
                state.clone(),
                interrupt.clone(),
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        pin_mut!(stats);

        // The next queue is used for reporting messages
        let reporting = if (acked_features & (1 << VIRTIO_BALLOON_F_PAGE_REPORTING)) != 0 {
            handle_reporting_queue(
                &mem,
                queues.pop_front().unwrap(),
                queue_evts.pop_front().unwrap(),
                &release_memory_tube,
                interrupt.clone(),
                |guest_address, len| {
                    sys::free_memory(
                        &guest_address,
                        len,
                        #[cfg(windows)]
                        &dynamic_mapping_tube,
                        #[cfg(unix)]
                        &mem,
                    )
                },
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        pin_mut!(reporting);

        // Future to handle command messages that resize the balloon.
        let command =
            handle_command_tube(&command_tube, interrupt.clone(), state.clone(), stats_tx);
        pin_mut!(command);

        // Process any requests to resample the irq value.
        let resample = async_utils::handle_irq_resample(&ex, interrupt.clone());
        pin_mut!(resample);

        // Exit if the kill event is triggered.
        let kill = async_utils::await_and_exit(&ex, kill_evt);
        pin_mut!(kill);

        // The next queue is used for events if VIRTIO_BALLOON_F_EVENTS_VQ is negotiated.
        let events = if (acked_features & (1 << VIRTIO_BALLOON_F_EVENTS_VQ)) != 0 {
            handle_events_queue(
                &mem,
                queues.pop_front().unwrap(),
                queue_evts.pop_front().unwrap(),
                state,
                interrupt,
                &command_tube,
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        pin_mut!(events);

        if let Err(e) = ex
            .run_until(select8(
                inflate, deflate, stats, reporting, command, resample, kill, events,
            ))
            .map(|_| ())
        {
            error!("error happened in executor: {}", e);
        }
    }

    release_memory_tube
}

/// Virtio device for memory balloon inflation/deflation.
pub struct Balloon {
    command_tube: Option<Tube>,
    #[cfg(windows)]
    dynamic_mapping_tube: Option<Tube>,
    release_memory_tube: Option<Tube>,
    state: Arc<AsyncMutex<BalloonState>>,
    features: u64,
    acked_features: u64,
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Option<Tube>>>,
}

/// Operation mode of the balloon.
#[derive(PartialEq, Eq)]
pub enum BalloonMode {
    /// The driver can access pages in the balloon (i.e. F_DEFLATE_ON_OOM)
    Relaxed,
    /// The driver cannot access pages in the balloon. Implies F_RESPONSIVE_DEVICE.
    Strict,
}

impl Balloon {
    /// Creates a new virtio balloon device.
    /// To let Balloon able to successfully release the memory which are pinned
    /// by CoIOMMU to host, the release_memory_tube will be used to send the inflate
    /// ranges to CoIOMMU with UnpinRequest/UnpinResponse messages, so that The
    /// memory in the inflate range can be unpinned first.
    pub fn new(
        base_features: u64,
        command_tube: Tube,
        #[cfg(windows)] dynamic_mapping_tube: Tube,
        release_memory_tube: Option<Tube>,
        init_balloon_size: u64,
        mode: BalloonMode,
        enabled_features: u64,
    ) -> Result<Balloon> {
        let features = base_features
            | 1 << VIRTIO_BALLOON_F_MUST_TELL_HOST
            | 1 << VIRTIO_BALLOON_F_STATS_VQ
            | 1 << VIRTIO_BALLOON_F_EVENTS_VQ
            | enabled_features
            | if mode == BalloonMode::Strict {
                1 << VIRTIO_BALLOON_F_RESPONSIVE_DEVICE
            } else {
                1 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM
            };

        Ok(Balloon {
            command_tube: Some(command_tube),
            #[cfg(windows)]
            dynamic_mapping_tube: Some(dynamic_mapping_tube),
            release_memory_tube,
            state: Arc::new(AsyncMutex::new(BalloonState {
                num_pages: (init_balloon_size >> VIRTIO_BALLOON_PFN_SHIFT) as u32,
                actual_pages: 0,
                failable_update: false,
            })),
            kill_evt: None,
            worker_thread: None,
            features,
            acked_features: 0,
        })
    }

    fn get_config(&self) -> virtio_balloon_config {
        let state = block_on(self.state.lock());
        virtio_balloon_config {
            num_pages: state.num_pages.into(),
            actual: state.actual_pages.into(),
        }
    }

    fn num_expected_queues(acked_features: u64) -> usize {
        // mandatory inflate and deflate queues plus any optional ack'ed queues
        let queue_bits = (1 << VIRTIO_BALLOON_F_STATS_VQ)
            | (1 << VIRTIO_BALLOON_F_EVENTS_VQ)
            | (1 << VIRTIO_BALLOON_F_PAGE_REPORTING);
        2 + (acked_features & queue_bits as u64).count_ones() as usize
    }
}

impl Drop for Balloon {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do with a failure.
            let _ = kill_evt.signal();
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

impl VirtioDevice for Balloon {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = Vec::new();
        if let Some(command_tube) = &self.command_tube {
            rds.push(command_tube.as_raw_descriptor());
        }
        if let Some(release_memory_tube) = &self.release_memory_tube {
            rds.push(release_memory_tube.as_raw_descriptor());
        }
        rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Balloon
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

        sys::send_adjusted_response_if_needed(&self.state, &self.command_tube, config);
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, mut value: u64) {
        if value & !self.features != 0 {
            warn!("virtio_balloon got unknown feature ack {:x}", value);
            value &= self.features;
        }
        self.acked_features |= value;
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
    ) -> anyhow::Result<()> {
        let expected_queues = Balloon::num_expected_queues(self.acked_features);
        if queues.len() != expected_queues || queue_evts.len() != expected_queues {
            return Err(anyhow!(
                "expected {} queues, got {}",
                expected_queues,
                queues.len()
            ));
        }

        let (self_kill_evt, kill_evt) = Event::new()
            .and_then(|e| Ok((e.try_clone()?, e)))
            .context("failed to create kill Event pair")?;
        self.kill_evt = Some(self_kill_evt);

        let state = self.state.clone();

        // TODO(b/222588331): this relies on Tube::try_clone working
        #[cfg(unix)]
        #[allow(deprecated)]
        let command_tube = self
            .command_tube
            .as_ref()
            .unwrap()
            .try_clone()
            .context("failed to clone command tube")?;
        #[cfg(windows)]
        let command_tube = self.command_tube.take().unwrap();
        #[cfg(windows)]
        let mapping_tube = self.dynamic_mapping_tube.take().unwrap();
        let release_memory_tube = self.release_memory_tube.take();
        let acked_features = self.acked_features;
        let worker_thread = thread::Builder::new()
            .name("v_balloon".to_string())
            .spawn(move || {
                run_worker(
                    queue_evts,
                    queues,
                    command_tube,
                    #[cfg(windows)]
                    mapping_tube,
                    release_memory_tube,
                    interrupt,
                    kill_evt,
                    mem,
                    state,
                    acked_features,
                )
            })
            .context("failed to spawn virtio_balloon worker")?;
        self.worker_thread = Some(worker_thread);
        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Some(kill_evt) = self.kill_evt.take() {
            if kill_evt.signal().is_err() {
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
                Ok(release_memory_tube) => {
                    self.release_memory_tube = release_memory_tube;
                    return true;
                }
            }
        }
        false
    }
}

impl Suspendable for Balloon {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::descriptor_utils::create_descriptor_chain;
    use crate::virtio::descriptor_utils::DescriptorType;

    #[test]
    fn desc_parsing_inflate() {
        // Check that the memory addresses are parsed correctly by 'handle_address_chain' and passed
        // to the closure.
        let memory_start_addr = GuestAddress(0x0);
        let memory = GuestMemory::new(&[(memory_start_addr, 0x10000)]).unwrap();
        memory
            .write_obj_at_addr(0x10u32, GuestAddress(0x100))
            .unwrap();
        memory
            .write_obj_at_addr(0xaa55aa55u32, GuestAddress(0x104))
            .unwrap();

        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0x0),
            GuestAddress(0x100),
            vec![(DescriptorType::Readable, 8)],
            0,
        )
        .expect("create_descriptor_chain failed");

        let mut addrs = Vec::new();
        let res = handle_address_chain(&None, chain, &memory, &mut |guest_address, len| {
            addrs.push((guest_address, len));
        });
        assert!(res.is_ok());
        assert_eq!(addrs.len(), 2);
        assert_eq!(
            addrs[0].0,
            GuestAddress(0x10u64 << VIRTIO_BALLOON_PFN_SHIFT)
        );
        assert_eq!(
            addrs[1].0,
            GuestAddress(0xaa55aa55u64 << VIRTIO_BALLOON_PFN_SHIFT)
        );
    }

    #[test]
    fn num_expected_queues() {
        let to_feature_bits =
            |features: &[u32]| -> u64 { features.iter().fold(0, |acc, f| acc | (1_u64 << f)) };

        assert_eq!(2, Balloon::num_expected_queues(0));
        assert_eq!(
            2,
            Balloon::num_expected_queues(to_feature_bits(&[VIRTIO_BALLOON_F_MUST_TELL_HOST]))
        );
        assert_eq!(
            3,
            Balloon::num_expected_queues(to_feature_bits(&[VIRTIO_BALLOON_F_STATS_VQ]))
        );
        assert_eq!(
            5,
            Balloon::num_expected_queues(to_feature_bits(&[
                VIRTIO_BALLOON_F_STATS_VQ,
                VIRTIO_BALLOON_F_EVENTS_VQ,
                VIRTIO_BALLOON_F_PAGE_REPORTING
            ]))
        );
    }
}
