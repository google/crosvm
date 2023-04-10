// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod sys;

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use balloon_control::BalloonStats;
use balloon_control::BalloonTubeCommand;
use balloon_control::BalloonTubeResult;
use balloon_control::BalloonWSS;
use balloon_control::VIRTIO_BALLOON_WSS_CONFIG_SIZE;
use balloon_control::VIRTIO_BALLOON_WSS_NUM_BINS;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::SendTube;
use base::Tube;
use base::WorkerThread;
use cros_async::block_on;
use cros_async::select12;
use cros_async::sync::Mutex as AsyncMutex;
use cros_async::AsyncTube;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::SendTubeAsync;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use futures::channel::mpsc;
use futures::pin_mut;
use futures::FutureExt;
use futures::StreamExt;
use remain::sorted;
use thiserror::Error as ThisError;
use vm_control::RegisteredEvent;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use super::async_utils;
use super::copy_config;
use super::descriptor_utils;
use super::DescriptorChain;
use super::DescriptorError;
use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::Reader;
use super::SignalableInterrupt;
use super::VirtioDevice;
use super::Writer;
use crate::Suspendable;
use crate::UnpinRequest;
use crate::UnpinResponse;

#[sorted]
#[derive(ThisError, Debug)]
pub enum BalloonError {
    /// Failed an async await
    #[error("failed async await: {0}")]
    AsyncAwait(cros_async::AsyncError),
    /// Failed to create event.
    #[error("failed to create event: {0}")]
    CreatingEvent(base::Error),
    /// Failed to create async message receiver.
    #[error("failed to create async message receiver: {0}")]
    CreatingMessageReceiver(base::TubeError),
    /// Virtio descriptor error
    #[error("virtio descriptor error: {0}")]
    Descriptor(DescriptorError),
    /// Failed to receive command message.
    #[error("failed to receive command message: {0}")]
    ReceivingCommand(base::TubeError),
    /// Failed to send command response.
    #[error("failed to send command response: {0}")]
    SendResponse(base::TubeError),
    /// Error while writing to virtqueue
    #[error("failed to write to virtqueue: {0}")]
    WriteQueue(std::io::Error),
    /// Failed to write config event.
    #[error("failed to write config event: {0}")]
    WritingConfigEvent(base::Error),
}
pub type Result<T> = std::result::Result<T, BalloonError>;

// Balloon implements six virt IO queues: Inflate, Deflate, Stats, Event, WssData, WssCmd.
const QUEUE_SIZE: u16 = 128;
const QUEUE_SIZES: &[u16] = &[
    QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE,
];

const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;
const VIRTIO_BALLOON_PF_SIZE: u64 = 1 << VIRTIO_BALLOON_PFN_SHIFT;

// The feature bitmap for virtio balloon
const VIRTIO_BALLOON_F_MUST_TELL_HOST: u32 = 0; // Tell before reclaiming pages
const VIRTIO_BALLOON_F_STATS_VQ: u32 = 1; // Stats reporting enabled
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2; // Deflate balloon on OOM
const VIRTIO_BALLOON_F_PAGE_REPORTING: u32 = 5; // Page reporting virtqueue
                                                // TODO(b/273973298): this should maybe be bit 6? to be changed later
const VIRTIO_BALLOON_F_WSS_REPORTING: u32 = 8; // Working Set Size reporting virtqueues

#[derive(Copy, Clone)]
#[repr(u32)]
// Balloon virtqueues
pub enum BalloonFeatures {
    // Page Reporting enabled
    PageReporting = VIRTIO_BALLOON_F_PAGE_REPORTING,
    // WSS Reporting enabled
    WSSReporting = VIRTIO_BALLOON_F_WSS_REPORTING,
}

// These feature bits are part of the proposal:
//  https://lists.oasis-open.org/archives/virtio-comment/202201/msg00139.html
const VIRTIO_BALLOON_F_RESPONSIVE_DEVICE: u32 = 6; // Device actively watching guest memory
const VIRTIO_BALLOON_F_EVENTS_VQ: u32 = 7; // Event vq is enabled

// virtio_balloon_config is the balloon device configuration space defined by the virtio spec.
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
#[repr(C)]
struct virtio_balloon_config {
    num_pages: Le32,
    actual: Le32,
    free_page_hint_cmd_id: Le32,
    poison_val: Le32,
    // WSS field is part of proposed spec extension (b/273973298).
    wss_num_bins: Le32,
}

// BalloonState is shared by the worker and device thread.
#[derive(Default)]
struct BalloonState {
    num_pages: u32,
    actual_pages: u32,
    expecting_wss: bool,
    expected_wss_id: u64,
    // Flag indicating that the balloon is in the process of a failable update. This
    // is set by an Adjust command that has allow_failure set, and is cleared when the
    // Adjusted success/failure response is sent.
    failable_update: bool,
    pending_adjusted_responses: VecDeque<u32>,
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
#[derive(Copy, Clone, FromBytes, AsBytes)]
#[repr(C, packed)]
struct BalloonStat {
    tag: Le16,
    val: Le64,
}

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
#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
struct virtio_balloon_event_header {
    evt_type: Le32,
}

// virtio_balloon_wss is used to deserialize from the wss data vq.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
struct virtio_balloon_wss {
    tag: Le16,
    node_id: Le16,
    // virtio prefers field members to align on a word boundary so we must pad. see:
    // https://crsrc.org/o/src/third_party/kernel/v5.15/include/uapi/linux/virtio_balloon.h;l=105
    _reserved: [u8; 4],
    idle_age_ms: Le64,
    // TODO(b/273973298): these should become separate fields - bytes for ANON and FILE
    memory_size_bytes: [Le64; 2],
}

impl virtio_balloon_wss {
    fn update_wss(&self, wss: &mut BalloonWSS, index: usize) {
        if index >= VIRTIO_BALLOON_WSS_NUM_BINS {
            error!(
                "index {} outside of known WSS bins: {}",
                index, VIRTIO_BALLOON_WSS_NUM_BINS
            );
            return;
        }
        wss.wss[index].age = self.idle_age_ms.to_native();
        wss.wss[index].bytes[0] = self.memory_size_bytes[0].to_native();
        wss.wss[index].bytes[1] = self.memory_size_bytes[1].to_native();
    }
}

const _VIRTIO_BALLOON_WSS_OP_INVALID: u16 = 0;
const VIRTIO_BALLOON_WSS_OP_REQUEST: u16 = 1;
const VIRTIO_BALLOON_WSS_OP_CONFIG: u16 = 2;
const _VIRTIO_BALLOON_WSS_OP_DISCARD: u16 = 3;

// virtio_balloon_op is used to serialize to the wss cmd vq.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
struct virtio_balloon_op {
    type_: Le16,
}

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
    release_memory_tube: Option<&Tube>,
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
    release_memory_tube: Option<&Tube>,
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
    release_memory_tube: Option<&Tube>,
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
    release_memory_tube: Option<&Tube>,
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
    release_memory_tube: Option<&Tube>,
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
    registered_evt_q: Option<&SendTubeAsync>,
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

        if let Some(registered_evt_q) = registered_evt_q {
            if let Err(e) = registered_evt_q
                .send(&RegisteredEvent::VirtioBalloonResize)
                .await
            {
                error!("failed to send VirtioBalloonResize event: {}", e);
            }
        }
    }
}

async fn send_adjusted_response(
    tube: &AsyncTube,
    num_pages: u32,
) -> std::result::Result<(), base::TubeError> {
    let num_bytes = (num_pages as u64) << VIRTIO_BALLOON_PFN_SHIFT;
    let result = BalloonTubeResult::Adjusted { num_bytes };
    tube.send(result).await
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
                    send_adjusted_response(command_tube, state.actual_pages)
                        .await
                        .map_err(BalloonError::SendResponse)?;
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

enum WSSOp {
    WSSReport {
        id: u64,
    },
    WSSConfig {
        config: [u64; VIRTIO_BALLOON_WSS_CONFIG_SIZE],
    },
}

async fn handle_wss_op_queue(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    mut wss_op_rx: mpsc::Receiver<WSSOp>,
    state: Arc<AsyncMutex<BalloonState>>,
    interrupt: Interrupt,
) -> Result<()> {
    loop {
        let op = match wss_op_rx.next().await {
            Some(op) => op,
            None => {
                error!("wss op tube was closed");
                break;
            }
        };
        let avail_desc = queue
            .next_async(mem, &mut queue_event)
            .await
            .map_err(BalloonError::AsyncAwait)?;
        let index = avail_desc.index;

        let mut writer = Writer::new(mem.clone(), avail_desc).map_err(BalloonError::Descriptor)?;

        match op {
            WSSOp::WSSReport { id } => {
                {
                    let mut state = state.lock().await;
                    state.expecting_wss = true;
                    state.expected_wss_id = id;
                }

                let wss_r = virtio_balloon_op {
                    type_: VIRTIO_BALLOON_WSS_OP_REQUEST.into(),
                };

                writer.write_obj(wss_r).map_err(BalloonError::WriteQueue)?;
            }
            WSSOp::WSSConfig { config } => {
                let cmd = virtio_balloon_op {
                    type_: VIRTIO_BALLOON_WSS_OP_CONFIG.into(),
                };

                writer.write_obj(cmd).map_err(BalloonError::WriteQueue)?;
                writer.write_obj(config).map_err(BalloonError::WriteQueue)?;
            }
        }

        queue.add_used(mem, index, writer.bytes_written() as u32);
        queue.trigger_interrupt(mem, &interrupt);
    }

    Ok(())
}

fn parse_balloon_wss(reader: &mut Reader) -> BalloonWSS {
    let mut count = 0;
    let mut wss = BalloonWSS::new();
    for res in reader.iter::<virtio_balloon_wss>() {
        match res {
            Ok(wss_msg) => {
                wss_msg.update_wss(&mut wss, count);
                count += 1;
                if count > VIRTIO_BALLOON_WSS_NUM_BINS {
                    error!(
                        "we should never receive more than {} wss buckets",
                        VIRTIO_BALLOON_WSS_NUM_BINS
                    );
                    break;
                }
            }
            Err(e) => {
                error!("error while reading wss: {}", e);
                break;
            }
        }
    }
    wss
}

// Async task that handles the stats queue. Note that the arrival of events on
// the WSS vq may be the result of either a WSS request (WSS-R) command having
// been sent to the guest, or an unprompted send due to memory pressue in the
// guest. If the data was requested, we should also send that back on the
// command tube.
async fn handle_wss_data_queue(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    wss_op_tube: Option<&AsyncTube>,
    registered_evt_q: Option<&SendTubeAsync>,
    state: Arc<AsyncMutex<BalloonState>>,
    interrupt: Interrupt,
) -> Result<()> {
    if let Some(wss_op_tube) = wss_op_tube {
        loop {
            let avail_desc = queue
                .next_async(mem, &mut queue_event)
                .await
                .map_err(BalloonError::AsyncAwait)?;
            let index = avail_desc.index;
            let mut reader = match Reader::new(mem.clone(), avail_desc) {
                Ok(r) => r,
                Err(e) => {
                    error!("balloon: failed to CREATE Reader: {}", e);
                    continue;
                }
            };

            let wss = parse_balloon_wss(&mut reader);

            // Closure to hold the mutex for handling a WSS-R command response
            {
                let mut state = state.lock().await;
                if state.expecting_wss {
                    let result = BalloonTubeResult::WorkingSetSize {
                        wss,
                        id: state.expected_wss_id,
                    };
                    let send_result = wss_op_tube.send(result).await;
                    if let Err(e) = send_result {
                        error!("failed to send wss result: {}", e);
                    }

                    state.expecting_wss = false;
                }
            }

            // TODO: pipe back the wss to the registered event socket, needs
            // event-with-payload, currently events are simple enums
            if let Some(registered_evt_q) = registered_evt_q {
                if let Err(e) = registered_evt_q
                    .send(&RegisteredEvent::VirtioBalloonWssReport)
                    .await
                {
                    error!("failed to send VirtioBalloonWSSReport event: {}", e);
                }
            }

            queue.add_used(mem, index, 0);
            queue.trigger_interrupt(mem, &interrupt);
        }
    } else {
        error!("no wss device tube even though we have wss vqueues");
        Ok(())
    }
}

fn send_initial_wss_config(mut wss_op_tx: mpsc::Sender<WSSOp>) {
    // NOTE: first VIRTIO_BALLOON_WSS_NUM_BINS - 1 values are the
    // interval boundaries, then refresh and reporting thresholds.
    let config = WSSOp::WSSConfig {
        config: [1_000, 5_000, 10_000, 750, 1_000],
    };

    if let Err(e) = wss_op_tx.try_send(config) {
        error!("failed to send inital WSS config to guest: {}", e);
    }
}

// Async task that handles the command socket. The command socket handles messages from the host
// requesting that the guest balloon be adjusted or to report guest memory statistics.
async fn handle_command_tube(
    command_tube: &AsyncTube,
    interrupt: Interrupt,
    state: Arc<AsyncMutex<BalloonState>>,
    mut stats_tx: mpsc::Sender<u64>,
    mut wss_config_tx: mpsc::Sender<WSSOp>,
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
                            send_adjusted_response(command_tube, num_pages)
                                .await
                                .map_err(BalloonError::SendResponse)?;
                        } else {
                            state.failable_update = true;
                        }
                    }
                }
                BalloonTubeCommand::WorkingSetSizeConfig { config } => {
                    if let Err(e) = wss_config_tx.try_send(WSSOp::WSSConfig { config }) {
                        error!("failed to send config to config handler: {}", e);
                    }
                }
                BalloonTubeCommand::Stats { id } => {
                    if let Err(e) = stats_tx.try_send(id) {
                        error!("failed to signal the stat handler: {}", e);
                    }
                }
                BalloonTubeCommand::WorkingSetSize { .. } => {
                    error!("should not get a working set size command on this tube!");
                }
            },
            Err(e) => {
                return Err(BalloonError::ReceivingCommand(e));
            }
        }
    }
}

// Async task that handles the command socket. The command socket handles messages from the host
// requesting that the guest balloon be adjusted or to report guest memory statistics.
async fn handle_wss_op_tube(
    wss_op_tube: Option<&AsyncTube>,
    mut wss_op_tx: mpsc::Sender<WSSOp>,
) -> Result<()> {
    if let Some(wss_op_tube) = wss_op_tube {
        loop {
            match wss_op_tube.next().await {
                Ok(command) => match command {
                    BalloonTubeCommand::WorkingSetSize { id } => {
                        if let Err(e) = wss_op_tx.try_send(WSSOp::WSSReport { id }) {
                            error!("failed to signal the wss handler: {}", e);
                        }
                    }
                    _ => {
                        error!("should only ever get a working set size command on this tube!");
                    }
                },
                Err(e) => {
                    return Err(BalloonError::ReceivingCommand(e));
                }
            }
        }
    } else {
        // No wss_op_tube; just park this future.
        futures::future::pending::<()>().await;
        Ok(())
    }
}

async fn handle_pending_adjusted_responses(
    pending_adjusted_response_event: EventAsync,
    command_tube: &AsyncTube,
    state: Arc<AsyncMutex<BalloonState>>,
) -> Result<()> {
    loop {
        pending_adjusted_response_event
            .next_val()
            .await
            .map_err(BalloonError::AsyncAwait)?;
        while let Some(num_pages) = state.lock().await.pending_adjusted_responses.pop_front() {
            send_adjusted_response(command_tube, num_pages)
                .await
                .map_err(BalloonError::SendResponse)?;
        }
    }
}

// The main worker thread. Initialized the asynchronous worker tasks and passes them to the executor
// to be processed.
fn run_worker(
    inflate_queue: (Queue, Event),
    deflate_queue: (Queue, Event),
    stats_queue: Option<(Queue, Event)>,
    reporting_queue: Option<(Queue, Event)>,
    events_queue: Option<(Queue, Event)>,
    wss_queues: (Option<(Queue, Event)>, Option<(Queue, Event)>),
    command_tube: Tube,
    wss_op_tube: Option<Tube>,
    #[cfg(windows)] dynamic_mapping_tube: Tube,
    release_memory_tube: Option<Tube>,
    interrupt: Interrupt,
    kill_evt: Event,
    pending_adjusted_response_event: Event,
    mem: GuestMemory,
    state: Arc<AsyncMutex<BalloonState>>,
    registered_evt_q: Option<SendTube>,
) -> (Option<Tube>, Tube, Option<Tube>, Option<SendTube>) {
    let ex = Executor::new().unwrap();
    let command_tube = AsyncTube::new(&ex, command_tube).unwrap();
    let wss_op_tube = wss_op_tube.map(|t| AsyncTube::new(&ex, t).unwrap());
    let registered_evt_q_async = registered_evt_q
        .as_ref()
        .map(|q| SendTubeAsync::new(q.try_clone().unwrap(), &ex).unwrap());

    // We need a block to release all references to command_tube at the end before returning it.
    {
        // The first queue is used for inflate messages
        let inflate = handle_queue(
            &mem,
            inflate_queue.0,
            EventAsync::new(inflate_queue.1, &ex).expect("failed to create async event"),
            release_memory_tube.as_ref(),
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
            deflate_queue.0,
            EventAsync::new(deflate_queue.1, &ex).expect("failed to create async event"),
            None,
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
        let stats = if let Some((stats_queue, stats_queue_evt)) = stats_queue {
            handle_stats_queue(
                &mem,
                stats_queue,
                EventAsync::new(stats_queue_evt, &ex).expect("failed to create async event"),
                stats_rx,
                &command_tube,
                registered_evt_q_async.as_ref(),
                state.clone(),
                interrupt.clone(),
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        pin_mut!(stats);

        // The next queue is used for reporting messages
        let reporting = if let Some((reporting_queue, reporting_queue_evt)) = reporting_queue {
            handle_reporting_queue(
                &mem,
                reporting_queue,
                EventAsync::new(reporting_queue_evt, &ex).expect("failed to create async event"),
                release_memory_tube.as_ref(),
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

        // If VIRTIO_BALLOON_F_WSS_REPORTING is set 2 queues must handled - one for WSS data and one
        // for WSS notifications.
        let wss_data = if let Some((wss_data_queue, wss_data_queue_evt)) = wss_queues.0 {
            handle_wss_data_queue(
                &mem,
                wss_data_queue,
                EventAsync::new(wss_data_queue_evt, &ex).expect("failed to create async event"),
                wss_op_tube.as_ref(),
                registered_evt_q_async.as_ref(),
                state.clone(),
                interrupt.clone(),
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        pin_mut!(wss_data);

        let (wss_op_tx, wss_op_rx) = mpsc::channel::<WSSOp>(1);
        let wss_op = if let Some((wss_op_queue, wss_op_queue_evt)) = wss_queues.1 {
            send_initial_wss_config(wss_op_tx.clone());

            handle_wss_op_queue(
                &mem,
                wss_op_queue,
                EventAsync::new(wss_op_queue_evt, &ex).expect("failed to create async event"),
                wss_op_rx,
                state.clone(),
                interrupt.clone(),
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        pin_mut!(wss_op);

        // Future to handle command messages that resize the balloon.
        let command = handle_command_tube(
            &command_tube,
            interrupt.clone(),
            state.clone(),
            stats_tx,
            wss_op_tx.clone(),
        );
        pin_mut!(command);

        // Future to handle wss command messages for the balloon.
        let wss_op_tube = handle_wss_op_tube(wss_op_tube.as_ref(), wss_op_tx);
        pin_mut!(wss_op_tube);

        // Process any requests to resample the irq value.
        let resample = async_utils::handle_irq_resample(&ex, interrupt.clone());
        pin_mut!(resample);

        // Exit if the kill event is triggered.
        let kill = async_utils::await_and_exit(&ex, kill_evt);
        pin_mut!(kill);

        // The next queue is used for events if VIRTIO_BALLOON_F_EVENTS_VQ is negotiated.
        let events = if let Some((events_queue, events_queue_evt)) = events_queue {
            handle_events_queue(
                &mem,
                events_queue,
                EventAsync::new(events_queue_evt, &ex).expect("failed to create async event"),
                state.clone(),
                interrupt,
                &command_tube,
            )
            .left_future()
        } else {
            std::future::pending().right_future()
        };
        pin_mut!(events);

        let pending_adjusted = handle_pending_adjusted_responses(
            EventAsync::new(pending_adjusted_response_event, &ex)
                .expect("failed to create async event"),
            &command_tube,
            state,
        );
        pin_mut!(pending_adjusted);

        if let Err(e) = ex
            .run_until(select12(
                inflate,
                deflate,
                stats,
                reporting,
                command,
                wss_op,
                resample,
                kill,
                events,
                pending_adjusted,
                wss_data,
                wss_op_tube,
            ))
            .map(|_| ())
        {
            error!("error happened in executor: {}", e);
        }
    }

    (
        release_memory_tube,
        command_tube.into(),
        wss_op_tube.map(Into::into),
        registered_evt_q,
    )
}

/// Virtio device for memory balloon inflation/deflation.
pub struct Balloon {
    command_tube: Option<Tube>,
    wss_op_tube: Option<Tube>,
    #[cfg(windows)]
    dynamic_mapping_tube: Option<Tube>,
    release_memory_tube: Option<Tube>,
    pending_adjusted_response_event: Event,
    state: Arc<AsyncMutex<BalloonState>>,
    features: u64,
    acked_features: u64,
    worker_thread: Option<WorkerThread<(Option<Tube>, Tube, Option<Tube>, Option<SendTube>)>>,
    registered_evt_q: Option<SendTube>,
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
        wss_op_tube: Option<Tube>,
        #[cfg(windows)] dynamic_mapping_tube: Tube,
        release_memory_tube: Option<Tube>,
        init_balloon_size: u64,
        mode: BalloonMode,
        enabled_features: u64,
        registered_evt_q: Option<SendTube>,
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
            wss_op_tube,
            #[cfg(windows)]
            dynamic_mapping_tube: Some(dynamic_mapping_tube),
            release_memory_tube,
            pending_adjusted_response_event: Event::new().map_err(BalloonError::CreatingEvent)?,
            state: Arc::new(AsyncMutex::new(BalloonState {
                num_pages: (init_balloon_size >> VIRTIO_BALLOON_PFN_SHIFT) as u32,
                actual_pages: 0,
                failable_update: false,
                pending_adjusted_responses: VecDeque::new(),
                expecting_wss: false,
                expected_wss_id: 0,
            })),
            worker_thread: None,
            features,
            acked_features: 0,
            registered_evt_q,
        })
    }

    fn get_config(&self) -> virtio_balloon_config {
        let state = block_on(self.state.lock());
        virtio_balloon_config {
            num_pages: state.num_pages.into(),
            actual: state.actual_pages.into(),
            // crosvm does not (currently) use free_page_hint_cmd_id or
            // poison_val, but they must be present in the right order and size
            // for the virtio-balloon driver in the guest to deserialize the
            // config correctly.
            free_page_hint_cmd_id: 0.into(),
            poison_val: 0.into(),
            wss_num_bins: (VIRTIO_BALLOON_WSS_NUM_BINS as u32).into(),
        }
    }

    fn num_expected_queues(acked_features: u64) -> usize {
        // at minimum we have inflate and deflate vqueues.
        let mut num_queues = 2;
        // stats vqueue
        if acked_features & (1 << VIRTIO_BALLOON_F_STATS_VQ) != 0 {
            num_queues += 1;
        }
        // events vqueue
        if acked_features & (1 << VIRTIO_BALLOON_F_EVENTS_VQ) != 0 {
            num_queues += 1;
        }
        // page reporting vqueue
        if acked_features & (1 << VIRTIO_BALLOON_F_PAGE_REPORTING) != 0 {
            num_queues += 1;
        }
        // working set size vqueues
        if acked_features & (1 << VIRTIO_BALLOON_F_WSS_REPORTING) != 0 {
            num_queues += 2;
        }

        num_queues
    }
}

impl VirtioDevice for Balloon {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = Vec::new();
        if let Some(command_tube) = &self.command_tube {
            rds.push(command_tube.as_raw_descriptor());
        }
        if let Some(wss_op_tube) = &self.wss_op_tube {
            rds.push(wss_op_tube.as_raw_descriptor());
        }
        if let Some(release_memory_tube) = &self.release_memory_tube {
            rds.push(release_memory_tube.as_raw_descriptor());
        }
        if let Some(registered_evt_q) = &self.registered_evt_q {
            rds.push(registered_evt_q.as_raw_descriptor());
        }
        rds.push(self.pending_adjusted_response_event.as_raw_descriptor());
        rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Balloon
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.get_config().as_bytes(), offset);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let mut config = self.get_config();
        copy_config(config.as_bytes_mut(), offset, data, 0);
        let mut state = block_on(self.state.lock());
        state.actual_pages = config.actual.to_native();
        if state.failable_update && state.actual_pages == state.num_pages {
            state.failable_update = false;
            let num_pages = state.num_pages;
            state.pending_adjusted_responses.push_back(num_pages);
            let _ = self.pending_adjusted_response_event.signal();
        }
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
        mut queues: Vec<(Queue, Event)>,
    ) -> anyhow::Result<()> {
        let expected_queues = Balloon::num_expected_queues(self.acked_features);
        if queues.len() != expected_queues {
            return Err(anyhow!(
                "expected {} queues, got {}",
                expected_queues,
                queues.len()
            ));
        }

        let inflate_queue = queues.remove(0);
        let deflate_queue = queues.remove(0);
        let stats_queue = if self.acked_features & (1 << VIRTIO_BALLOON_F_STATS_VQ) != 0 {
            Some(queues.remove(0))
        } else {
            None
        };
        let reporting_queue = if self.acked_features & (1 << VIRTIO_BALLOON_F_PAGE_REPORTING) != 0 {
            Some(queues.remove(0))
        } else {
            None
        };
        let events_queue = if self.acked_features & (1 << VIRTIO_BALLOON_F_EVENTS_VQ) != 0 {
            Some(queues.remove(0))
        } else {
            None
        };
        let wss_queues = if self.acked_features & (1 << VIRTIO_BALLOON_F_WSS_REPORTING) != 0 {
            (Some(queues.remove(0)), Some(queues.remove(0)))
        } else {
            (None, None)
        };

        let state = self.state.clone();

        let command_tube = self.command_tube.take().unwrap();

        let wss_op_tube = self.wss_op_tube.take();

        #[cfg(windows)]
        let mapping_tube = self.dynamic_mapping_tube.take().unwrap();
        let release_memory_tube = self.release_memory_tube.take();
        let registered_evt_q = self.registered_evt_q.take();
        let pending_adjusted_response_event = self
            .pending_adjusted_response_event
            .try_clone()
            .context("failed to clone Event")?;

        self.worker_thread = Some(WorkerThread::start("v_balloon", move |kill_evt| {
            run_worker(
                inflate_queue,
                deflate_queue,
                stats_queue,
                reporting_queue,
                events_queue,
                wss_queues,
                command_tube,
                wss_op_tube,
                #[cfg(windows)]
                mapping_tube,
                release_memory_tube,
                interrupt,
                kill_evt,
                pending_adjusted_response_event,
                mem,
                state,
                registered_evt_q,
            )
        }));

        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Some(worker_thread) = self.worker_thread.take() {
            let (release_memory_tube, command_tube, wss_op_tube, registered_evt_q) =
                worker_thread.stop();
            self.release_memory_tube = release_memory_tube;
            self.command_tube = Some(command_tube);
            self.registered_evt_q = registered_evt_q;
            self.wss_op_tube = wss_op_tube;
            return true;
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
        let res = handle_address_chain(None, chain, &memory, &mut |guest_address, len| {
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
        assert_eq!(
            7,
            Balloon::num_expected_queues(to_feature_bits(&[
                VIRTIO_BALLOON_F_STATS_VQ,
                VIRTIO_BALLOON_F_EVENTS_VQ,
                VIRTIO_BALLOON_F_PAGE_REPORTING,
                VIRTIO_BALLOON_F_WSS_REPORTING
            ]))
        );
    }
}
