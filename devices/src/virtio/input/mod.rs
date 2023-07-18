// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(dead_code)]
mod constants;
mod defaults;
mod evdev;
mod event_source;

use std::collections::BTreeMap;
use std::io::Read;
use std::io::Write;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use base::custom_serde::deserialize_seq_to_arr;
use base::custom_serde::serialize_arr;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::WaitContext;
use base::WorkerThread;
use data_model::Le16;
use data_model::Le32;
use linux_input_sys::virtio_input_event;
use linux_input_sys::InputEventDecoder;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use self::constants::*;
use self::event_source::EvdevEventSource;
use self::event_source::EventSource;
use self::event_source::SocketEventSource;
use super::copy_config;
use super::DescriptorChain;
use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::VirtioDevice;

const EVENT_QUEUE_SIZE: u16 = 64;
const STATUS_QUEUE_SIZE: u16 = 64;
const QUEUE_SIZES: &[u16] = &[EVENT_QUEUE_SIZE, STATUS_QUEUE_SIZE];

#[sorted]
#[derive(Error, Debug)]
pub enum InputError {
    // Failed to get axis information of event device
    #[error("failed to get axis information of event device: {0}")]
    EvdevAbsInfoError(base::Error),
    // Failed to get event types supported by device
    #[error("failed to get event types supported by device: {0}")]
    EvdevEventTypesError(base::Error),
    // Failed to grab event device
    #[error("failed to grab event device: {0}")]
    EvdevGrabError(base::Error),
    // Failed to get name of event device
    #[error("failed to get id of event device: {0}")]
    EvdevIdError(base::Error),
    // Failed to get name of event device
    #[error("failed to get name of event device: {0}")]
    EvdevNameError(base::Error),
    // Failed to get properties of event device
    #[error("failed to get properties of event device: {0}")]
    EvdevPropertiesError(base::Error),
    // Failed to get serial name of event device
    #[error("failed to get serial name of event device: {0}")]
    EvdevSerialError(base::Error),
    /// Failed to read events from the source
    #[error("failed to read events from the source: {0}")]
    EventsReadError(std::io::Error),
    /// Failed to write events to the source
    #[error("failed to write events to the source: {0}")]
    EventsWriteError(std::io::Error),
    // Detected error on guest side
    #[error("detected error on guest side: {0}")]
    GuestError(String),
    // Error while reading from virtqueue
    #[error("failed to read from virtqueue: {0}")]
    ReadQueue(std::io::Error),
    // Error while writing to virtqueue
    #[error("failed to write to virtqueue: {0}")]
    WriteQueue(std::io::Error),
}

pub type Result<T> = std::result::Result<T, InputError>;

#[derive(Copy, Clone, Default, Debug, AsBytes, FromBytes, Serialize, Deserialize)]
#[repr(C)]
pub struct virtio_input_device_ids {
    bustype: Le16,
    vendor: Le16,
    product: Le16,
    version: Le16,
}

impl virtio_input_device_ids {
    fn new(bustype: u16, product: u16, vendor: u16, version: u16) -> virtio_input_device_ids {
        virtio_input_device_ids {
            bustype: Le16::from(bustype),
            vendor: Le16::from(vendor),
            product: Le16::from(product),
            version: Le16::from(version),
        }
    }
}

#[derive(Copy, Clone, Default, Debug, AsBytes, FromBytes, Serialize, Deserialize)]
#[repr(C)]
pub struct virtio_input_absinfo {
    min: Le32,
    max: Le32,
    fuzz: Le32,
    flat: Le32,
}

impl virtio_input_absinfo {
    fn new(min: u32, max: u32, fuzz: u32, flat: u32) -> virtio_input_absinfo {
        virtio_input_absinfo {
            min: Le32::from(min),
            max: Le32::from(max),
            fuzz: Le32::from(fuzz),
            flat: Le32::from(flat),
        }
    }
}

#[derive(Copy, Clone, AsBytes, FromBytes)]
#[repr(C)]
struct virtio_input_config {
    select: u8,
    subsel: u8,
    size: u8,
    reserved: [u8; 5],
    payload: [u8; 128],
}

impl virtio_input_config {
    fn new() -> virtio_input_config {
        virtio_input_config {
            select: 0,
            subsel: 0,
            size: 0,
            reserved: [0u8; 5],
            payload: [0u8; 128],
        }
    }

    fn set_payload_slice(&mut self, slice: &[u8]) {
        let bytes_written = match (&mut self.payload[..]).write(slice) {
            Ok(x) => x,
            Err(_) => {
                // This won't happen because write is guaranteed to succeed with slices
                unreachable!();
            }
        };
        self.size = bytes_written as u8;
        if bytes_written < slice.len() {
            // This shouldn't happen since everywhere this function is called the size is guaranteed
            // to be at most 128 bytes (the size of the payload)
            warn!("Slice is too long to fit in payload");
        }
    }

    fn set_payload_bitmap(&mut self, bitmap: &virtio_input_bitmap) {
        self.size = bitmap.min_size();
        self.payload.copy_from_slice(&bitmap.bitmap);
    }

    fn set_absinfo(&mut self, absinfo: &virtio_input_absinfo) {
        self.set_payload_slice(absinfo.as_bytes());
    }

    fn set_device_ids(&mut self, device_ids: &virtio_input_device_ids) {
        self.set_payload_slice(device_ids.as_bytes());
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
#[repr(C)]
pub struct virtio_input_bitmap {
    #[serde(
        serialize_with = "serialize_arr",
        deserialize_with = "deserialize_seq_to_arr"
    )]
    bitmap: [u8; 128],
}

impl virtio_input_bitmap {
    fn new(bitmap: [u8; 128]) -> virtio_input_bitmap {
        virtio_input_bitmap { bitmap }
    }

    fn len(&self) -> usize {
        self.bitmap.len()
    }

    // Creates a bitmap from an array of bit indices
    fn from_bits(set_indices: &[u16]) -> virtio_input_bitmap {
        let mut ret = virtio_input_bitmap { bitmap: [0u8; 128] };
        for idx in set_indices {
            let byte_pos = (idx / 8) as usize;
            let bit_byte = 1u8 << (idx % 8);
            if byte_pos < ret.len() {
                ret.bitmap[byte_pos] |= bit_byte;
            } else {
                // This would only happen if new event codes (or types, or ABS_*, etc) are defined to be
                // larger than or equal to 1024, in which case a new version of the virtio input
                // protocol needs to be defined.
                // There is nothing we can do about this error except log it.
                error!("Attempted to set an out of bounds bit: {}", idx);
            }
        }
        ret
    }

    // Returns the length of the minimum array that can hold all set bits in the map
    fn min_size(&self) -> u8 {
        self.bitmap
            .iter()
            .rposition(|v| *v != 0)
            .map_or(0, |i| i + 1) as u8
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VirtioInputConfig {
    select: u8,
    subsel: u8,
    device_ids: virtio_input_device_ids,
    name: Vec<u8>,
    serial_name: Vec<u8>,
    properties: virtio_input_bitmap,
    supported_events: BTreeMap<u16, virtio_input_bitmap>,
    axis_info: BTreeMap<u16, virtio_input_absinfo>,
}

impl VirtioInputConfig {
    fn new(
        device_ids: virtio_input_device_ids,
        name: Vec<u8>,
        serial_name: Vec<u8>,
        properties: virtio_input_bitmap,
        supported_events: BTreeMap<u16, virtio_input_bitmap>,
        axis_info: BTreeMap<u16, virtio_input_absinfo>,
    ) -> VirtioInputConfig {
        VirtioInputConfig {
            select: 0,
            subsel: 0,
            device_ids,
            name,
            serial_name,
            properties,
            supported_events,
            axis_info,
        }
    }

    fn from_evdev<T: AsRawDescriptor>(source: &T) -> Result<VirtioInputConfig> {
        Ok(VirtioInputConfig::new(
            evdev::device_ids(source)?,
            evdev::name(source)?,
            evdev::serial_name(source)?,
            evdev::properties(source)?,
            evdev::supported_events(source)?,
            evdev::abs_info(source),
        ))
    }

    fn build_config_memory(&self) -> virtio_input_config {
        let mut cfg = virtio_input_config::new();
        cfg.select = self.select;
        cfg.subsel = self.subsel;
        match self.select {
            VIRTIO_INPUT_CFG_ID_NAME => {
                cfg.set_payload_slice(&self.name);
            }
            VIRTIO_INPUT_CFG_ID_SERIAL => {
                cfg.set_payload_slice(&self.serial_name);
            }
            VIRTIO_INPUT_CFG_PROP_BITS => {
                cfg.set_payload_bitmap(&self.properties);
            }
            VIRTIO_INPUT_CFG_EV_BITS => {
                let ev_type = self.subsel as u16;
                // zero is a special case: return all supported event types (just like EVIOCGBIT)
                if ev_type == 0 {
                    let events_bm = virtio_input_bitmap::from_bits(
                        &self.supported_events.keys().cloned().collect::<Vec<u16>>(),
                    );
                    cfg.set_payload_bitmap(&events_bm);
                } else if let Some(supported_codes) = self.supported_events.get(&ev_type) {
                    cfg.set_payload_bitmap(supported_codes);
                }
            }
            VIRTIO_INPUT_CFG_ABS_INFO => {
                let abs_axis = self.subsel as u16;
                if let Some(absinfo) = self.axis_info.get(&abs_axis) {
                    cfg.set_absinfo(absinfo);
                } // else all zeroes in the payload
            }
            VIRTIO_INPUT_CFG_ID_DEVIDS => {
                cfg.set_device_ids(&self.device_ids);
            }
            VIRTIO_INPUT_CFG_UNSET => {
                // Per the virtio spec at https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/virtio-v1.1-cs01.html#x1-3390008,
                // there is no action required of us when this is set. It's unclear whether we
                // should be zeroing the virtio_input_config, but empirically we know that the
                // existing behavior of doing nothing works with the Linux virtio-input frontend.
            }
            _ => {
                warn!("Unsuported virtio input config selection: {}", self.select);
            }
        }
        cfg
    }

    fn read(&self, offset: usize, data: &mut [u8]) {
        copy_config(
            data,
            0,
            self.build_config_memory().as_bytes(),
            offset as u64,
        );
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        let mut config = self.build_config_memory();
        copy_config(config.as_bytes_mut(), offset as u64, data, 0);
        self.select = config.select;
        self.subsel = config.subsel;
    }
}

struct Worker<T: EventSource> {
    interrupt: Interrupt,
    event_source: T,
    event_queue: Queue,
    status_queue: Queue,
    guest_memory: GuestMemory,
}

impl<T: EventSource> Worker<T> {
    // Fills a virtqueue with events from the source.  Returns the number of bytes written.
    fn fill_event_virtqueue(
        event_source: &mut T,
        avail_desc: &mut DescriptorChain,
    ) -> Result<usize> {
        let writer = &mut avail_desc.writer;

        while writer.available_bytes() >= virtio_input_event::SIZE {
            if let Some(evt) = event_source.pop_available_event() {
                writer.write_obj(evt).map_err(InputError::WriteQueue)?;
            } else {
                break;
            }
        }

        Ok(writer.bytes_written())
    }

    // Send events from the source to the guest
    fn send_events(&mut self) -> bool {
        let mut needs_interrupt = false;

        // Only consume from the queue iterator if we know we have events to send
        while self.event_source.available_events_count() > 0 {
            match self.event_queue.pop(&self.guest_memory) {
                None => {
                    break;
                }
                Some(mut avail_desc) => {
                    let bytes_written =
                        match Worker::fill_event_virtqueue(&mut self.event_source, &mut avail_desc)
                        {
                            Ok(count) => count,
                            Err(e) => {
                                error!("Input: failed to send events to guest: {}", e);
                                break;
                            }
                        };

                    self.event_queue
                        .add_used(&self.guest_memory, avail_desc, bytes_written as u32);
                    needs_interrupt = true;
                }
            }
        }

        needs_interrupt
    }

    // Sends events from the guest to the source.  Returns the number of bytes read.
    fn read_event_virtqueue(
        avail_desc: &mut DescriptorChain,
        event_source: &mut T,
    ) -> Result<usize> {
        let reader = &mut avail_desc.reader;
        while reader.available_bytes() >= virtio_input_event::SIZE {
            let evt: virtio_input_event = reader.read_obj().map_err(InputError::ReadQueue)?;
            event_source.send_event(&evt)?;
        }

        Ok(reader.bytes_read())
    }

    fn process_status_queue(&mut self) -> Result<bool> {
        let mut needs_interrupt = false;
        while let Some(mut avail_desc) = self.status_queue.pop(&self.guest_memory) {
            let bytes_read =
                match Worker::read_event_virtqueue(&mut avail_desc, &mut self.event_source) {
                    Ok(count) => count,
                    Err(e) => {
                        error!("Input: failed to read events from virtqueue: {}", e);
                        return Err(e);
                    }
                };

            self.status_queue
                .add_used(&self.guest_memory, avail_desc, bytes_read as u32);
            needs_interrupt = true;
        }

        Ok(needs_interrupt)
    }

    // Allow error! and early return anywhere in function
    #[allow(clippy::needless_return)]
    fn run(&mut self, event_queue_evt: Event, status_queue_evt: Event, kill_evt: Event) {
        if let Err(e) = self.event_source.init() {
            error!("failed initializing event source: {}", e);
            return;
        }

        #[derive(EventToken)]
        enum Token {
            EventQAvailable,
            StatusQAvailable,
            InputEventsAvailable,
            InterruptResample,
            Kill,
        }
        let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
            (&event_queue_evt, Token::EventQAvailable),
            (&status_queue_evt, Token::StatusQAvailable),
            (&self.event_source, Token::InputEventsAvailable),
            (&kill_evt, Token::Kill),
        ]) {
            Ok(wait_ctx) => wait_ctx,
            Err(e) => {
                error!("failed creating WaitContext: {}", e);
                return;
            }
        };
        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            if wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .is_err()
            {
                error!("failed adding resample event to WaitContext.");
                return;
            }
        }

        'wait: loop {
            let wait_events = match wait_ctx.wait() {
                Ok(wait_events) => wait_events,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };

            let mut eventq_needs_interrupt = false;
            let mut statusq_needs_interrupt = false;
            for wait_event in wait_events.iter().filter(|e| e.is_readable) {
                match wait_event.token {
                    Token::EventQAvailable => {
                        if let Err(e) = event_queue_evt.wait() {
                            error!("failed reading event queue Event: {}", e);
                            break 'wait;
                        }
                        eventq_needs_interrupt |= self.send_events();
                    }
                    Token::StatusQAvailable => {
                        if let Err(e) = status_queue_evt.wait() {
                            error!("failed reading status queue Event: {}", e);
                            break 'wait;
                        }
                        match self.process_status_queue() {
                            Ok(b) => statusq_needs_interrupt |= b,
                            Err(e) => error!("failed processing status events: {}", e),
                        }
                    }
                    Token::InputEventsAvailable => match self.event_source.receive_events() {
                        Err(e) => error!("error receiving events: {}", e),
                        Ok(_cnt) => eventq_needs_interrupt |= self.send_events(),
                    },
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => {
                        let _ = kill_evt.wait();
                        break 'wait;
                    }
                }
            }
            if eventq_needs_interrupt {
                self.event_queue
                    .trigger_interrupt(&self.guest_memory, &self.interrupt);
            }
            if statusq_needs_interrupt {
                self.status_queue
                    .trigger_interrupt(&self.guest_memory, &self.interrupt);
            }
        }

        if let Err(e) = self.event_source.finalize() {
            error!("failed finalizing event source: {}", e);
            return;
        }
    }
}

/// Virtio input device

pub struct Input<T: EventSource + Send + 'static> {
    worker_thread: Option<WorkerThread<Worker<T>>>,
    config: VirtioInputConfig,
    source: Option<T>,
    virtio_features: u64,
}

/// Snapshot of [Input]'s state.
#[derive(Serialize, Deserialize)]
struct InputSnapshot {
    config: VirtioInputConfig,
    virtio_features: u64,
}

impl<T> VirtioDevice for Input<T>
where
    T: 'static + EventSource + Send,
{
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        if let Some(source) = &self.source {
            return vec![source.as_raw_descriptor()];
        }
        Vec::new()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Input
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.config.read(offset as usize, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.config.write(offset as usize, data);
    }

    fn features(&self) -> u64 {
        self.virtio_features
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, (Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() != 2 {
            return Err(anyhow!("expected 2 queues, got {}", queues.len()));
        }
        let (event_queue, event_queue_evt) = queues.remove(&0).unwrap();
        let (status_queue, status_queue_evt) = queues.remove(&1).unwrap();

        let source = self
            .source
            .take()
            .context("tried to activate device without a source for events")?;
        self.worker_thread = Some(WorkerThread::start("v_input", move |kill_evt| {
            let mut worker = Worker {
                interrupt,
                event_source: source,
                event_queue,
                status_queue,
                guest_memory: mem,
            };
            worker.run(event_queue_evt, status_queue_evt, kill_evt);
            worker
        }));

        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Some(worker_thread) = self.worker_thread.take() {
            let worker = worker_thread.stop();
            self.source = Some(worker.event_source);
            return true;
        }
        false
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        if let Some(worker_thread) = self.worker_thread.take() {
            let worker = worker_thread.stop();
            self.source = Some(worker.event_source);
            let queues = BTreeMap::from([(0, worker.event_queue), (1, worker.status_queue)]);
            Ok(Some(queues))
        } else {
            Ok(None)
        }
    }

    fn virtio_wake(
        &mut self,
        queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, (Queue, Event)>)>,
    ) -> anyhow::Result<()> {
        if let Some((mem, interrupt, queues)) = queues_state {
            self.activate(mem, interrupt, queues)?;
        }
        Ok(())
    }

    fn virtio_snapshot(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(InputSnapshot {
            virtio_features: self.virtio_features,
            config: self.config.clone(),
        })
        .context("failed to serialize InputSnapshot")
    }

    fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let snap: InputSnapshot = serde_json::from_value(data).context("error deserializing")?;
        if snap.virtio_features != self.virtio_features {
            bail!(
                "expected virtio_features to match, but they did not. Live: {:?}, snapshot {:?}",
                self.virtio_features,
                snap.virtio_features,
            );
        }
        self.config = snap.config;
        Ok(())
    }
}

/// Creates a new virtio input device from an event device node
pub fn new_evdev<T>(source: T, virtio_features: u64) -> Result<Input<EvdevEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input {
        worker_thread: None,
        config: VirtioInputConfig::from_evdev(&source)?,
        source: Some(EvdevEventSource::new(source)),
        virtio_features,
    })
}

/// Creates a new virtio touch device which supports single touch only.
pub fn new_single_touch<T>(
    idx: u32,
    source: T,
    width: u32,
    height: u32,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input {
        worker_thread: None,
        config: defaults::new_single_touch_config(idx, width, height),
        source: Some(SocketEventSource::new(source)),
        virtio_features,
    })
}

/// Creates a new virtio touch device which supports multi touch.
pub fn new_multi_touch<T>(
    idx: u32,
    source: T,
    width: u32,
    height: u32,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input {
        worker_thread: None,
        config: defaults::new_multi_touch_config(idx, width, height),
        source: Some(SocketEventSource::new(source)),
        virtio_features,
    })
}

/// Creates a new virtio trackpad device which supports (single) touch, primary and secondary
/// buttons as well as X and Y axis.
pub fn new_trackpad<T>(
    idx: u32,
    source: T,
    width: u32,
    height: u32,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input {
        worker_thread: None,
        config: defaults::new_trackpad_config(idx, width, height),
        source: Some(SocketEventSource::new(source)),
        virtio_features,
    })
}

/// Creates a new virtio mouse which supports primary, secondary, wheel and REL events.
pub fn new_mouse<T>(
    idx: u32,
    source: T,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input {
        worker_thread: None,
        config: defaults::new_mouse_config(idx),
        source: Some(SocketEventSource::new(source)),
        virtio_features,
    })
}

/// Creates a new virtio keyboard, which supports the same events as an en-us physical keyboard.
pub fn new_keyboard<T>(
    idx: u32,
    source: T,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input {
        worker_thread: None,
        config: defaults::new_keyboard_config(idx),
        source: Some(SocketEventSource::new(source)),
        virtio_features,
    })
}

/// Creates a new virtio device for switches.
pub fn new_switches<T>(
    idx: u32,
    source: T,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input {
        worker_thread: None,
        config: defaults::new_switches_config(idx),
        source: Some(SocketEventSource::new(source)),
        virtio_features,
    })
}

/// Creates a new virtio device for rotary.
pub fn new_rotary<T>(
    idx: u32,
    source: T,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input {
        worker_thread: None,
        config: defaults::new_rotary_config(idx),
        source: Some(SocketEventSource::new(source)),
        virtio_features,
    })
}
