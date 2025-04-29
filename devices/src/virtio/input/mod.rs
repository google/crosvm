// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(dead_code)]
mod defaults;
mod evdev;
mod event_source;

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use base::custom_serde::deserialize_seq_to_arr;
use base::custom_serde::serialize_arr;
use base::error;
use base::info;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::WaitContext;
use base::WorkerThread;
use data_model::Le16;
use data_model::Le32;
use linux_input_sys::constants::*;
use linux_input_sys::virtio_input_event;
use linux_input_sys::InputEventDecoder;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
use thiserror::Error;
use vm_memory::GuestMemory;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

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
    // Invalid UTF-8 string
    #[error("invalid UTF-8 string: {0}")]
    InvalidString(std::string::FromUtf8Error),
    // Failed to parse event config file
    #[error("failed to parse event config file: {0}")]
    ParseEventConfigError(String),
    // Error while reading from virtqueue
    #[error("failed to read from virtqueue: {0}")]
    ReadQueue(std::io::Error),
    // Error while writing to virtqueue
    #[error("failed to write to virtqueue: {0}")]
    WriteQueue(std::io::Error),
}

pub type Result<T> = std::result::Result<T, InputError>;

#[derive(
    Copy,
    Clone,
    Default,
    Debug,
    FromBytes,
    Immutable,
    IntoBytes,
    KnownLayout,
    Serialize,
    Deserialize,
)]
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

#[derive(
    Copy,
    Clone,
    Default,
    Debug,
    FromBytes,
    Immutable,
    IntoBytes,
    KnownLayout,
    PartialEq,
    Serialize,
    Deserialize,
)]
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

#[derive(Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
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

    fn set_payload_str(&mut self, s: &str) {
        self.set_payload_slice(s.as_bytes());
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

// virtio_input_config_select is the prefix of virtio_input_config consisting of only the writable
// fields (select and subsel), which multiplex the rest of the (read-only) config data.
#[repr(C)]
#[derive(Copy, Clone, Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct virtio_input_config_select {
    select: u8,
    subsel: u8,
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
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
                // This would only happen if new event codes (or types, or ABS_*, etc) are defined
                // to be larger than or equal to 1024, in which case a new version
                // of the virtio input protocol needs to be defined.
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

#[derive(Debug)]
pub struct VirtioInputConfig {
    device_ids: virtio_input_device_ids,
    name: String,
    serial_name: String,
    properties: virtio_input_bitmap,
    supported_events: BTreeMap<u16, virtio_input_bitmap>,
    axis_info: BTreeMap<u16, virtio_input_absinfo>,
}

impl VirtioInputConfig {
    fn new(
        device_ids: virtio_input_device_ids,
        name: String,
        serial_name: String,
        properties: virtio_input_bitmap,
        supported_events: BTreeMap<u16, virtio_input_bitmap>,
        axis_info: BTreeMap<u16, virtio_input_absinfo>,
    ) -> VirtioInputConfig {
        VirtioInputConfig {
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

    fn build_config_memory(&self, select: u8, subsel: u8) -> virtio_input_config {
        let mut cfg = virtio_input_config::new();
        cfg.select = select;
        cfg.subsel = subsel;
        match select {
            VIRTIO_INPUT_CFG_ID_NAME => {
                cfg.set_payload_str(&self.name);
            }
            VIRTIO_INPUT_CFG_ID_SERIAL => {
                cfg.set_payload_str(&self.serial_name);
            }
            VIRTIO_INPUT_CFG_PROP_BITS => {
                cfg.set_payload_bitmap(&self.properties);
            }
            VIRTIO_INPUT_CFG_EV_BITS => {
                let ev_type = subsel as u16;
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
                let abs_axis = subsel as u16;
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
                warn!("Unsuported virtio input config selection: {}", select);
            }
        }
        cfg
    }
}

struct Worker<T: EventSource> {
    event_source: T,
    event_queue: Queue,
    status_queue: Queue,
    name: String,
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
            match self.event_queue.pop() {
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
                        .add_used_with_bytes_written(avail_desc, bytes_written as u32);
                    needs_interrupt = true;
                }
            }
        }

        needs_interrupt
    }

    // Sends events from the guest to the source.
    fn read_event_virtqueue(avail_desc: &mut DescriptorChain, event_source: &mut T) -> Result<()> {
        let reader = &mut avail_desc.reader;
        while reader.available_bytes() >= virtio_input_event::SIZE {
            let evt: virtio_input_event = reader.read_obj().map_err(InputError::ReadQueue)?;
            event_source.send_event(&evt)?;
        }

        Ok(())
    }

    fn process_status_queue(&mut self) -> Result<bool> {
        let mut needs_interrupt = false;
        while let Some(mut avail_desc) = self.status_queue.pop() {
            Worker::read_event_virtqueue(&mut avail_desc, &mut self.event_source)
                .inspect_err(|e| error!("Input: failed to read events from virtqueue: {}", e))?;

            self.status_queue.add_used(avail_desc);
            needs_interrupt = true;
        }

        Ok(needs_interrupt)
    }

    // Allow error! and early return anywhere in function
    #[allow(clippy::needless_return)]
    fn run(&mut self, kill_evt: Event) {
        if let Err(e) = self.event_source.init() {
            error!("failed initializing event source: {}", e);
            return;
        }

        #[derive(EventToken)]
        enum Token {
            EventQAvailable,
            StatusQAvailable,
            InputEventsAvailable,
            Kill,
        }
        let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
            (self.event_queue.event(), Token::EventQAvailable),
            (self.status_queue.event(), Token::StatusQAvailable),
            (&self.event_source, Token::InputEventsAvailable),
            (&kill_evt, Token::Kill),
        ]) {
            Ok(wait_ctx) => wait_ctx,
            Err(e) => {
                error!("failed creating WaitContext: {}", e);
                return;
            }
        };

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
                        if let Err(e) = self.event_queue.event().wait() {
                            error!("failed reading event queue Event: {}", e);
                            break 'wait;
                        }
                        eventq_needs_interrupt |= self.send_events();
                    }
                    Token::StatusQAvailable => {
                        if let Err(e) = self.status_queue.event().wait() {
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
                    Token::Kill => {
                        let _ = kill_evt.wait();
                        break 'wait;
                    }
                }
            }

            for event in wait_events.iter().filter(|e| e.is_hungup) {
                if let Token::InputEventsAvailable = event.token {
                    warn!("input event source for '{}' disconnected", self.name);
                    let _ = wait_ctx.delete(&self.event_source);
                }
            }

            if eventq_needs_interrupt {
                self.event_queue.trigger_interrupt();
            }
            if statusq_needs_interrupt {
                self.status_queue.trigger_interrupt();
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
    config_select: u8,
    config_subsel: u8,
    config_data: virtio_input_config,
    source: Option<T>,
    virtio_features: u64,
}

/// Snapshot of [Input]'s state.
#[derive(Serialize, Deserialize)]
struct InputSnapshot {
    config_select: u8,
    config_subsel: u8,
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
        copy_config(data, 0, self.config_data.as_bytes(), offset);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let mut config = virtio_input_config_select {
            select: self.config_select,
            subsel: self.config_subsel,
        };
        copy_config(config.as_mut_bytes(), offset, data, 0);

        if config.select != self.config_select || config.subsel != self.config_subsel {
            self.config_select = config.select;
            self.config_subsel = config.subsel;
            self.config_data = self
                .config
                .build_config_memory(config.select, config.subsel);
        }
    }

    fn features(&self) -> u64 {
        self.virtio_features
    }

    fn activate(
        &mut self,
        _mem: GuestMemory,
        _interrupt: Interrupt,
        mut queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        if queues.len() != 2 {
            return Err(anyhow!("expected 2 queues, got {}", queues.len()));
        }
        let event_queue = queues.remove(&0).unwrap();
        let status_queue = queues.remove(&1).unwrap();

        let name = self.config.name.clone();
        let source = self
            .source
            .take()
            .context("tried to activate device without a source for events")?;
        self.worker_thread = Some(WorkerThread::start("v_input", move |kill_evt| {
            let mut worker = Worker {
                event_source: source,
                event_queue,
                status_queue,
                name,
            };
            worker.run(kill_evt);
            worker
        }));

        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        if let Some(worker_thread) = self.worker_thread.take() {
            let worker = worker_thread.stop();
            self.source = Some(worker.event_source);
        }
        Ok(())
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
        queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        if let Some((mem, interrupt, queues)) = queues_state {
            self.activate(mem, interrupt, queues)?;
        }
        Ok(())
    }

    fn virtio_snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        AnySnapshot::to_any(InputSnapshot {
            virtio_features: self.virtio_features,
            config_select: self.config_select,
            config_subsel: self.config_subsel,
        })
        .context("failed to serialize InputSnapshot")
    }

    fn virtio_restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        let snap: InputSnapshot = AnySnapshot::from_any(data).context("error deserializing")?;
        if snap.virtio_features != self.virtio_features {
            bail!(
                "expected virtio_features to match, but they did not. Live: {:?}, snapshot {:?}",
                self.virtio_features,
                snap.virtio_features,
            );
        }
        self.config_select = snap.config_select;
        self.config_subsel = snap.config_subsel;
        Ok(())
    }
}

impl<T> Input<T>
where
    T: EventSource + Send + 'static,
{
    fn new(config: VirtioInputConfig, source: Option<T>, virtio_features: u64) -> Self {
        let config_select = 0;
        let config_subsel = 0;
        let config_data = config.build_config_memory(config_select, config_subsel);
        Input {
            worker_thread: None,
            config,
            config_select,
            config_subsel,
            config_data,
            source,
            virtio_features,
        }
    }
}

/// Creates a new virtio input device from an event device node
pub fn new_evdev<T>(source: T, virtio_features: u64) -> Result<Input<EvdevEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input::new(
        VirtioInputConfig::from_evdev(&source)?,
        Some(EvdevEventSource::new(source)),
        virtio_features,
    ))
}

/// Creates a new virtio touch device which supports single touch only.
pub fn new_single_touch<T>(
    idx: u32,
    source: T,
    width: u32,
    height: u32,
    name: Option<&str>,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input::new(
        defaults::new_single_touch_config(idx, width, height, name),
        Some(SocketEventSource::new(source)),
        virtio_features,
    ))
}

/// Creates a new virtio touch device which supports multi touch.
pub fn new_multi_touch<T>(
    idx: u32,
    source: T,
    width: u32,
    height: u32,
    name: Option<&str>,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input::new(
        defaults::new_multi_touch_config(idx, width, height, name),
        Some(SocketEventSource::new(source)),
        virtio_features,
    ))
}

/// Creates a new virtio trackpad device which supports (single) touch, primary and secondary
/// buttons as well as X and Y axis.
pub fn new_trackpad<T>(
    idx: u32,
    source: T,
    width: u32,
    height: u32,
    name: Option<&str>,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input::new(
        defaults::new_trackpad_config(idx, width, height, name),
        Some(SocketEventSource::new(source)),
        virtio_features,
    ))
}

/// Creates a new virtio trackpad device which supports multi touch, primary and secondary
/// buttons as well as X and Y axis.
pub fn new_multitouch_trackpad<T>(
    idx: u32,
    source: T,
    width: u32,
    height: u32,
    name: Option<&str>,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    Ok(Input::new(
        defaults::new_multitouch_trackpad_config(idx, width, height, name),
        Some(SocketEventSource::new(source)),
        virtio_features,
    ))
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
    Ok(Input::new(
        defaults::new_mouse_config(idx),
        Some(SocketEventSource::new(source)),
        virtio_features,
    ))
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
    Ok(Input::new(
        defaults::new_keyboard_config(idx),
        Some(SocketEventSource::new(source)),
        virtio_features,
    ))
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
    Ok(Input::new(
        defaults::new_switches_config(idx),
        Some(SocketEventSource::new(source)),
        virtio_features,
    ))
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
    Ok(Input::new(
        defaults::new_rotary_config(idx),
        Some(SocketEventSource::new(source)),
        virtio_features,
    ))
}

/// Creates a new custom virtio input device
pub fn new_custom<T>(
    idx: u32,
    source: T,
    input_config_path: PathBuf,
    virtio_features: u64,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawDescriptor + Send + 'static,
{
    let config = parse_input_config_file(&input_config_path, idx)?;

    Ok(Input::new(
        defaults::new_custom_config(
            idx,
            &config.name,
            &config.serial_name,
            config.properties,
            config.supported_events,
            config.axis_info,
        ),
        Some(SocketEventSource::new(source)),
        virtio_features,
    ))
}

#[derive(Debug, Deserialize)]
struct InputConfigFile {
    name: Option<String>,
    serial_name: Option<String>,
    #[serde(default)]
    properties: BTreeMap<String, u16>,
    events: Vec<InputConfigFileEvent>,
    #[serde(default)]
    axis_info: Vec<InputConfigFileAbsInfo>,
}

#[derive(Debug, Deserialize)]
struct InputConfigFileEvent {
    event_type: String,
    event_type_code: u16,
    supported_events: BTreeMap<String, u16>,
}

#[derive(Debug, Deserialize)]
struct InputConfigFileAbsInfo {
    #[allow(dead_code)]
    axis: String,
    axis_code: u16,
    min: u32,
    max: u32,
    #[serde(default)]
    fuzz: u32,
    #[serde(default)]
    flat: u32,
}

struct CustomInputConfig {
    name: String,
    serial_name: String,
    properties: virtio_input_bitmap,
    supported_events: BTreeMap<u16, virtio_input_bitmap>,
    axis_info: BTreeMap<u16, virtio_input_absinfo>,
}

// Read and parse input event config file to input device bitmaps. If parsing is successful, this
// function returns a CustomInputConfig. The field in CustomInputConfig are corresponding to the
// same field in struct VirtioInputConfig.
fn parse_input_config_file(config_path: &PathBuf, device_idx: u32) -> Result<CustomInputConfig> {
    let mut supported_events: BTreeMap<u16, virtio_input_bitmap> = BTreeMap::new();

    // Read the json file to String
    let contents = fs::read_to_string(config_path).map_err(|e| {
        InputError::ParseEventConfigError(format!(
            "Failed to read input event config from {}: {}",
            config_path.display(),
            e
        ))
    })?;

    // Parse the string into a JSON object
    let config_file: InputConfigFile = serde_json::from_str(contents.as_str()).map_err(|e| {
        InputError::ParseEventConfigError(format!("Failed to parse json string: {}", e))
    })?;
    // Parse the supported events
    for event in config_file.events {
        let bitmap = bitmap_from_map(&event.supported_events).map_err(|e| {
            InputError::ParseEventConfigError(format!(
                "The config file's {} event can't be parsed: {:?}",
                config_path.display(),
                e
            ))
        })?;
        if supported_events
            .insert(event.event_type_code, bitmap)
            .is_some()
        {
            return Err(InputError::ParseEventConfigError(format!(
                "The {} event has been repeatedly defined by {}",
                event.event_type,
                config_path.display()
            )));
        }
        info!(
            "{} event is defined by {} for input device id {}",
            event.event_type,
            config_path.display(),
            device_idx
        );
    }

    let properties = bitmap_from_map(&config_file.properties).map_err(|e| {
        InputError::ParseEventConfigError(format!("Unable to parse device properties: {:?}", e))
    })?;

    let axis_info: BTreeMap<u16, virtio_input_absinfo> = config_file
        .axis_info
        .iter()
        .map(|a| {
            (
                a.axis_code,
                virtio_input_absinfo::new(a.min, a.max, a.fuzz, a.flat),
            )
        })
        .collect();

    let name = config_file
        .name
        .unwrap_or_else(|| "Crosvm Virtio Custom".to_string());
    let serial_name = config_file
        .serial_name
        .unwrap_or_else(|| "virtio-custom".to_string());

    Ok(CustomInputConfig {
        name,
        serial_name,
        properties,
        supported_events,
        axis_info,
    })
}

fn bitmap_from_map(map: &BTreeMap<String, u16>) -> Result<virtio_input_bitmap> {
    let mut bitmap_idx: Vec<u16> = Vec::new();
    for (key, &value) in map {
        if value >= 1024 {
            return Err(InputError::ParseEventConfigError(format!(
                "Value exceeds bitmap bounds: {} ({})",
                value, key
            )));
        }
        bitmap_idx.push(value);
    }
    Ok(virtio_input_bitmap::from_bits(&bitmap_idx))
}

#[cfg(test)]
mod tests {
    use defaults::new_keyboard_config;
    use defaults::new_multi_touch_config;
    use linux_input_sys::constants::ABS_MT_POSITION_X;
    use linux_input_sys::constants::ABS_MT_POSITION_Y;
    use linux_input_sys::constants::ABS_MT_SLOT;
    use linux_input_sys::constants::ABS_MT_TRACKING_ID;
    use linux_input_sys::constants::ABS_X;
    use linux_input_sys::constants::ABS_Y;
    use linux_input_sys::constants::BTN_TOUCH;
    use linux_input_sys::constants::EV_ABS;
    use linux_input_sys::constants::EV_KEY;
    use linux_input_sys::constants::EV_LED;
    use linux_input_sys::constants::EV_REP;
    use linux_input_sys::constants::INPUT_PROP_DIRECT;
    use tempfile::TempDir;

    use super::*;
    #[test]
    fn parse_keyboard_like_input_config_file_success() {
        // Create a sample JSON file for testing
        let temp_file = TempDir::new().unwrap();
        let path = temp_file.path().join("test.json");
        let test_json = r#"
        {
          "name": "Virtio Custom Test",
          "serial_name": "virtio-custom-test",
          "events": [
            {
              "event_type": "EV_KEY",
              "event_type_code": 1,
              "supported_events": {
                "KEY_ESC": 1,
                "KEY_1": 2,
                "KEY_2": 3,
                "KEY_A": 30,
                "KEY_B": 48,
                "KEY_SPACE": 57
              }
            },
            {
              "event_type": "EV_REP",
              "event_type_code": 20,
              "supported_events": {
                "REP_DELAY": 0,
                "REP_PERIOD": 1
            }
            },
            {
              "event_type": "EV_LED",
              "event_type_code": 17,
              "supported_events": {
                "LED_NUML": 0,
                "LED_CAPSL": 1,
                "LED_SCROLLL": 2
              }
            }
          ]
        }"#;
        fs::write(&path, test_json).expect("Unable to write test file");

        // Call the function and assert the result
        let result = parse_input_config_file(&path, 0);
        assert!(result.is_ok());

        let supported_event = result.unwrap().supported_events;
        // EV_KEY type
        let ev_key_events = supported_event.get(&EV_KEY);
        assert!(ev_key_events.is_some());
        let ev_key_bitmap = ev_key_events.unwrap();
        let expected_ev_key_bitmap = &virtio_input_bitmap::from_bits(&[1, 2, 3, 30, 48, 57]);
        assert_eq!(ev_key_bitmap, expected_ev_key_bitmap);
        // EV_REP type
        let ev_rep_events = supported_event.get(&EV_REP);
        assert!(ev_rep_events.is_some());
        let ev_rep_bitmap = ev_rep_events.unwrap();
        let expected_ev_rep_bitmap = &virtio_input_bitmap::from_bits(&[0, 1]);
        assert_eq!(ev_rep_bitmap, expected_ev_rep_bitmap);
        // EV_LED type
        let ev_led_events = supported_event.get(&EV_LED);
        assert!(ev_led_events.is_some());
        let ev_led_bitmap = ev_led_events.unwrap();
        let expected_ev_led_bitmap = &virtio_input_bitmap::from_bits(&[0, 1, 2]);
        assert_eq!(ev_led_bitmap, expected_ev_led_bitmap);
    }

    // Test the example custom keyboard config file
    // (tests/data/input/example_custom_keyboard_config.json) provides the same supported events as
    // default keyboard's supported events.
    #[test]
    fn example_custom_keyboard_config_file_events_eq_default_keyboard_events() {
        let temp_file = TempDir::new().unwrap();
        let path = temp_file.path().join("test.json");
        let test_json =
            include_str!("../../../tests/data/input/example_custom_keyboard_config.json");
        fs::write(&path, test_json).expect("Unable to write test file");

        let keyboard_supported_events = new_keyboard_config(0).supported_events;
        let custom_supported_events = parse_input_config_file(&path, 0).unwrap().supported_events;

        assert_eq!(keyboard_supported_events, custom_supported_events);
    }

    #[test]
    fn parse_touchscreen_like_input_config_file_success() {
        // Create a sample JSON file for testing
        let temp_file = TempDir::new().unwrap();
        let path = temp_file.path().join("touchscreen.json");
        let test_json = r#"
        {
          "name": "Virtio Custom Test",
          "serial_name": "virtio-custom-test",
          "properties": {"INPUT_PROP_DIRECT": 1},
          "events": [
            {
              "event_type": "EV_KEY",
              "event_type_code": 1,
              "supported_events": {
                "BTN_TOUCH": 330
              }
            }, {
              "event_type": "EV_ABS",
              "event_type_code": 3,
              "supported_events": {
                "ABS_MT_SLOT": 47,
                "ABS_MT_TRACKING_ID": 57,
                "ABS_MT_POSITION_X": 53,
                "ABS_MT_POSITION_Y": 54,
                "ABS_X": 0,
                "ABS_Y": 1
              }
            }
          ],
          "axis_info": [
            {
              "axis": "ABS_MT_SLOT",
              "axis_code": 47,
              "min": 0,
              "max": 10,
              "fuzz": 0,
              "flat": 0
            }, {
              "axis": "ABS_MT_TRACKING_ID",
              "axis_code": 57,
              "min": 0,
              "max": 10,
              "fuzz": 0,
              "flat": 0
            }, {
              "axis": "ABS_MT_POSITION_X",
              "axis_code": 53,
              "min": 0,
              "max": 720,
              "fuzz": 0,
              "flat": 0
            }, {
              "axis": "ABS_MT_POSITION_Y",
              "axis_code": 54,
              "min": 0,
              "max": 1280,
              "fuzz": 0,
              "flat": 0
            }, {
              "axis": "ABS_X",
              "axis_code": 0,
              "min": 0,
              "max": 720,
              "fuzz": 0,
              "flat": 0
            }, {
              "axis": "ABS_Y",
              "axis_code": 1,
              "min": 0,
              "max": 1280,
              "fuzz": 0,
              "flat": 0
            }
          ]
        }"#;

        fs::write(&path, test_json).expect("Unable to write test file");

        // Call the function and assert the result
        let config = parse_input_config_file(&path, 0).expect("failed to parse config");

        let properties = &config.properties;
        let expected_properties = virtio_input_bitmap::from_bits(&[INPUT_PROP_DIRECT]);
        assert_eq!(properties, &expected_properties);

        let supported_events = &config.supported_events;

        // EV_KEY type
        let ev_key_events = supported_events.get(&EV_KEY);
        assert!(ev_key_events.is_some());
        let ev_key_bitmap = ev_key_events.unwrap();
        let expected_ev_key_bitmap = virtio_input_bitmap::from_bits(&[BTN_TOUCH]);
        assert_eq!(ev_key_bitmap, &expected_ev_key_bitmap);

        // EV_ABS type
        let ev_abs_events = supported_events.get(&EV_ABS);
        assert!(ev_abs_events.is_some());
        let ev_abs_bitmap = ev_abs_events.unwrap();
        let expected_ev_abs_bitmap = virtio_input_bitmap::from_bits(&[
            ABS_MT_SLOT,
            ABS_MT_TRACKING_ID,
            ABS_MT_POSITION_X,
            ABS_MT_POSITION_Y,
            ABS_X,
            ABS_Y,
        ]);
        assert_eq!(ev_abs_bitmap, &expected_ev_abs_bitmap);

        let axis_info = &config.axis_info;
        let slot_opt = axis_info.get(&ABS_MT_SLOT);
        assert!(slot_opt.is_some());
        let slot_info = slot_opt.unwrap();
        let expected_slot_info = virtio_input_absinfo::new(0, 10, 0, 0);
        assert_eq!(slot_info, &expected_slot_info);

        let axis_info = &config.axis_info;
        let tracking_id_opt = axis_info.get(&ABS_MT_TRACKING_ID);
        assert!(tracking_id_opt.is_some());
        let tracking_id_info = tracking_id_opt.unwrap();
        let expected_tracking_id_info = virtio_input_absinfo::new(0, 10, 0, 0);
        assert_eq!(tracking_id_info, &expected_tracking_id_info);

        let axis_info = &config.axis_info;
        let position_x_opt = axis_info.get(&ABS_MT_POSITION_X);
        assert!(position_x_opt.is_some());
        let position_x_info = position_x_opt.unwrap();
        let expected_position_x_info = virtio_input_absinfo::new(0, 720, 0, 0);
        assert_eq!(position_x_info, &expected_position_x_info);

        let axis_info = &config.axis_info;
        let position_y_opt = axis_info.get(&ABS_MT_POSITION_Y);
        assert!(position_y_opt.is_some());
        let position_y_info = position_y_opt.unwrap();
        let expected_position_y_info = virtio_input_absinfo::new(0, 1280, 0, 0);
        assert_eq!(position_y_info, &expected_position_y_info);

        let axis_info = &config.axis_info;
        let x_opt = axis_info.get(&ABS_X);
        assert!(x_opt.is_some());
        let x_info = x_opt.unwrap();
        let expected_x_info = virtio_input_absinfo::new(0, 720, 0, 0);
        assert_eq!(x_info, &expected_x_info);

        let axis_info = &config.axis_info;
        let y_opt = axis_info.get(&ABS_Y);
        assert!(y_opt.is_some());
        let y_info = y_opt.unwrap();
        let expected_y_info = virtio_input_absinfo::new(0, 1280, 0, 0);
        assert_eq!(y_info, &expected_y_info);
    }

    // Test the example custom touchscreen config file
    // (tests/data/input/example_custom_multitouchscreen_config.json) provides the same
    // configuration as the default multi touch screen.
    #[test]
    fn example_custom_touchscreen_config_file_events_eq_default_multitouchscreen_events() {
        let temp_file = TempDir::new().unwrap();
        let path = temp_file.path().join("test.json");
        let test_json =
            include_str!("../../../tests/data/input/example_custom_multitouchscreen_config.json");
        fs::write(&path, test_json).expect("Unable to write test file");

        let default_config = new_multi_touch_config(0, 720, 1280, None);
        let custom_config = parse_input_config_file(&path, 0).expect("Failed to parse JSON file");

        assert_eq!(
            default_config.supported_events,
            custom_config.supported_events
        );
        assert_eq!(default_config.properties, custom_config.properties);
        assert_eq!(default_config.axis_info, custom_config.axis_info);
    }
}
