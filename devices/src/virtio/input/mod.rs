// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(dead_code)]
mod constants;
mod defaults;
mod evdev;
mod event_source;

use self::constants::*;

use std::os::unix::io::{AsRawFd, RawFd};

use data_model::{DataInit, Le16, Le32};
use sys_util::{error, warn, EventFd, GuestMemory, PollContext, PollToken};

use self::event_source::{input_event, EvdevEventSource, EventSource, SocketEventSource};
use super::{Queue, VirtioDevice, INTERRUPT_STATUS_USED_RING, TYPE_INPUT};
use std::cmp::min;
use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::io::Read;
use std::io::Write;
use std::mem::size_of;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

const EVENT_QUEUE_SIZE: u16 = 64;
const STATUS_QUEUE_SIZE: u16 = 64;
const QUEUE_SIZES: &[u16] = &[EVENT_QUEUE_SIZE, STATUS_QUEUE_SIZE];

#[derive(Debug)]
pub enum InputError {
    /// Failed to write events to the source
    EventsWriteError(sys_util::GuestMemoryError),
    /// Failed to read events from the source
    EventsReadError(std::io::Error),
    // Failed to get name of event device
    EvdevIdError(sys_util::Error),
    // Failed to get name of event device
    EvdevNameError(sys_util::Error),
    // Failed to get serial name of event device
    EvdevSerialError(sys_util::Error),
    // Failed to get properties of event device
    EvdevPropertiesError(sys_util::Error),
    // Failed to get event types supported by device
    EvdevEventTypesError(sys_util::Error),
    // Failed to get axis information of event device
    EvdevAbsInfoError(sys_util::Error),
    // Failed to grab event device
    EvdevGrabError(sys_util::Error),
}
pub type Result<T> = std::result::Result<T, InputError>;

impl Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::InputError::*;

        match self {
            EventsWriteError(e) => write!(f, "failed to write events to the source: {}", e),
            EventsReadError(e) => write!(f, "failed to read events from the source: {}", e),
            EvdevIdError(e) => write!(f, "failed to get id of event device: {}", e),
            EvdevNameError(e) => write!(f, "failed to get name of event device: {}", e),
            EvdevSerialError(e) => write!(f, "failed to get serial name of event device: {}", e),
            EvdevPropertiesError(e) => write!(f, "failed to get properties of event device: {}", e),
            EvdevEventTypesError(e) => {
                write!(f, "failed to get event types supported by device: {}", e)
            }
            EvdevAbsInfoError(e) => {
                write!(f, "failed to get axis information of event device: {}", e)
            }
            EvdevGrabError(e) => write!(f, "failed to grab event device: {}", e),
        }
    }
}

#[derive(Copy, Clone, Default, Debug)]
#[repr(C)]
pub struct virtio_input_device_ids {
    bustype: Le16,
    vendor: Le16,
    product: Le16,
    version: Le16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_input_device_ids {}

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

#[derive(Copy, Clone, Default, Debug)]
#[repr(C)]
pub struct virtio_input_absinfo {
    min: Le32,
    max: Le32,
    fuzz: Le32,
    flat: Le32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_input_absinfo {}

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

#[derive(Copy, Clone)]
#[repr(C)]
struct virtio_input_config {
    select: u8,
    subsel: u8,
    size: u8,
    reserved: [u8; 5],
    payload: [u8; 128],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_input_config {}

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
        self.set_payload_slice(absinfo.as_slice());
    }

    fn set_device_ids(&mut self, device_ids: &virtio_input_device_ids) {
        self.set_payload_slice(device_ids.as_slice());
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct virtio_input_bitmap {
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
    const CONFIG_MEM_SIZE: usize = size_of::<virtio_input_config>();

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

    fn from_evdev<T: AsRawFd>(source: &T) -> Result<VirtioInputConfig> {
        Ok(VirtioInputConfig::new(
            evdev::device_ids(source)?,
            evdev::name(source)?,
            evdev::serial_name(source)?,
            evdev::properties(source)?,
            evdev::supported_events(source)?,
            evdev::abs_info(source),
        ))
    }

    fn validate_read_offsets(&self, offset: usize, len: usize) -> bool {
        if offset + len > VirtioInputConfig::CONFIG_MEM_SIZE {
            error!(
                "Attempt to read from invalid config range: [{}..{}], valid ranges in [0..{}]",
                offset,
                offset + len,
                VirtioInputConfig::CONFIG_MEM_SIZE
            );
            return false;
        }
        true
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
                    cfg.set_payload_bitmap(&supported_codes);
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
            _ => {
                warn!("Unsuported virtio input config selection: {}", self.select);
            }
        }
        cfg
    }

    fn read(&self, offset: usize, data: &mut [u8]) {
        let data_len = data.len();
        if self.validate_read_offsets(offset, data_len) {
            let config = self.build_config_memory();
            data.clone_from_slice(&config.as_slice()[offset..offset + data_len]);
        }
    }

    fn validate_write_offsets(&self, offset: usize, len: usize) -> bool {
        const MAX_WRITABLE_BYTES: usize = 2;
        if offset + len > MAX_WRITABLE_BYTES {
            error!(
                "Attempt to write to invalid config range: [{}..{}], valid ranges in [0..{}]",
                offset,
                offset + len,
                MAX_WRITABLE_BYTES
            );
            return false;
        }
        true
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        let len = data.len();
        if self.validate_write_offsets(offset, len) {
            let mut selectors: [u8; 2] = [self.select, self.subsel];
            selectors[offset..offset + len].clone_from_slice(&data);
            self.select = selectors[0];
            self.subsel = selectors[1];
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
struct virtio_input_event {
    type_: Le16,
    code: Le16,
    value: Le32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_input_event {}

impl virtio_input_event {
    const EVENT_SIZE: usize = size_of::<virtio_input_event>();
    fn new(type_: u16, code: u16, value: u32) -> virtio_input_event {
        virtio_input_event {
            type_: Le16::from(type_),
            code: Le16::from(code),
            value: Le32::from(value),
        }
    }

    fn from_input_event(other: &input_event) -> virtio_input_event {
        virtio_input_event {
            type_: Le16::from(other.type_),
            code: Le16::from(other.code),
            value: Le32::from(other.value),
        }
    }
}

struct Worker<T: EventSource> {
    event_source: T,
    event_queue: Queue,
    status_queue: Queue,
    guest_memory: GuestMemory,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    interrupt_resample_evt: EventFd,
}

impl<T: EventSource> Worker<T> {
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    // Send events from the source to the guest
    fn send_events(&mut self) -> bool {
        let queue = &mut self.event_queue;
        let mut needs_interrupt = false;

        // Only consume from the queue iterator if we know we have events to send
        while self.event_source.available_events_count() > 0 {
            match queue.pop(&self.guest_memory) {
                None => {
                    break;
                }
                Some(avail_desc) => {
                    if !avail_desc.is_write_only() {
                        panic!("Received a read only descriptor on event queue");
                    }
                    let avail_events_size =
                        self.event_source.available_events_count() * virtio_input_event::EVENT_SIZE;
                    let len = min(avail_desc.len as usize, avail_events_size);
                    if let Err(e) =
                        self.guest_memory
                            .read_to_memory(avail_desc.addr, &self.event_source, len)
                    {
                        // Read is guaranteed to succeed here, so the only possible failure would be
                        // writing outside the guest memory region, which would mean the address and
                        // length given in the queue descriptor are wrong.
                        panic!("failed reading events into guest memory: {}", e);
                    }

                    queue.add_used(&self.guest_memory, avail_desc.index, len as u32);
                    needs_interrupt = true;
                }
            }
        }

        needs_interrupt
    }

    fn process_status_queue(&mut self) -> Result<bool> {
        let queue = &mut self.status_queue;

        let mut needs_interrupt = false;
        while let Some(avail_desc) = queue.pop(&self.guest_memory) {
            if !avail_desc.is_read_only() {
                panic!("Received a writable descriptor on status queue");
            }
            let len = avail_desc.len as usize;
            if len % virtio_input_event::EVENT_SIZE != 0 {
                warn!(
                    "Ignoring buffer of unexpected size on status queue: {:0}",
                    len
                );
            } else {
                self.guest_memory
                    .write_from_memory(avail_desc.addr, &self.event_source, len)
                    .map_err(InputError::EventsWriteError)?;
            }

            queue.add_used(&self.guest_memory, avail_desc.index, len as u32);
            needs_interrupt = true;
        }

        Ok(needs_interrupt)
    }

    fn run(
        &mut self,
        event_queue_evt_fd: EventFd,
        status_queue_evt_fd: EventFd,
        kill_evt: EventFd,
    ) {
        if let Err(e) = self.event_source.init() {
            error!("failed initializing event source: {}", e);
            return;
        }

        #[derive(PollToken)]
        enum Token {
            EventQAvailable,
            StatusQAvailable,
            InputEventsAvailable,
            InterruptResample,
            Kill,
        }
        let poll_ctx: PollContext<Token> = match PollContext::new()
            .and_then(|pc| {
                pc.add(&event_queue_evt_fd, Token::EventQAvailable)
                    .and(Ok(pc))
            })
            .and_then(|pc| {
                pc.add(&status_queue_evt_fd, Token::StatusQAvailable)
                    .and(Ok(pc))
            })
            .and_then(|pc| {
                pc.add(&self.event_source, Token::InputEventsAvailable)
                    .and(Ok(pc))
            })
            .and_then(|pc| {
                pc.add(&self.interrupt_resample_evt, Token::InterruptResample)
                    .and(Ok(pc))
            })
            .and_then(|pc| pc.add(&kill_evt, Token::Kill).and(Ok(pc)))
        {
            Ok(poll_ctx) => poll_ctx,
            Err(e) => {
                error!("failed creating PollContext: {}", e);
                return;
            }
        };

        'poll: loop {
            let poll_events = match poll_ctx.wait() {
                Ok(poll_events) => poll_events,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };

            let mut needs_interrupt = false;
            for poll_event in poll_events.iter_readable() {
                match poll_event.token() {
                    Token::EventQAvailable => {
                        if let Err(e) = event_queue_evt_fd.read() {
                            error!("failed reading event queue EventFd: {}", e);
                            break 'poll;
                        }
                        needs_interrupt |= self.send_events();
                    }
                    Token::StatusQAvailable => {
                        if let Err(e) = status_queue_evt_fd.read() {
                            error!("failed reading status queue EventFd: {}", e);
                            break 'poll;
                        }
                        match self.process_status_queue() {
                            Ok(b) => needs_interrupt |= b,
                            Err(e) => error!("failed processing status events: {}", e),
                        }
                    }
                    Token::InputEventsAvailable => match self.event_source.receive_events() {
                        Err(e) => error!("error receiving events: {}", e),
                        Ok(_cnt) => needs_interrupt |= self.send_events(),
                    },
                    Token::InterruptResample => {
                        let _ = self.interrupt_resample_evt.read();
                        if self.interrupt_status.load(Ordering::SeqCst) != 0 {
                            self.interrupt_evt.write(1).unwrap();
                        }
                    }
                    Token::Kill => {
                        let _ = kill_evt.read();
                        break 'poll;
                    }
                }
            }
            if needs_interrupt {
                self.signal_used_queue();
            }
        }

        if let Err(e) = self.event_source.finalize() {
            error!("failed finalizing event source: {}", e);
            return;
        }
    }
}

/// Virtio input device

pub struct Input<T: EventSource> {
    kill_evt: Option<EventFd>,
    config: VirtioInputConfig,
    source: Option<T>,
}

impl<T: EventSource> Drop for Input<T> {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl<T> VirtioDevice for Input<T>
where
    T: 'static + EventSource + Send,
{
    fn keep_fds(&self) -> Vec<RawFd> {
        if let Some(source) = &self.source {
            return vec![source.as_raw_fd()];
        }
        Vec::new()
    }

    fn device_type(&self) -> u32 {
        TYPE_INPUT
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

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt_evt: EventFd,
        interrupt_resample_evt: EventFd,
        status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != 2 || queue_evts.len() != 2 {
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

        // Status is queue 1, event is queue 0
        let status_queue = queues.remove(1);
        let status_queue_evt_fd = queue_evts.remove(1);

        let event_queue = queues.remove(0);
        let event_queue_evt_fd = queue_evts.remove(0);

        if let Some(source) = self.source.take() {
            let worker_result = thread::Builder::new()
                .name(String::from("virtio_input"))
                .spawn(move || {
                    let mut worker = Worker {
                        event_source: source,
                        event_queue,
                        status_queue,
                        guest_memory: mem,
                        interrupt_status: status,
                        interrupt_evt,
                        interrupt_resample_evt,
                    };
                    worker.run(event_queue_evt_fd, status_queue_evt_fd, kill_evt);
                });

            if let Err(e) = worker_result {
                error!("failed to spawn virtio_input worker: {}", e);
                return;
            }
        } else {
            error!("tried to activate device without a source for events");
            return;
        }
    }
}

/// Creates a new virtio input device from an event device node
pub fn new_evdev<T>(source: T) -> Result<Input<EvdevEventSource<T>>>
where
    T: Read + Write + AsRawFd,
{
    Ok(Input {
        kill_evt: None,
        config: VirtioInputConfig::from_evdev(&source)?,
        source: Some(EvdevEventSource::new(source)),
    })
}

/// Creates a new virtio touch device which supports single touch only.
pub fn new_single_touch<T>(
    source: T,
    width: u32,
    height: u32,
) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawFd,
{
    Ok(Input {
        kill_evt: None,
        config: defaults::new_single_touch_config(width, height),
        source: Some(SocketEventSource::new(source)),
    })
}

/// Creates a new virtio trackpad device which supports (single) touch, primary and secondary
/// buttons as well as X and Y axis.
pub fn new_trackpad<T>(source: T, width: u32, height: u32) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawFd,
{
    Ok(Input {
        kill_evt: None,
        config: defaults::new_trackpad_config(width, height),
        source: Some(SocketEventSource::new(source)),
    })
}

/// Creates a new virtio mouse which supports primary, secondary, wheel and REL events.
pub fn new_mouse<T>(source: T) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawFd,
{
    Ok(Input {
        kill_evt: None,
        config: defaults::new_mouse_config(),
        source: Some(SocketEventSource::new(source)),
    })
}

/// Creates a new virtio keyboard, which supports the same events as an en-us physical keyboard.
pub fn new_keyboard<T>(source: T) -> Result<Input<SocketEventSource<T>>>
where
    T: Read + Write + AsRawFd,
{
    Ok(Input {
        kill_evt: None,
        config: defaults::new_keyboard_config(),
        source: Some(SocketEventSource::new(source)),
    })
}
