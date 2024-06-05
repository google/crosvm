// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub(crate) mod sys;

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::TryRecvError;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use base::error;
use base::warn;
use base::Event;
use base::EventToken;
use base::Result;
use base::WaitContext;
use base::WorkerThread;
use serde::Deserialize;
use serde::Serialize;

use crate::bus::BusAccessInfo;
use crate::pci::CrosvmDeviceId;
use crate::serial_device::SerialInput;
use crate::suspendable::DeviceState;
use crate::suspendable::Suspendable;
use crate::BusDevice;
use crate::DeviceId;

const LOOP_SIZE: usize = 0x40;

const DATA: u8 = 0;
const IER: u8 = 1;
const IIR: u8 = 2;
const LCR: u8 = 3;
const MCR: u8 = 4;
const LSR: u8 = 5;
const MSR: u8 = 6;
const SCR: u8 = 7;
const DLAB_LOW: u8 = 0;
const DLAB_HIGH: u8 = 1;

const IER_RECV_BIT: u8 = 0x1;
const IER_THR_BIT: u8 = 0x2;
const IER_FIFO_BITS: u8 = 0x0f;

const IIR_FIFO_BITS: u8 = 0xc0;
const IIR_NONE_BIT: u8 = 0x1;
const IIR_THR_BIT: u8 = 0x2;
const IIR_RECV_BIT: u8 = 0x4;

const LSR_DATA_BIT: u8 = 0x1;
const LSR_EMPTY_BIT: u8 = 0x20;
const LSR_IDLE_BIT: u8 = 0x40;

const MCR_DTR_BIT: u8 = 0x01; // Data Terminal Ready
const MCR_RTS_BIT: u8 = 0x02; // Request to Send
const MCR_OUT1_BIT: u8 = 0x04;
const MCR_OUT2_BIT: u8 = 0x08;
const MCR_LOOP_BIT: u8 = 0x10;

const MSR_CTS_BIT: u8 = 0x10; // Clear to Send
const MSR_DSR_BIT: u8 = 0x20; // Data Set Ready
const MSR_RI_BIT: u8 = 0x40; // Ring Indicator
const MSR_DCD_BIT: u8 = 0x80; // Data Carrier Detect

const DEFAULT_INTERRUPT_IDENTIFICATION: u8 = IIR_NONE_BIT; // no pending interrupt
const DEFAULT_LINE_STATUS: u8 = LSR_EMPTY_BIT | LSR_IDLE_BIT; // THR empty and line is idle
const DEFAULT_LINE_CONTROL: u8 = 0x3; // 8-bits per character
const DEFAULT_MODEM_CONTROL: u8 = MCR_OUT2_BIT;
const DEFAULT_MODEM_STATUS: u8 = MSR_DSR_BIT | MSR_CTS_BIT | MSR_DCD_BIT;
const DEFAULT_BAUD_DIVISOR: u16 = 12; // 9600 bps

const TIMESTAMP_PREFIX_FMT: &str = "[ %F %T%.9f ]: ";

/// Emulates serial COM ports commonly seen on x86 I/O ports 0x3f8/0x2f8/0x3e8/0x2e8.
///
/// This can optionally write the guest's output to a Write trait object. To send input to the
/// guest, use `queue_input_bytes` directly, or give a Read trait object which will be used queue
/// bytes when `used_command` is called.
pub struct Serial {
    // Serial port registers
    interrupt_enable: Arc<AtomicU8>,
    interrupt_identification: u8,
    interrupt_evt: Event,
    line_control: u8,
    line_status: u8,
    modem_control: u8,
    modem_status: u8,
    scratch: u8,
    baud_divisor: u16,

    // Host input/output
    in_buffer: VecDeque<u8>,
    in_channel: Option<Receiver<u8>>,
    input: Option<Box<dyn SerialInput>>,
    out: Option<Box<dyn io::Write + Send>>,
    out_timestamp: bool,
    last_write_was_newline: bool,
    #[cfg(windows)]
    pub system_params: sys::windows::SystemSerialParams,
    device_state: DeviceState,
    worker: Option<WorkerThread<Box<dyn SerialInput>>>,
}

impl Serial {
    fn new_common(
        interrupt_evt: Event,
        input: Option<Box<dyn SerialInput>>,
        out: Option<Box<dyn io::Write + Send>>,
        out_timestamp: bool,
        #[cfg(windows)] system_params: sys::windows::SystemSerialParams,
    ) -> Serial {
        Serial {
            interrupt_enable: Default::default(),
            interrupt_identification: DEFAULT_INTERRUPT_IDENTIFICATION,
            interrupt_evt,
            line_control: DEFAULT_LINE_CONTROL,
            line_status: DEFAULT_LINE_STATUS,
            modem_control: DEFAULT_MODEM_CONTROL,
            modem_status: DEFAULT_MODEM_STATUS,
            scratch: 0,
            baud_divisor: DEFAULT_BAUD_DIVISOR,
            in_buffer: Default::default(),
            in_channel: None,
            input,
            out,
            out_timestamp,
            last_write_was_newline: true,
            #[cfg(windows)]
            system_params,
            device_state: DeviceState::Awake,
            worker: None,
        }
    }

    /// Returns a unique ID for the serial device.
    pub fn device_id() -> DeviceId {
        CrosvmDeviceId::Serial.into()
    }

    /// Returns a debug label for the serial device. Used when setting up `IrqEventSource`.
    pub fn debug_label() -> String {
        "serial".to_owned()
    }

    /// Queues raw bytes for the guest to read and signals the interrupt if the line status would
    /// change. These bytes will be read by the guest before any bytes from the input stream that
    /// have not already been queued.
    pub fn queue_input_bytes(&mut self, c: &[u8]) -> Result<()> {
        if !c.is_empty() && !self.is_loop() {
            self.in_buffer.extend(c);
            self.set_data_bit();
            self.trigger_recv_interrupt()?;
        }

        Ok(())
    }

    fn spawn_input_thread(&mut self) {
        let mut rx = match self.input.take() {
            Some(input) => input,
            None => return,
        };

        let (send_channel, recv_channel) = channel();

        // The interrupt enable and interrupt event are used to trigger the guest serial driver to
        // read the serial device, which will give the VCPU threads time to queue input bytes from
        // the input thread's buffer, changing the serial device state accordingly.
        let interrupt_enable = self.interrupt_enable.clone();
        let interrupt_evt = match self.interrupt_evt.try_clone() {
            Ok(e) => e,
            Err(e) => {
                error!("failed to clone interrupt event: {}", e);
                return;
            }
        };

        self.worker = Some(WorkerThread::start(
            format!("{} input thread", self.debug_label()),
            move |kill_evt| {
                let mut rx_buf = [0u8; 1];

                #[derive(EventToken)]
                enum Token {
                    Kill,
                    SerialEvent,
                }

                let wait_ctx_res: Result<WaitContext<Token>> = WaitContext::build_with(&[
                    (&kill_evt, Token::Kill),
                    (rx.get_read_notifier(), Token::SerialEvent),
                ]);
                let wait_ctx = match wait_ctx_res {
                    Ok(wait_context) => wait_context,
                    Err(e) => {
                        error!("Failed to create wait context. {}", e);
                        return rx;
                    }
                };
                let mut kill_timeout = None;
                loop {
                    let events = match wait_ctx.wait() {
                        Ok(events) => events,
                        Err(e) => {
                            error!("Failed to wait for events. {}", e);
                            return rx;
                        }
                    };
                    for event in events.iter() {
                        match event.token {
                            Token::Kill => {
                                // Ignore the kill event until there are no other events to process
                                // so that we drain `rx` as much as possible. The next
                                // `wait_ctx.wait()` call will immediately re-entry this case since
                                // we don't call `kill_evt.wait()`.
                                if events.iter().all(|e| matches!(e.token, Token::Kill)) {
                                    return rx;
                                }
                                const TIMEOUT_DURATION: Duration = Duration::from_millis(500);
                                match kill_timeout {
                                    None => {
                                        kill_timeout = Some(Instant::now() + TIMEOUT_DURATION);
                                    }
                                    Some(t) => {
                                        if Instant::now() >= t {
                                            error!(
                                                "failed to drain serial input within {:?}, giving up",
                                                TIMEOUT_DURATION
                                            );
                                            return rx;
                                        }
                                    }
                                }
                            }
                            Token::SerialEvent => {
                                // Matches both is_readable and is_hungup.
                                // In the case of is_hungup, there might still be data in the
                                // buffer, and a regular read would occur. When the buffer is
                                // empty, is_hungup would read EOF.
                                match rx.read(&mut rx_buf) {
                                    // Assume the stream of input has ended.
                                    Ok(0) => {
                                        return rx;
                                    }
                                    Ok(_n) => {
                                        if send_channel.send(rx_buf[0]).is_err() {
                                            // The receiver has disconnected.
                                            return rx;
                                        }
                                        if (interrupt_enable.load(Ordering::SeqCst) & IER_RECV_BIT)
                                            != 0
                                        {
                                            interrupt_evt.signal().unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        // Being interrupted is not an error, but everything else
                                        // is.
                                        if e.kind() != io::ErrorKind::Interrupted {
                                            error!(
                                                "failed to read for bytes to queue into serial device: {}",
                                                e
                                            );
                                            return rx;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
        ));
        self.in_channel = Some(recv_channel);
    }

    fn drain_in_channel(&mut self) {
        loop {
            let in_channel = match self.in_channel.as_ref() {
                Some(v) => v,
                None => return,
            };
            match in_channel.try_recv() {
                Ok(byte) => {
                    self.queue_input_bytes(&[byte]).unwrap();
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.in_channel = None;
                    return;
                }
            }
        }
    }

    /// Gets the interrupt event used to interrupt the driver when it needs to respond to this
    /// device.
    pub fn interrupt_event(&self) -> &Event {
        &self.interrupt_evt
    }

    fn is_dlab_set(&self) -> bool {
        (self.line_control & 0x80) != 0
    }

    fn is_recv_intr_enabled(&self) -> bool {
        (self.interrupt_enable.load(Ordering::SeqCst) & IER_RECV_BIT) != 0
    }

    fn is_thr_intr_enabled(&self) -> bool {
        (self.interrupt_enable.load(Ordering::SeqCst) & IER_THR_BIT) != 0
    }

    fn is_thr_intr_changed(&self, bit: u8) -> bool {
        (self.interrupt_enable.load(Ordering::SeqCst) ^ bit) & IER_FIFO_BITS != 0
    }

    fn is_loop(&self) -> bool {
        (self.modem_control & MCR_LOOP_BIT) != 0
    }

    fn add_intr_bit(&mut self, bit: u8) {
        self.interrupt_identification &= !IIR_NONE_BIT;
        self.interrupt_identification |= bit;
    }

    fn del_intr_bit(&mut self, bit: u8) {
        self.interrupt_identification &= !bit;
        if self.interrupt_identification == 0x0 {
            self.interrupt_identification = IIR_NONE_BIT;
        }
    }

    fn trigger_thr_empty(&mut self) -> Result<()> {
        if self.is_thr_intr_enabled() {
            self.add_intr_bit(IIR_THR_BIT);
            self.trigger_interrupt()?
        }
        Ok(())
    }

    fn trigger_recv_interrupt(&mut self) -> Result<()> {
        if self.is_recv_intr_enabled() {
            // Only bother triggering the interrupt if the identification bit wasn't set or
            // acknowledged.
            if self.interrupt_identification & IIR_RECV_BIT == 0 {
                self.add_intr_bit(IIR_RECV_BIT);
                self.trigger_interrupt()?
            }
        }
        Ok(())
    }

    fn trigger_interrupt(&mut self) -> Result<()> {
        self.interrupt_evt.signal()
    }

    fn set_data_bit(&mut self) {
        self.line_status |= LSR_DATA_BIT;
    }

    fn is_data_avaiable(&self) -> bool {
        (self.line_status & LSR_DATA_BIT) != 0
    }

    fn iir_reset(&mut self) {
        self.interrupt_identification = DEFAULT_INTERRUPT_IDENTIFICATION;
    }

    fn handle_write(&mut self, offset: u8, v: u8) -> Result<()> {
        match offset {
            DLAB_LOW if self.is_dlab_set() => {
                self.baud_divisor = (self.baud_divisor & 0xff00) | v as u16
            }
            DLAB_HIGH if self.is_dlab_set() => {
                self.baud_divisor = (self.baud_divisor & 0x00ff) | ((v as u16) << 8)
            }
            DATA => {
                if self.is_loop() {
                    if self.in_buffer.len() < LOOP_SIZE {
                        self.in_buffer.push_back(v);
                        self.set_data_bit();
                        self.trigger_recv_interrupt()?;
                    }
                } else {
                    self.handle_write_data(v)?;
                    self.trigger_thr_empty()?;
                }
            }
            IER => {
                let tx_changed = self.is_thr_intr_changed(v);
                self.interrupt_enable
                    .store(v & IER_FIFO_BITS, Ordering::SeqCst);

                if self.is_data_avaiable() {
                    self.trigger_recv_interrupt()?;
                }

                if tx_changed {
                    self.trigger_thr_empty()?;
                }
            }
            LCR => self.line_control = v,
            MCR => self.modem_control = v,
            SCR => self.scratch = v,
            _ => {}
        }
        Ok(())
    }

    // Write a single byte of data to `self.out`.
    fn handle_write_data(&mut self, v: u8) -> Result<()> {
        let out = match self.out.as_mut() {
            Some(out) => out,
            None => return Ok(()),
        };

        if self.out_timestamp && self.last_write_was_newline {
            write!(out, "{}", chrono::Utc::now().format(TIMESTAMP_PREFIX_FMT))?;
        }

        self.last_write_was_newline = v == b'\n';

        out.write_all(&[v])?;
        out.flush()?;
        Ok(())
    }
}

impl BusDevice for Serial {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::Serial.into()
    }

    fn debug_label(&self) -> String {
        "serial".to_owned()
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        if matches!(self.device_state, DeviceState::Sleep) {
            panic!("Unexpected action: Attempt to write to serial when device is in sleep mode");
        }

        if data.len() != 1 {
            return;
        }

        #[cfg(windows)]
        self.handle_sync_thread();

        if let Err(e) = self.handle_write(info.offset as u8, data[0]) {
            error!("serial failed write: {}", e);
        }
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        if matches!(self.device_state, DeviceState::Sleep) {
            panic!("Unexpected action: Attempt to write to serial when device is in sleep mode");
        }

        if data.len() != 1 {
            return;
        }

        if self.input.is_some() {
            self.spawn_input_thread();
        }
        self.drain_in_channel();

        data[0] = match info.offset as u8 {
            DLAB_LOW if self.is_dlab_set() => self.baud_divisor as u8,
            DLAB_HIGH if self.is_dlab_set() => (self.baud_divisor >> 8) as u8,
            DATA => {
                self.del_intr_bit(IIR_RECV_BIT);
                if self.in_buffer.len() <= 1 {
                    self.line_status &= !LSR_DATA_BIT;
                }
                self.in_buffer.pop_front().unwrap_or_default()
            }
            IER => self.interrupt_enable.load(Ordering::SeqCst),
            IIR => {
                let v = self.interrupt_identification | IIR_FIFO_BITS;
                self.iir_reset();
                v
            }
            LCR => self.line_control,
            MCR => self.modem_control,
            LSR => self.line_status,
            MSR => {
                if self.is_loop() {
                    let mut msr =
                        self.modem_status & !(MSR_DSR_BIT | MSR_CTS_BIT | MSR_RI_BIT | MSR_DCD_BIT);
                    if self.modem_control & MCR_DTR_BIT != 0 {
                        msr |= MSR_DSR_BIT;
                    }
                    if self.modem_control & MCR_RTS_BIT != 0 {
                        msr |= MSR_CTS_BIT;
                    }
                    if self.modem_control & MCR_OUT1_BIT != 0 {
                        msr |= MSR_RI_BIT;
                    }
                    if self.modem_control & MCR_OUT2_BIT != 0 {
                        msr |= MSR_DCD_BIT;
                    }
                    msr
                } else {
                    self.modem_status
                }
            }
            SCR => self.scratch,
            _ => 0,
        };
    }
}

#[derive(Serialize, Deserialize)]
struct SerialSnapshot {
    interrupt_enable: u8,
    interrupt_identification: u8,
    line_control: u8,
    line_status: u8,
    modem_control: u8,
    modem_status: u8,
    scratch: u8,
    baud_divisor: u16,

    in_buffer: VecDeque<u8>,

    has_input: bool,
    has_output: bool,

    last_write_was_newline: bool,
}

impl Suspendable for Serial {
    fn snapshot(&mut self) -> anyhow::Result<serde_json::Value> {
        self.spawn_input_thread();
        if let Some(worker) = self.worker.take() {
            self.input = Some(worker.stop());
        }
        self.drain_in_channel();
        let snap = SerialSnapshot {
            interrupt_enable: self.interrupt_enable.load(Ordering::SeqCst),
            interrupt_identification: self.interrupt_identification,
            line_control: self.line_control,
            line_status: self.line_status,
            modem_control: self.modem_control,
            modem_status: self.modem_status,
            scratch: self.scratch,
            baud_divisor: self.baud_divisor,
            in_buffer: self.in_buffer.clone(),
            has_input: self.input.is_some(),
            has_output: self.out.is_some(),
            last_write_was_newline: self.last_write_was_newline,
        };

        let serialized = serde_json::to_value(snap).context("error serializing")?;
        Ok(serialized)
    }

    fn restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let serial_snapshot: SerialSnapshot =
            serde_json::from_value(data).context("error deserializing")?;
        self.interrupt_enable = Arc::new(AtomicU8::new(serial_snapshot.interrupt_enable));
        self.interrupt_identification = serial_snapshot.interrupt_identification;
        self.line_control = serial_snapshot.line_control;
        self.line_status = serial_snapshot.line_status;
        self.modem_control = serial_snapshot.modem_control;
        self.modem_status = serial_snapshot.modem_status;
        self.scratch = serial_snapshot.scratch;
        self.baud_divisor = serial_snapshot.baud_divisor;
        self.in_buffer = serial_snapshot.in_buffer;
        if serial_snapshot.has_input && self.input.is_none() {
            warn!("Restore serial input missing when restore expected an input");
        }
        if serial_snapshot.has_output && self.out.is_none() {
            warn!("Restore serial out missing when restore expected an out");
        }
        self.last_write_was_newline = serial_snapshot.last_write_was_newline;
        Ok(())
    }

    fn sleep(&mut self) -> anyhow::Result<()> {
        if !matches!(self.device_state, DeviceState::Sleep) {
            self.device_state = DeviceState::Sleep;
            if let Some(worker) = self.worker.take() {
                self.input = Some(worker.stop());
            }

            self.drain_in_channel();
            self.in_channel = None;
        }
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        if !matches!(self.device_state, DeviceState::Awake) {
            self.device_state = DeviceState::Awake;
            if self.input.is_some() {
                self.spawn_input_thread();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use hypervisor::ProtectionType;
    use sync::Mutex;

    use super::*;
    use crate::serial_device::SerialOptions;
    use crate::suspendable_tests;
    pub use crate::sys::serial_device::SerialDevice;

    #[derive(Clone)]
    pub(super) struct SharedBuffer {
        pub(super) buf: Arc<Mutex<Vec<u8>>>,
    }

    /// Empties the in_buffer.
    impl Serial {
        pub fn clear_in_buffer(&mut self) {
            self.in_buffer.clear()
        }
    }

    impl SharedBuffer {
        pub(super) fn new() -> SharedBuffer {
            SharedBuffer {
                buf: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buf.lock().write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.buf.lock().flush()
        }
    }

    pub(super) fn serial_bus_address(offset: u8) -> BusAccessInfo {
        // Serial devices only use the offset of the BusAccessInfo
        BusAccessInfo {
            offset: offset as u64,
            address: 0,
            id: 0,
        }
    }

    #[test]
    fn serial_output() {
        let intr_evt = Event::new().unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new(
            ProtectionType::Unprotected,
            intr_evt,
            None,
            Some(Box::new(serial_out.clone())),
            None,
            Default::default(),
            Vec::new(),
        );

        serial.write(serial_bus_address(DATA), &[b'a']);
        serial.write(serial_bus_address(DATA), &[b'b']);
        serial.write(serial_bus_address(DATA), &[b'c']);
        assert_eq!(serial_out.buf.lock().as_slice(), &[b'a', b'b', b'c']);
    }

    #[test]
    fn serial_input() {
        let intr_evt = Event::new().unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new(
            ProtectionType::Unprotected,
            intr_evt.try_clone().unwrap(),
            None,
            Some(Box::new(serial_out)),
            None,
            Default::default(),
            Vec::new(),
        );

        serial.write(serial_bus_address(IER), &[IER_RECV_BIT]);
        serial.queue_input_bytes(&[b'a', b'b', b'c']).unwrap();

        assert_eq!(intr_evt.wait(), Ok(()));
        let mut data = [0u8; 1];
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'a');
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'c');
    }

    #[test]
    fn serial_input_sleep_snapshot_restore_wake() {
        let intr_evt = Event::new().unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new(
            ProtectionType::Unprotected,
            intr_evt.try_clone().unwrap(),
            None,
            Some(Box::new(serial_out)),
            None,
            Default::default(),
            Vec::new(),
        );

        serial.write(serial_bus_address(IER), &[IER_RECV_BIT]);
        serial.queue_input_bytes(&[b'a', b'b', b'c']).unwrap();

        assert_eq!(intr_evt.wait(), Ok(()));
        let mut data = [0u8; 1];
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'a');
        let sleep_res = serial.sleep();
        match sleep_res {
            Ok(_res) => (),
            Err(e) => println!("{}", e),
        }
        let snap_res = serial.snapshot();
        match snap_res {
            Ok(snap) => {
                let restore_res = serial.restore(snap);
                match restore_res {
                    Ok(_rest) => (),
                    Err(e) => println!("{}", e),
                }
            }
            Err(e) => println!("{}", e),
        }
        let wake_res = serial.wake();
        match wake_res {
            Ok(_res) => (),
            Err(e) => println!("{}", e),
        }
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'c');
    }

    #[test]
    fn serial_input_snapshot_restore() {
        let intr_evt = Event::new().unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new(
            ProtectionType::Unprotected,
            intr_evt.try_clone().unwrap(),
            None,
            Some(Box::new(serial_out)),
            None,
            Default::default(),
            Vec::new(),
        );

        serial.write(serial_bus_address(IER), &[IER_RECV_BIT]);
        serial.queue_input_bytes(&[b'a', b'b', b'c']).unwrap();

        assert_eq!(intr_evt.wait(), Ok(()));
        let mut data = [0u8; 1];
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'a');
        // Take snapshot after reading b'a'. Serial still contains b'b' and b'c'.
        let snap = serial.snapshot().expect("failed to snapshot serial");
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
        // Restore snapshot taken after reading b'a'. New reading should give us b'b' since it was
        // the saved state at the moment of taking a snapshot.
        let restore_res = serial.restore(snap);
        match restore_res {
            Ok(()) => (),
            Err(e) => println!("Error: {}", e),
        }
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'c');
    }

    #[test]
    fn serial_input_snapshot_write_restore() {
        let intr_evt = Event::new().unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new(
            ProtectionType::Unprotected,
            intr_evt.try_clone().unwrap(),
            None,
            Some(Box::new(serial_out)),
            None,
            Default::default(),
            Vec::new(),
        );

        serial.write(serial_bus_address(IER), &[IER_RECV_BIT]);
        serial.queue_input_bytes(&[b'a', b'b', b'c']).unwrap();

        assert_eq!(intr_evt.wait(), Ok(()));
        let mut data = [0u8; 1];
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'a');
        // Take snapshot after reading b'a'. Serial still contains b'b' and b'c'.
        let snap = serial.snapshot().expect("failed to snapshot serial");
        serial.clear_in_buffer();
        serial.queue_input_bytes(&[b'a', b'b', b'c']).unwrap();
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'a');
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'c');
        // Restore snapshot taken after reading b'a'. New reading should give us b'b' since it was
        // the saved state at the moment of taking a snapshot.
        let restore_res = serial.restore(snap);
        match restore_res {
            Ok(()) => (),
            Err(e) => println!("Error: {}", e),
        }
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'c');
    }

    // Test should panic. Sleep, try to read while sleeping.
    #[test]
    #[should_panic]
    fn serial_input_sleep_read_panic() {
        let intr_evt = Event::new().unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new(
            ProtectionType::Unprotected,
            intr_evt.try_clone().unwrap(),
            None,
            Some(Box::new(serial_out)),
            None,
            Default::default(),
            Vec::new(),
        );

        serial.write(serial_bus_address(IER), &[IER_RECV_BIT]);
        serial.queue_input_bytes(&[b'a', b'b', b'c']).unwrap();

        assert_eq!(intr_evt.wait(), Ok(()));
        let mut data = [0u8; 1];
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'a');
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
        let sleep_res = serial.sleep();
        match sleep_res {
            Ok(_res) => (),
            Err(e) => println!("{}", e),
        }
        // Test should panic when trying to read after sleep.
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
    }

    // Test should panic. Sleep, try to read while sleeping.
    #[test]
    #[should_panic]
    fn serial_input_sleep_write_panic() {
        let intr_evt = Event::new().unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new(
            ProtectionType::Unprotected,
            intr_evt.try_clone().unwrap(),
            None,
            Some(Box::new(serial_out)),
            None,
            Default::default(),
            Vec::new(),
        );

        let sleep_res = serial.sleep();
        match sleep_res {
            Ok(_res) => (),
            Err(e) => println!("{}", e),
        }
        // Test should panic when trying to read after sleep.
        serial.write(serial_bus_address(IER), &[IER_RECV_BIT]);
    }

    #[test]
    fn serial_input_sleep_wake() {
        let intr_evt = Event::new().unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new(
            ProtectionType::Unprotected,
            intr_evt.try_clone().unwrap(),
            None,
            Some(Box::new(serial_out)),
            None,
            Default::default(),
            Vec::new(),
        );

        serial.write(serial_bus_address(IER), &[IER_RECV_BIT]);
        serial.queue_input_bytes(&[b'a', b'b', b'c']).unwrap();

        assert_eq!(intr_evt.wait(), Ok(()));
        let mut data = [0u8; 1];
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'a');
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
        let sleep_res = serial.sleep();
        match sleep_res {
            Ok(_res) => (),
            Err(e) => println!("{}", e),
        }
        let wake_res = serial.wake();
        match wake_res {
            Ok(_res) => (),
            Err(e) => println!("{}", e),
        }
        serial.read(serial_bus_address(DATA), &mut data[..]);
        assert_eq!(data[0], b'c');
    }

    fn modify_device(serial: &mut Serial) {
        serial.clear_in_buffer();
        serial.queue_input_bytes(&[b'a', b'b', b'c']).unwrap();
    }

    suspendable_tests!(
        serial,
        Serial::new(
            ProtectionType::Unprotected,
            Event::new().unwrap(),
            None,
            Some(Box::new(SharedBuffer::new())),
            None,
            Default::default(),
            Vec::new(),
        ),
        modify_device
    );

    fn assert_timestamp_is_present(data: &[u8], serial_message: &str) {
        const TIMESTAMP_START: &str = "[";
        const TIMESTAMP_END: &str = "]: ";

        let data_str = std::str::from_utf8(data).unwrap();
        let timestamp_bracket = data_str
            .find(TIMESTAMP_END)
            .expect("missing timestamp end bracket");
        let (timestamp, message) = data_str.split_at(timestamp_bracket + TIMESTAMP_END.len());

        assert!(timestamp.starts_with(TIMESTAMP_START));
        assert!(timestamp.ends_with(TIMESTAMP_END));

        assert_eq!(message.trim_end(), serial_message);
    }

    #[test]
    fn serial_output_timestamp() {
        let intr_evt = Event::new().unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new(
            ProtectionType::Unprotected,
            intr_evt,
            None,
            Some(Box::new(serial_out.clone())),
            None,
            SerialOptions {
                out_timestamp: true,
                ..Default::default()
            },
            Vec::new(),
        );

        serial.write(serial_bus_address(DATA), &[b'a']);
        serial.write(serial_bus_address(DATA), &[b'\n']);
        assert_timestamp_is_present(serial_out.buf.lock().as_slice(), "a");
        serial_out.buf.lock().clear();

        serial.write(serial_bus_address(DATA), &[b'b']);
        serial.write(serial_bus_address(DATA), &[b'\n']);
        assert_timestamp_is_present(serial_out.buf.lock().as_slice(), "b");
        serial_out.buf.lock().clear();

        serial.write(serial_bus_address(DATA), &[b'c']);
        serial.write(serial_bus_address(DATA), &[b'\n']);
        assert_timestamp_is_present(serial_out.buf.lock().as_slice(), "c");
        serial_out.buf.lock().clear();
    }
}
