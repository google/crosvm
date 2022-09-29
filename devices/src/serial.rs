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
use std::thread;

use base::error;
use base::Event;
use base::Result;

use crate::bus::BusAccessInfo;
use crate::pci::CrosvmDeviceId;
use crate::serial_device::SerialInput;
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
    #[cfg(windows)]
    pub system_params: sys::windows::SystemSerialParams,
}

impl Serial {
    fn new_common(
        interrupt_evt: Event,
        input: Option<Box<dyn SerialInput>>,
        out: Option<Box<dyn io::Write + Send>>,
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
            #[cfg(windows)]
            system_params,
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

        // The input thread runs in detached mode and will exit when channel is disconnected because
        // the serial device has been dropped. Initial versions of this kept a `JoinHandle` and had
        // the drop implementation of serial join on this thread, but the input thread can block
        // indefinitely depending on the `Box<io::Read>` implementation.
        let res = thread::Builder::new()
            .name(format!("{} input thread", self.debug_label()))
            .spawn(move || {
                let mut rx_buf = [0u8; 1];
                loop {
                    match rx.read(&mut rx_buf) {
                        Ok(0) => break, // Assume the stream of input has ended.
                        Ok(_) => {
                            if send_channel.send(rx_buf[0]).is_err() {
                                // The receiver has disconnected.
                                break;
                            }
                            if (interrupt_enable.load(Ordering::SeqCst) & IER_RECV_BIT) != 0 {
                                interrupt_evt.signal().unwrap();
                            }
                        }
                        Err(e) => {
                            // Being interrupted is not an error, but everything else is.
                            if e.kind() != io::ErrorKind::Interrupted {
                                error!(
                                    "failed to read for bytes to queue into serial device: {}",
                                    e
                                );
                                break;
                            }
                        }
                    }
                }
            });
        if let Err(e) = res {
            error!("failed to spawn input thread: {}", e);
            return;
        }
        self.in_channel = Some(recv_channel);
    }

    fn handle_input_thread(&mut self) {
        if self.input.is_some() {
            self.spawn_input_thread();
        }

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

    fn iir_reset(&mut self) {
        self.interrupt_identification = DEFAULT_INTERRUPT_IDENTIFICATION;
    }

    fn handle_write(&mut self, offset: u8, v: u8) -> Result<()> {
        match offset as u8 {
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
                    self.system_handle_write(v)?;
                    self.trigger_thr_empty()?;
                }
            }
            IER => self
                .interrupt_enable
                .store(v & IER_FIFO_BITS, Ordering::SeqCst),
            LCR => self.line_control = v,
            MCR => self.modem_control = v,
            SCR => self.scratch = v,
            _ => {}
        }
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
        if data.len() != 1 {
            return;
        }

        self.handle_input_thread();

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

impl Suspendable for Serial {}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use hypervisor::ProtectionType;
    use sync::Mutex;

    use super::*;
    pub use crate::sys::serial_device::SerialDevice;

    #[derive(Clone)]
    pub(super) struct SharedBuffer {
        pub(super) buf: Arc<Mutex<Vec<u8>>>,
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
            false,
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
            false,
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
}
