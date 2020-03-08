// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, stdin, stdout, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::Arc;
use std::thread::{self};

use sys_util::{error, read_raw_stdin, syslog, EventFd, Result};

use crate::BusDevice;

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

#[derive(Debug)]
pub enum Error {
    CloneEventFd(sys_util::Error),
    InvalidSerialType(String),
    PathRequired,
    FileError(std::io::Error),
    Unimplemented(SerialType),
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            CloneEventFd(e) => write!(f, "unable to clone an EventFd: {}", e),
            FileError(e) => write!(f, "Unable to open/create file: {}", e),
            InvalidSerialType(e) => write!(f, "invalid serial type: {}", e),
            PathRequired => write!(f, "serial device type file requires a path"),
            Unimplemented(e) => write!(f, "serial device type {} not implemented", e.to_string()),
        }
    }
}

/// Enum for possible type of serial devices
#[derive(Debug)]
pub enum SerialType {
    File,
    Stdout,
    Sink,
    Syslog,
    UnixSocket, // NOT IMPLEMENTED
}

impl Display for SerialType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match &self {
            SerialType::File => "File".to_string(),
            SerialType::Stdout => "Stdout".to_string(),
            SerialType::Sink => "Sink".to_string(),
            SerialType::Syslog => "Syslog".to_string(),
            SerialType::UnixSocket => "UnixSocket".to_string(),
        };

        write!(f, "{}", s)
    }
}

impl FromStr for SerialType {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "file" | "File" => Ok(SerialType::File),
            "stdout" | "Stdout" => Ok(SerialType::Stdout),
            "sink" | "Sink" => Ok(SerialType::Sink),
            "syslog" | "Syslog" => Ok(SerialType::Syslog),
            "unix" | "UnixSocket" => Ok(SerialType::UnixSocket),
            _ => Err(Error::InvalidSerialType(s.to_string())),
        }
    }
}

/// Holds the parameters for a serial device
#[derive(Debug)]
pub struct SerialParameters {
    pub type_: SerialType,
    pub path: Option<PathBuf>,
    pub num: u8,
    pub console: bool,
    pub stdin: bool,
}

impl SerialParameters {
    /// Helper function to create a serial device from the defined parameters.
    ///
    /// # Arguments
    /// * `evt_fd` - eventfd used for interrupt events
    /// * `keep_fds` - Vector of FDs required by this device if it were sandboxed in a child
    ///                process. `evt_fd` will always be added to this vector by this function.
    pub fn create_serial_device(
        &self,
        evt_fd: &EventFd,
        keep_fds: &mut Vec<RawFd>,
    ) -> std::result::Result<Serial, Error> {
        let evt_fd = evt_fd.try_clone().map_err(Error::CloneEventFd)?;
        keep_fds.push(evt_fd.as_raw_fd());
        let input: Option<Box<dyn io::Read + Send>> = if self.stdin {
            keep_fds.push(stdin().as_raw_fd());
            // This wrapper is used in place of the libstd native version because we don't want
            // buffering for stdin.
            struct StdinWrapper;
            impl io::Read for StdinWrapper {
                fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                    read_raw_stdin(out).map_err(|e| e.into())
                }
            }
            Some(Box::new(StdinWrapper))
        } else {
            None
        };
        match self.type_ {
            SerialType::Stdout => {
                keep_fds.push(stdout().as_raw_fd());
                Ok(Serial::new(evt_fd, input, Some(Box::new(stdout()))))
            }
            SerialType::Sink => Ok(Serial::new(evt_fd, input, None)),
            SerialType::Syslog => {
                syslog::push_fds(keep_fds);
                Ok(Serial::new(
                    evt_fd,
                    input,
                    Some(Box::new(syslog::Syslogger::new(
                        syslog::Priority::Info,
                        syslog::Facility::Daemon,
                    ))),
                ))
            }
            SerialType::File => match &self.path {
                None => Err(Error::PathRequired),
                Some(path) => {
                    let file = File::create(path.as_path()).map_err(Error::FileError)?;
                    keep_fds.push(file.as_raw_fd());
                    Ok(Serial::new(evt_fd, input, Some(Box::new(file))))
                }
            },
            SerialType::UnixSocket => Err(Error::Unimplemented(SerialType::UnixSocket)),
        }
    }
}

// Structure for holding the default configuration of the serial devices.
pub const DEFAULT_SERIAL_PARAMS: [SerialParameters; 4] = [
    SerialParameters {
        type_: SerialType::Stdout,
        path: None,
        num: 1,
        console: true,
        stdin: true,
    },
    SerialParameters {
        type_: SerialType::Sink,
        path: None,
        num: 2,
        console: false,
        stdin: false,
    },
    SerialParameters {
        type_: SerialType::Sink,
        path: None,
        num: 3,
        console: false,
        stdin: false,
    },
    SerialParameters {
        type_: SerialType::Sink,
        path: None,
        num: 4,
        console: false,
        stdin: false,
    },
];

/// Address for Serial ports in x86
pub const SERIAL_ADDR: [u64; 4] = [0x3f8, 0x2f8, 0x3e8, 0x2e8];

/// String representations of serial devices
pub const SERIAL_TTY_STRINGS: [&str; 4] = ["ttyS0", "ttyS1", "ttyS2", "ttyS3"];

/// Helper function to get the tty string of a serial device based on the port number. Will default
///  to ttyS0 if an invalid number is given.
pub fn get_serial_tty_string(stdio_serial_num: u8) -> String {
    match stdio_serial_num {
        1 => SERIAL_TTY_STRINGS[0].to_string(),
        2 => SERIAL_TTY_STRINGS[1].to_string(),
        3 => SERIAL_TTY_STRINGS[2].to_string(),
        4 => SERIAL_TTY_STRINGS[3].to_string(),
        _ => SERIAL_TTY_STRINGS[0].to_string(),
    }
}

/// Emulates serial COM ports commonly seen on x86 I/O ports 0x3f8/0x2f8/0x3e8/0x2e8.
///
/// This can optionally write the guest's output to a Write trait object. To send input to the
/// guest, use `queue_input_bytes` directly, or give a Read trait object which will be used queue
/// bytes when `used_command` is called.
pub struct Serial {
    // Serial port registers
    interrupt_enable: Arc<AtomicU8>,
    interrupt_identification: u8,
    interrupt_evt: EventFd,
    line_control: u8,
    line_status: u8,
    modem_control: u8,
    modem_status: u8,
    scratch: u8,
    baud_divisor: u16,

    // Host input/output
    in_buffer: VecDeque<u8>,
    in_channel: Option<Receiver<u8>>,
    input: Option<Box<dyn io::Read + Send>>,
    out: Option<Box<dyn io::Write + Send>>,
}

impl Serial {
    fn new(
        interrupt_evt: EventFd,
        input: Option<Box<dyn io::Read + Send>>,
        out: Option<Box<dyn io::Write + Send>>,
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
        }
    }

    /// Constructs a Serial port ready for input and output.
    ///
    /// The stream `input` should not block, instead returning 0 bytes if are no bytes available.
    pub fn new_in_out(
        interrupt_evt: EventFd,
        input: Box<dyn io::Read + Send>,
        out: Box<dyn io::Write + Send>,
    ) -> Serial {
        Self::new(interrupt_evt, Some(input), Some(out))
    }

    /// Constructs a Serial port ready for output but not input.
    pub fn new_out(interrupt_evt: EventFd, out: Box<dyn io::Write + Send>) -> Serial {
        Self::new(interrupt_evt, None, Some(out))
    }

    /// Constructs a Serial port with no connected input or output.
    pub fn new_sink(interrupt_evt: EventFd) -> Serial {
        Self::new(interrupt_evt, None, None)
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
                error!("failed to clone interrupt eventfd: {}", e);
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
                                interrupt_evt.write(1).unwrap();
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

    /// Gets the interrupt eventfd used to interrupt the driver when it needs to respond to this
    /// device.
    pub fn interrupt_eventfd(&self) -> &EventFd {
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
        self.interrupt_evt.write(1)
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
                    if let Some(out) = self.out.as_mut() {
                        out.write_all(&[v])?;
                        out.flush()?;
                    }
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
    fn debug_label(&self) -> String {
        "serial".to_owned()
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            return;
        }

        if let Err(e) = self.handle_write(offset as u8, data[0]) {
            error!("serial failed write: {}", e);
        }
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }

        self.handle_input_thread();

        data[0] = match offset as u8 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Arc;

    use sync::Mutex;

    #[derive(Clone)]
    struct SharedBuffer {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedBuffer {
        fn new() -> SharedBuffer {
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

    #[test]
    fn serial_output() {
        let intr_evt = EventFd::new().unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new_out(intr_evt, Box::new(serial_out.clone()));

        serial.write(DATA as u64, &['a' as u8]);
        serial.write(DATA as u64, &['b' as u8]);
        serial.write(DATA as u64, &['c' as u8]);
        assert_eq!(
            serial_out.buf.lock().as_slice(),
            &['a' as u8, 'b' as u8, 'c' as u8]
        );
    }

    #[test]
    fn serial_input() {
        let intr_evt = EventFd::new().unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial =
            Serial::new_out(intr_evt.try_clone().unwrap(), Box::new(serial_out.clone()));

        serial.write(IER as u64, &[IER_RECV_BIT]);
        serial
            .queue_input_bytes(&['a' as u8, 'b' as u8, 'c' as u8])
            .unwrap();

        assert_eq!(intr_evt.read(), Ok(1));
        let mut data = [0u8; 1];
        serial.read(DATA as u64, &mut data[..]);
        assert_eq!(data[0], 'a' as u8);
        serial.read(DATA as u64, &mut data[..]);
        assert_eq!(data[0], 'b' as u8);
        serial.read(DATA as u64, &mut data[..]);
        assert_eq!(data[0], 'c' as u8);
    }
}
