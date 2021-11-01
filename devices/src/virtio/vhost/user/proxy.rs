// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the "Vhost User" Virtio device as specified here -
//! <https://stefanha.github.io/virtio/vhost-user-slave.html#x1-2830007>. The
//! device implements the Virtio-Vhost-User protocol. It acts as a proxy between
//! the Vhost-user Master (referred to as the `Vhost-user sibling` in this
//! module) running in a sibling VM's VMM and Virtio-Vhost-User Slave
//! implementation (referred to as `device backend` in this module) in the
//! device VM.

use std::fs::File;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::thread;

use base::{error, info, AsRawDescriptor, Event, EventType, PollToken, RawDescriptor, WaitContext};
use data_model::{DataInit, Le32};
use libc::{recv, MSG_DONTWAIT, MSG_PEEK};
use resources::Alloc;
use vm_memory::GuestMemory;
use vmm_vhost::{
    connection::socket::Endpoint as SocketEndpoint,
    connection::EndpointExt,
    message::{MasterReq, VhostUserMsgHeader},
    Protocol, SlaveReqHelper,
};

use crate::pci::{
    PciBarConfiguration, PciBarIndex, PciBarPrefetchable, PciBarRegionType, PciCapability,
    PciCapabilityID,
};
use crate::virtio::descriptor_utils::Error as DescriptorUtilsError;
use crate::virtio::{
    copy_config, DescriptorChain, Interrupt, PciCapabilityType, Queue, Reader, VirtioDevice,
    VirtioPciCap, Writer, TYPE_VHOST_USER,
};
use crate::PciAddress;

use remain::sorted;
use thiserror::Error as ThisError;
use vmm_vhost::Error as VhostError;

// Note: There are two sets of queues that will be mentioned here. 1st set is
// for this Virtio PCI device itself. 2nd set is the actual device backends
// which are set up via Virtio Vhost User (a protocol whose messages are
// forwarded by this device) such as block, net, etc..
//
// The queue configuration about any device backends this proxy may support.
const MAX_VHOST_DEVICE_QUEUES: usize = 16;

// Proxy device i.e. this device's configuration.
const NUM_PROXY_DEVICE_QUEUES: usize = 2;
const PROXY_DEVICE_QUEUE_SIZE: u16 = 256;
const PROXY_DEVICE_QUEUE_SIZES: &[u16] = &[PROXY_DEVICE_QUEUE_SIZE; NUM_PROXY_DEVICE_QUEUES];
const BAR_INDEX: u8 = 2;
// Bar size represents the amount of memory to be mapped for a sibling VM. Each
// Virtio Vhost User Slave implementation requires access to the entire sibling
// memory. It's assumed that sibling VM memory would be <= 8GB, hence this
// constant value.
//
// TODO(abhishekbh): Understand why shared memory region size and overall bar
// size differ in the QEMU implementation. The metadata required to map sibling
// memory is about 16 MB per GB of sibling memory per device. Therefore, it is
// in our interest to not waste space here and correlate it tightly to the
// actual maximum memory a sibling VM can have.
const BAR_SIZE: u64 = 1 << 33;
const CONFIG_UUID_SIZE: usize = 16;
const VIRTIO_VHOST_USER_STATUS_SLAVE_UP: u8 = 0;

// Bar configuration.
// All offsets are from the starting of bar `BAR_INDEX`.
const DOORBELL_OFFSET: u64 = 0;
// TODO(abhishekbh): Copied from lspci in qemu with VVU support.
const DOORBELL_SIZE: u64 = 0x2000;
const NOTIFICATIONS_OFFSET: u64 = DOORBELL_OFFSET + DOORBELL_SIZE;
const NOTIFICATIONS_SIZE: u64 = 0x1000;
const SHARED_MEMORY_OFFSET: u64 = NOTIFICATIONS_OFFSET + NOTIFICATIONS_SIZE;
// TODO(abhishekbh): Copied from qemu with VVU support. This should be same as
// `BAR_SIZE` but it's significantly lower than the memory allocated to a
// sibling VM. Figure out how these two are related.
const SHARED_MEMORY_SIZE: u64 = 0x1000;

// Notifications region related constants.
const NOTIFICATIONS_VRING_SELECT_OFFSET: u64 = 0;
const NOTIFICATIONS_MSIX_VECTOR_SELECT_OFFSET: u64 = 2;

// Capabilities related configuration.
//
// Values written in the Doorbell must be within 32 bit i.e. a write to offset 0
// to 3 represents a Vring 0 related event, a write to offset 4 to 7 represents
// a Vring 1 related event.
const DOORBELL_OFFSET_MULTIPLIER: u32 = 4;

// Vhost-user sibling message types that require extra processing by this proxy. All
// other messages are passed through to the device backend.
const SIBLING_ACTION_MESSAGE_TYPES: &[MasterReq] = &[
    MasterReq::SET_MEM_TABLE,
    MasterReq::SET_LOG_BASE,
    MasterReq::SET_LOG_FD,
    MasterReq::SET_VRING_KICK,
    MasterReq::SET_VRING_CALL,
    MasterReq::SET_VRING_ERR,
    MasterReq::SET_SLAVE_REQ_FD,
    MasterReq::SET_INFLIGHT_FD,
];

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// Failed to accept connection on a socket.
    #[error("failed to accept connection on a socket: {0}")]
    AcceptConnection(std::io::Error),
    /// Failed to create a listener.
    #[error("failed to create a listener: {0}")]
    CreateListener(std::io::Error),
    /// Failed to create a wait context object.
    #[error("failed to create a wait context object: {0}")]
    CreateWaitContext(base::Error),
    /// Failed to create a Writer object.
    #[error("failed to create a Writer")]
    CreateWriter,
    /// Failed to send ACK in response to Vhost-user sibling message.
    #[error("Failed to send Ack: {0}")]
    FailedAck(VhostError),
    /// Invalid Vhost-user sibling message.
    #[error("invalid Vhost-user sibling message")]
    InvalidSiblingMessage,
    /// Failed to read payload of a Vhost-user sibling header.
    #[error("failed to read Vhost-user sibling message header: {0}")]
    ReadSiblingHeader(VhostError),
    /// Failed to read payload of a Vhost-user sibling message.
    #[error("failed to read Vhost-user sibling message payload: {0}")]
    ReadSiblingPayload(VhostError),
    /// Rx buffer too small to accomodate data.
    #[error("rx buffer too small")]
    RxBufferTooSmall,
    /// There are no more available descriptors to receive into.
    #[error("no rx descriptors available")]
    RxDescriptorsExhausted,
    /// Removing read event from the sibling VM socket events failed.
    #[error("failed to disable EPOLLIN on sibling VM socket fd: {0}")]
    WaitContextDisableSiblingVmSocket(base::Error),
    /// Adding read event to the sibling VM socket events failed.
    #[error("failed to enable EPOLLIN on sibling VM socket fd: {0}")]
    WaitContextEnableSiblingVmSocket(base::Error),
    /// Failed to wait for events.
    #[error("failed to wait for events: {0}")]
    WaitError(base::Error),
    /// Writing to a buffer in the guest failed.
    #[error("failed to write to guest buffer: {0}")]
    WriteBuffer(std::io::Error),
    /// Failed to create a Writer.
    #[error("failed to create a Writer: {0}")]
    WriterCreation(DescriptorUtilsError),
}

pub type Result<T> = std::result::Result<T, Error>;

// Device configuration as per section 5.7.4.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct VirtioVhostUserConfig {
    status: Le32,
    max_vhost_queues: Le32,
    uuid: [u8; CONFIG_UUID_SIZE],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioVhostUserConfig {}

impl Default for VirtioVhostUserConfig {
    fn default() -> Self {
        VirtioVhostUserConfig {
            status: Le32::from(0),
            max_vhost_queues: Le32::from(MAX_VHOST_DEVICE_QUEUES as u32),
            uuid: [0; CONFIG_UUID_SIZE],
        }
    }
}

impl VirtioVhostUserConfig {
    fn is_slave_up(&mut self) -> bool {
        self.check_status_bit(VIRTIO_VHOST_USER_STATUS_SLAVE_UP)
    }

    fn check_status_bit(&mut self, bit: u8) -> bool {
        let status = self.status.to_native();
        status & (1 << bit) > 0
    }
}

// Checks if the message requires any extra processing by this proxy.
fn is_action_request(hdr: &VhostUserMsgHeader<MasterReq>) -> bool {
    SIBLING_ACTION_MESSAGE_TYPES
        .iter()
        .any(|&h| h == hdr.get_code())
}

// Checks if |files| are sent by the Vhost-user sibling only for specific messages.
fn check_attached_files(
    hdr: &VhostUserMsgHeader<MasterReq>,
    files: &Option<Vec<File>>,
) -> Result<()> {
    match hdr.get_code() {
        MasterReq::SET_MEM_TABLE
        | MasterReq::SET_VRING_CALL
        | MasterReq::SET_VRING_KICK
        | MasterReq::SET_VRING_ERR
        | MasterReq::SET_LOG_BASE
        | MasterReq::SET_LOG_FD
        | MasterReq::SET_SLAVE_REQ_FD
        | MasterReq::SET_INFLIGHT_FD
        | MasterReq::ADD_MEM_REG => {
            // These messages are always associated with an fd.
            if files.is_some() {
                Ok(())
            } else {
                Err(Error::InvalidSiblingMessage)
            }
        }
        _ if files.is_some() => Err(Error::InvalidSiblingMessage),
        _ => Ok(()),
    }
}

// Processes messages from the Vhost-user sibling and sends it to the device backend and
// vice-versa.
struct Worker {
    mem: GuestMemory,
    interrupt: Interrupt,
    rx_queue: Queue,
    tx_queue: Queue,

    // Helper to receive and parse messages from the Vhost-user sibling.
    slave_req_helper: SlaveReqHelper<SocketEndpoint<MasterReq>>,
}

impl Worker {
    fn run(&mut self, rx_queue_evt: Event, tx_queue_evt: Event, kill_evt: Event) -> Result<()> {
        #[derive(PollToken, Debug, Clone)]
        pub enum Token {
            // Data is available on the Vhost-user sibling socket.
            SiblingSocket,
            // The device backend has made a read buffer available.
            RxQueue,
            // The device backend has sent a buffer to the `Worker::tx_queue`.
            TxQueue,
            // crosvm has requested the device to shut down.
            Kill,
        }

        // TODO(abhishekbh): Should interrupt.signal_config_changed be called here ?.
        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (&self.slave_req_helper, Token::SiblingSocket),
            (&rx_queue_evt, Token::RxQueue),
            (&tx_queue_evt, Token::TxQueue),
            (&kill_evt, Token::Kill),
        ])
        .map_err(Error::CreateWaitContext)?;

        // Represents if |slave_req_helper.endpoint| is being monitored for data
        // from the Vhost-user sibling.
        let mut sibling_socket_polling_enabled = true;
        'wait: loop {
            let events = wait_ctx.wait().map_err(Error::WaitError)?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::SiblingSocket => match self.process_rx() {
                        Ok(()) => {}
                        Err(Error::RxDescriptorsExhausted) => {
                            // If the driver has no Rx buffers left, then no
                            // point monitoring the Vhost-user sibling for data. There
                            // would be no way to send it to the device backend.
                            wait_ctx
                                .modify(
                                    &self.slave_req_helper,
                                    EventType::None,
                                    Token::SiblingSocket,
                                )
                                .map_err(Error::WaitContextDisableSiblingVmSocket)?;
                            sibling_socket_polling_enabled = false;
                        }
                        Err(e) => return Err(e),
                    },
                    Token::RxQueue => {
                        if let Err(e) = rx_queue_evt.read() {
                            error!("error reading rx queue Event: {}", e);
                            break 'wait;
                        }

                        // Rx buffers are available, now we should monitor the
                        // Vhost-user sibling connection for data.
                        if !sibling_socket_polling_enabled {
                            wait_ctx
                                .modify(
                                    &self.slave_req_helper,
                                    EventType::Read,
                                    Token::SiblingSocket,
                                )
                                .map_err(Error::WaitContextEnableSiblingVmSocket)?;
                            sibling_socket_polling_enabled = true;
                        }
                    }
                    Token::TxQueue => {
                        if let Err(e) = tx_queue_evt.read() {
                            error!("error reading tx queue event: {}", e);
                            break 'wait;
                        }
                        self.process_tx();
                    }
                    Token::Kill => {
                        let _ = kill_evt.read();
                        break 'wait;
                    }
                }
            }
        }
        Ok(())
    }

    // Processes data from the Vhost-user sibling and forward to the driver via Rx buffers.
    fn process_rx(&mut self) -> Result<()> {
        // Keep looping until -
        // - No more Rx buffers are available on the Rx queue. OR
        // - No more data is available on the Vhost-user sibling socket (checked via a
        //   peek).
        //
        // If a Rx buffer is available and if data is present on the Vhost
        // master socket then -
        // - Parse the Vhost-user sibling message. If it's not an action type message
        //   then copy the message as is to the Rx buffer and forward it to the
        //   device backend.
        let mut exhausted_queue = false;
        // Peek if any data is left on the Vhost-user sibling socket. If no, then
        // nothing to forwad to the device backend.
        while self.is_sibling_data_available() {
            if let Some(desc) = self.rx_queue.peek(&self.mem) {
                // To successfully receive attached file descriptors, we need to
                // receive messages and corresponding attached file descriptors in
                // this way:
                // - receive messsage header and optional attached files.
                // - receive optional message body and payload according size field
                //   in message header.
                // - forward it to the device backend.
                let (hdr, files) = self
                    .slave_req_helper
                    .as_mut()
                    .recv_header()
                    .map_err(Error::ReadSiblingHeader)?;
                check_attached_files(&hdr, &files)?;
                let buf = self.get_sibling_msg_data(&hdr)?;

                let index = desc.index;
                let bytes_written = {
                    if is_action_request(&hdr) {
                        // TODO(abhishekbh): Implement action messages.
                        unimplemented!()
                    } else {
                        // If no special processing is required. Forward this
                        // message as is to the device backend.
                        self.forward_msg_to_device(desc, &hdr, &buf)
                    }
                };

                // If some bytes were written to the virt queue, now it's time
                // to add a used buffer and notify the guest. Else if there was
                // an error of any sort, we notify the sibling by sending an ACK
                // with failure.
                match bytes_written {
                    Ok(bytes_written) => {
                        // The driver is able to deal with a descriptor with 0 bytes written.
                        self.rx_queue.pop_peeked(&self.mem);
                        self.rx_queue.add_used(&self.mem, index, bytes_written);
                        if !self.rx_queue.trigger_interrupt(&self.mem, &self.interrupt) {
                            // This interrupt should always be injected. We'd rather fail fast
                            // if there is an error.
                            panic!("failed to send interrupt");
                        }
                    }
                    Err(_) => {
                        self.slave_req_helper
                            .send_ack_message(&hdr, false)
                            .map_err(Error::FailedAck)?;
                    }
                }
            } else {
                // No buffer left to fill up. No point processing any data
                // from the Vhost-user sibling.
                exhausted_queue = true;
                break;
            }
        }

        if exhausted_queue {
            Err(Error::RxDescriptorsExhausted)
        } else {
            info!("no more data available on the sibling socket");
            Ok(())
        }
    }

    // Returns true iff any data is available on the Vhost-user sibling socket.
    fn is_sibling_data_available(&mut self) -> bool {
        // Peek if any data is left on the Vhost-user sibling socket. If no, then
        // nothing to forwad to the device backend.
        let mut peek_buf = [0; 1];
        let raw_fd = self.slave_req_helper.as_raw_fd();
        // Safe because `raw_fd` and `peek_buf` are owned by this struct.
        let peek_ret = unsafe {
            recv(
                raw_fd,
                peek_buf.as_mut_ptr() as *mut libc::c_void,
                peek_buf.len(),
                MSG_PEEK | MSG_DONTWAIT,
            )
        };

        // TODO(abhishekbh): Should we log on < 0 ?. Peek should
        // succeed.
        peek_ret > 0
    }

    // Returns any data attached to a Vhost-user sibling message.
    fn get_sibling_msg_data(&mut self, hdr: &VhostUserMsgHeader<MasterReq>) -> Result<Vec<u8>> {
        let buf = match hdr.get_size() {
            0 => vec![0u8; 0],
            len => {
                let rbuf = self
                    .slave_req_helper
                    .as_mut()
                    .recv_data(len as usize)
                    .map_err(Error::ReadSiblingPayload)?;
                if rbuf.len() != len as usize {
                    self.slave_req_helper
                        .send_ack_message(hdr, false)
                        .map_err(Error::FailedAck)?;
                    return Err(Error::InvalidSiblingMessage);
                }
                rbuf
            }
        };
        Ok(buf)
    }

    // Forwards |hdr, buf| to the device backend via |desc_chain| in the virtio
    // queue. Returns the number of bytes written to the virt queue.
    fn forward_msg_to_device(
        &mut self,
        desc_chain: DescriptorChain,
        hdr: &VhostUserMsgHeader<MasterReq>,
        buf: &[u8],
    ) -> Result<u32> {
        let bytes_written = match Writer::new(self.mem.clone(), desc_chain) {
            Ok(mut writer) => {
                if writer.available_bytes()
                    < buf.len() + std::mem::size_of::<VhostUserMsgHeader<MasterReq>>()
                {
                    error!("rx buffer too small to accomodate server data");
                    return Err(Error::RxBufferTooSmall);
                }
                // Write header first then any data. Do these separately to prevent any reorders.
                let mut written = writer.write(hdr.as_slice()).map_err(Error::WriteBuffer)?;
                written += writer.write(buf).map_err(Error::WriteBuffer)?;
                written as u32
            }
            Err(e) => {
                error!("failed to create Writer: {}", e);
                return Err(Error::CreateWriter);
            }
        };
        Ok(bytes_written)
    }

    // Processes data from the device backend (via virtio Tx queue) and forward it to
    // the Vhost-user sibling over its socket connection.
    fn process_tx(&mut self) {
        while let Some(desc_chain) = self.tx_queue.pop(&self.mem) {
            let index = desc_chain.index;
            match Reader::new(self.mem.clone(), desc_chain) {
                Ok(mut reader) => {
                    let expected_count = reader.available_bytes();
                    match reader.read_to(self.slave_req_helper.as_mut().as_mut(), expected_count) {
                        Ok(count) => {
                            // The |reader| guarantees that all the available data is read.
                            if count != expected_count {
                                error!("wrote only {} bytes of {}", count, expected_count);
                            }
                        }
                        Err(e) => error!("failed to write message to vhost-vmm: {}", e),
                    }
                }
                Err(e) => error!("failed to create Reader: {}", e),
            }
            self.tx_queue.add_used(&self.mem, index, 0);
            if !self.tx_queue.trigger_interrupt(&self.mem, &self.interrupt) {
                panic!("failed inject tx queue interrupt");
            }
        }
    }
}

// Doorbell capability of the proxy device.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtioPciDoorbellCap {
    cap: VirtioPciCap,
    doorbell_off_multiplier: Le32,
}
// It is safe to implement DataInit; `VirtioPciCap` implements DataInit and for
// Le32 any value is valid.
unsafe impl DataInit for VirtioPciDoorbellCap {}

impl PciCapability for VirtioPciDoorbellCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    // TODO: What should this be.
    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::VendorSpecific
    }

    // TODO: What should this be.
    fn writable_bits(&self) -> Vec<u32> {
        vec![0u32; 4]
    }
}

impl VirtioPciDoorbellCap {
    pub fn new(cap: VirtioPciCap, doorbell_off_multiplier: u32) -> Self {
        VirtioPciDoorbellCap {
            cap,
            doorbell_off_multiplier: Le32::from(doorbell_off_multiplier),
        }
    }
}

// Used to store parameters passed in the |activate| function.
struct ActivateParams {
    mem: GuestMemory,
    interrupt: Interrupt,
    queues: Vec<Queue>,
    queue_evts: Vec<Event>,
}

pub struct VirtioVhostUser {
    base_features: u64,

    // Bound socket waiting to accept a socket connection from the Vhost-user
    // sibling.
    listener: UnixListener,

    // Device configuration.
    config: VirtioVhostUserConfig,
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    pci_bar: Option<Alloc>,
    // The device backend queue index selected by the driver by writing to the
    // Notifications region at offset `NOTIFICATIONS_MSIX_VECTOR_SELECT_OFFSET`
    // in the bar. This points into `notification_msix_vectors`.
    notification_select: Option<u16>,
    // Stores msix vectors corresponding to each device backend queue.
    notification_msix_vectors: [Option<u16>; MAX_VHOST_DEVICE_QUEUES],

    // Cache for params stored in |activate|.
    activate_params: Option<ActivateParams>,

    // Is Vhost-user sibling connected.
    sibling_connected: bool,
}

impl VirtioVhostUser {
    pub fn new(base_features: u64, listener: UnixListener) -> Result<VirtioVhostUser> {
        Ok(VirtioVhostUser {
            base_features,
            listener,
            config: VirtioVhostUserConfig {
                status: Le32::from(0),
                max_vhost_queues: Le32::from(MAX_VHOST_DEVICE_QUEUES as u32),
                uuid: [0; CONFIG_UUID_SIZE],
            },
            kill_evt: None,
            worker_thread: None,
            pci_bar: None,
            notification_select: None,
            notification_msix_vectors: [None; MAX_VHOST_DEVICE_QUEUES],
            activate_params: None,
            sibling_connected: false,
        })
    }

    // Implement writing to the notifications bar as per the VVU spec.
    fn write_bar_notifications(&mut self, offset: u64, data: &[u8]) {
        if data.len() < std::mem::size_of::<u16>() {
            error!("data buffer is too small: {}", data.len());
            return;
        }

        // The driver will first write to `NOTIFICATIONS_VRING_SELECT_OFFSET` to
        // specify which index in `self.notification_msix_vectors` to write to.
        // Then it writes the msix vector value by writing to
        // `NOTIFICATIONS_MSIX_VECTOR_SELECT_OFFSET`.
        let mut dst = [0u8; 2];
        dst.copy_from_slice(&data[..2]);
        let val = u16::from_le_bytes(dst);
        match offset {
            NOTIFICATIONS_VRING_SELECT_OFFSET => {
                self.notification_select = Some(val);
            }
            NOTIFICATIONS_MSIX_VECTOR_SELECT_OFFSET => {
                if let Some(notification_select) = self.notification_select {
                    if notification_select as usize >= self.notification_msix_vectors.len() {
                        error!("invalid notification select: {}", notification_select);
                        return;
                    }
                    self.notification_msix_vectors[notification_select as usize] = Some(val);
                } else {
                    error!("no notification select set");
                }
            }
            _ => {
                error!("invalid notification cfg offset: {}", offset);
            }
        }
    }

    // Implement reading from the notifications bar as per the VVU spec.
    fn read_bar_notifications(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() < std::mem::size_of::<u16>() {
            error!("data buffer is too small: {}", data.len());
            return;
        }

        // The driver will first write to `NOTIFICATIONS_VRING_SELECT_OFFSET` to
        // specify which index in `self.notification_msix_vectors` to read from.
        // Then it reads the msix vector value by reading from
        // `NOTIFICATIONS_MSIX_VECTOR_SELECT_OFFSET`.
        // Return 0 if a vector value hasn't been set for the queue.
        let mut val = 0;
        if offset == NOTIFICATIONS_VRING_SELECT_OFFSET {
            val = self.notification_select.unwrap_or(0);
        } else if offset == NOTIFICATIONS_MSIX_VECTOR_SELECT_OFFSET {
            if let Some(notification_select) = self.notification_select {
                val = self.notification_msix_vectors[notification_select as usize].unwrap_or(0);
            } else {
                error!("no notification select set");
            }
        } else {
            error!("invalid notification cfg offset: {}", offset);
        }
        let d = u16::to_le_bytes(val);
        data[..2].copy_from_slice(&d);
    }

    // Wait for Vhost-user sibling to connect.
    fn wait_for_sibling(&mut self) {
        // This function should never be called if this device hasn't been
        // activated.
        if self.activate_params.is_none() {
            panic!("device not activated");
        }

        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed creating kill Event pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let socket = match self.listener.accept() {
            Ok((socket, _)) => socket,
            Err(e) => {
                error!("failed to accept connection: {}", e);
                return;
            }
        };
        // Although this device is relates to Virtio Vhost User but it uses
        // `slave_req_helper` to parse messages from  a Vhost-user sibling.
        // Thus, we need `slave_req_helper` in `Protocol::Regular` mode and not
        // in `Protocol::Virtio' mode.
        let slave_req_helper: SlaveReqHelper<SocketEndpoint<MasterReq>> =
            SlaveReqHelper::new(SocketEndpoint::from(socket), Protocol::Regular);

        // TODO(abhishekbh): Should interrupt.signal_config_changed be called ?
        self.sibling_connected = true;
        let mut activate_params = self.activate_params.take().unwrap();
        let worker_result = thread::Builder::new()
            .name("virtio_vhost_user".to_string())
            .spawn(move || {
                let rx_queue = activate_params.queues.remove(0);
                let tx_queue = activate_params.queues.remove(0);
                let mut worker = Worker {
                    mem: activate_params.mem,
                    interrupt: activate_params.interrupt,
                    rx_queue,
                    tx_queue,
                    slave_req_helper,
                };
                let rx_queue_evt = activate_params.queue_evts.remove(0);
                let tx_queue_evt = activate_params.queue_evts.remove(0);
                let _ = worker.run(rx_queue_evt, tx_queue_evt, kill_evt);
                worker
            });

        match worker_result {
            Err(e) => {
                error!("failed to spawn virtio_vhost_user worker: {}", e);
            }
            Ok(join_handle) => {
                self.worker_thread = Some(join_handle);
            }
        }
    }
}

impl Drop for VirtioVhostUser {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            match kill_evt.write(1) {
                Ok(()) => {
                    if let Some(worker_thread) = self.worker_thread.take() {
                        // Ignore the result because there is nothing we can do about it.
                        let _ = worker_thread.join();
                    }
                }
                Err(e) => error!("failed to write kill event: {}", e),
            }
        }
    }
}

impl VirtioDevice for VirtioVhostUser {
    fn features(&self) -> u64 {
        self.base_features
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = vec![self.listener.as_raw_fd()];
        if let Some(kill_evt) = &self.kill_evt {
            rds.push(kill_evt.as_raw_descriptor());
        }
        rds
    }

    fn device_type(&self) -> u32 {
        TYPE_VHOST_USER
    }

    fn queue_max_sizes(&self) -> &[u16] {
        PROXY_DEVICE_QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(
            data,
            0, /* dst_offset */
            self.config.as_slice(),
            offset,
        );
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        copy_config(
            self.config.as_mut_slice(),
            offset,
            data,
            0, /* src_offset */
        );

        // The driver has indicated that it's safe for the Vhost-user sibling to
        // initiate a connection and send data over.
        if self.config.is_slave_up() && !self.sibling_connected {
            // TODO(abhishekbh): This function blocks till the sibling connects
            // to the proxy. `write_config` is synchronous so we're blocking the
            // guest vCPU indefinitely here. Figure out a way to do this
            // asynchronously.
            self.wait_for_sibling();
        }
    }

    fn get_device_caps(&self) -> Vec<Box<dyn crate::pci::PciCapability>> {
        // Allocate capabilities as per sections 5.7.7.5, 5.7.7.6, 5.7.7.7 of
        // the link at the top of the file. The PCI bar is organized in the
        // following format |Doorbell|Notification|Shared Memory|.
        let mut doorbell_virtio_pci_cap = VirtioPciCap::new(
            PciCapabilityType::DoorbellConfig,
            BAR_INDEX,
            DOORBELL_OFFSET as u32,
            DOORBELL_SIZE as u32,
        );
        doorbell_virtio_pci_cap.set_cap_len(std::mem::size_of::<VirtioPciDoorbellCap>() as u8);
        let doorbell = Box::new(VirtioPciDoorbellCap::new(
            doorbell_virtio_pci_cap,
            DOORBELL_OFFSET_MULTIPLIER,
        ));

        let notification = Box::new(VirtioPciCap::new(
            PciCapabilityType::NotificationConfig,
            BAR_INDEX,
            NOTIFICATIONS_OFFSET as u32,
            NOTIFICATIONS_SIZE as u32,
        ));

        let shared_memory = Box::new(VirtioPciCap::new(
            PciCapabilityType::SharedMemoryConfig,
            BAR_INDEX,
            SHARED_MEMORY_OFFSET as u32,
            SHARED_MEMORY_SIZE as u32,
        ));

        vec![doorbell, notification, shared_memory]
    }

    fn get_device_bars(&mut self, address: PciAddress) -> Vec<PciBarConfiguration> {
        self.pci_bar = Some(Alloc::PciBar {
            bus: address.bus,
            dev: address.dev,
            func: address.func,
            bar: BAR_INDEX,
        });

        vec![PciBarConfiguration::new(
            BAR_INDEX as usize,
            BAR_SIZE as u64,
            PciBarRegionType::Memory64BitRegion,
            PciBarPrefetchable::NotPrefetchable,
        )]
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
    ) {
        if queues.len() != NUM_PROXY_DEVICE_QUEUES || queue_evts.len() != NUM_PROXY_DEVICE_QUEUES {
            error!("bad queue length: {} {}", queues.len(), queue_evts.len());
            return;
        }

        // Cache these to be used later in the `wait_for_sibling` function.
        self.activate_params = Some(ActivateParams {
            mem,
            interrupt,
            queues,
            queue_evts,
        });
    }

    fn read_bar(&mut self, bar_index: PciBarIndex, offset: u64, data: &mut [u8]) {
        if self.pci_bar.is_none() {
            error!("PCI bar is not allocated");
            return;
        }

        if bar_index != BAR_INDEX as PciBarIndex {
            error!("wrong PCI bar: {}", bar_index);
            return;
        }

        if (NOTIFICATIONS_OFFSET..SHARED_MEMORY_OFFSET).contains(&offset) {
            self.read_bar_notifications(offset - NOTIFICATIONS_OFFSET, data);
        } else {
            error!("addr is outside known region for reads");
        }
    }

    fn write_bar(&mut self, bar_index: PciBarIndex, offset: u64, data: &[u8]) {
        if self.pci_bar.is_none() {
            error!("PCI bar is not allocated");
            return;
        }

        if bar_index != BAR_INDEX as PciBarIndex {
            error!("wrong PCI bar: {}", bar_index);
            return;
        }

        if (DOORBELL_OFFSET..NOTIFICATIONS_OFFSET).contains(&offset) {
            // TODO(abhishekbh): Implement doorbell writes.
            unimplemented!();
        } else if (NOTIFICATIONS_OFFSET..SHARED_MEMORY_OFFSET).contains(&offset) {
            self.write_bar_notifications(offset - NOTIFICATIONS_OFFSET, data);
        } else {
            error!("addr is outside known region for writes");
        }
    }

    fn reset(&mut self) -> bool {
        if let Some(kill_evt) = self.kill_evt.take() {
            if let Err(e) = kill_evt.write(1) {
                error!("failed to notify the kill event: {}", e);
                return false;
            }
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            if let Err(e) = worker_thread.join() {
                error!("failed to get back resources: {:?}", e);
                return false;
            }
        }

        // TODO(abhishekbh): Disconnect from sibling and reset
        // `sibling_connected`.
        false
    }
}
