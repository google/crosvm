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

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::thread;

use anyhow::{anyhow, bail, Context};
use base::{
    error, info, AsRawDescriptor, Event, EventToken, EventType, FromRawDescriptor,
    IntoRawDescriptor, RawDescriptor, SafeDescriptor, Tube, WaitContext,
};
use data_model::{DataInit, Le32};
use libc::{recv, MSG_DONTWAIT, MSG_PEEK};
use resources::Alloc;
use uuid::Uuid;
use vm_control::{VmMemoryDestination, VmMemoryRequest, VmMemoryResponse, VmMemorySource};
use vm_memory::GuestMemory;
use vmm_vhost::{
    connection::socket::Endpoint as SocketEndpoint,
    connection::EndpointExt,
    message::{
        MasterReq, VhostUserMemory, VhostUserMemoryRegion, VhostUserMsgHeader,
        VhostUserMsgValidator, VhostUserU64,
    },
    Protocol, SlaveReqHelper,
};

use crate::virtio::{
    copy_config, DescriptorChain, DeviceType, Interrupt, PciCapabilityType, Queue, Reader,
    SignalableInterrupt, VirtioDevice, VirtioPciCap, Writer,
};
use crate::PciAddress;
use crate::{
    pci::{
        PciBarConfiguration, PciBarIndex, PciBarPrefetchable, PciBarRegionType, PciCapability,
        PciCapabilityID,
    },
    virtio::{VIRTIO_F_ACCESS_PLATFORM, VIRTIO_MSI_NO_VECTOR},
};

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
const CONFIG_UUID_SIZE: usize = 16;
// Defined in the specification here -
// https://stefanha.github.io/virtio/vhost-user-slave.html#x1-2870004.
const VIRTIO_VHOST_USER_STATUS_SLAVE_UP: u8 = 0;

const BAR_INDEX: u8 = 2;

// Bar configuration.
// All offsets are from the starting of bar `BAR_INDEX`.
const DOORBELL_OFFSET: u64 = 0;
// TODO(abhishekbh): Copied from lspci in qemu with VVU support.
const DOORBELL_SIZE: u64 = 0x2000;
const NOTIFICATIONS_OFFSET: u64 = DOORBELL_OFFSET + DOORBELL_SIZE;
const NOTIFICATIONS_SIZE: u64 = 0x1000;
const SHARED_MEMORY_OFFSET: u64 = NOTIFICATIONS_OFFSET + NOTIFICATIONS_SIZE;
// TODO(abhishekbh): Copied from qemu with VVU support. This should be same as
// VirtioVhostUser.device_bar_size, but it's significantly  lower than the
// memory allocated to a sibling VM. Figure out how these two are related.
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

pub type Result<T> = anyhow::Result<T>;

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
    fn is_slave_up(&self) -> bool {
        self.check_status_bit(VIRTIO_VHOST_USER_STATUS_SLAVE_UP)
    }

    fn check_status_bit(&self, bit: u8) -> bool {
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
                bail!("fd is expected for {:?}", hdr.get_code());
            }
        }
        _ if files.is_some() => {
            bail!("unexpected fd for {:?}", hdr.get_code());
        }
        _ => Ok(()),
    }
}

// Check if `hdr` is valid.
fn is_header_valid(hdr: &VhostUserMsgHeader<MasterReq>) -> bool {
    if hdr.is_reply() || hdr.get_version() != 0x1 {
        return false;
    }
    true
}

// Payload sent by the sibling in a |SET_VRING_KICK| message.
#[derive(Default)]
struct KickData {
    // Fd sent by the sibling. This is monitored and when it's written to an interrupt is injected
    // into the guest.
    kick_evt: Option<Event>,

    // The interrupt to be injected to the guest in response to an event to |kick_evt|.
    msi_vector: Option<u16>,
}

// Vring related data sent through |SET_VRING_KICK| and |SET_VRING_CALL|.
#[derive(Default)]
struct Vring {
    kick_data: KickData,
    call_evt: Option<Event>,
}

// Processes messages from the Vhost-user sibling and sends it to the device backend and
// vice-versa.
struct Worker {
    mem: GuestMemory,
    interrupt: Interrupt,
    rx_queue: Queue,
    tx_queue: Queue,

    // To communicate with the main process.
    main_process_tube: Tube,

    // The bar representing the doorbell, notification and shared memory regions.
    pci_bar: Alloc,

    // Offset at which to allocate the next shared memory region, corresponding
    // to the |SET_MEM_TABLE| sibling message.
    mem_offset: usize,

    // Vring related data sent through |SET_VRING_KICK| and |SET_VRING_CALL|
    // messages.
    vrings: [Vring; MAX_VHOST_DEVICE_QUEUES],

    // Helps with communication and parsing messages from the sibling.
    slave_req_helper: SlaveReqHelper<SocketEndpoint<MasterReq>>,
}

#[derive(EventToken, Debug, Clone)]
enum Token {
    // Data is available on the Vhost-user sibling socket.
    SiblingSocket,
    // The device backend has made a read buffer available.
    RxQueue,
    // The device backend has sent a buffer to the |Worker::tx_queue|.
    TxQueue,
    // The sibling writes a kick event for the |index|-th vring.
    SiblingKick { index: usize },
    // crosvm has requested the device to shut down.
    Kill,
    // Message from the main thread.
    MainThread,
}

/// Represents the status of connection to the sibling.
enum ConnStatus {
    DataAvailable,
    NoDataAvailable,
    Disconnected,
}

/// Reason why rxq processing is stopped.
enum RxqStatus {
    /// All pending data have been processed.
    Processed,
    /// No descriptors available to forward vhost-user messages.
    DescriptorsExhausted,
    /// Sibling disconnected.
    Disconnected,
}

/// Reason for a worker's successful exit.
enum ExitReason {
    Killed,
    Disconnected,
}

impl Worker {
    // The entry point into `Worker`.
    // - At this point the connection with the sibling is already established.
    // - Process messages from the device over Virtio, from the sibling over a unix domain socket,
    //   from the main thread in this device over a tube and from the main crosvm process over a
    //   tube.
    fn run(
        &mut self,
        rx_queue_evt: Event,
        tx_queue_evt: Event,
        main_thread_tube: Tube,
        kill_evt: Event,
    ) -> Result<ExitReason> {
        // TODO(abhishekbh): Should interrupt.signal_config_changed be called here ?.
        let mut wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (&self.slave_req_helper, Token::SiblingSocket),
            (&rx_queue_evt, Token::RxQueue),
            (&tx_queue_evt, Token::TxQueue),
            (&main_thread_tube, Token::MainThread),
            (&kill_evt, Token::Kill),
        ])
        .context("failed to create a wait context object")?;

        // Represents if |slave_req_helper.endpoint| is being monitored for data
        // from the Vhost-user sibling.
        let mut sibling_socket_polling_enabled = true;
        loop {
            let events = wait_ctx.wait().context("failed to wait for events")?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::SiblingSocket => {
                        match self.process_rx(&mut wait_ctx) {
                            Ok(RxqStatus::Processed) => (),
                            Ok(RxqStatus::DescriptorsExhausted) => {
                                // If the driver has no Rx buffers left, then no
                                // point monitoring the Vhost-user sibling for data. There
                                // would be no way to send it to the device backend.
                                wait_ctx
                                    .modify(
                                        &self.slave_req_helper,
                                        EventType::None,
                                        Token::SiblingSocket,
                                    )
                                    .context("failed to disable EPOLLIN on sibling VM socket fd")?;
                                sibling_socket_polling_enabled = false;
                            }
                            Ok(RxqStatus::Disconnected) => {
                                return Ok(ExitReason::Disconnected);
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Token::RxQueue => {
                        if let Err(e) = rx_queue_evt.read() {
                            bail!("error reading rx queue Event: {}", e);
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
                                .context("failed to add kick event to the epoll set")?;
                            sibling_socket_polling_enabled = true;
                        }
                    }
                    Token::TxQueue => {
                        if let Err(e) = tx_queue_evt.read() {
                            bail!("error reading tx queue event: {}", e);
                        }
                        self.process_tx();
                    }
                    Token::SiblingKick { index } => {
                        if let Err(e) = self.process_sibling_kick(index) {
                            bail!(
                                "error processing sibling kick for {}-th vring: {}",
                                index,
                                e
                            );
                        }
                    }
                    Token::MainThread => {
                        if let Err(e) = self.process_doorbell_message(&main_thread_tube) {
                            bail!("error processing doorbell message: {}", e);
                        }
                    }
                    Token::Kill => {
                        let _ = kill_evt.read();
                        return Ok(ExitReason::Killed);
                    }
                }
            }
        }
    }

    // Processes data from the Vhost-user sibling and forwards to the driver via Rx buffers.
    fn process_rx(&mut self, wait_ctx: &mut WaitContext<Token>) -> Result<RxqStatus> {
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
        //
        // Peek if any data is left on the Vhost-user sibling socket. If no, then
        // nothing to forwad to the device backend.
        loop {
            let is_connected = match self.check_sibling_connection() {
                ConnStatus::DataAvailable => true,
                ConnStatus::Disconnected => false,
                ConnStatus::NoDataAvailable => return Ok(RxqStatus::Processed),
            };

            let desc = match self.rx_queue.peek(&self.mem) {
                Some(d) => d,
                None => {
                    return Ok(RxqStatus::DescriptorsExhausted);
                }
            };

            // If a sibling is disconnected, send 0-length data to the guest and return an error.
            if !is_connected {
                // Send 0-length data
                let index = desc.index;
                self.rx_queue.pop_peeked(&self.mem);
                self.rx_queue.add_used(&self.mem, index, 0 /* len */);
                if !self.rx_queue.trigger_interrupt(&self.mem, &self.interrupt) {
                    // This interrupt should always be injected. We'd rather fail
                    // fast if there is an error.
                    panic!("failed to send interrupt");
                }
                return Ok(RxqStatus::Disconnected);
            };

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
                .context("failed to read Vhost-user sibling message header")?;
            check_attached_files(&hdr, &files)?;
            let buf = self.get_sibling_msg_data(&hdr)?;

            let index = desc.index;
            let bytes_written = {
                if is_action_request(&hdr) {
                    // TODO(abhishekbh): Implement action messages.
                    let res = match hdr.get_code() {
                        MasterReq::SET_MEM_TABLE => {
                            // Map the sibling memory in this process and forward the
                            // sibling memory info to the slave. Only if the mapping
                            // succeeds send info along to the slave, else send a failed
                            // Ack back to the master.
                            self.set_mem_table(&hdr, &buf, files)
                        }
                        MasterReq::SET_VRING_CALL => self.set_vring_call(&hdr, &buf, files),
                        MasterReq::SET_VRING_KICK => {
                            self.set_vring_kick(wait_ctx, &hdr, &buf, files)
                        }
                        _ => {
                            unimplemented!("unimplemented action message:{:?}", hdr.get_code());
                        }
                    };

                    // If the "action" in response to the action messages
                    // failed then no bytes have been written to the virt
                    // queue. Else, the action is done. Now forward the
                    // message to the virt queue and return how many bytes
                    // were written.
                    match res {
                        Ok(()) => self.forward_msg_to_device(desc, &hdr, &buf),
                        Err(e) => Err(e),
                    }
                } else {
                    // If no special processing required. Forward this message as is
                    // to the device backend.
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
                        // This interrupt should always be injected. We'd rather fail
                        // fast if there is an error.
                        panic!("failed to send interrupt");
                    }
                }
                Err(e) => {
                    error!("failed to forward message to the device: {}", e);
                    self.slave_req_helper
                        .send_ack_message(&hdr, false)
                        .context("failed to send ack")?;
                }
            }
        }
    }

    // Returns the sibling connection status.
    fn check_sibling_connection(&self) -> ConnStatus {
        // Peek if any data is left on the Vhost-user sibling socket. If no, then
        // nothing to forwad to the device backend.
        let mut peek_buf = [0; 1];
        let raw_fd = self.slave_req_helper.as_raw_descriptor();
        // Safe because `raw_fd` and `peek_buf` are owned by this struct.
        let peek_ret = unsafe {
            recv(
                raw_fd,
                peek_buf.as_mut_ptr() as *mut libc::c_void,
                peek_buf.len(),
                MSG_PEEK | MSG_DONTWAIT,
            )
        };

        match peek_ret {
            0 => ConnStatus::Disconnected,
            ret if ret < 0 => match base::Error::last() {
                // EAGAIN means that no data is available. Any other error means that the sibling
                // has disconnected.
                e if e.errno() == libc::EAGAIN => ConnStatus::NoDataAvailable,
                _ => ConnStatus::Disconnected,
            },
            _ => ConnStatus::DataAvailable,
        }
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
                    .context("failed to read Vhost-user sibling message payload")?;
                if rbuf.len() != len as usize {
                    self.slave_req_helper
                        .send_ack_message(hdr, false)
                        .context("failed to send ack")?;
                    bail!(
                        "unexpected message length for {:?}: expected={}, got={}",
                        hdr.get_code(),
                        len,
                        rbuf.len(),
                    );
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
                    bail!("rx buffer too small to accomodate server data");
                }
                // Write header first then any data. Do these separately to prevent any reorders.
                let mut written = writer
                    .write(hdr.as_slice())
                    .context("failed to write header")?;
                written += writer.write(buf).context("failed to write message body")?;
                written as u32
            }
            Err(e) => {
                bail!("failed to create Writer: {}", e);
            }
        };
        Ok(bytes_written)
    }

    // Handles `SET_MEM_TABLE` message from sibling. Parses `hdr` into
    // memory region information. For each memory region sent by the Vhost
    // Master, it mmaps a region of memory in the main process. At the end of
    // this function both this VMM and the sibling have two regions of
    // virtual memory pointing to the same physical page. These regions will be
    // accessed by the device VM and the silbing VM.
    fn set_mem_table(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        payload: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<()> {
        if !is_header_valid(hdr) {
            bail!("invalid header for SET_MEM_TABLE");
        }

        // `hdr` is followed by a `payload`. `payload` consists of metadata about the number of
        // memory regions and then memory regions themeselves. The memory regions structs consist of
        // metadata about actual device related memory passed from the sibling. Ensure that the size
        // of the payload is consistent with this structure.
        let payload_size = payload.len();
        if payload_size < std::mem::size_of::<VhostUserMemory>() {
            bail!("payload size {} lesser than minimum required", payload_size);
        }
        let (msg_slice, regions_slice) = payload.split_at(std::mem::size_of::<VhostUserMemory>());
        let msg = VhostUserMemory::from_slice(msg_slice).ok_or(anyhow!(
            "failed to convert SET_MEM_TABLE message to VhostUserMemory"
        ))?;
        if !msg.is_valid() {
            bail!("invalid message for SET_MEM_TABLE");
        }

        let memory_region_metadata_size = std::mem::size_of::<VhostUserMemory>();
        if payload_size
            != memory_region_metadata_size
                + msg.num_regions as usize * std::mem::size_of::<VhostUserMemoryRegion>()
        {
            bail!("invalid payload size for SET_MEM_TABLE");
        }

        let regions: Vec<&VhostUserMemoryRegion> = regions_slice
            .chunks(std::mem::size_of::<VhostUserMemoryRegion>())
            .map(VhostUserMemoryRegion::from_slice)
            .collect::<Option<_>>()
            .context("failed to construct VhostUserMemoryRegion array")?;

        if !regions.iter().all(|r| r.is_valid()) {
            bail!("invalid memory region is included");
        }

        let files = files.ok_or(anyhow!("FD is expected for SET_MEM_TABLE"))?;
        if files.len() != msg.num_regions as usize {
            bail!(
                "{} files are expected for SET_MEM_TABLE but got {}",
                msg.num_regions as usize,
                files.len()
            );
        }

        self.create_sibling_guest_memory(&regions, files)?;
        Ok(())
    }

    // Mmaps sibling memory in this device's VMM's main process' address
    // space.
    pub fn create_sibling_guest_memory(
        &mut self,
        contexts: &[&VhostUserMemoryRegion],
        files: Vec<File>,
    ) -> Result<()> {
        if contexts.len() != files.len() {
            bail!(
                "number of contexts {} mismatches with number of files ({})",
                contexts.len(),
                files.len()
            );
        }

        for (region, file) in contexts.iter().zip(files.into_iter()) {
            let request = VmMemoryRequest::RegisterMemory {
                source: VmMemorySource::Descriptor {
                    descriptor: SafeDescriptor::from(file),
                    offset: region.mmap_offset,
                    size: region.memory_size,
                },
                dest: VmMemoryDestination::ExistingAllocation {
                    allocation: self.pci_bar,
                    offset: self.mem_offset as u64,
                },
                read_only: false,
            };
            self.process_memory_mapping_request(&request)?;
            self.mem_offset += region.memory_size as usize;
        }
        Ok(())
    }

    // Sends memory mapping request to the main process. If successful adds the
    // mmaped info into |sibling_mem|, else returns error.
    fn process_memory_mapping_request(&mut self, request: &VmMemoryRequest) -> Result<()> {
        self.main_process_tube
            .send(request)
            .context("sending mapping request to tube failed")?;

        let response = self
            .main_process_tube
            .recv()
            .context("receiving mapping request from tube failed")?;

        match response {
            VmMemoryResponse::RegisterMemory { .. } => Ok(()),
            VmMemoryResponse::Err(e) => {
                bail!("memory mapping failed: {}", e);
            }
            _ => {
                bail!("unexpected response: {:?}", response);
            }
        }
    }

    // Handles |SET_VRING_CALL|.
    fn set_vring_call(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        payload: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<()> {
        if !is_header_valid(hdr) {
            bail!("invalid header for SET_VRING_CALL");
        }

        let payload_size = payload.len();
        if payload_size != std::mem::size_of::<VhostUserU64>() {
            bail!("wrong payload size {} for SET_VRING_CALL", payload_size);
        }

        let (index, file) = self
            .slave_req_helper
            .handle_vring_fd_request(payload, files)
            .context("failed to parse vring call file descriptors")?;

        if index as usize >= MAX_VHOST_DEVICE_QUEUES {
            bail!("illegal vring index: {}", index);
        }

        let file = file.ok_or_else(|| anyhow!("no file found for SET_VRING_CALL"))?;

        // Safe because we own the file.
        self.vrings[index as usize].call_evt =
            unsafe { Some(Event::from_raw_descriptor(file.into_raw_descriptor())) };

        Ok(())
    }

    // Handles |SET_VRING_KICK|. If successful it sets up an event handler for a
    // write to the sent kick fd.
    fn set_vring_kick(
        &mut self,
        wait_ctx: &mut WaitContext<Token>,
        hdr: &VhostUserMsgHeader<MasterReq>,
        payload: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<()> {
        if !is_header_valid(hdr) {
            bail!("invalid header for SET_VRING_KICK");
        }

        let payload_size = payload.len();
        if payload_size != std::mem::size_of::<VhostUserU64>() {
            bail!("wrong payload size {} for SET_VRING_KICK", payload_size);
        }

        let (index, file) = self
            .slave_req_helper
            .handle_vring_fd_request(payload, files)
            .context("failed to parse vring kill file descriptors")?;

        if index as usize >= MAX_VHOST_DEVICE_QUEUES {
            bail!("illegal vring index:{}", index);
        }

        let file = file.ok_or_else(|| anyhow!("no file found for SET_VRING_KICK"))?;

        // Safe because we own the file.
        let kick_evt = unsafe { Event::from_raw_descriptor(file.into_raw_descriptor()) };
        let kick_data = &mut self.vrings[index as usize].kick_data;

        wait_ctx
            .add(
                &kick_evt,
                Token::SiblingKick {
                    index: index as usize,
                },
            )
            .context("failed to add kick event to the epoll set")?;
        kick_data.kick_evt = Some(kick_evt);

        Ok(())
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

    // Processes a sibling kick for the |index|-th vring and injects the corresponding interrupt
    // into the guest.
    fn process_sibling_kick(&mut self, index: usize) -> Result<()> {
        // The sibling is indicating a used queue event on
        // vring number |index|. Acknowledge the event and
        // inject the related interrupt into the guest.
        let kick_data = &self.vrings[index as usize].kick_data;
        let kick_evt = kick_data
            .kick_evt
            .as_ref()
            .with_context(|| format!("kick data not set for {}-th vring", index))?;
        kick_evt
            .read()
            .map_err(|e| anyhow!("failed to read kick event for {}-th vring: {}", index, e))?;
        match kick_data.msi_vector {
            Some(msi_vector) => {
                self.interrupt.signal_used_queue(msi_vector);
                Ok(())
            }
            None => {
                bail!("MSI vector not set for {}-th vring", index);
            }
        }
    }

    // Processes a message sent, on `main_thread_tube`, in response to a doorbell write. It writes
    // to the corresponding call event of the vring index sent over `main_thread_tube`.
    fn process_doorbell_message(&mut self, main_thread_tube: &Tube) -> Result<()> {
        let index: usize = main_thread_tube
            .recv()
            .context("failed to receive doorbell data")?;
        let call_evt = self.vrings[index]
            .call_evt
            .as_ref()
            .ok_or(anyhow!("call event for {}-th ring is not set", index))?;
        call_evt
            .write(1)
            .with_context(|| format!("failed to write call event for {}-th ring", index))?;
        Ok(())
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

/// Represents the `VirtioVhostUser` device's state.
enum State {
    /// The device is initialized but not activated.
    Initialized {
        // Bound socket waiting to accept a socket connection from the Vhost-user
        // sibling.
        listener: UnixListener,

        // The tube communicate with the main process from a worker.
        // This will be passed on to a worker thread when it's spawned.
        main_process_tube: Tube,
    },
    /// The VVU-proxy PCI device is activated but its worker thread hasn't started.
    Activated {
        listener: UnixListener,
        main_process_tube: Tube,

        mem: GuestMemory,
        interrupt: Interrupt,
        rx_queue: Queue,
        tx_queue: Queue,
        rx_queue_evt: Event,
        tx_queue_evt: Event,
    },
    /// The worker thread is running.
    Running {
        // To communicate with the worker thread.
        worker_thread_tube: Tube,

        kill_evt: Event,
        worker_thread: thread::JoinHandle<Result<()>>,
    },
    /// Something wrong happened and the device is unusable.
    Invalid,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Initialized { .. } => {
                write!(f, "Initialized")
            }
            State::Activated { .. } => {
                write!(f, "Activated")
            }
            State::Running { .. } => {
                write!(f, "Running")
            }
            State::Invalid { .. } => {
                write!(f, "Invalid")
            }
        }
    }
}

pub struct VirtioVhostUser {
    base_features: u64,

    // Represents the amount of memory to be mapped for a sibling VM. Each
    // Virtio Vhost User Slave implementation requires access to the entire sibling
    // memory.
    //
    // TODO(abhishekbh): Understand why shared memory region size and overall bar
    // size differ in the QEMU implementation.
    device_bar_size: u64,

    // Device configuration.
    config: VirtioVhostUserConfig,

    // The bar representing the doorbell, notification and shared memory regions.
    pci_bar: Option<Alloc>,
    // The device backend queue index selected by the driver by writing to the
    // Notifications region at offset `NOTIFICATIONS_MSIX_VECTOR_SELECT_OFFSET`
    // in the bar. This points into `notification_msix_vectors`.
    notification_select: Option<u16>,
    // Stores msix vectors corresponding to each device backend queue.
    notification_msix_vectors: [Option<u16>; MAX_VHOST_DEVICE_QUEUES],

    // PCI address that this device needs to be allocated if specified.
    pci_address: Option<PciAddress>,

    // The device's state.
    state: State,
}

impl VirtioVhostUser {
    pub fn new(
        base_features: u64,
        listener: UnixListener,
        main_process_tube: Tube,
        pci_address: Option<PciAddress>,
        uuid: Option<Uuid>,
        max_sibling_mem_size: u64,
    ) -> Result<VirtioVhostUser> {
        let device_bar_size = max_sibling_mem_size
            .checked_next_power_of_two()
            .expect("Sibling too large");

        Ok(VirtioVhostUser {
            base_features: base_features | 1 << VIRTIO_F_ACCESS_PLATFORM,
            device_bar_size,
            config: VirtioVhostUserConfig {
                status: Le32::from(0),
                max_vhost_queues: Le32::from(MAX_VHOST_DEVICE_QUEUES as u32),
                uuid: *uuid.unwrap_or_default().as_bytes(),
            },
            pci_bar: None,
            notification_select: None,
            notification_msix_vectors: [None; MAX_VHOST_DEVICE_QUEUES],
            state: State::Initialized {
                main_process_tube,
                listener,
            },
            pci_address,
        })
    }

    fn check_bar_metadata(&self, bar_index: PciBarIndex) -> Result<()> {
        if bar_index != BAR_INDEX as usize {
            bail!("invalid bar index: {}", bar_index);
        }

        if self.pci_bar.is_none() {
            bail!("bar is not allocated for {}", bar_index);
        }

        Ok(())
    }

    // Handles writes to the DOORBELL region of the BAR as per the VVU spec.
    fn write_bar_doorbell(&mut self, offset: u64) {
        match &self.state {
            State::Running {
                worker_thread_tube, ..
            } => {
                // The |offset| represents the Vring number who call event needs to be
                // written to.
                let vring = (offset / DOORBELL_OFFSET_MULTIPLIER as u64) as usize;

                if let Err(e) = worker_thread_tube.send(&vring) {
                    error!("failed to send doorbell write request: {}", e);
                }
            }
            s => {
                error!(
                    "write_bar_doorbell is called in an invalid state {} with offset={}",
                    s, offset,
                );
            }
        }
    }

    // Implement writing to the notifications bar as per the VVU spec.
    fn write_bar_notifications(&mut self, offset: u64, data: &[u8]) {
        if data.len() < std::mem::size_of::<u16>() {
            error!("data buffer is too small: {}", data.len());
            return;
        }

        // The driver will first write to |NOTIFICATIONS_VRING_SELECT_OFFSET| to
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
                    self.notification_msix_vectors[notification_select as usize] =
                        if val == VIRTIO_MSI_NO_VECTOR {
                            None
                        } else {
                            Some(val)
                        };
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

        // The driver will first write to |NOTIFICATIONS_VRING_SELECT_OFFSET| to
        // specify which index in |self.notification_msix_vectors| to read from.
        // Then it reads the msix vector value by reading from
        // |NOTIFICATIONS_MSIX_VECTOR_SELECT_OFFSET|.
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

    // Initializes state and starts the worker thread which will process all messages to this device
    // and send out messages in response.
    // This method must be called when a state is `State::Activated`.
    fn start_worker(&mut self) {
        // Create tube to communicate with the worker thread and update the state.
        let (worker_thread_tube, main_thread_tube) =
            Tube::pair().expect("failed to create tube pair");

        // Use `State::Invalid` as the intermediate state while preparing the proper next state.
        // Once a worker thread is successfully started, `self.state` will be updated to `Running`.
        let old_state: State = std::mem::replace(&mut self.state, State::Invalid);

        // Retrieve values stored in the state value.
        let (
            main_process_tube,
            listener,
            mem,
            interrupt,
            rx_queue,
            tx_queue,
            rx_queue_evt,
            tx_queue_evt,
        ) = match old_state {
            State::Activated {
                main_process_tube,
                listener,
                mem,
                interrupt,
                rx_queue,
                tx_queue,
                rx_queue_evt,
                tx_queue_evt,
            } => (
                main_process_tube,
                listener,
                mem,
                interrupt,
                rx_queue,
                tx_queue,
                rx_queue_evt,
                tx_queue_evt,
            ),
            s => {
                error!("start_worker was called with invalid state: {}", s);
                return;
            }
        };

        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed creating kill Event pair: {}", e);
                return;
            }
        };

        // Safe because a PCI bar is guaranteed to be allocated at this point.
        let pci_bar = self.pci_bar.expect("PCI bar unallocated");

        // Initialize the Worker with the Msix vector values to be injected for
        // each Vhost device queue.
        let mut vrings: [Vring; MAX_VHOST_DEVICE_QUEUES] = Default::default();
        for (i, vring) in vrings.iter_mut().enumerate() {
            vring.kick_data = KickData {
                kick_evt: None,
                msi_vector: self.notification_msix_vectors[i],
            };
        }

        // This thread will wait for the sibling to connect and the continuously parse messages from
        // the sibling as well as the device (over Virtio).
        let worker_result = thread::Builder::new()
            .name("virtio_vhost_user".to_string())
            .spawn(move || {
                // Block until the connection with the sibling is established. We do this in a
                // thread to avoid blocking the main thread.
                let (socket, _) = listener
                    .accept()
                    .context("failed to accept sibling connection")?;

                // Although this device is relates to Virtio Vhost User but it uses
                // `slave_req_helper` to parse messages from  a Vhost-user sibling.
                // Thus, we need `slave_req_helper` in `Protocol::Regular` mode and not
                // in `Protocol::Virtio' mode.
                let slave_req_helper: SlaveReqHelper<SocketEndpoint<MasterReq>> =
                    SlaveReqHelper::new(SocketEndpoint::from(socket), Protocol::Regular);

                let mut worker = Worker {
                    mem,
                    interrupt,
                    rx_queue,
                    tx_queue,
                    main_process_tube,
                    pci_bar,
                    mem_offset: SHARED_MEMORY_OFFSET as usize,
                    vrings,
                    slave_req_helper,
                };
                match worker.run(
                    rx_queue_evt.try_clone().unwrap(),
                    tx_queue_evt.try_clone().unwrap(),
                    main_thread_tube,
                    kill_evt,
                ) {
                    Ok(ExitReason::Killed) => {
                        info!("worker thread exited successfully");
                        Ok(())
                    }
                    Ok(ExitReason::Disconnected) => {
                        info!("worker thread exited: sibling disconnected");
                        // TODO(b/216407443): Handle sibling reconnect events and update the state.
                        Ok(())
                    }
                    Err(e) => {
                        error!("worker thread exited with an error: {:?}", e);
                        Ok(())
                    }
                }
            });

        match worker_result {
            Err(e) => {
                error!("failed to spawn virtio_vhost_user worker: {}", e);
                return;
            }
            Ok(worker_thread) => {
                self.state = State::Running {
                    worker_thread_tube,
                    kill_evt: self_kill_evt,
                    worker_thread,
                };
            }
        }
    }
}

impl Drop for VirtioVhostUser {
    fn drop(&mut self) {
        if let State::Running {
            kill_evt,
            worker_thread,
            ..
        } = std::mem::replace(&mut self.state, State::Invalid)
        {
            match kill_evt.write(1) {
                Ok(()) => {
                    // Ignore the result because there is nothing we can do about it.
                    let _ = worker_thread.join();
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

    fn supports_iommu(&self) -> bool {
        true
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = Vec::new();

        match &self.state {
            State::Initialized {
                main_process_tube,
                listener,
            } => {
                rds.push(main_process_tube.as_raw_descriptor());
                rds.push(listener.as_raw_descriptor());
            }
            State::Activated { .. } | State::Running { .. } | State::Invalid => {
                error!("keep_rds is called in an unexpected state");
            }
        };

        // `self.worker_thread_tube` is set after a fork / keep_rds is called in multiprocess mode.
        // Hence, it's not required to be processed in this function.
        rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::VhostUser
    }

    fn queue_max_sizes(&self) -> &[u16] {
        PROXY_DEVICE_QUEUE_SIZES
    }

    fn num_interrupts(&self) -> usize {
        // The total interrupts include both this device's interrupts as well as
        // the VVU device related interrupt.
        NUM_PROXY_DEVICE_QUEUES + MAX_VHOST_DEVICE_QUEUES
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

        let is_activated = matches!(self.state, State::Activated { .. });

        // The driver has indicated that it's safe for the Vhost-user sibling to
        // initiate a connection and send data over.
        if self.config.is_slave_up() && is_activated {
            self.start_worker();
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
        // A PCI bar corresponding to |Doorbell|Notification|Shared Memory| will
        // be allocated and its address (64 bit) will be stored in BAR 2 and BAR
        // 3. This is as per the VVU spec and qemu implementation.
        self.pci_bar = Some(Alloc::PciBar {
            bus: address.bus,
            dev: address.dev,
            func: address.func,
            bar: BAR_INDEX,
        });

        vec![PciBarConfiguration::new(
            BAR_INDEX as usize,
            self.device_bar_size,
            PciBarRegionType::Memory64BitRegion,
            // NotPrefetchable so as to exit on every read / write event in the
            // guest.
            PciBarPrefetchable::NotPrefetchable,
        )]
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<Event>,
    ) {
        if queues.len() != NUM_PROXY_DEVICE_QUEUES || queue_evts.len() != NUM_PROXY_DEVICE_QUEUES {
            error!("bad queue length: {} {}", queues.len(), queue_evts.len());
            return;
        }

        // Use `State::Invalid` as the intermediate state here.
        let old_state: State = std::mem::replace(&mut self.state, State::Invalid);
        match old_state {
            State::Initialized {
                listener,
                main_process_tube,
            } => {
                self.state = State::Activated {
                    listener,
                    main_process_tube,
                    mem,
                    interrupt,
                    rx_queue: queues.remove(0),
                    tx_queue: queues.remove(0),
                    rx_queue_evt: queue_evts.remove(0),
                    tx_queue_evt: queue_evts.remove(0),
                };
            }
            s => {
                // If the old state is not `Initialized`, it becomes `Invalid`.
                error!("activate() is called in an unexpected state: {}", s);
            }
        }
    }

    fn read_bar(&mut self, bar_index: PciBarIndex, offset: u64, data: &mut [u8]) {
        if let Err(e) = self.check_bar_metadata(bar_index) {
            error!("invalid bar metadata: {}", e);
            return;
        }

        if (NOTIFICATIONS_OFFSET..SHARED_MEMORY_OFFSET).contains(&offset) {
            self.read_bar_notifications(offset - NOTIFICATIONS_OFFSET, data);
        } else {
            error!("addr is outside known region for reads");
        }
    }

    fn write_bar(&mut self, bar_index: PciBarIndex, offset: u64, data: &[u8]) {
        if let Err(e) = self.check_bar_metadata(bar_index) {
            error!("invalid bar metadata: {}", e);
            return;
        }

        if (DOORBELL_OFFSET..NOTIFICATIONS_OFFSET).contains(&offset) {
            self.write_bar_doorbell(offset - DOORBELL_OFFSET);
        } else if (NOTIFICATIONS_OFFSET..SHARED_MEMORY_OFFSET).contains(&offset) {
            self.write_bar_notifications(offset - NOTIFICATIONS_OFFSET, data);
        } else {
            error!("addr is outside known region for writes");
        }
    }

    fn reset(&mut self) -> bool {
        let new_state = match std::mem::replace(&mut self.state, State::Invalid) {
            old_state @ State::Initialized { .. } => old_state,
            State::Activated {
                listener,
                main_process_tube,
                ..
            } => State::Initialized {
                listener,
                main_process_tube,
            },
            State::Running {
                kill_evt,
                worker_thread,
                ..
            } => {
                if let Err(e) = kill_evt.write(1) {
                    error!("failed to notify the kill event: {}", e);
                }
                if let Err(e) = worker_thread.join() {
                    error!("failed to get back resources: {:?}", e);
                }

                // TODO(b/216407443): Support the case where vvu-proxy is reset while running.
                // e.g. The VVU device backend in the guest is killed unexpectedly.
                State::Invalid
            }
            State::Invalid => State::Invalid,
        };

        self.state = new_state;

        true
    }

    fn pci_address(&self) -> Option<PciAddress> {
        self.pci_address
    }
}
