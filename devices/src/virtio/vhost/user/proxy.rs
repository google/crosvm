// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the "Vhost User" Virtio device as specified here -
//! <https://stefanha.github.io/virtio/vhost-user-slave.html#x1-2830007>. The
//! device implements the Virtio-Vhost-User protocol. It acts as a proxy between
//! the Vhost-user Master (referred to as the `Vhost-user sibling` in this
//! module) running in a sibling VM's VMM and Virtio-Vhost-User Slave
//! implementation (referred to as `device backend` in this module) in the
//! device VM.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::IoSlice;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use base::error;
use base::info;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::EventToken;
use base::EventType;
use base::FromRawDescriptor;
use base::IntoRawDescriptor;
use base::Protection;
use base::RawDescriptor;
use base::SafeDescriptor;
use base::ScmSocket;
use base::Tube;
use base::WaitContext;
use base::WorkerThread;
use data_model::DataInit;
use data_model::Le32;
use hypervisor::Datamatch;
use libc::recv;
use libc::MSG_DONTWAIT;
use libc::MSG_PEEK;
use resources::Alloc;
use sync::Mutex;
use uuid::Uuid;
use vm_control::MemSlot;
use vm_control::VmMemoryDestination;
use vm_control::VmMemoryRequest;
use vm_control::VmMemoryResponse;
use vm_control::VmMemorySource;
use vm_memory::udmabuf::UdmabufDriver;
use vm_memory::udmabuf::UdmabufDriverTrait;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vmm_vhost::connection::socket::Endpoint as SocketEndpoint;
use vmm_vhost::connection::EndpointExt;
use vmm_vhost::message::MasterReq;
use vmm_vhost::message::Req;
use vmm_vhost::message::SlaveReq;
use vmm_vhost::message::VhostUserMemory;
use vmm_vhost::message::VhostUserMemoryRegion;
use vmm_vhost::message::VhostUserMsgHeader;
use vmm_vhost::message::VhostUserMsgValidator;
use vmm_vhost::message::VhostUserShmemMapMsg;
use vmm_vhost::message::VhostUserShmemUnmapMsg;
use vmm_vhost::message::VhostUserU64;
use vmm_vhost::Error as VhostError;
use vmm_vhost::Protocol;
use vmm_vhost::Result as VhostResult;
use vmm_vhost::SlaveReqHelper;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::pci::PciBarConfiguration;
use crate::pci::PciBarIndex;
use crate::pci::PciBarPrefetchable;
use crate::pci::PciBarRegionType;
use crate::pci::PciCapability;
use crate::pci::PciCapabilityID;
use crate::virtio::copy_config;
use crate::virtio::ipc_memory_mapper::IpcMemoryMapper;
use crate::virtio::vhost::vhost_body_from_message_bytes;
use crate::virtio::vhost::vhost_header_from_bytes;
use crate::virtio::DescriptorChain;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::PciCapabilityType;
use crate::virtio::Queue;
use crate::virtio::Reader;
use crate::virtio::SignalableInterrupt;
use crate::virtio::VirtioDevice;
use crate::virtio::VirtioPciCap;
use crate::virtio::Writer;
use crate::virtio::VIRTIO_F_ACCESS_PLATFORM;
use crate::virtio::VIRTIO_MSI_NO_VECTOR;
use crate::PciAddress;
use crate::Suspendable;

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

const IO_BAR_INDEX: u8 = 2;
const SHMEM_BAR_INDEX: u8 = 4;

// Bar configuration.
// All offsets are from the starting of bar `IO_BAR_INDEX`.
const DOORBELL_OFFSET: u64 = 0;
// TODO(abhishekbh): Copied from lspci in qemu with VVU support.
const DOORBELL_SIZE: u64 = 0x2000;
const NOTIFICATIONS_OFFSET: u64 = DOORBELL_OFFSET + DOORBELL_SIZE;
const NOTIFICATIONS_SIZE: u64 = 0x1000;
const NOTIFICATIONS_END: u64 = NOTIFICATIONS_OFFSET + NOTIFICATIONS_SIZE;

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
#[derive(Debug, Clone, Copy, AsBytes, FromBytes)]
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
    // The call event is registered with KVM_IOEVENTFD so that the kernel signals it
    // directly. Although the proxy device doesn't write to it, we need to keep a reference
    // because unregistering the eventfd requires passing the it back to KVM_IOEVENTFD
    // with a deassign flag.
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

    // The bar representing the doorbell and notification.
    io_pci_bar: Alloc,

    // The bar representing the shared memory regions.
    shmem_pci_bar: Alloc,

    // Offset within `shmem_pci_bar`at which to allocate the next shared memory region,
    // corresponding to the |SET_MEM_TABLE| sibling message.
    shmem_pci_bar_mem_offset: usize,

    // Vring related data sent through |SET_VRING_KICK| and |SET_VRING_CALL|
    // messages.
    vrings: [Vring; MAX_VHOST_DEVICE_QUEUES],

    // Helps with communication and parsing messages from the sibling.
    slave_req_helper: SlaveReqHelper<SocketEndpoint<MasterReq>>,

    // Stores memory regions that the worker has asked the main thread to register.
    registered_memory: Vec<MemSlot>,

    // Channel for backend mesages.
    slave_req_fd: Option<SocketEndpoint<SlaveReq>>,

    // Driver for exporting memory as udmabufs for shared memory regions.
    udmabuf_driver: Option<UdmabufDriver>,

    // Iommu to translate IOVAs into GPAs for shared memory regions.
    iommu: Arc<Mutex<IpcMemoryMapper>>,

    // Exported regions mapped via shared memory regions.
    exported_regions:
        BTreeMap<u64 /* shmem_offset */, (u8, u64, u64) /* shmid, iova, size */>,

    // The currently pending unmap operation. Becomes `Some` when the proxy
    // receives a SHMEM_UNMAP message from the guest, and becomes `None` when
    // the proxy receives the corresponding SHMEM_UNMAP reply from the frontend.
    pending_unmap: Option<u64 /* shmem_offset */>,
}

#[derive(EventToken, Debug, Clone, PartialEq, Eq)]
enum Token {
    // Data is available on the Vhost-user sibling socket.
    SiblingSocket,
    // Data is available on the vhost-user backend socket.
    BackendSocket,
    // The device backend has made a read buffer available.
    RxQueue,
    // The device backend has sent a buffer to the |Worker::tx_queue|.
    TxQueue,
    // The sibling writes a kick event for the |index|-th vring.
    SiblingKick { index: usize },
    // crosvm has requested the device to shut down.
    Kill,
    // An iommu fault occured. Generally means the device process died.
    IommuFault,
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
    IommuFault,
    Killed,
    Disconnected,
}

// Trait used to process an incoming vhost-user message
trait RxAction: Req {
    // Checks whether the header is valid
    fn is_header_valid(hdr: &VhostUserMsgHeader<Self>) -> bool;

    // Process a message before forwarding it on to the virtqueue
    fn process_message(
        worker: &mut Worker,
        wait_ctx: &mut WaitContext<Token>,
        hdr: &VhostUserMsgHeader<Self>,
        payload: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<()>;

    // Get the endpoint from which to read messages
    fn get_ep(worker: &mut Worker) -> &mut SocketEndpoint<Self>;

    // Handle a failure processing a message
    fn handle_failure(worker: &mut Worker, hdr: &VhostUserMsgHeader<Self>) -> Result<()>;
}

impl RxAction for MasterReq {
    fn is_header_valid(hdr: &VhostUserMsgHeader<MasterReq>) -> bool {
        if hdr.is_reply() || hdr.get_version() != 0x1 {
            return false;
        }
        true
    }

    fn process_message(
        worker: &mut Worker,
        wait_ctx: &mut WaitContext<Token>,
        hdr: &VhostUserMsgHeader<MasterReq>,
        payload: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<()> {
        check_attached_files(hdr, &files)?;
        if !is_action_request(hdr) {
            return Ok(());
        }
        match hdr.get_code() {
            MasterReq::SET_MEM_TABLE => worker.set_mem_table(payload, files),
            MasterReq::SET_VRING_CALL => worker.set_vring_call(payload, files),
            MasterReq::SET_VRING_KICK => worker.set_vring_kick(wait_ctx, payload, files),
            MasterReq::SET_SLAVE_REQ_FD => worker.set_slave_req_fd(wait_ctx, files),
            _ => unimplemented!("unimplemented action message: {:?}", hdr.get_code()),
        }
    }

    fn get_ep(worker: &mut Worker) -> &mut SocketEndpoint<MasterReq> {
        worker.slave_req_helper.as_mut()
    }

    fn handle_failure(worker: &mut Worker, hdr: &VhostUserMsgHeader<MasterReq>) -> Result<()> {
        worker
            .slave_req_helper
            .send_ack_message(hdr, false)
            .context("failed to send ack")
    }
}

impl RxAction for SlaveReq {
    fn is_header_valid(hdr: &VhostUserMsgHeader<SlaveReq>) -> bool {
        if !hdr.is_reply() || hdr.get_version() != 0x1 {
            return false;
        }
        true
    }

    fn process_message(
        worker: &mut Worker,
        _wait_ctx: &mut WaitContext<Token>,
        hdr: &VhostUserMsgHeader<SlaveReq>,
        payload: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<()> {
        if files.is_some() {
            bail!("unexpected fd for {:?}", hdr.get_code());
        }
        match hdr.get_code() {
            SlaveReq::SHMEM_UNMAP => worker.handle_unmap_reply(payload),
            _ => Ok(()),
        }
    }

    fn get_ep(worker: &mut Worker) -> &mut SocketEndpoint<SlaveReq> {
        // We can only be here if we slave_req_fd became readable, so it must exist.
        worker.slave_req_fd.as_mut().unwrap()
    }

    fn handle_failure(_worker: &mut Worker, hdr: &VhostUserMsgHeader<SlaveReq>) -> Result<()> {
        // There's nothing we can do to directly handle this failure here.
        error!("failed to process reply to backend {:?}", hdr.get_code());
        Ok(())
    }
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
        kill_evt: Event,
    ) -> Result<ExitReason> {
        let fault_event = self
            .iommu
            .lock()
            .start_export_session()
            .context("failed to prepare for exporting")?;

        // Now that an export session has been started, we can export the virtqueues to
        // fetch the GuestAddresses corresponding to their IOVA-based config.
        self.rx_queue
            .export_memory(&self.mem)
            .context("failed to export rx_queue")?;
        self.tx_queue
            .export_memory(&self.mem)
            .context("failed to export tx_queue")?;

        // TODO(abhishekbh): Should interrupt.signal_config_changed be called here ?.
        let mut wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (&self.slave_req_helper, Token::SiblingSocket),
            (&rx_queue_evt, Token::RxQueue),
            (&tx_queue_evt, Token::TxQueue),
            (&kill_evt, Token::Kill),
            (&fault_event, Token::IommuFault),
        ])
        .context("failed to create a wait context object")?;

        // Represents if |slave_req_helper.endpoint| is being monitored for data
        // from the Vhost-user sibling.
        let mut sibling_socket_polling_enabled = true;
        loop {
            let events = wait_ctx.wait().context("failed to wait for events")?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::SiblingSocket | Token::BackendSocket => {
                        let res = if event.token == Token::SiblingSocket {
                            self.process_rx::<MasterReq>(&mut wait_ctx)
                        } else {
                            self.process_rx::<SlaveReq>(&mut wait_ctx)
                        };
                        match res {
                            Ok(RxqStatus::Processed) => (),
                            Ok(RxqStatus::DescriptorsExhausted) => {
                                // If the driver has no Rx buffers left, then no
                                // point monitoring the Vhost-user sibling for data. There
                                // would be no way to send it to the device backend.
                                self.set_rx_polling_state(&mut wait_ctx, EventType::None)?;
                                sibling_socket_polling_enabled = false;
                            }
                            Ok(RxqStatus::Disconnected) => {
                                return Ok(ExitReason::Disconnected);
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Token::RxQueue => {
                        if let Err(e) = rx_queue_evt.wait() {
                            bail!("error reading rx queue Event: {}", e);
                        }

                        // Rx buffers are available, now we should monitor the
                        // Vhost-user sibling connection for data.
                        if !sibling_socket_polling_enabled {
                            self.set_rx_polling_state(&mut wait_ctx, EventType::Read)?;
                            sibling_socket_polling_enabled = true;
                        }
                    }
                    Token::TxQueue => {
                        if let Err(e) = tx_queue_evt.wait() {
                            bail!("error reading tx queue event: {}", e);
                        }
                        self.process_tx()
                            .context("error processing tx queue event")?;
                    }
                    Token::IommuFault => {
                        return Ok(ExitReason::IommuFault);
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
                    Token::Kill => {
                        let _ = kill_evt.wait();
                        return Ok(ExitReason::Killed);
                    }
                }
            }
        }
    }

    // Set the target event to poll for on rx descriptors.
    fn set_rx_polling_state(
        &mut self,
        wait_ctx: &mut WaitContext<Token>,
        target_event: EventType,
    ) -> Result<()> {
        let fds = std::iter::once((
            &self.slave_req_helper as &dyn AsRawDescriptor,
            Token::SiblingSocket,
        ))
        .chain(
            self.slave_req_fd
                .as_ref()
                .map(|fd| (fd as &dyn AsRawDescriptor, Token::BackendSocket))
                .into_iter(),
        );
        for (fd, token) in fds {
            wait_ctx
                .modify(fd, target_event, token)
                .context("failed to set EPOLLIN on socket fd")?;
        }
        Ok(())
    }

    // Processes data from the Vhost-user sibling and forwards to the driver via Rx buffers.
    fn process_rx<R: RxAction>(&mut self, wait_ctx: &mut WaitContext<Token>) -> Result<RxqStatus> {
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
            let is_connected = match self.check_sibling_connection::<R>() {
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
            let (hdr, files) = R::get_ep(self)
                .recv_header()
                .context("failed to read Vhost-user sibling message header")?;
            let buf = self.get_sibling_msg_data::<R>(&hdr)?;

            let index = desc.index;
            let bytes_written = {
                let res = if !R::is_header_valid(&hdr) {
                    Err(anyhow!("invalid header for {:?}", hdr.get_code()))
                } else {
                    R::process_message(self, wait_ctx, &hdr, &buf, files)
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
                    R::handle_failure(self, &hdr)?
                }
            }
        }
    }

    // Returns the sibling connection status.
    fn check_sibling_connection<R: RxAction>(&mut self) -> ConnStatus {
        // Peek if any data is left on the Vhost-user sibling socket. If no, then
        // nothing to forwad to the device backend.
        let mut peek_buf = [0; 1];
        let raw_fd = R::get_ep(self).as_raw_descriptor();
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
    fn get_sibling_msg_data<R: RxAction>(
        &mut self,
        hdr: &VhostUserMsgHeader<R>,
    ) -> Result<Vec<u8>> {
        let buf = match hdr.get_size() {
            0 => vec![0u8; 0],
            len => {
                let rbuf = R::get_ep(self)
                    .recv_data(len as usize)
                    .context("failed to read Vhost-user sibling message payload")?;
                if rbuf.len() != len as usize {
                    R::handle_failure(self, hdr)?;
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
    fn forward_msg_to_device<R: Req>(
        &mut self,
        desc_chain: DescriptorChain,
        hdr: &VhostUserMsgHeader<R>,
        buf: &[u8],
    ) -> Result<u32> {
        let bytes_written = match Writer::new(self.mem.clone(), desc_chain) {
            Ok(mut writer) => {
                if writer.available_bytes()
                    < buf.len() + std::mem::size_of::<VhostUserMsgHeader<R>>()
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
    fn set_mem_table(&mut self, payload: &[u8], files: Option<Vec<File>>) -> Result<()> {
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

        let sibling_memory_size: u64 = contexts.iter().map(|region| region.memory_size).sum();
        if self.mem.memory_size() - self.shmem_pci_bar_mem_offset as u64 <= sibling_memory_size {
            bail!(
                "Memory size of Sibling VM ({}) must be smaller than the current memory size ({})",
                sibling_memory_size,
                self.mem.memory_size()
            );
        }

        for (region, file) in contexts.iter().zip(files.into_iter()) {
            let source = VmMemorySource::Descriptor {
                descriptor: SafeDescriptor::from(file),
                offset: region.mmap_offset,
                size: region.memory_size,
            };
            let dest = VmMemoryDestination::ExistingAllocation {
                allocation: self.shmem_pci_bar,
                offset: self.shmem_pci_bar_mem_offset as u64,
            };
            self.register_memory(source, dest)?;
            self.shmem_pci_bar_mem_offset += region.memory_size as usize;
        }
        Ok(())
    }

    fn register_memory(&mut self, source: VmMemorySource, dest: VmMemoryDestination) -> Result<()> {
        let request = VmMemoryRequest::RegisterMemory {
            source,
            dest,
            prot: Protection::read_write(),
        };
        self.send_memory_request(&request)?;
        Ok(())
    }

    // Sends memory mapping request to the main process. If successful adds the
    // mmaped info into `registered_memory`, else returns error.
    fn send_memory_request(&mut self, request: &VmMemoryRequest) -> Result<()> {
        self.main_process_tube
            .send(request)
            .context("sending mapping request to tube failed")?;

        let response = self
            .main_process_tube
            .recv()
            .context("receiving mapping request from tube failed")?;

        match response {
            VmMemoryResponse::Ok => Ok(()),
            VmMemoryResponse::RegisterMemory { slot, .. } => {
                // Store the registered memory slot so we can unregister it when the thread ends.
                self.registered_memory.push(slot);
                Ok(())
            }
            VmMemoryResponse::Err(e) => {
                bail!("memory mapping failed: {}", e);
            }
        }
    }

    // Handles |SET_VRING_CALL|.
    fn set_vring_call(&mut self, payload: &[u8], files: Option<Vec<File>>) -> Result<()> {
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
        let evt = unsafe { Event::from_raw_descriptor(file.into_raw_descriptor()) };

        self.send_memory_request(&VmMemoryRequest::IoEventWithAlloc {
            evt: evt.try_clone().context("failed to dup event")?,
            allocation: self.io_pci_bar,
            offset: DOORBELL_OFFSET + DOORBELL_OFFSET_MULTIPLIER as u64 * index as u64,
            datamatch: Datamatch::AnyLength,
            register: true,
        })
        .context("failed to register IoEvent")?;

        // Save the eventfd because we will need to supply it to KVM to unregister the eventfd.
        self.vrings[index as usize].call_evt = Some(evt);
        Ok(())
    }

    // Handles |SET_VRING_KICK|. If successful it sets up an event handler for a
    // write to the sent kick fd.
    fn set_vring_kick(
        &mut self,
        wait_ctx: &mut WaitContext<Token>,
        payload: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<()> {
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

    // Handles |SET_SLAVE_REQ_FD|. Prepares the proxy to handle backend messages by
    // proxying messages/replies to/from the slave_req_fd.
    fn set_slave_req_fd(
        &mut self,
        wait_ctx: &mut WaitContext<Token>,
        files: Option<Vec<File>>,
    ) -> Result<()> {
        // Validated by check_attached_files
        let mut files = files.expect("missing files");
        let file = files.pop().context("missing file for set_slave_req_fd")?;
        if !files.is_empty() {
            bail!("invalid file count for SET_SLAVE_REQ_FD {}", files.len());
        }

        self.udmabuf_driver = Some(UdmabufDriver::new().context("failed to get udmabuf driver")?);
        // Safe because we own the file.
        let socket = unsafe { UnixStream::from_raw_descriptor(file.into_raw_descriptor()) };

        wait_ctx
            .add(&socket, Token::BackendSocket)
            .context("failed to set EPOLLIN on socket fd")?;

        self.slave_req_fd = Some(SocketEndpoint::from(socket));
        Ok(())
    }

    // Exports the udmabuf necessary to fulfil the |msg| mapping request.
    fn handle_map_message(
        &mut self,
        msg: &VhostUserShmemMapMsg,
    ) -> Result<Box<dyn AsRawDescriptor>> {
        let regions = self
            .iommu
            .lock()
            .export(msg.fd_offset, msg.len)
            .context("failed to export")?;

        let prot = Protection::from(msg.flags);
        let regions = regions
            .iter()
            .map(|r| {
                if !r.prot.allows(&prot) {
                    Err(anyhow!("invalid permissions"))
                } else {
                    Ok((r.gpa, r.len as usize))
                }
            })
            .collect::<Result<Vec<(GuestAddress, usize)>>>()?;

        // udmabuf_driver is set at the same time as slave_req_fd, so if we've
        // received a message on slave_req_fd, udmabuf_driver must be present.
        let udmabuf = self
            .udmabuf_driver
            .as_ref()
            .expect("missing udmabuf driver")
            .create_udmabuf(&self.mem, &regions)
            .context("failed to create udmabuf")?;

        self.exported_regions
            .insert(msg.shm_offset, (msg.shmid, msg.fd_offset, msg.len));

        Ok(Box::new(udmabuf))
    }

    fn handle_unmap_message(&mut self, msg: &VhostUserShmemUnmapMsg) -> Result<()> {
        if self.pending_unmap.is_some() {
            bail!("simultanious unmaps not supported");
        }
        let shm_offset = msg.shm_offset;
        self.exported_regions
            .get(&shm_offset)
            .context("unknown shmid")?;
        self.pending_unmap = Some(shm_offset);
        Ok(())
    }

    fn handle_unmap_reply(&mut self, payload: &[u8]) -> Result<()> {
        let ack = VhostUserU64::from_slice(payload)
            .context("failed to parse ack")?
            .value;
        if ack != 0 {
            bail!("failed to unmap region {}", ack);
        }

        let pending_unmap = self.pending_unmap.take().context("unexpected unmap ack")?;
        // Both handle_unmap_message and unmap_all_exported_shmem ensure that
        // self.pending_unmap is in the exported_regions map.
        let (_, iova, size) = self
            .exported_regions
            .remove(&pending_unmap)
            .expect("missing region");
        self.iommu
            .lock()
            .release(iova, size)
            .context("failed to release export")?;

        Ok(())
    }

    fn process_message_from_backend(
        &mut self,
        mut msg: Vec<u8>,
    ) -> Result<(Vec<u8>, Option<Box<dyn AsRawDescriptor>>)> {
        // The message was already parsed as a MasterReq, so this can't fail
        let hdr = vhost_header_from_bytes::<SlaveReq>(&msg).unwrap();

        let fd = match hdr.get_code() {
            SlaveReq::SHMEM_MAP => {
                let mut msg =
                    vhost_body_from_message_bytes(&mut msg).context("incomplete message")?;
                let fd = self
                    .handle_map_message(msg)
                    .context("failed to handle map message")?;
                // VVU reuses the fd_offset field for the IOVA of the buffer. The
                // udmabuf corresponds to exactly what should be mapped, so set
                // fd_offset to 0 for regular vhost-user.
                msg.fd_offset = 0;
                Some(fd)
            }
            SlaveReq::SHMEM_UNMAP => {
                let msg = vhost_body_from_message_bytes(&mut msg).context("incomplete message")?;
                self.handle_unmap_message(msg)
                    .context("failed to handle unmap message")?;
                None
            }
            _ => None,
        };
        Ok((msg, fd))
    }

    // Processes data from the device backend (via virtio Tx queue) and forward it to
    // the Vhost-user sibling over its socket connection.
    fn process_tx(&mut self) -> Result<()> {
        while let Some(desc_chain) = self.tx_queue.pop(&self.mem) {
            let index = desc_chain.index;
            match Reader::new(self.mem.clone(), desc_chain) {
                Ok(mut reader) => {
                    let expected_count = reader.available_bytes();
                    let mut msg = vec![0; expected_count];
                    reader
                        .read_exact(&mut msg)
                        .context("virtqueue read failed")?;

                    // This may be a SlaveReq, but the bytes of any valid SlaveReq
                    // are also a valid MasterReq.
                    let hdr =
                        vhost_header_from_bytes::<MasterReq>(&msg).context("message too short")?;
                    let (dest, (msg, fd)) = if hdr.is_reply() {
                        (self.slave_req_helper.as_mut().as_mut(), (msg, None))
                    } else {
                        let processed_msg = self.process_message_from_backend(msg)?;
                        (
                            self.slave_req_fd
                                .as_mut()
                                .context("missing slave_req_fd")?
                                .as_mut(),
                            processed_msg,
                        )
                    };

                    if let Some(fd) = fd {
                        let written = dest
                            .send_with_fd(&[IoSlice::new(msg.as_slice())], fd.as_raw_descriptor())
                            .context("failed to foward message")?;
                        dest.write_all(&msg[written..])
                    } else {
                        dest.write_all(msg.as_slice())
                    }
                    .context("failed to foward message")?;
                }
                Err(e) => error!("failed to create Reader: {}", e),
            }
            self.tx_queue.add_used(&self.mem, index, 0);
            if !self.tx_queue.trigger_interrupt(&self.mem, &self.interrupt) {
                panic!("failed inject tx queue interrupt");
            }
        }
        Ok(())
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
            .wait()
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

    // Clean up memory regions that the worker registered so that the device can start another
    // worker later.
    fn cleanup_registered_memory(&mut self) {
        while let Some(slot) = self.registered_memory.pop() {
            let req = VmMemoryRequest::UnregisterMemory(slot);
            if let Err(e) = self.send_memory_request(&req) {
                error!("failed to unregister memory slot: {}", e);
            }
        }
    }

    // Unmaps all exported regions
    fn release_exported_regions(&mut self) -> Result<()> {
        self.rx_queue.release_exported_memory();
        self.tx_queue.release_exported_memory();

        match self.unmap_all_exported_shmem() {
            Ok(()) => Ok(()),
            Err(VhostError::SocketBroken(_)) | Err(VhostError::Disconnect) => {
                // If the socket is broken or the sibling is disconnected, then we assume
                // the sibling is no longer running, so unmapping is unnecessary.
                for (_, iova, size) in self.exported_regions.values() {
                    self.iommu
                        .lock()
                        .release(*iova, *size)
                        .context("failed to release export")?;
                }
                Ok(())
            }
            err => err.context("error while unmapping exported regions"),
        }
    }

    // Unmaps anything mapped into the shmem regions.
    fn unmap_all_exported_shmem(&mut self) -> VhostResult<()> {
        loop {
            let endpoint = match self.slave_req_fd.as_mut() {
                Some(e) => e,
                None => return Ok(()),
            };

            // There may already be pending unmap operation when we enter the loop,
            // so reply handling needs to come first.
            if self.pending_unmap.is_some() {
                loop {
                    let (hdr, _) = endpoint.recv_header()?;
                    let payload = endpoint.recv_data(hdr.get_size() as usize)?;
                    // This function is only called when the worker is aborting, so
                    // there's nothing to do for other replies - just drop them.
                    if hdr.get_code() == SlaveReq::SHMEM_UNMAP {
                        if let Err(e) = self.handle_unmap_reply(&payload) {
                            error!("failed to unmap: {:?}", e);
                            return Err(VhostError::SlaveInternalError);
                        }
                        break;
                    }
                }
            } else if let Some((offset, (shmid, _, size))) = self.exported_regions.iter().next() {
                let hdr = VhostUserMsgHeader::new(
                    SlaveReq::SHMEM_UNMAP,
                    0,
                    std::mem::size_of::<VhostUserShmemUnmapMsg>() as u32,
                );
                let msg = VhostUserShmemUnmapMsg::new(*shmid, *offset, *size);
                endpoint.send_message(&hdr, &msg, None)?;
                self.pending_unmap = Some(*offset);
            } else {
                break;
            }
        }
        Ok(())
    }

    // Unregister all vring_call eventfds.
    fn unregister_vring_call_eventfds(&mut self) -> Result<()> {
        let mut last_err = None;
        let vring_call_evts: Vec<(usize, Event)> = self
            .vrings
            .iter_mut()
            .enumerate()
            .filter_map(|(idx, v)| v.call_evt.take().map(|e| (idx, e)))
            .collect();
        for (idx, evt) in vring_call_evts {
            if let Err(e) = self.send_memory_request(&VmMemoryRequest::IoEventWithAlloc {
                evt,
                allocation: self.io_pci_bar,
                offset: DOORBELL_OFFSET + DOORBELL_OFFSET_MULTIPLIER as u64 * idx as u64,
                datamatch: Datamatch::AnyLength,
                register: false,
            }) {
                error!("failed to unregister ioevent: idx={}:, {:#}", idx, e);
                last_err = Some(e);
            }
        }
        last_err.map_or(Ok(()), Err)
    }
}

// Doorbell capability of the proxy device.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, AsBytes)]
pub struct VirtioPciDoorbellCap {
    cap: VirtioPciCap,
    doorbell_off_multiplier: Le32,
}

impl PciCapability for VirtioPciDoorbellCap {
    fn bytes(&self) -> &[u8] {
        self.as_bytes()
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
#[allow(clippy::large_enum_variant)]
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

        iommu: Arc<Mutex<IpcMemoryMapper>>,
    },
    /// The worker thread is running.
    Running,
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

    // The bar representing the doorbell and notification.
    io_pci_bar: Option<Alloc>,
    // The bar representing the shared memory regions.
    shmem_pci_bar: Option<Alloc>,
    // The device backend queue index selected by the driver by writing to the
    // Notifications region at offset `NOTIFICATIONS_MSIX_VECTOR_SELECT_OFFSET`
    // in the bar. This points into `notification_msix_vectors`.
    notification_select: Option<u16>,
    // Stores msix vectors corresponding to each device backend queue.
    notification_msix_vectors: [Option<u16>; MAX_VHOST_DEVICE_QUEUES],

    // PCI address that this device needs to be allocated if specified.
    pci_address: Option<PciAddress>,

    // The device's state.
    // The value is wrapped with `Arc<Mutex<_>>` because it can be modified from the worker thread
    // as well as the main device thread.
    state: Arc<Mutex<State>>,

    // The worker thread for this proxy device, if it has been started.
    worker_thread: Option<WorkerThread<Result<()>>>,

    iommu: Option<Arc<Mutex<IpcMemoryMapper>>>,
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
            io_pci_bar: None,
            shmem_pci_bar: None,
            notification_select: None,
            notification_msix_vectors: [None; MAX_VHOST_DEVICE_QUEUES],
            state: Arc::new(Mutex::new(State::Initialized {
                main_process_tube,
                listener,
            })),
            pci_address,
            worker_thread: None,
            iommu: None,
        })
    }

    fn check_io_bar_metadata(&self, bar_index: PciBarIndex) -> Result<()> {
        if bar_index != IO_BAR_INDEX as usize {
            bail!("invalid bar index: {}", bar_index);
        }

        if self.io_pci_bar.is_none() {
            bail!("bar is not allocated for {}", bar_index);
        }

        Ok(())
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

    // Checks the device's state and starts a worker thread if it's ready.
    // The thread will process all messages to this device and send out messages in response.
    fn try_starting_worker(&mut self) {
        // If a thread is already running, do nothing here.
        if self.worker_thread.is_some() {
            return;
        }

        let mut state = self.state.lock();

        // Check the device state to decide whether start a new worker thread.
        // Note that this check cannot be done by the caller of this function because `self.state`
        // can be modified by another thread technically.
        match *state {
            State::Activated { .. } => (),
            _ => {
                // If the device is not ready, do nothing here.
                return;
            }
        };

        // We'll prepare values that will be used in a new thread below.

        // Clone to pass it into a worker thread.
        let state_cloned = Arc::clone(&self.state);

        // Use `State::Invalid` as the intermediate state while preparing the proper next state.
        // Once a worker thread is successfully started, `self.state` will be updated to `Running`.
        let old_state: State = std::mem::replace(&mut *state, State::Invalid);

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
            iommu,
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
                iommu,
            } => (
                main_process_tube,
                listener,
                mem,
                interrupt,
                rx_queue,
                tx_queue,
                rx_queue_evt,
                tx_queue_evt,
                iommu,
            ),
            s => {
                // Unreachable because we've checked the state at the beginning of this function.
                unreachable!("invalid state: {}", s)
            }
        };

        // Safe because a PCI bar is guaranteed to be allocated at this point.
        let io_pci_bar = self.io_pci_bar.expect("PCI bar unallocated");
        let shmem_pci_bar = self.shmem_pci_bar.expect("PCI bar unallocated");

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
        self.worker_thread = Some(WorkerThread::start("v_vhost_user", move |kill_evt| {
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
                io_pci_bar,
                shmem_pci_bar,
                shmem_pci_bar_mem_offset: 0,
                vrings,
                slave_req_helper,
                registered_memory: Vec::new(),
                slave_req_fd: None,
                udmabuf_driver: None,
                iommu: iommu.clone(),
                exported_regions: BTreeMap::new(),
                pending_unmap: None,
            };

            let run_result = worker.run(
                rx_queue_evt.try_clone().unwrap(),
                tx_queue_evt.try_clone().unwrap(),
                kill_evt,
            );

            if let Err(e) = worker.release_exported_regions() {
                error!("failed to release exported memory: {:?}", e);
                *state_cloned.lock() = State::Invalid;
                return Ok(());
            }

            // Unregister any vring_call eventfds in case we need to
            // reuse the proxy device later.
            if let Err(e) = worker.unregister_vring_call_eventfds() {
                error!("error unmapping ioevent: {:#}", e);
                *state_cloned.lock() = State::Invalid;
                return Ok(());
            }

            match run_result {
                Ok(ExitReason::IommuFault) => {
                    info!("worker thread exited due to IOMMU fault");
                    Ok(())
                }

                Ok(ExitReason::Killed) => {
                    info!("worker thread exited successfully");
                    Ok(())
                }
                Ok(ExitReason::Disconnected) => {
                    info!("worker thread exited: sibling disconnected");

                    worker.cleanup_registered_memory();

                    let mut state = state_cloned.lock();
                    let Worker {
                        mem,
                        interrupt,
                        rx_queue,
                        tx_queue,
                        main_process_tube,
                        ..
                    } = worker;

                    *state = State::Activated {
                        main_process_tube,
                        listener,
                        mem,
                        interrupt,
                        rx_queue,
                        tx_queue,
                        rx_queue_evt,
                        tx_queue_evt,
                        iommu,
                    };

                    Ok(())
                }
                Err(e) => {
                    error!("worker thread exited with an error: {:?}", e);
                    Ok(())
                }
            }
        }));
        *state = State::Running;
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

        match &*self.state.lock() {
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
            self.config.as_bytes(),
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
        if self.config.is_slave_up() {
            self.try_starting_worker();
        }
    }

    fn get_device_caps(&self) -> Vec<Box<dyn crate::pci::PciCapability>> {
        // Allocate capabilities as per sections 5.7.7.5, 5.7.7.6, 5.7.7.7 of
        // the link at the top of the file. The PCI bar is organized in the
        // following format |Doorbell|Notification|Shared Memory|.
        let mut doorbell_virtio_pci_cap = VirtioPciCap::new(
            PciCapabilityType::DoorbellConfig,
            IO_BAR_INDEX,
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
            IO_BAR_INDEX,
            NOTIFICATIONS_OFFSET as u32,
            NOTIFICATIONS_SIZE as u32,
        ));

        let shared_memory = Box::new(VirtioPciCap::new(
            PciCapabilityType::SharedMemoryConfig,
            SHMEM_BAR_INDEX,
            0,
            self.device_bar_size as u32,
        ));

        vec![doorbell, notification, shared_memory]
    }

    fn get_device_bars(&mut self, address: PciAddress) -> Vec<PciBarConfiguration> {
        // Allocate one PCI bar for the doorbells and notifications, and a second
        // bar for shared memory. These are 64 bit bars, and go in bars 2|3 and 4|5,
        // respectively. The shared memory bar is prefetchable, as recommended
        // by the VVU spec.
        self.io_pci_bar = Some(Alloc::PciBar {
            bus: address.bus,
            dev: address.dev,
            func: address.func,
            bar: IO_BAR_INDEX,
        });
        self.shmem_pci_bar = Some(Alloc::PciBar {
            bus: address.bus,
            dev: address.dev,
            func: address.func,
            bar: SHMEM_BAR_INDEX,
        });

        vec![
            PciBarConfiguration::new(
                IO_BAR_INDEX as usize,
                NOTIFICATIONS_END.next_power_of_two(),
                PciBarRegionType::Memory64BitRegion,
                // Accesses to the IO bar trigger EPT faults, so it doesn't matter
                // whether or not the bar is prefetchable.
                PciBarPrefetchable::NotPrefetchable,
            ),
            PciBarConfiguration::new(
                SHMEM_BAR_INDEX as usize,
                self.device_bar_size,
                PciBarRegionType::Memory64BitRegion,
                // The shared memory bar is for regular memory mappings and
                // should be prefetchable for better performance.
                PciBarPrefetchable::Prefetchable,
            ),
        ]
    }

    fn set_iommu(&mut self, iommu: &Arc<Mutex<IpcMemoryMapper>>) {
        self.iommu = Some(iommu.clone());
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<(Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() != NUM_PROXY_DEVICE_QUEUES {
            return Err(anyhow!("bad queue length: {}", queues.len()));
        }

        let (rx_queue, rx_queue_evt) = queues.remove(0);
        let (tx_queue, tx_queue_evt) = queues.remove(0);

        let mut state = self.state.lock();
        // Use `State::Invalid` as the intermediate state here.
        let old_state: State = std::mem::replace(&mut *state, State::Invalid);

        match old_state {
            State::Initialized {
                listener,
                main_process_tube,
            } => {
                *state = State::Activated {
                    listener,
                    main_process_tube,
                    mem,
                    interrupt,
                    rx_queue,
                    tx_queue,
                    rx_queue_evt,
                    tx_queue_evt,
                    iommu: self.iommu.take().unwrap(),
                };
            }
            s => {
                // If the old state is not `Initialized`, it becomes `Invalid`.
                return Err(anyhow!(
                    "activate() is called in an unexpected state: {}",
                    s
                ));
            }
        };
        Ok(())
    }

    fn read_bar(&mut self, bar_index: PciBarIndex, offset: u64, data: &mut [u8]) {
        if let Err(e) = self.check_io_bar_metadata(bar_index) {
            error!("invalid bar metadata: {}", e);
            return;
        }

        if (NOTIFICATIONS_OFFSET..NOTIFICATIONS_END).contains(&offset) {
            self.read_bar_notifications(offset - NOTIFICATIONS_OFFSET, data);
        } else {
            error!("addr is outside known region for reads");
        }
    }

    fn write_bar(&mut self, bar_index: PciBarIndex, offset: u64, data: &[u8]) {
        if let Err(e) = self.check_io_bar_metadata(bar_index) {
            error!("invalid bar metadata: {}", e);
            return;
        }

        if (DOORBELL_OFFSET..NOTIFICATIONS_OFFSET).contains(&offset) {
            // The vring_call eventfds which back doorbells are registered with the
            // host kernel via KVM_IOEVENTFD, so the host kernel will signal them
            // directly. If we're here, then that means the guest wrote to a doorbell
            // without a registered eventfd, so there's nothing for us to signal.
            warn!(
                "doorbell write with no corresponding evenetfd: offset={}",
                offset
            );
        } else if (NOTIFICATIONS_OFFSET..NOTIFICATIONS_END).contains(&offset) {
            self.write_bar_notifications(offset - NOTIFICATIONS_OFFSET, data);
        } else {
            error!("addr is outside known region for writes");
        }
    }

    fn reset(&mut self) -> bool {
        info!("resetting vvu-proxy device");

        let mut state = self.state.lock();
        match std::mem::replace(&mut *state, State::Invalid) {
            old_state @ State::Initialized { .. } => {
                *state = old_state;
            }
            State::Activated {
                listener,
                main_process_tube,
                ref mut rx_queue,
                ref mut tx_queue,
                ..
            } => {
                rx_queue.reset_counters();
                tx_queue.reset_counters();
                *state = State::Initialized {
                    listener,
                    main_process_tube,
                };
            }
            State::Running => {
                // TODO(b/216407443): The current implementation doesn't support the case where
                // vvu-proxy is reset while running.
                // So, the state is changed to `Invalid` in this case below.
                // We should support this case eventually.
                // e.g. The VVU device backend in the guest is killed unexpectedly.
                // To support this case, we might need to reset iommu's state as well.

                // Drop the lock, as the worker thread might change the state.
                drop(state);

                if let Some(worker_thread) = self.worker_thread.take() {
                    if let Err(e) = worker_thread.stop() {
                        error!("failed to get back resources: {:?}", e);
                    }
                }

                let mut state = self.state.lock();
                *state = State::Invalid;
            }
            State::Invalid => {
                // TODO(b/216407443): Support this case.
            }
        };

        true
    }

    fn pci_address(&self) -> Option<PciAddress> {
        self.pci_address
    }
}

impl Suspendable for VirtioVhostUser {}
