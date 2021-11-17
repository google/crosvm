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

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread;

use base::{error, info, Event, EventType, PollToken, RawDescriptor, WaitContext};
use data_model::{DataInit, Le32};
use resources::Alloc;
use vm_memory::GuestMemory;

use crate::pci::{
    PciBarConfiguration, PciBarIndex, PciBarPrefetchable, PciBarRegionType, PciCapability,
    PciCapabilityID,
};
use crate::virtio::descriptor_utils::Error as DescriptorUtilsError;
use crate::virtio::{
    copy_config, Interrupt, PciCapabilityType, Queue, Reader, VirtioDevice, VirtioPciCap, Writer,
    TYPE_VHOST_USER,
};
use crate::PciAddress;

use remain::sorted;
use thiserror::Error as ThisError;

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

struct Worker {
    mem: GuestMemory,
    interrupt: Interrupt,
    rx_queue: Queue,
    tx_queue: Queue,
    sibling_socket: UnixStream,
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

        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (&self.sibling_socket, Token::SiblingSocket),
            (&rx_queue_evt, Token::RxQueue),
            (&tx_queue_evt, Token::TxQueue),
            (&kill_evt, Token::Kill),
        ])
        .map_err(Error::CreateWaitContext)?;

        let mut sibling_socket_polling_enabled = true;
        'wait: loop {
            let events = wait_ctx.wait().map_err(Error::WaitError)?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::SiblingSocket => match self.process_rx() {
                        Ok(()) => {}
                        Err(Error::RxDescriptorsExhausted) => {
                            wait_ctx
                                .modify(&self.sibling_socket, EventType::None, Token::SiblingSocket)
                                .map_err(Error::WaitContextDisableSiblingVmSocket)?;
                            sibling_socket_polling_enabled = false;
                        }
                        Err(e) => return Err(e),
                    },
                    Token::RxQueue => {
                        if let Err(e) = rx_queue_evt.read() {
                            error!("net: error reading rx queue Event: {}", e);
                            break 'wait;
                        }
                        if !sibling_socket_polling_enabled {
                            wait_ctx
                                .modify(&self.sibling_socket, EventType::Read, Token::SiblingSocket)
                                .map_err(Error::WaitContextEnableSiblingVmSocket)?;
                            sibling_socket_polling_enabled = true;
                        }
                    }
                    Token::TxQueue => {
                        if let Err(e) = tx_queue_evt.read() {
                            error!("error reading rx queue event: {}", e);
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

    fn process_rx(&mut self) -> Result<()> {
        let mut exhausted_queue = false;

        // Read as many frames as possible.
        loop {
            let desc_chain = match self.rx_queue.peek(&self.mem) {
                Some(desc) => desc,
                None => {
                    exhausted_queue = true;
                    break;
                }
            };

            let index = desc_chain.index;
            let bytes_written = match Writer::new(self.mem.clone(), desc_chain) {
                Ok(mut writer) => {
                    match writer.write_from(&mut self.sibling_socket, writer.available_bytes()) {
                        Ok(_) => {}
                        Err(ref e) if e.kind() == io::ErrorKind::WriteZero => {
                            error!("rx: buffer is too small to hold frame");
                            break;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // No more to read.
                            break;
                        }
                        Err(e) => {
                            error!("rx: failed to write slice: {}", e);
                            return Err(Error::WriteBuffer(e));
                        }
                    };

                    writer.bytes_written() as u32
                }
                Err(e) => {
                    error!("failed to create Writer: {}", e);
                    0
                }
            };

            // The driver is able to deal with a descriptor with 0 bytes written.
            self.rx_queue.pop_peeked(&self.mem);
            self.rx_queue.add_used(&self.mem, index, bytes_written);
            self.rx_queue.trigger_interrupt(&self.mem, &self.interrupt);
        }

        if exhausted_queue {
            Err(Error::RxDescriptorsExhausted)
        } else {
            Ok(())
        }
    }

    fn process_tx(&mut self) {
        while let Some(desc_chain) = self.tx_queue.pop(&self.mem) {
            let index = desc_chain.index;
            match Reader::new(self.mem.clone(), desc_chain) {
                Ok(mut reader) => {
                    let expected_count = reader.available_bytes();
                    match reader.read_to(&mut self.sibling_socket, expected_count) {
                        Ok(count) => {
                            // Datagram messages should be sent as whole.
                            // TODO: Should this be a panic! as it will violate the Linux API.
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
            self.tx_queue.trigger_interrupt(&self.mem, &self.interrupt);
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

pub struct VirtioVhostUser {
    // Path to open and accept a socket connection from the Vhost-user sibling.
    sibling_socket: Option<UnixStream>,

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

    // Is Vhost-user sibling connected.
    sibling_connected: bool,
}

impl VirtioVhostUser {
    pub fn new(sibling_socket_path: &Path) -> Result<VirtioVhostUser> {
        let listener = UnixListener::bind(sibling_socket_path).map_err(Error::CreateListener)?;
        let (socket, _) = listener.accept().map_err(Error::AcceptConnection)?;
        Ok(VirtioVhostUser {
            sibling_socket: Some(socket),
            config: Default::default(),
            kill_evt: None,
            worker_thread: None,
            pci_bar: None,
            notification_select: None,
            notification_msix_vectors: [None; MAX_VHOST_DEVICE_QUEUES],
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
    fn wait_for_sibling(&self) {
        // TODO(abhishekbh): Implement incoming sibling connection.
        info!("wait for sibling to connect");
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
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        vec![]
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
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<Event>,
    ) {
        if queues.len() != NUM_PROXY_DEVICE_QUEUES || queue_evts.len() != NUM_PROXY_DEVICE_QUEUES {
            error!("bad queue length: {} {}", queues.len(), queue_evts.len());
            return;
        }

        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed creating kill Event pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        // The socket will be moved to the worker thread. Guaranteed to be valid as a connection is
        // ensured in `VirtioVhostUser::new`.
        let sibling_socket = self
            .sibling_socket
            .take()
            .expect("socket connection missing");

        let worker_result = thread::Builder::new()
            .name("virtio_vhost_user".to_string())
            .spawn(move || {
                let rx_queue = queues.remove(0);
                let tx_queue = queues.remove(0);
                let mut worker = Worker {
                    mem,
                    interrupt,
                    rx_queue,
                    tx_queue,
                    sibling_socket,
                };
                let rx_queue_evt = queue_evts.remove(0);
                let tx_queue_evt = queue_evts.remove(0);
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
        // TODO
        true
    }
}
