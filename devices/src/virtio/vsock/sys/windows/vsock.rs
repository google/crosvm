// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::windows::io::RawHandle;
use std::rc::Rc;
use std::result;
use std::sync::Arc;
use std::thread;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::info;
use base::named_pipes;
use base::named_pipes::BlockingMode;
use base::named_pipes::FramingMode;
use base::named_pipes::OverlappedWrapper;
use base::named_pipes::PipeConnection;
use base::warn;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::Event;
use base::EventExt;
use base::WorkerThread;
use cros_async::select2;
use cros_async::select6;
use cros_async::sync::RwLock;
use cros_async::AsyncError;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::SelectResult;
use data_model::Le32;
use data_model::Le64;
use futures::channel::mpsc;
use futures::pin_mut;
use futures::stream::FuturesUnordered;
use futures::FutureExt;
use futures::SinkExt;
use futures::StreamExt;
use remain::sorted;
use thiserror::Error as ThisError;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::virtio::async_utils;
use crate::virtio::copy_config;
use crate::virtio::vsock::sys::windows::protocol::virtio_vsock_config;
use crate::virtio::vsock::sys::windows::protocol::virtio_vsock_event;
use crate::virtio::vsock::sys::windows::protocol::virtio_vsock_hdr;
use crate::virtio::vsock::sys::windows::protocol::vsock_op;
use crate::virtio::vsock::sys::windows::protocol::TYPE_STREAM_SOCKET;
use crate::virtio::DescriptorChain;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::SignalableInterrupt;
use crate::virtio::VirtioDevice;
use crate::virtio::Writer;
use crate::Suspendable;

#[sorted]
#[derive(ThisError, Debug)]
pub enum VsockError {
    #[error("Failed to await next descriptor chain from queue: {0}")]
    AwaitQueue(AsyncError),
    #[error("OverlappedWrapper error.")]
    BadOverlappedWrapper,
    #[error("Failed to clone descriptor: {0}")]
    CloneDescriptor(SysError),
    #[error("Failed to create EventAsync: {0}")]
    CreateEventAsync(AsyncError),
    #[error("Failed to create wait context: {0}")]
    CreateWaitContext(SysError),
    #[error("Failed to read queue: {0}")]
    ReadQueue(io::Error),
    #[error("Failed to reset event object: {0}")]
    ResetEventObject(SysError),
    #[error("Failed to run executor: {0}")]
    RunExecutor(AsyncError),
    #[error("Failed to write to pipe, port {0}: {1}")]
    WriteFailed(PortPair, io::Error),
    #[error("Failed to write queue: {0}")]
    WriteQueue(io::Error),
}
pub type Result<T> = result::Result<T, VsockError>;

// Vsock has three virt IO queues: rx, tx, and event.
const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE];
// We overload port numbers so that if message is to be received from
// CONNECTION_EVENT_PORT_NUM (invalid port number), we recognize that a
// new connection was set up.
const CONNECTION_EVENT_PORT_NUM: u32 = u32::MAX;

/// Number of bytes in a kilobyte. Used to simplify and clarify buffer size definitions.
const KB: usize = 1024;

/// Size of the buffer we read into from the host side named pipe. Note that data flows from the
/// host pipe -> this buffer -> rx queue.
/// This should be large enough to facilitate fast transmission of host data, see b/232950349.
const TEMP_READ_BUF_SIZE_BYTES: usize = 4 * KB;

/// In the case where the host side named pipe does not have a specified buffer size, we'll default
/// to telling the guest that this is the amount of extra RX space available (e.g. buf_alloc).
/// This should be larger than the volume of data that the guest will generally send at one time to
/// minimize credit update packtes (see MIN_FREE_BUFFER_PCT below).
const DEFAULT_BUF_ALLOC_BYTES: usize = 128 * KB;

/// Minimum free buffer threshold to notify the peer with a credit update
/// message. This is in case we are ingesting many messages without an
/// opportunity to send a message back to the peer with a buffer size update.
/// This value is a percentage of `buf_alloc`.
/// TODO(b/204246759): This value was chosen without much more thought than "it
/// works". It should probably be adjusted, along with DEFAULT_BUF_ALLOC, to a
/// value that makes empirical sense for the packet sizes that we expect to
/// receive.
/// TODO(b/239848326): Replace float with integer, in order to remove risk
/// of losing precision. Ie. change to `10` and perform
/// `FOO * MIN_FREE_BUFFER_PCT / 100`
const MIN_FREE_BUFFER_PCT: f64 = 0.1;

// Number of packets to buffer in the tx processing channels.
const CHANNEL_SIZE: usize = 256;

/// Virtio device for exposing entropy to the guest OS through virtio.
pub struct Vsock {
    guest_cid: u64,
    host_guid: Option<String>,
    features: u64,
    worker_thread: Option<WorkerThread<()>>,
}

impl Vsock {
    pub fn new(guest_cid: u64, host_guid: Option<String>, base_features: u64) -> Result<Vsock> {
        Ok(Vsock {
            guest_cid,
            host_guid,
            features: base_features,
            worker_thread: None,
        })
    }

    fn get_config(&self) -> virtio_vsock_config {
        virtio_vsock_config {
            guest_cid: Le64::from(self.guest_cid),
        }
    }
}

impl VirtioDevice for Vsock {
    fn keep_rds(&self) -> Vec<RawHandle> {
        Vec::new()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.get_config().as_bytes(), offset);
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Vsock
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, value: u64) {
        self.features &= value;
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<(Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() != QUEUE_SIZES.len() {
            return Err(anyhow!(
                "Failed to activate vsock device. queues.len(): {} != {}",
                queues.len(),
                QUEUE_SIZES.len(),
            ));
        }

        let (rx_queue, rx_queue_evt) = queues.remove(0);
        let (tx_queue, tx_queue_evt) = queues.remove(0);
        let (event_queue, event_queue_evt) = queues.remove(0);

        let host_guid = self.host_guid.clone();
        let guest_cid = self.guest_cid;
        self.worker_thread = Some(WorkerThread::start(
            "userspace_virtio_vsock",
            move |kill_evt| {
                let mut worker = Worker::new(mem, interrupt, host_guid, guest_cid);
                let result = worker.run(
                    rx_queue,
                    tx_queue,
                    event_queue,
                    rx_queue_evt,
                    tx_queue_evt,
                    event_queue_evt,
                    kill_evt,
                );

                if let Err(e) = result {
                    error!("userspace vsock worker thread exited with error: {:?}", e);
                }
            },
        ));

        Ok(())
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct PortPair {
    host: u32,
    guest: u32,
}

impl Display for PortPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(host port: {}, guest port: {})", self.host, self.guest)
    }
}

impl PortPair {
    fn from_tx_header(header: &virtio_vsock_hdr) -> PortPair {
        PortPair {
            host: header.dst_port.to_native(),
            guest: header.src_port.to_native(),
        }
    }
}

// Note: variables herein do not have to be atomic because this struct is guarded
// by a RwLock.
struct VsockConnection {
    // The guest port.
    guest_port: Le32,

    // The actual named (asynchronous) pipe connection.
    pipe: PipeConnection,
    // The overlapped struct contains an event object for the named pipe.
    // This lets us select() on the pipes by waiting on the events.
    // This is for Reads only.
    overlapped: Box<OverlappedWrapper>,
    // Read buffer for the named pipes. These are needed because reads complete
    // asynchronously.
    buffer: Box<[u8; TEMP_READ_BUF_SIZE_BYTES]>,

    // Total free-running count of received bytes.
    recv_cnt: usize,

    // Total free-running count of received bytes that the peer has been informed of.
    prev_recv_cnt: usize,

    // Total auxiliary buffer space available to receive packets from the driver, not including
    // the virtqueue itself. For us, this is tx buffer on the named pipe into which we drain packets
    // for the connection. Note that if the named pipe has a grow on demand TX buffer, we use
    // DEFAULT_BUF_ALLOC instead.
    buf_alloc: usize,

    // Peer (driver) total free-running count of received bytes.
    peer_recv_cnt: usize,

    // Peer (driver) total rx buffer allocated.
    peer_buf_alloc: usize,

    // Total free-running count of transmitted bytes.
    tx_cnt: usize,

    // State tracking for full buffer condition. Currently just used for logging. If the peer's
    // buffer does not have space for a maximum-sized message (TEMP_READ_BUF_SIZE_BYTES), this
    // gets set to `true`. Once there's enough space in the buffer, this gets unset.
    is_buffer_full: bool,
}

struct Worker {
    mem: GuestMemory,
    interrupt: Interrupt,
    host_guid: Option<String>,
    guest_cid: u64,
    // Map of host port to a VsockConnection.
    connections: RwLock<HashMap<PortPair, VsockConnection>>,
    connection_event: Event,
}

impl Worker {
    fn new(
        mem: GuestMemory,
        interrupt: Interrupt,
        host_guid: Option<String>,
        guest_cid: u64,
    ) -> Worker {
        Worker {
            mem,
            interrupt,
            host_guid,
            guest_cid,
            connections: RwLock::new(HashMap::new()),
            connection_event: Event::new().unwrap(),
        }
    }

    async fn process_rx_queue(
        &self,
        recv_queue: Arc<RwLock<Queue>>,
        mut rx_queue_evt: EventAsync,
        ex: &Executor,
    ) -> Result<()> {
        'connections_changed: loop {
            // Run continuously until exit evt

            // TODO(b/200810561): Optimize this FuturesUnordered code.
            // Set up the EventAsyncs to select on
            let futures = FuturesUnordered::new();
            // This needs to be its own scope since it holds a RwLock on `self.connections`.
            {
                let connections = self.connections.read_lock().await;
                for (port, connection) in connections.iter() {
                    let h_evt = connection
                        .overlapped
                        .get_h_event_ref()
                        .ok_or_else(|| {
                            error!("Missing h_event in OverlappedWrapper.");
                            VsockError::BadOverlappedWrapper
                        })
                        .unwrap()
                        .try_clone()
                        .map_err(|e| {
                            error!("Could not clone h_event.");
                            VsockError::CloneDescriptor(e)
                        })?;
                    let evt_async = EventAsync::new(h_evt, ex).map_err(|e| {
                        error!("Could not create EventAsync.");
                        VsockError::CreateEventAsync(e)
                    })?;
                    futures.push(wait_event_and_return_port_pair(evt_async, *port));
                }
            }
            let connection_evt_clone = self.connection_event.try_clone().map_err(|e| {
                error!("Could not clone connection_event.");
                VsockError::CloneDescriptor(e)
            })?;
            let connection_evt_async = EventAsync::new(connection_evt_clone, ex).map_err(|e| {
                error!("Could not create EventAsync.");
                VsockError::CreateEventAsync(e)
            })?;
            futures.push(wait_event_and_return_port_pair(
                connection_evt_async,
                PortPair {
                    host: CONNECTION_EVENT_PORT_NUM,
                    guest: 0,
                },
            ));

            // Wait to service the sockets. Note that for fairness, it is critical that we service
            // all ready sockets in a single wakeup to avoid starvation. This is why ready_chunks
            // is used, as it returns all currently *ready* futures from the stream.
            //
            // The expect here only triggers if the FuturesUnordered stream is exhausted. This never
            // happens because it has at least one item, and we only request chunks once.
            let futures_len = futures.len();
            for port in futures
                .ready_chunks(futures_len)
                .next()
                .await
                .expect("failed to wait on vsock sockets")
            {
                if port.host == CONNECTION_EVENT_PORT_NUM {
                    // New connection event. Setup futures again.
                    if let Err(e) = self.connection_event.reset() {
                        error!("vsock: port: {}: could not reset connection_event.", port);
                        return Err(VsockError::ResetEventObject(e));
                    }
                    continue 'connections_changed;
                }
                let mut connections = self.connections.lock().await;
                let connection = if let Some(conn) = connections.get_mut(&port) {
                    conn
                } else {
                    // We could have been scheduled to run the rx queue *before* the connection was
                    // closed. In that case, we do nothing. The code which closed the connection
                    // (e.g. in response to a message in the tx/rx queues) will handle notifying
                    // the guest/host as required.
                    continue 'connections_changed;
                };

                // Check if the peer has enough space in their buffer to
                // receive the maximum amount of data that we could possibly
                // read from the host pipe. If not, we should continue to
                // process other sockets as each socket has an independent
                // buffer.
                let peer_free_buf_size =
                    connection.peer_buf_alloc - (connection.tx_cnt - connection.peer_recv_cnt);
                if peer_free_buf_size < TEMP_READ_BUF_SIZE_BYTES {
                    if !connection.is_buffer_full {
                        warn!(
                            "vsock: port {}: Peer has insufficient free buffer space ({} bytes available)",
                            port, peer_free_buf_size
                        );
                        connection.is_buffer_full = true;
                    }
                    continue;
                } else if connection.is_buffer_full {
                    connection.is_buffer_full = false;
                }

                let pipe_connection = &mut connection.pipe;
                let overlapped = &mut connection.overlapped;
                let guest_port = connection.guest_port;
                let buffer = &mut connection.buffer;

                match overlapped.get_h_event_ref() {
                    Some(h_event) => {
                        if let Err(e) = h_event.reset() {
                            error!(
                                "vsock: port: {}: Could not reset event in OverlappedWrapper.",
                                port
                            );
                            return Err(VsockError::ResetEventObject(e));
                        }
                    }
                    None => {
                        error!(
                            "vsock: port: {}: missing h_event in OverlappedWrapper.",
                            port
                        );
                        return Err(VsockError::BadOverlappedWrapper);
                    }
                }

                let data_size = match pipe_connection.get_overlapped_result(&mut *overlapped) {
                    Ok(size) => size as usize,
                    Err(e) => {
                        error!("vsock: port {}: Failed to read from pipe {}", port, e);
                        // TODO(b/237278629): Close the connection if we fail to read.
                        continue 'connections_changed;
                    }
                };

                let response_header = virtio_vsock_hdr {
                    src_cid: 2.into(),              // Host CID
                    dst_cid: self.guest_cid.into(), // Guest CID
                    src_port: Le32::from(port.host),
                    dst_port: guest_port,
                    len: Le32::from(data_size as u32),
                    r#type: TYPE_STREAM_SOCKET.into(),
                    op: vsock_op::VIRTIO_VSOCK_OP_RW.into(),
                    buf_alloc: Le32::from(connection.buf_alloc as u32),
                    fwd_cnt: Le32::from(connection.recv_cnt as u32),
                    ..Default::default()
                };

                connection.prev_recv_cnt = connection.recv_cnt;

                // We have to only write to the queue once, so we construct a new buffer
                // with the concatenated header and data.
                const HEADER_SIZE: usize = std::mem::size_of::<virtio_vsock_hdr>();
                let data_read = &buffer[..data_size];
                let mut header_and_data = vec![0u8; HEADER_SIZE + data_size];
                header_and_data[..HEADER_SIZE].copy_from_slice(response_header.as_bytes());
                header_and_data[HEADER_SIZE..].copy_from_slice(data_read);
                self.write_bytes_to_queue(
                    &mut *recv_queue.lock().await,
                    &mut rx_queue_evt,
                    &header_and_data[..],
                )
                .await?;

                connection.tx_cnt += data_size;

                // Start reading again so we receive the message and
                // event signal immediately.

                // Unsafe because the read could happen at any time
                // after this function is called. We ensure safety
                // by allocating the buffer and overlapped struct
                // on the heap.
                unsafe {
                    match pipe_connection.read_overlapped(&mut buffer[..], &mut *overlapped) {
                        Ok(()) => {}
                        Err(e) => {
                            error!("vsock: port {}: Failed to read from pipe {}", port, e);
                        }
                    }
                }
            }
        }
    }

    async fn process_tx_queue(
        &self,
        mut queue: Queue,
        mut queue_evt: EventAsync,
        mut process_packets_queue: mpsc::Sender<(virtio_vsock_hdr, Vec<u8>)>,
    ) -> Result<()> {
        loop {
            // Run continuously until exit evt
            let mut avail_desc = match queue.next_async(&self.mem, &mut queue_evt).await {
                Ok(d) => d,
                Err(e) => {
                    error!("vsock: Failed to read descriptor {}", e);
                    return Err(VsockError::AwaitQueue(e));
                }
            };

            let reader = &mut avail_desc.reader;
            while reader.available_bytes() >= std::mem::size_of::<virtio_vsock_hdr>() {
                let header = match reader.read_obj::<virtio_vsock_hdr>() {
                    Ok(hdr) => hdr,
                    Err(e) => {
                        error!("vsock: Error while reading header: {}", e);
                        break;
                    }
                };

                let len = header.len.to_native() as usize;
                if reader.available_bytes() < len {
                    error!("vsock: Error reading packet data");
                    break;
                }

                let mut data = vec![0_u8; len];
                if len > 0 {
                    if let Err(e) = reader.read_exact(&mut data) {
                        error!("vosck: failed to read data from tx packet: {:?}", e);
                    }
                }

                if let Err(e) = process_packets_queue.send((header, data)).await {
                    error!(
                        "Error while sending packet to queue, dropping packet: {:?}",
                        e
                    )
                };
            }

            queue.add_used(&self.mem, avail_desc, 0);
            queue.trigger_interrupt(&self.mem, &self.interrupt);
        }
    }

    fn calculate_buf_alloc_from_pipe(pipe: &PipeConnection, port: PortPair) -> usize {
        match pipe.get_info(/* is_server_connection= */ false) {
            Ok(info) => {
                if info.outgoing_buffer_size > 0 {
                    info.outgoing_buffer_size as usize
                } else {
                    info!(
                        "vsock: port {}: using default extra rx buffer size \
                                            (named pipe does not have an explicit buffer size)",
                        port
                    );

                    // A zero buffer size implies that the buffer grows as
                    // needed. We set our own cap here for flow control
                    // purposes.
                    DEFAULT_BUF_ALLOC_BYTES
                }
            }
            Err(e) => {
                error!(
                    "vsock: port {}: failed to get named pipe info, using default \
                                        buf size. Error: {}",
                    port, e
                );
                DEFAULT_BUF_ALLOC_BYTES
            }
        }
    }

    /// Processes a connection request and returns whether to return a response (true), or reset
    /// (false).
    async fn handle_vsock_connection_request(&self, header: virtio_vsock_hdr) -> bool {
        let port = PortPair::from_tx_header(&header);
        info!("vsock: Received connection request for port {}", port);

        if self.connections.read_lock().await.contains_key(&port) {
            // Connection exists, nothing for us to do.
            warn!(
                "vsock: accepting connection request on already connected port {}",
                port
            );
            return true;
        }

        if self.host_guid.is_none() {
            error!(
                "vsock: Cannot accept guest-initiated connections \
                        without host-guid, rejecting connection"
            );
            return false;
        }

        // We have a new connection to establish.
        let mut overlapped_wrapper =
            Box::new(OverlappedWrapper::new(/* include_event= */ true).unwrap());
        let pipe_result = named_pipes::create_client_pipe(
            get_pipe_name(
                self.host_guid.as_ref().unwrap(),
                header.dst_port.to_native(),
            )
            .as_str(),
            &FramingMode::Byte,
            &BlockingMode::Wait,
            true, /* overlapped */
        );

        match pipe_result {
            Ok(mut pipe_connection) => {
                let mut buffer = Box::new([0u8; TEMP_READ_BUF_SIZE_BYTES]);

                // Unsafe because the read could happen at any time
                // after this function is called. We ensure safety
                // by allocating the buffer and overlapped struct
                // on the heap.
                unsafe {
                    match pipe_connection.read_overlapped(&mut buffer[..], &mut overlapped_wrapper)
                    {
                        Ok(()) => {}
                        Err(e) => {
                            error!("vsock: port {}: Failed to read from pipe {}", port, e);
                            return false;
                        }
                    }
                }

                let buf_alloc = Self::calculate_buf_alloc_from_pipe(&pipe_connection, port);
                let connection = VsockConnection {
                    guest_port: header.src_port,
                    pipe: pipe_connection,
                    overlapped: overlapped_wrapper,
                    peer_buf_alloc: header.buf_alloc.to_native() as usize,
                    peer_recv_cnt: header.fwd_cnt.to_native() as usize,
                    buf_alloc,
                    buffer,
                    // The connection has just been made, so we haven't received
                    // anything yet.
                    recv_cnt: 0_usize,
                    prev_recv_cnt: 0_usize,
                    tx_cnt: 0_usize,
                    is_buffer_full: false,
                };
                self.connections.lock().await.insert(port, connection);
                self.connection_event.signal().unwrap_or_else(|_| {
                    panic!(
                        "Failed to signal new connection event for vsock port {}.",
                        port
                    )
                });
                true
            }
            Err(e) => {
                info!(
                    "vsock: No waiting pipe connection on port {}, \
                                not connecting (err: {:?})",
                    port, e
                );
                false
            }
        }
    }

    async fn handle_vsock_guest_data(
        &self,
        header: virtio_vsock_hdr,
        data: &[u8],
        ex: &Executor,
    ) -> Result<()> {
        let port = PortPair::from_tx_header(&header);
        let mut overlapped_wrapper = OverlappedWrapper::new(/* include_event= */ true).unwrap();
        {
            let mut connections = self.connections.lock().await;
            if let Some(connection) = connections.get_mut(&port) {
                // Update peer buffer/recv counters
                connection.peer_recv_cnt = header.fwd_cnt.to_native() as usize;
                connection.peer_buf_alloc = header.buf_alloc.to_native() as usize;

                let pipe = &mut connection.pipe;
                // We have to provide a OVERLAPPED struct to write to the pipe.
                //
                // SAFETY: safe because data & overlapped_wrapper live until the
                // overlapped operation completes (we wait on completion below).
                if let Err(e) = unsafe { pipe.write_overlapped(data, &mut overlapped_wrapper) } {
                    return Err(VsockError::WriteFailed(port, e));
                }
            } else {
                error!(
                    "vsock: Guest attempted to send data packet over unconnected \
                            port ({}), dropping packet",
                    port
                );
                return Ok(());
            }
        }
        if let Some(write_completed_event) = overlapped_wrapper.get_h_event_ref() {
            // Don't block the executor while the write completes. This time should
            // always be negligible, but will sometimes be non-zero in cases where
            // traffic is high on the NamedPipe, especially a duplex pipe.
            if let Ok(cloned_event) = write_completed_event.try_clone() {
                if let Ok(async_event) = EventAsync::new_without_reset(cloned_event, ex) {
                    let _ = async_event.next_val().await;
                } else {
                    error!(
                        "vsock: port {}: Failed to convert write event to async",
                        port
                    );
                }
            } else {
                error!(
                    "vsock: port {}: Failed to clone write completion event",
                    port
                );
            }
        } else {
            error!(
                "vsock: port: {}: Failed to get overlapped event for write",
                port
            );
        }

        let mut connections = self.connections.lock().await;
        if let Some(connection) = connections.get_mut(&port) {
            let pipe = &mut connection.pipe;
            match pipe.get_overlapped_result(&mut overlapped_wrapper) {
                Ok(len) => {
                    // We've received bytes from the guest, account for them in our
                    // received bytes counter.
                    connection.recv_cnt += len as usize;

                    if len != data.len() as u32 {
                        return Err(VsockError::WriteFailed(
                            port,
                            std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!(
                                    "failed to write correct number of bytes:
                                        (expected: {}, wrote: {})",
                                    data.len(),
                                    len
                                ),
                            ),
                        ));
                    }
                }
                Err(e) => {
                    return Err(VsockError::WriteFailed(port, e));
                }
            }
        } else {
            error!(
                "vsock: Guest attempted to send data packet over unconnected \
                        port ({}), dropping packet",
                port
            );
        }
        Ok(())
    }

    async fn process_tx_packets(
        &self,
        send_queue: &Arc<RwLock<Queue>>,
        rx_queue_evt: Event,
        mut packet_recv_queue: mpsc::Receiver<(virtio_vsock_hdr, Vec<u8>)>,
        ex: &Executor,
    ) {
        let mut packet_queues = HashMap::new();
        let mut futures = FuturesUnordered::new();
        // Push a pending future that will never complete into FuturesUnordered.
        // This will keep us from spinning on spurious notifications when we
        // don't have any open connections.
        futures.push(std::future::pending::<PortPair>().left_future());
        loop {
            let (new_packet, connection) = select2(packet_recv_queue.next(), futures.next()).await;
            match connection {
                SelectResult::Finished(Some(port)) => {
                    packet_queues.remove(&port);
                }
                SelectResult::Finished(_) => {
                    // This is only triggered when FuturesUnordered completes
                    // all pending futures. Right now, this can never happen, as
                    // we have a pending future that we push that will never
                    // complete.
                }
                SelectResult::Pending(_) => {
                    // Nothing to do.
                }
            };
            match new_packet {
                SelectResult::Finished(Some(packet)) => {
                    let port = PortPair::from_tx_header(&packet.0);
                    let queue = packet_queues.entry(port).or_insert_with(|| {
                        let (send, recv) = mpsc::channel(CHANNEL_SIZE);
                        let event_async = EventAsync::new(
                            rx_queue_evt.try_clone().expect("Failed to clone event"),
                            ex,
                        )
                        .expect("Failed to set up the rx queue event");
                        futures.push(
                            self.process_tx_packets_for_port(
                                port,
                                recv,
                                send_queue,
                                event_async,
                                ex,
                            )
                            .right_future(),
                        );
                        send
                    });
                    // Try to send the packet. Do not block other ports if the queue is full.
                    if let Err(e) = queue.try_send(packet) {
                        error!("Error sending packet to queue, dropping packet: {:?}", e)
                    }
                }
                SelectResult::Finished(_) => {
                    // Triggers when the channel is closed; no more packets coming.
                    packet_recv_queue.close();
                    return;
                }
                SelectResult::Pending(_) => {
                    // Nothing to do.
                }
            }
        }
    }

    async fn process_tx_packets_for_port(
        &self,
        port: PortPair,
        mut packet_recv_queue: mpsc::Receiver<(virtio_vsock_hdr, Vec<u8>)>,
        send_queue: &Arc<RwLock<Queue>>,
        mut rx_queue_evt: EventAsync,
        ex: &Executor,
    ) -> PortPair {
        while let Some((header, data)) = packet_recv_queue.next().await {
            if !self
                .handle_tx_packet(header, &data, send_queue, &mut rx_queue_evt, ex)
                .await
            {
                packet_recv_queue.close();
                if let Ok(Some(_)) = packet_recv_queue.try_next() {
                    warn!("vsock: closing port {} with unprocessed packets", port);
                } else {
                    info!("vsock: closing port {} cleanly", port)
                }
                break;
            }
        }
        port
    }

    async fn handle_tx_packet(
        &self,
        header: virtio_vsock_hdr,
        data: &[u8],
        send_queue: &Arc<RwLock<Queue>>,
        rx_queue_evt: &mut EventAsync,
        ex: &Executor,
    ) -> bool {
        let mut is_open = true;
        match header.op.to_native() {
            vsock_op::VIRTIO_VSOCK_OP_INVALID => {
                error!("vsock: Invalid Operation requested, dropping packet");
            }
            vsock_op::VIRTIO_VSOCK_OP_REQUEST => {
                let (resp_op, buf_alloc, fwd_cnt) =
                    if self.handle_vsock_connection_request(header).await {
                        let connections = self.connections.read_lock().await;
                        let port = PortPair::from_tx_header(&header);

                        connections.get(&port).map_or_else(
                            || {
                                warn!("vsock: port: {} connection closed during connect", port);
                                is_open = false;
                                (vsock_op::VIRTIO_VSOCK_OP_RST, 0, 0)
                            },
                            |conn| {
                                (
                                    vsock_op::VIRTIO_VSOCK_OP_RESPONSE,
                                    conn.buf_alloc as u32,
                                    conn.recv_cnt as u32,
                                )
                            },
                        )
                    } else {
                        is_open = false;
                        (vsock_op::VIRTIO_VSOCK_OP_RST, 0, 0)
                    };

                let response_header = virtio_vsock_hdr {
                    src_cid: { header.dst_cid },
                    dst_cid: { header.src_cid },
                    src_port: { header.dst_port },
                    dst_port: { header.src_port },
                    len: 0.into(),
                    r#type: TYPE_STREAM_SOCKET.into(),
                    op: resp_op.into(),
                    buf_alloc: Le32::from(buf_alloc),
                    fwd_cnt: Le32::from(fwd_cnt),
                    ..Default::default()
                };
                // Safe because virtio_vsock_hdr is a simple data struct and converts cleanly to
                // bytes.
                self.write_bytes_to_queue(
                    &mut *send_queue.lock().await,
                    rx_queue_evt,
                    response_header.as_bytes(),
                )
                .await
                .expect("vsock: failed to write to queue");
            }
            vsock_op::VIRTIO_VSOCK_OP_RESPONSE => {
                // TODO(b/237811512): Implement this for host-initiated connections
            }
            vsock_op::VIRTIO_VSOCK_OP_RST => {
                // TODO(b/237811512): Implement this for host-initiated connections
            }
            vsock_op::VIRTIO_VSOCK_OP_SHUTDOWN => {
                // While the header provides flags to specify tx/rx-specific shutdown,
                // we only support full shutdown.
                // TODO(b/237811512): Provide an optimal way to notify host of shutdowns
                // while still maintaining easy reconnections.
                let port = PortPair::from_tx_header(&header);
                let mut connections = self.connections.lock().await;
                if connections.remove(&port).is_some() {
                    let mut response = virtio_vsock_hdr {
                        src_cid: { header.dst_cid },
                        dst_cid: { header.src_cid },
                        src_port: { header.dst_port },
                        dst_port: { header.src_port },
                        len: 0.into(),
                        r#type: TYPE_STREAM_SOCKET.into(),
                        op: vsock_op::VIRTIO_VSOCK_OP_RST.into(),
                        // There is no buffer on a closed connection
                        buf_alloc: 0.into(),
                        // There is no fwd_cnt anymore on a closed connection
                        fwd_cnt: 0.into(),
                        ..Default::default()
                    };
                    // Safe because virtio_vsock_hdr is a simple data struct and converts cleanly to bytes
                    self.write_bytes_to_queue(
                        &mut *send_queue.lock().await,
                        rx_queue_evt,
                        response.as_bytes_mut(),
                    )
                    .await
                    .expect("vsock: failed to write to queue");
                    self.connection_event
                        .signal()
                        .expect("vsock: failed to write to event");
                } else {
                    error!("vsock: Attempted to close unopened port: {}", port);
                }
                is_open = false;
            }
            vsock_op::VIRTIO_VSOCK_OP_RW => {
                match self.handle_vsock_guest_data(header, data, ex).await {
                    Ok(()) => {
                        if self
                            .check_free_buffer_threshold(header)
                            .await
                            .unwrap_or(false)
                        {
                            // Send a credit update if we're below the minimum free
                            // buffer size. We skip this if the connection is closed,
                            // which could've happened if we were closed on the other
                            // end.
                            info!("vsock: Buffer below threshold; sending credit update.");
                            self.send_vsock_credit_update(send_queue, rx_queue_evt, header)
                                .await;
                        }
                    }
                    Err(e) => {
                        error!("vsock: resetting connection: {}", e);
                        self.send_vsock_reset(send_queue, rx_queue_evt, header)
                            .await;
                        is_open = false;
                    }
                }
            }
            // An update from our peer with their buffer state, which they are sending
            // (probably) due to a a credit request *we* made.
            vsock_op::VIRTIO_VSOCK_OP_CREDIT_UPDATE => {
                let port = PortPair::from_tx_header(&header);
                let mut connections = self.connections.lock().await;
                if let Some(connection) = connections.get_mut(&port) {
                    connection.peer_recv_cnt = header.fwd_cnt.to_native() as usize;
                    connection.peer_buf_alloc = header.buf_alloc.to_native() as usize;
                } else {
                    error!("vsock: got credit update on unknown port {}", port);
                    is_open = false;
                }
            }
            // A request from our peer to get *our* buffer state. We reply to the RX queue.
            vsock_op::VIRTIO_VSOCK_OP_CREDIT_REQUEST => {
                info!(
                    "vsock: Got credit request from peer {}; sending credit update.",
                    PortPair::from_tx_header(&header)
                );
                self.send_vsock_credit_update(send_queue, rx_queue_evt, header)
                    .await;
            }
            _ => {
                error!("vsock: Unknown operation requested, dropping packet");
            }
        }
        is_open
    }

    // Checks if how much free buffer our peer thinks that *we* have available
    // is below our threshold percentage. If the connection is closed, returns `None`.
    async fn check_free_buffer_threshold(&self, header: virtio_vsock_hdr) -> Option<bool> {
        let mut connections = self.connections.lock().await;
        let port = PortPair::from_tx_header(&header);
        connections.get_mut(&port).map(|connection| {
            let threshold: usize = (MIN_FREE_BUFFER_PCT * connection.buf_alloc as f64) as usize;
            connection.buf_alloc - (connection.recv_cnt - connection.prev_recv_cnt) < threshold
        })
    }

    async fn send_vsock_credit_update(
        &self,
        send_queue: &Arc<RwLock<Queue>>,
        rx_queue_evt: &mut EventAsync,
        header: virtio_vsock_hdr,
    ) {
        let mut connections = self.connections.lock().await;
        let port = PortPair::from_tx_header(&header);

        if let Some(connection) = connections.get_mut(&port) {
            let mut response = virtio_vsock_hdr {
                src_cid: { header.dst_cid },
                dst_cid: { header.src_cid },
                src_port: { header.dst_port },
                dst_port: { header.src_port },
                len: 0.into(),
                r#type: TYPE_STREAM_SOCKET.into(),
                op: vsock_op::VIRTIO_VSOCK_OP_CREDIT_UPDATE.into(),
                buf_alloc: Le32::from(connection.buf_alloc as u32),
                fwd_cnt: Le32::from(connection.recv_cnt as u32),
                ..Default::default()
            };

            connection.prev_recv_cnt = connection.recv_cnt;

            // Safe because virtio_vsock_hdr is a simple data struct and converts cleanly
            // to bytes
            self.write_bytes_to_queue(
                &mut *send_queue.lock().await,
                rx_queue_evt,
                response.as_bytes_mut(),
            )
            .await
            .expect("vsock: failed to write to queue");
        } else {
            error!(
                "vsock: error sending credit update on unknown port {}",
                port
            );
        }
    }

    async fn send_vsock_reset(
        &self,
        send_queue: &Arc<RwLock<Queue>>,
        rx_queue_evt: &mut EventAsync,
        header: virtio_vsock_hdr,
    ) {
        let mut connections = self.connections.lock().await;
        let port = PortPair::from_tx_header(&header);
        if let Some(connection) = connections.remove(&port) {
            let mut response = virtio_vsock_hdr {
                src_cid: { header.dst_cid },
                dst_cid: { header.src_cid },
                src_port: { header.dst_port },
                dst_port: { header.src_port },
                len: 0.into(),
                r#type: TYPE_STREAM_SOCKET.into(),
                op: vsock_op::VIRTIO_VSOCK_OP_RST.into(),
                buf_alloc: Le32::from(connection.buf_alloc as u32),
                fwd_cnt: Le32::from(connection.recv_cnt as u32),
                ..Default::default()
            };

            // Safe because virtio_vsock_hdr is a simple data struct and converts cleanly
            // to bytes
            self.write_bytes_to_queue(
                &mut *send_queue.lock().await,
                rx_queue_evt,
                response.as_bytes_mut(),
            )
            .await
            .expect("failed to write to queue");
        } else {
            error!("vsock: error closing unknown port {}", port);
        }
    }

    async fn write_bytes_to_queue(
        &self,
        queue: &mut Queue,
        queue_evt: &mut EventAsync,
        bytes: &[u8],
    ) -> Result<()> {
        let mut avail_desc = match queue.next_async(&self.mem, queue_evt).await {
            Ok(d) => d,
            Err(e) => {
                error!("vsock: Failed to read descriptor {}", e);
                return Err(VsockError::AwaitQueue(e));
            }
        };

        let writer = &mut avail_desc.writer;
        let res = writer.write_all(bytes);

        if let Err(e) = res {
            error!(
                "vsock: failed to write {} bytes to queue, err: {:?}",
                bytes.len(),
                e
            );
            return Err(VsockError::WriteQueue(e));
        }

        let bytes_written = writer.bytes_written() as u32;
        if bytes_written > 0 {
            queue.add_used(&self.mem, avail_desc, bytes_written);
            queue.trigger_interrupt(&self.mem, &self.interrupt);
            Ok(())
        } else {
            error!("vsock: Failed to write bytes to queue");
            Err(VsockError::WriteQueue(std::io::Error::new(
                std::io::ErrorKind::Other,
                "failed to write bytes to queue",
            )))
        }
    }

    async fn process_event_queue(&self, mut queue: Queue, mut queue_evt: EventAsync) -> Result<()> {
        loop {
            // Log but don't act on events. They are reserved exclusively for guest migration events
            // resulting in CID resets, which we don't support.
            let mut avail_desc = match queue.next_async(&self.mem, &mut queue_evt).await {
                Ok(d) => d,
                Err(e) => {
                    error!("vsock: Failed to read descriptor {}", e);
                    return Err(VsockError::AwaitQueue(e));
                }
            };

            for event in avail_desc.reader.iter::<virtio_vsock_event>() {
                if event.is_ok() {
                    error!(
                        "Received event with id {:?}, this should not happen, and will not be handled",
                        event.unwrap().id.to_native()
                    );
                }
            }
        }
    }

    fn run(
        &mut self,
        rx_queue: Queue,
        tx_queue: Queue,
        event_queue: Queue,
        rx_queue_evt: Event,
        tx_queue_evt: Event,
        event_queue_evt: Event,
        kill_evt: Event,
    ) -> Result<()> {
        let ex = Executor::new().unwrap();

        // Note that this mutex won't ever be contended because the HandleExecutor is single
        // threaded. We need the mutex for compile time correctness, but technically it is not
        // actually providing mandatory locking, at least not at the moment. If we later use a
        // multi-threaded executor, then this lock will be important.
        let rx_queue_arc = Arc::new(RwLock::new(rx_queue));

        let rx_evt_async = EventAsync::new(
            rx_queue_evt
                .try_clone()
                .map_err(VsockError::CloneDescriptor)?,
            &ex,
        )
        .expect("Failed to set up the rx queue event");
        let rx_handler = self.process_rx_queue(rx_queue_arc.clone(), rx_evt_async, &ex);
        pin_mut!(rx_handler);

        let (send, recv) = mpsc::channel(CHANNEL_SIZE);

        let tx_evt_async =
            EventAsync::new(tx_queue_evt, &ex).expect("Failed to set up the tx queue event");
        let tx_handler = self.process_tx_queue(tx_queue, tx_evt_async, send);
        pin_mut!(tx_handler);

        let packet_handler = self.process_tx_packets(&rx_queue_arc, rx_queue_evt, recv, &ex);
        pin_mut!(packet_handler);

        let event_evt_async =
            EventAsync::new(event_queue_evt, &ex).expect("Failed to set up the event queue event");
        let event_handler = self.process_event_queue(event_queue, event_evt_async);
        pin_mut!(event_handler);

        // Process any requests to resample the irq value.
        let resample_handler = async_utils::handle_irq_resample(&ex, self.interrupt.clone());
        pin_mut!(resample_handler);

        let kill_evt = EventAsync::new(kill_evt, &ex).expect("Failed to set up the kill event");
        let kill_handler = kill_evt.next_val();
        pin_mut!(kill_handler);

        if let Err(e) = ex.run_until(select6(
            rx_handler,
            tx_handler,
            packet_handler,
            event_handler,
            resample_handler,
            kill_handler,
        )) {
            error!("Error happened when running executor: {}", e);
            return Err(VsockError::RunExecutor(e));
        }
        Ok(())
    }
}

fn get_pipe_name(guid: &str, pipe: u32) -> String {
    format!("\\\\.\\pipe\\{}\\vsock-{}", guid, pipe)
}

async fn wait_event_and_return_port_pair(evt: EventAsync, pair: PortPair) -> PortPair {
    // This doesn't reset the event since we have to call GetOverlappedResult
    // on the OVERLAPPED struct first before resetting it.
    let _ = evt.get_io_source_ref().wait_for_handle().await;
    pair
}
