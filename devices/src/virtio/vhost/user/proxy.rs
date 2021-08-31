// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread;

use base::{error, Event, EventType, PollToken, RawDescriptor, WaitContext};
use data_model::{DataInit, Le32};
use vm_memory::GuestMemory;

use crate::virtio::descriptor_utils::Error as DescriptorUtilsError;
use crate::virtio::{copy_config, Interrupt, Queue, Reader, VirtioDevice, Writer};

use remain::sorted;
use thiserror::Error as ThisError;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

const TYPE_VIRTIO_VHOST_USER: u32 = 43;

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
    /// Removing read event from the VhostVmmSocket fd events failed.
    #[error("failed to disable EPOLLIN on VhostVmmSocket fd: {0}")]
    WaitContextDisableVhostVmmSocket(base::Error),
    /// Adding read event to the VhostVmmSocket fd events failed.
    #[error("failed to enable EPOLLIN on VhostVmmSocket fd: {0}")]
    WaitContextEnableVhostVmmSocket(base::Error),
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

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
struct VirtioVhostUserConfig {
    status: Le32,
    max_vhost_queues: Le32,
    uuid: [u8; 16],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioVhostUserConfig {}

struct Worker {
    mem: GuestMemory,
    interrupt: Interrupt,
    rx_queue: Queue,
    tx_queue: Queue,
    vhost_vmm_socket: UnixStream,
}

impl Worker {
    fn run(&mut self, rx_queue_evt: Event, tx_queue_evt: Event, kill_evt: Event) -> Result<()> {
        #[derive(PollToken, Debug, Clone)]
        pub enum Token {
            // Data is available on the vhost vmm socket.
            VhostVmmSocket,
            // The vhost-device has made a read buffer available.
            RxQueue,
            // The vhost-device has sent a buffer to the |Worker::tx_queue|.
            TxQueue,
            // crosvm has requested the device to shut down.
            Kill,
        }

        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (&self.vhost_vmm_socket, Token::VhostVmmSocket),
            (&rx_queue_evt, Token::RxQueue),
            (&tx_queue_evt, Token::TxQueue),
            (&kill_evt, Token::Kill),
        ])
        .map_err(Error::CreateWaitContext)?;

        let mut vhost_vmm_socket_polling_enabled = true;
        'wait: loop {
            let events = wait_ctx.wait().map_err(Error::WaitError)?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::VhostVmmSocket => match self.process_rx() {
                        Ok(()) => {}
                        Err(Error::RxDescriptorsExhausted) => {
                            wait_ctx
                                .modify(
                                    &self.vhost_vmm_socket,
                                    EventType::None,
                                    Token::VhostVmmSocket,
                                )
                                .map_err(Error::WaitContextDisableVhostVmmSocket)?;
                            vhost_vmm_socket_polling_enabled = false;
                        }
                        Err(e) => return Err(e),
                    },
                    Token::RxQueue => {
                        if let Err(e) = rx_queue_evt.read() {
                            error!("net: error reading rx queue Event: {}", e);
                            break 'wait;
                        }
                        if !vhost_vmm_socket_polling_enabled {
                            wait_ctx
                                .modify(
                                    &self.vhost_vmm_socket,
                                    EventType::Read,
                                    Token::VhostVmmSocket,
                                )
                                .map_err(Error::WaitContextEnableVhostVmmSocket)?;
                            vhost_vmm_socket_polling_enabled = true;
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
                    match writer.write_from(&mut self.vhost_vmm_socket, writer.available_bytes()) {
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
                    match reader.read_to(&mut self.vhost_vmm_socket, expected_count) {
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

pub struct VirtioVhostUser {
    vhost_vmm_socket: Option<UnixStream>,
    config: VirtioVhostUserConfig,
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
}

impl VirtioVhostUser {
    pub fn new(vhost_vmm_socket_path: &Path) -> Result<VirtioVhostUser> {
        let listener = UnixListener::bind(vhost_vmm_socket_path).map_err(Error::CreateListener)?;
        let (socket, _) = listener.accept().map_err(Error::AcceptConnection)?;
        Ok(VirtioVhostUser {
            vhost_vmm_socket: Some(socket),
            config: Default::default(),
            kill_evt: None,
            worker_thread: None,
        })
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
        TYPE_VIRTIO_VHOST_USER
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
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
        // TODO: Confirm if |data| is guaranteed to be sent in LE.
        copy_config(
            self.config.as_mut_slice(),
            offset,
            data,
            0, /* src_offset */
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<Event>,
    ) {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
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
        // ensured in |VirtioVhostUser::new|.
        let vhost_vmm_socket = self
            .vhost_vmm_socket
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
                    vhost_vmm_socket,
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

    fn reset(&mut self) -> bool {
        // TODO
        true
    }
}
