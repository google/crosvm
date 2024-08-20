// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio console device worker thread.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::Event;
use base::EventToken;
use base::WaitContext;
use base::WorkerThread;
use sync::Mutex;

use crate::virtio::console::control::process_control_receive_queue;
use crate::virtio::console::control::process_control_transmit_queue;
use crate::virtio::console::control::ControlMsgBytes;
use crate::virtio::console::input::process_receive_queue;
use crate::virtio::console::output::process_transmit_queue;
use crate::virtio::console::port::ConsolePort;
use crate::virtio::console::port::ConsolePortInfo;
use crate::virtio::Interrupt;
use crate::virtio::Queue;

const PORT0_RECEIVEQ_IDX: usize = 0;
const PORT0_TRANSMITQ_IDX: usize = 1;
const CONTROL_RECEIVEQ_IDX: usize = 2;
const CONTROL_TRANSMITQ_IDX: usize = 3;
const PORT1_RECEIVEQ_IDX: usize = 4;
const PORT1_TRANSMITQ_IDX: usize = 5;

pub struct WorkerPort {
    info: Option<ConsolePortInfo>,

    in_avail_evt: Event,
    input_buffer: Arc<Mutex<VecDeque<u8>>>,
    output: Box<dyn std::io::Write + Send>,
}

impl WorkerPort {
    pub fn from_console_port(port: &mut ConsolePort) -> WorkerPort {
        let in_avail_evt = port.clone_in_avail_evt().unwrap();
        let input_buffer = port.clone_input_buffer();
        let output = port
            .take_output()
            .unwrap_or_else(|| Box::new(std::io::sink()));
        let info = port.port_info().cloned();
        WorkerPort {
            info,
            in_avail_evt,
            input_buffer,
            output,
        }
    }

    /// Restore the state retrieved from `ConsolePort` by `WorkerPort::from_console_port()`.
    pub fn into_console_port(self, console_port: &mut ConsolePort) {
        console_port.restore_output(self.output);
    }

    pub fn is_console(&self) -> bool {
        self.info
            .as_ref()
            .map(|info| info.console)
            .unwrap_or_default()
    }

    pub fn name(&self) -> Option<&str> {
        self.info.as_ref().and_then(ConsolePortInfo::name)
    }
}

#[derive(EventToken)]
enum Token {
    ReceiveQueueAvailable(u32),
    TransmitQueueAvailable(u32),
    InputAvailable(u32),
    ControlReceiveQueueAvailable,
    ControlTransmitQueueAvailable,
    InterruptResample,
    WorkerRequest,
    Kill,
}

pub enum WorkerRequest {
    StartQueue {
        idx: usize,
        queue: Queue,
        response_sender: mpsc::SyncSender<anyhow::Result<()>>,
    },
    StopQueue {
        idx: usize,
        response_sender: mpsc::SyncSender<Option<Queue>>,
    },
}

pub struct Worker {
    wait_ctx: WaitContext<Token>,
    interrupt: Interrupt,

    // Currently running queues.
    queues: BTreeMap<usize, Queue>,

    // Console ports indexed by port ID. At least port 0 will exist, and other ports may be
    // available if `VIRTIO_CONSOLE_F_MULTIPORT` is enabled.
    ports: Vec<WorkerPort>,

    // Device-to-driver messages to be received by the driver via the control receiveq.
    pending_receive_control_msgs: VecDeque<ControlMsgBytes>,

    worker_receiver: mpsc::Receiver<WorkerRequest>,
    worker_event: Event,
}

impl Worker {
    pub fn new(
        interrupt: Interrupt,
        ports: Vec<WorkerPort>,
        worker_receiver: mpsc::Receiver<WorkerRequest>,
        worker_event: Event,
    ) -> anyhow::Result<Self> {
        let wait_ctx = WaitContext::new().context("WaitContext::new() failed")?;

        wait_ctx.add(&worker_event, Token::WorkerRequest)?;

        for (index, port) in ports.iter().enumerate() {
            let port_id = index as u32;
            wait_ctx.add(&port.in_avail_evt, Token::InputAvailable(port_id))?;
        }

        if let Some(resample_evt) = interrupt.get_resample_evt() {
            wait_ctx.add(resample_evt, Token::InterruptResample)?;
        }

        Ok(Worker {
            wait_ctx,
            interrupt,
            queues: BTreeMap::new(),
            ports,
            pending_receive_control_msgs: VecDeque::new(),
            worker_receiver,
            worker_event,
        })
    }

    pub fn run(&mut self, kill_evt: &Event) -> anyhow::Result<()> {
        self.wait_ctx.add(kill_evt, Token::Kill)?;
        let res = self.run_loop();
        self.wait_ctx.delete(kill_evt)?;
        res
    }

    fn run_loop(&mut self) -> anyhow::Result<()> {
        let mut running = true;
        while running {
            let events = self.wait_ctx.wait()?;

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::TransmitQueueAvailable(port_id) => {
                        if let (Some(port), Some(transmitq)) = (
                            self.ports.get_mut(port_id as usize),
                            transmitq_idx(port_id).and_then(|idx| self.queues.get_mut(&idx)),
                        ) {
                            transmitq
                                .event()
                                .wait()
                                .context("failed reading transmit queue Event")?;
                            process_transmit_queue(transmitq, &mut port.output);
                        }
                    }
                    Token::ReceiveQueueAvailable(port_id) | Token::InputAvailable(port_id) => {
                        let port = self.ports.get_mut(port_id as usize);
                        let receiveq =
                            receiveq_idx(port_id).and_then(|idx| self.queues.get_mut(&idx));

                        let event = if matches!(event.token, Token::ReceiveQueueAvailable(..)) {
                            receiveq.as_ref().map(|q| q.event())
                        } else {
                            port.as_ref().map(|p| &p.in_avail_evt)
                        };
                        if let Some(event) = event {
                            event.wait().context("failed to clear receive event")?;
                        }

                        if let (Some(port), Some(receiveq)) = (port, receiveq) {
                            let mut input_buffer = port.input_buffer.lock();
                            process_receive_queue(&mut input_buffer, receiveq);
                        }
                    }
                    Token::ControlReceiveQueueAvailable => {
                        if let Some(ctrl_receiveq) = self.queues.get_mut(&CONTROL_RECEIVEQ_IDX) {
                            ctrl_receiveq
                                .event()
                                .wait()
                                .context("failed waiting on control event")?;
                            process_control_receive_queue(
                                ctrl_receiveq,
                                &mut self.pending_receive_control_msgs,
                            );
                        }
                    }
                    Token::ControlTransmitQueueAvailable => {
                        if let Some(ctrl_transmitq) = self.queues.get_mut(&CONTROL_TRANSMITQ_IDX) {
                            ctrl_transmitq
                                .event()
                                .wait()
                                .context("failed waiting on control event")?;
                            process_control_transmit_queue(
                                ctrl_transmitq,
                                &self.ports,
                                &mut self.pending_receive_control_msgs,
                            );
                        }

                        // Attempt to send any new replies if there is space in the receiveq.
                        if let Some(ctrl_receiveq) = self.queues.get_mut(&CONTROL_RECEIVEQ_IDX) {
                            process_control_receive_queue(
                                ctrl_receiveq,
                                &mut self.pending_receive_control_msgs,
                            )
                        }
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::WorkerRequest => {
                        self.worker_event.wait()?;
                        self.process_worker_requests();
                    }
                    Token::Kill => running = false,
                }
            }
        }
        Ok(())
    }

    fn process_worker_requests(&mut self) {
        while let Ok(request) = self.worker_receiver.try_recv() {
            match request {
                WorkerRequest::StartQueue {
                    idx,
                    queue,
                    response_sender,
                } => {
                    let res = self.start_queue(idx, queue);
                    let _ = response_sender.send(res);
                }
                WorkerRequest::StopQueue {
                    idx,
                    response_sender,
                } => {
                    let res = self.stop_queue(idx);
                    let _ = response_sender.send(res);
                }
            }
        }
    }

    fn start_queue(&mut self, idx: usize, queue: Queue) -> anyhow::Result<()> {
        if let Some(port_id) = receiveq_port_id(idx) {
            self.wait_ctx
                .add(queue.event(), Token::ReceiveQueueAvailable(port_id))?;
        } else if let Some(port_id) = transmitq_port_id(idx) {
            self.wait_ctx
                .add(queue.event(), Token::TransmitQueueAvailable(port_id))?;
        } else if idx == CONTROL_RECEIVEQ_IDX {
            self.wait_ctx
                .add(queue.event(), Token::ControlReceiveQueueAvailable)?;
        } else if idx == CONTROL_TRANSMITQ_IDX {
            self.wait_ctx
                .add(queue.event(), Token::ControlTransmitQueueAvailable)?;
        } else {
            return Err(anyhow!("unhandled queue idx {idx}"));
        }

        let prev = self.queues.insert(idx, queue);
        assert!(prev.is_none());
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) -> Option<Queue> {
        if let Some(queue) = self.queues.remove(&idx) {
            let _ = self.wait_ctx.delete(queue.event());
            Some(queue)
        } else {
            None
        }
    }
}

pub struct WorkerHandle {
    worker_thread: WorkerThread<Vec<WorkerPort>>,
    worker_sender: mpsc::Sender<WorkerRequest>,
    worker_event: Event,
}

impl WorkerHandle {
    pub fn new(interrupt: Interrupt, ports: Vec<WorkerPort>) -> anyhow::Result<Self> {
        let worker_event = Event::new().context("Event::new")?;
        let worker_event_clone = worker_event.try_clone().context("Event::try_clone")?;
        let (worker_sender, worker_receiver) = mpsc::channel();
        let worker_thread = WorkerThread::start("v_console", move |kill_evt| {
            let mut worker = Worker::new(interrupt, ports, worker_receiver, worker_event_clone)
                .expect("console Worker::new() failed");
            if let Err(e) = worker.run(&kill_evt) {
                error!("console worker failed: {:#}", e);
            }
            worker.ports
        });
        Ok(WorkerHandle {
            worker_thread,
            worker_sender,
            worker_event,
        })
    }

    pub fn start_queue(&mut self, idx: usize, queue: Queue) -> anyhow::Result<()> {
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        self.worker_sender
            .send(WorkerRequest::StartQueue {
                idx,
                queue,
                response_sender,
            })
            .context("mpsc::Sender::send")?;
        self.worker_event.signal().context("Event::signal")?;
        response_receiver.recv().context("mpsc::Receiver::recv")?
    }

    pub fn stop_queue(&mut self, idx: usize) -> anyhow::Result<Option<Queue>> {
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        self.worker_sender
            .send(WorkerRequest::StopQueue {
                idx,
                response_sender,
            })
            .context("mpsc::Sender::send")?;
        self.worker_event.signal().context("Event::signal")?;
        response_receiver.recv().context("mpsc::Receiver::recv")
    }

    pub fn stop(self) -> Vec<WorkerPort> {
        self.worker_thread.stop()
    }
}

fn receiveq_idx(port_id: u32) -> Option<usize> {
    if port_id == 0 {
        Some(PORT0_RECEIVEQ_IDX)
    } else {
        PORT1_RECEIVEQ_IDX.checked_add((port_id - 1).checked_mul(2)?.try_into().ok()?)
    }
}

fn transmitq_idx(port_id: u32) -> Option<usize> {
    if port_id == 0 {
        Some(PORT0_TRANSMITQ_IDX)
    } else {
        PORT1_TRANSMITQ_IDX.checked_add((port_id - 1).checked_mul(2)?.try_into().ok()?)
    }
}

fn receiveq_port_id(queue_idx: usize) -> Option<u32> {
    if queue_idx == PORT0_RECEIVEQ_IDX {
        Some(0)
    } else if queue_idx >= PORT1_RECEIVEQ_IDX && (queue_idx & 1) == 0 {
        ((queue_idx - PORT1_RECEIVEQ_IDX) / 2)
            .checked_add(1)?
            .try_into()
            .ok()
    } else {
        None
    }
}

fn transmitq_port_id(queue_idx: usize) -> Option<u32> {
    if queue_idx == PORT0_TRANSMITQ_IDX {
        Some(0)
    } else if queue_idx >= PORT1_TRANSMITQ_IDX && (queue_idx & 1) == 1 {
        ((queue_idx - PORT1_TRANSMITQ_IDX) / 2)
            .checked_add(1)?
            .try_into()
            .ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receiveq_idx() {
        assert_eq!(receiveq_idx(0), Some(0));
        assert_eq!(receiveq_idx(1), Some(4));
        assert_eq!(receiveq_idx(2), Some(6));
        assert_eq!(receiveq_idx(3), Some(8));
    }

    #[test]
    fn test_transmitq_idx() {
        assert_eq!(transmitq_idx(0), Some(1));
        assert_eq!(transmitq_idx(1), Some(5));
        assert_eq!(transmitq_idx(2), Some(7));
        assert_eq!(transmitq_idx(3), Some(9));
    }

    #[test]
    fn test_receiveq_port_id() {
        assert_eq!(receiveq_port_id(0), Some(0));
        assert_eq!(receiveq_port_id(1), None); // port0 transmitq
        assert_eq!(receiveq_port_id(2), None); // ctrl receiveq
        assert_eq!(receiveq_port_id(3), None); // ctrl transmitq
        assert_eq!(receiveq_port_id(4), Some(1));
        assert_eq!(receiveq_port_id(5), None);
        assert_eq!(receiveq_port_id(6), Some(2));
        assert_eq!(receiveq_port_id(7), None);
        assert_eq!(receiveq_port_id(8), Some(3));
        assert_eq!(receiveq_port_id(9), None);
    }

    #[test]
    fn test_transmitq_port_id() {
        assert_eq!(transmitq_port_id(0), None); // port0 receiveq
        assert_eq!(transmitq_port_id(1), Some(0));
        assert_eq!(transmitq_port_id(2), None); // ctrl receiveq
        assert_eq!(transmitq_port_id(3), None); // ctrl transmitq
        assert_eq!(transmitq_port_id(4), None); // port1 receiveq
        assert_eq!(transmitq_port_id(5), Some(1));
        assert_eq!(transmitq_port_id(6), None);
        assert_eq!(transmitq_port_id(7), Some(2));
        assert_eq!(transmitq_port_id(8), None);
        assert_eq!(transmitq_port_id(9), Some(3));
    }
}
