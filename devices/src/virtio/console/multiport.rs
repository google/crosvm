// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of control port used for multi-port enabled virtio-console

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use base::debug;
use base::error;
use cros_async::select2;
use cros_async::EventAsync;
use cros_async::Executor;
use data_model::Le16;
use data_model::Le32;
use futures::channel::mpsc;
use futures::FutureExt;
use futures::SinkExt;
use futures::StreamExt;
use sync::Mutex;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use super::handle_input;
use crate::virtio;
use crate::virtio::async_device::AsyncQueueState;
use crate::virtio::console::ConsoleError;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::Reader;

type ControlMsgBytes = VecDeque<u8>;

#[derive(Clone, Debug, Default, FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
struct ControlMsg {
    id: Le32,
    event: Le16,
    value: Le16,
}

impl ControlMsg {
    fn new(id: u32, event: ControlEvent, value: u16) -> ControlMsg {
        ControlMsg {
            id: Le32::from(id),
            event: Le16::from(event as u16),
            value: Le16::from(value),
        }
    }
}

#[derive(Debug, PartialEq, enumn::N)]
enum ControlEvent {
    DeviceReady = 0,
    DeviceAdd = 1,
    DeviceRemove = 2,
    PortReady = 3,
    ConsolePort = 4,
    Resize = 5,
    PortOpen = 6,
    PortName = 7,
}
impl TryFrom<u16> for ControlEvent {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self> {
        match ControlEvent::n(value) {
            Some(event) => Ok(event),
            None => Err(anyhow!("unsupported event {}", value)),
        }
    }
}

fn process_tx_ctrl_msg(
    reader: &mut Reader,
    ports: &Vec<ConsolePortInfo>,
) -> Result<Vec<ControlMsgBytes>> {
    let mut messages = Vec::<ControlMsgBytes>::new();
    let ports_num = ports.len() as u32;
    let ctrl_msg: ControlMsg = reader.read_obj().context("failed to read from reader")?;
    let id = ctrl_msg.id.to_native();
    let event = ControlEvent::try_from(ctrl_msg.event.to_native())?;
    let value: u16 = ctrl_msg.value.to_native();

    if id >= ports_num && event != ControlEvent::DeviceReady {
        return Err(anyhow!("console: id {} out of range", id));
    }

    match event {
        ControlEvent::DeviceReady => {
            // value of 1 indicates success, and 0 indicates failure
            if value == 1 {
                for id in 0..ports_num {
                    let msg = ControlMsg::new(id, ControlEvent::DeviceAdd, 0);
                    let _ = msg.as_bytes();
                    messages.push(msg.as_bytes().to_owned().into());

                    let name = ports[id as usize].name.clone();
                    let msg = ControlMsg::new(id, ControlEvent::PortName, 0);
                    let mut reply: ControlMsgBytes = msg.as_bytes().to_owned().into();
                    reply.extend(name.as_bytes());
                    messages.push(reply);
                }
            } else {
                error!("console: received event {:?} value {}", event, value);
            }
        }
        ControlEvent::PortReady => {
            // value of 1 indicates success, and 0 indicates failure
            if value == 1 {
                let msg = ControlMsg::new(id, ControlEvent::PortOpen, 1);
                messages.push(msg.as_bytes().to_owned().into());

                let is_console = ports[id as usize].console;
                if is_console {
                    let msg = ControlMsg::new(id, ControlEvent::ConsolePort, 1);
                    messages.push(msg.as_bytes().to_owned().into());
                }
            } else {
                error!("console: received event {:?} value {}", event, value);
            }
        }
        ControlEvent::PortOpen => match value {
            // Currently, port state change is not supported, default is open.
            // And only print debug info here.
            0 => debug!("console port{} close", id),
            1 => debug!("console port{} open", id),
            _ => error!("console port{} open {}", id, value),
        },
        _ => {
            return Err(anyhow!("console: unexpected control event {:?}", event));
        }
    }

    Ok(messages)
}

fn process_tx_ctrl_queue(
    queue: &Arc<Mutex<Queue>>,
    doorbell: &Interrupt,
    ports: &Vec<ConsolePortInfo>,
) -> Vec<ControlMsgBytes> {
    let mut needs_interrupt = false;
    let mut messages = Vec::<ControlMsgBytes>::new();
    let mut queue = queue.try_lock().expect("Lock should not be unavailable");

    while let Some(mut avail_desc) = queue.pop() {
        match process_tx_ctrl_msg(&mut avail_desc.reader, ports) {
            Ok(mut msg) => messages.append(&mut msg),
            Err(e) => {
                error!("console: failed to handle control msg: {}", e);
            }
        }

        queue.add_used(avail_desc, 0);
        needs_interrupt = true;
    }

    if needs_interrupt {
        queue.trigger_interrupt(doorbell);
    }

    messages
}

async fn run_tx_ctrl_queue(
    queue: &Arc<Mutex<Queue>>,
    doorbell: Interrupt,
    kick_evt: EventAsync,
    sender: &mut mpsc::UnboundedSender<Vec<ControlMsgBytes>>,
    ports: Vec<ConsolePortInfo>,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for tx queue: {}", e);
            break;
        }

        let messages = process_tx_ctrl_queue(queue, &doorbell, &ports);

        if let Err(e) = sender.send(messages).await {
            error!("console: failed to send control msg: {}", e);
            break;
        }
    }
}

async fn run_rx_ctrl_queue(
    queue: &Arc<Mutex<Queue>>,
    doorbell: Interrupt,
    kick_evt: EventAsync,
    receiver: &mut mpsc::UnboundedReceiver<Vec<ControlMsgBytes>>,
) {
    loop {
        let messages = receiver.next().await;

        if let Some(messages) = messages {
            for mut msg in messages.into_iter() {
                while !msg.is_empty() {
                    match handle_input(&doorbell, &mut msg, queue) {
                        Ok(()) => {}
                        Err(ConsoleError::RxDescriptorsExhausted) => {
                            // Wait until a descriptor becomes available and try again.
                            if let Err(e) = kick_evt.next_val().await {
                                error!("Failed to read kick event for rx-ctrl queue: {}", e);
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Each port info for multi-port virtio-console
#[derive(Default, Clone)]
pub struct ConsolePortInfo {
    pub console: bool,
    pub name: String,
}

/// Control port for multi-port virtio-console
pub struct ControlPort {
    sender: AsyncQueueState<mpsc::UnboundedSender<Vec<ControlMsgBytes>>>,
    receiver: AsyncQueueState<mpsc::UnboundedReceiver<Vec<ControlMsgBytes>>>,
    ports: Vec<ConsolePortInfo>,
}

impl ControlPort {
    /// Create a control port with the given port info
    pub fn new(ports: Vec<ConsolePortInfo>) -> ControlPort {
        let (sender, receiver) = mpsc::unbounded::<Vec<ControlMsgBytes>>();

        ControlPort {
            sender: AsyncQueueState::Stopped(sender),
            receiver: AsyncQueueState::Stopped(receiver),
            ports,
        }
    }

    /// Start the control receiveq
    pub fn start_receive_queue(
        &mut self,
        ex: &Executor,
        queue: Arc<Mutex<virtio::Queue>>,
        doorbell: Interrupt,
    ) -> Result<()> {
        let kick_evt = queue
            .lock()
            .event()
            .try_clone()
            .context("Failed to clone queue event")?;
        let kick_evt =
            EventAsync::new(kick_evt, ex).context("Failed to create EventAsync for kick_evt")?;

        let receiver = &mut self.receiver;
        let rx_future = |mut receiver, abort| {
            Ok(async move {
                select2(
                    run_rx_ctrl_queue(&queue, doorbell, kick_evt, &mut receiver).boxed_local(),
                    abort,
                )
                .await;

                receiver
            })
        };

        receiver.start(ex, rx_future)
    }

    /// Stop the control receiveq
    pub fn stop_receive_queue(&mut self) -> anyhow::Result<bool> {
        self.receiver
            .stop()
            .context("failed to stop control rx queue")
    }

    /// Start the control transmitq
    pub fn start_transmit_queue(
        &mut self,
        ex: &Executor,
        queue: Arc<Mutex<virtio::Queue>>,
        doorbell: Interrupt,
    ) -> Result<()> {
        let kick_evt = queue
            .lock()
            .event()
            .try_clone()
            .context("Failed to clone queue event")?;
        let kick_evt =
            EventAsync::new(kick_evt, ex).context("Failed to create EventAsync for kick_evt")?;

        let sender = &mut self.sender;
        let ports = self.ports.clone();

        let tx_future = |mut sender, abort| {
            Ok(async move {
                select2(
                    run_tx_ctrl_queue(&queue, doorbell, kick_evt, &mut sender, ports).boxed_local(),
                    abort,
                )
                .await;

                sender
            })
        };

        sender.start(ex, tx_future)
    }

    /// Stop the control transmitq
    pub fn stop_transmit_queue(&mut self) -> anyhow::Result<bool> {
        self.sender
            .stop()
            .context("failed to stop control tx queue")
    }
}
