// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio console device control queue handling.

use std::collections::VecDeque;
use std::io::Write;

use anyhow::anyhow;
use anyhow::Context;
use base::debug;
use base::error;
use zerocopy::AsBytes;

use crate::virtio::console::worker::WorkerPort;
use crate::virtio::device_constants::console::virtio_console_control;
use crate::virtio::device_constants::console::VIRTIO_CONSOLE_CONSOLE_PORT;
use crate::virtio::device_constants::console::VIRTIO_CONSOLE_DEVICE_ADD;
use crate::virtio::device_constants::console::VIRTIO_CONSOLE_DEVICE_READY;
use crate::virtio::device_constants::console::VIRTIO_CONSOLE_PORT_NAME;
use crate::virtio::device_constants::console::VIRTIO_CONSOLE_PORT_OPEN;
use crate::virtio::device_constants::console::VIRTIO_CONSOLE_PORT_READY;
use crate::virtio::Queue;
use crate::virtio::Reader;

pub type ControlMsgBytes = Box<[u8]>;

fn control_msg(id: u32, event: u16, value: u16, extra_bytes: &[u8]) -> ControlMsgBytes {
    virtio_console_control {
        id: id.into(),
        event: event.into(),
        value: value.into(),
    }
    .as_bytes()
    .iter()
    .chain(extra_bytes.iter())
    .copied()
    .collect()
}

fn process_control_msg(
    reader: &mut Reader,
    ports: &[WorkerPort],
    pending_receive_control_msgs: &mut VecDeque<ControlMsgBytes>,
) -> anyhow::Result<()> {
    let ctrl_msg: virtio_console_control =
        reader.read_obj().context("failed to read from reader")?;
    let id = ctrl_msg.id.to_native();
    let event = ctrl_msg.event.to_native();
    let value = ctrl_msg.value.to_native();

    match event {
        VIRTIO_CONSOLE_DEVICE_READY => {
            // value of 1 indicates success, and 0 indicates failure
            if value != 1 {
                return Err(anyhow!("console device ready failure ({value})"));
            }

            for (index, port) in ports.iter().enumerate() {
                let port_id = index as u32;
                // TODO(dverkamp): cap the size of `pending_receive_control_msgs` somehow
                pending_receive_control_msgs.push_back(control_msg(
                    port_id,
                    VIRTIO_CONSOLE_DEVICE_ADD,
                    0,
                    &[],
                ));

                if let Some(name) = port.name() {
                    pending_receive_control_msgs.push_back(control_msg(
                        port_id,
                        VIRTIO_CONSOLE_PORT_NAME,
                        0,
                        name.as_bytes(),
                    ));
                }
            }
            Ok(())
        }
        VIRTIO_CONSOLE_PORT_READY => {
            // value of 1 indicates success, and 0 indicates failure
            if value != 1 {
                return Err(anyhow!("console port{id} ready failure ({value})"));
            }

            let port = ports
                .get(id as usize)
                .with_context(|| format!("invalid port id {id}"))?;

            pending_receive_control_msgs.push_back(control_msg(
                id,
                VIRTIO_CONSOLE_PORT_OPEN,
                1,
                &[],
            ));

            if port.is_console() {
                pending_receive_control_msgs.push_back(control_msg(
                    id,
                    VIRTIO_CONSOLE_CONSOLE_PORT,
                    1,
                    &[],
                ));
            }
            Ok(())
        }
        VIRTIO_CONSOLE_PORT_OPEN => {
            match value {
                // Currently, port state change is not supported, default is open.
                // And only print debug info here.
                0 => debug!("console port{id} close"),
                1 => debug!("console port{id} open"),
                _ => error!("console port{id} unknown value {value}"),
            }
            Ok(())
        }
        _ => Err(anyhow!("unexpected control event {}", event)),
    }
}

pub fn process_control_transmit_queue(
    queue: &mut Queue,
    ports: &[WorkerPort],
    pending_receive_control_msgs: &mut VecDeque<ControlMsgBytes>,
) {
    let mut needs_interrupt = false;

    while let Some(mut avail_desc) = queue.pop() {
        if let Err(e) =
            process_control_msg(&mut avail_desc.reader, ports, pending_receive_control_msgs)
        {
            error!("failed to handle control msg: {:#}", e);
        }

        queue.add_used(avail_desc, 0);
        needs_interrupt = true;
    }

    if needs_interrupt {
        queue.trigger_interrupt();
    }
}

pub fn process_control_receive_queue(
    queue: &mut Queue,
    pending_receive_control_msgs: &mut VecDeque<ControlMsgBytes>,
) {
    let mut needs_interrupt = false;

    while !pending_receive_control_msgs.is_empty() {
        let Some(mut avail_desc) = queue.pop() else {
            break;
        };

        // Get a reply to copy into `avail_desc`. This should never fail since we check that
        // `pending_receive_control_msgs` is not empty in the loop condition.
        let reply = pending_receive_control_msgs
            .pop_front()
            .expect("missing reply");

        let len = match avail_desc.writer.write_all(&reply) {
            Ok(()) => avail_desc.writer.bytes_written() as u32,
            Err(e) => {
                error!("failed to write control receiveq reply: {}", e);
                0
            }
        };

        queue.add_used(avail_desc, len);
        needs_interrupt = true;
    }

    if needs_interrupt {
        queue.trigger_interrupt();
    }
}
