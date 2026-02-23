// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Write;
use std::result;

use base::error;
use base::warn;
use base::EventType;
use base::ReadNotifier;
use base::WaitContext;
use net_util::TapT;
use virtio_sys::virtio_net;
use virtio_sys::virtio_net::virtio_net_hdr;
use zerocopy::IntoBytes;

use super::super::super::net::NetError;
use super::super::super::net::Token;
use super::super::super::net::Worker;
use super::super::super::Queue;
use super::PendingBuffer;

use std::mem;

pub fn validate_and_configure_tap<T: TapT>(_tap: &T, _vq_pairs: u16) -> Result<(), NetError> {
    // macOS does not support tap vnet header configuration
    Ok(())
}

pub fn virtio_features_to_tap_offload(_features: u64) -> u32 {
    // macOS does not support tap offload flags
    0
}

pub fn process_mrg_rx<T: TapT>(
    rx_queue: &mut Queue,
    tap: &mut T,
    pending: &mut PendingBuffer,
) -> result::Result<(), NetError> {
    let mut needs_interrupt = false;
    let mut exhausted_queue = false;

    loop {
        if pending.length == 0 {
            match tap.read(&mut *pending.buffer) {
                Ok(length) => {
                    pending.length = length as u32;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => {
                    warn!("net: rx: failed to write slice: {}", e);
                    return Err(NetError::WriteBuffer(e));
                }
            }
        }
        if pending.length == 0 {
            break;
        }
        let packet_len = pending.length;
        let Some(mut desc_list) = rx_queue.try_pop_length(packet_len as usize) else {
            exhausted_queue = true;
            break;
        };
        let num_buffers = desc_list.len() as u16;

        let num_buffers_offset = mem::size_of::<virtio_net_hdr>();
        pending.buffer[num_buffers_offset..num_buffers_offset + 2]
            .copy_from_slice(num_buffers.as_bytes());
        let mut offset = 0;
        let end = packet_len as usize;
        for desc in desc_list.iter_mut() {
            let writer = &mut desc.writer;
            let bytes_written = match writer.write(&pending.buffer[offset..end]) {
                Ok(n) => n,
                Err(e) => {
                    warn!(
                        "net: mrg_rx: failed to write slice from pending buffer: {}",
                        e
                    );
                    return Err(NetError::WriteBuffer(e));
                }
            };
            offset += bytes_written;
        }
        rx_queue.add_used_batch(desc_list);

        needs_interrupt = true;
        pending.length = 0;
    }

    if needs_interrupt {
        rx_queue.trigger_interrupt();
    }

    if exhausted_queue {
        Err(NetError::RxDescriptorsExhausted)
    } else {
        Ok(())
    }
}

pub fn process_rx<T: TapT>(rx_queue: &mut Queue, mut tap: &mut T) -> result::Result<(), NetError> {
    let mut needs_interrupt = false;
    let mut exhausted_queue = false;

    loop {
        let mut desc_chain = match rx_queue.peek() {
            Some(desc) => desc,
            None => {
                exhausted_queue = true;
                break;
            }
        };

        let writer = &mut desc_chain.writer;

        match writer.write_from(&mut tap, writer.available_bytes()) {
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::WriteZero => {
                warn!("net: rx: buffer is too small to hold frame");
                break;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                break;
            }
            Err(e) => {
                warn!("net: rx: failed to write slice: {}", e);
                return Err(NetError::WriteBuffer(e));
            }
        };

        let bytes_written = writer.bytes_written() as u32;
        cros_tracing::trace_simple_print!("{bytes_written} bytes read from tap");

        if bytes_written > 0 {
            let desc_chain = desc_chain.pop();
            rx_queue.add_used(desc_chain);
            needs_interrupt = true;
        }
    }

    if needs_interrupt {
        rx_queue.trigger_interrupt();
    }

    if exhausted_queue {
        Err(NetError::RxDescriptorsExhausted)
    } else {
        Ok(())
    }
}

pub fn process_tx<T: TapT>(tx_queue: &mut Queue, mut tap: &mut T) {
    while let Some(mut desc_chain) = tx_queue.pop() {
        let reader = &mut desc_chain.reader;
        let expected_count = reader.available_bytes();
        match reader.read_to(&mut tap, expected_count) {
            Ok(count) => {
                if count != expected_count {
                    error!(
                        "net: tx: wrote only {} bytes of {} byte frame",
                        count, expected_count
                    );
                }
                cros_tracing::trace_simple_print!("{count} bytes write to tap");
            }
            Err(e) => error!("net: tx: failed to write frame to tap: {}", e),
        }

        tx_queue.add_used(desc_chain);
    }

    tx_queue.trigger_interrupt();
}

impl<T> Worker<T>
where
    T: TapT + ReadNotifier,
{
    pub(in crate::virtio) fn handle_rx_token(
        &mut self,
        wait_ctx: &WaitContext<Token>,
        pending_buffer: &mut PendingBuffer,
    ) -> result::Result<(), NetError> {
        match self.process_rx(pending_buffer) {
            Ok(()) => Ok(()),
            Err(NetError::RxDescriptorsExhausted) => {
                wait_ctx
                    .modify(&self.tap, EventType::None, Token::RxTap)
                    .map_err(NetError::WaitContextDisableTap)?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    pub(in crate::virtio) fn handle_rx_queue(
        &mut self,
        wait_ctx: &WaitContext<Token>,
        tap_polling_enabled: bool,
    ) -> result::Result<(), NetError> {
        if !tap_polling_enabled {
            wait_ctx
                .modify(&self.tap, EventType::Read, Token::RxTap)
                .map_err(NetError::WaitContextEnableTap)?;
        }
        Ok(())
    }
    pub(super) fn process_rx(
        &mut self,
        pending_buffer: &mut PendingBuffer,
    ) -> result::Result<(), NetError> {
        if self.acked_features & 1 << virtio_net::VIRTIO_NET_F_MRG_RXBUF == 0 {
            process_rx(&mut self.rx_queue, &mut self.tap)
        } else {
            process_mrg_rx(&mut self.rx_queue, &mut self.tap, pending_buffer)
        }
    }
}
