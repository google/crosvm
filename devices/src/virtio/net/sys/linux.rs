// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::result;

use base::error;
use base::warn;
use base::EventType;
use base::ReadNotifier;
use base::WaitContext;
use net_util::TapT;
use virtio_sys::virtio_net;
use virtio_sys::virtio_net::virtio_net_hdr_v1;

use super::super::super::net::NetError;
use super::super::super::net::Token;
use super::super::super::net::Worker;
use super::super::super::Interrupt;
use super::super::super::Queue;

// Ensure that the tap interface has the correct flags and sets the offload and VNET header size
// to the appropriate values.
pub fn validate_and_configure_tap<T: TapT>(tap: &T, vq_pairs: u16) -> Result<(), NetError> {
    let flags = tap.if_flags();
    let mut required_flags = vec![
        (net_sys::IFF_TAP, "IFF_TAP"),
        (net_sys::IFF_NO_PI, "IFF_NO_PI"),
        (net_sys::IFF_VNET_HDR, "IFF_VNET_HDR"),
    ];
    if vq_pairs > 1 {
        required_flags.push((net_sys::IFF_MULTI_QUEUE, "IFF_MULTI_QUEUE"));
    }
    let missing_flags = required_flags
        .iter()
        .filter_map(
            |(value, name)| {
                if value & flags == 0 {
                    Some(name)
                } else {
                    None
                }
            },
        )
        .collect::<Vec<_>>();

    if !missing_flags.is_empty() {
        return Err(NetError::TapValidate(format!(
            "Missing flags: {:?}",
            missing_flags
        )));
    }

    let vnet_hdr_size = std::mem::size_of::<virtio_net_hdr_v1>();
    tap.set_vnet_hdr_size(vnet_hdr_size)
        .map_err(NetError::TapSetVnetHdrSize)?;

    Ok(())
}

/// Converts virtio-net feature bits to tap's offload bits.
pub fn virtio_features_to_tap_offload(features: u64) -> u32 {
    let mut tap_offloads: u32 = 0;
    if features & (1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM) != 0 {
        tap_offloads |= net_sys::TUN_F_CSUM;
    }
    if features & (1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4) != 0 {
        tap_offloads |= net_sys::TUN_F_TSO4;
    }
    if features & (1 << virtio_net::VIRTIO_NET_F_GUEST_TSO6) != 0 {
        tap_offloads |= net_sys::TUN_F_TSO6;
    }
    if features & (1 << virtio_net::VIRTIO_NET_F_GUEST_ECN) != 0 {
        tap_offloads |= net_sys::TUN_F_TSO_ECN;
    }
    if features & (1 << virtio_net::VIRTIO_NET_F_GUEST_UFO) != 0 {
        tap_offloads |= net_sys::TUN_F_UFO;
    }

    tap_offloads
}

pub fn process_rx<T: TapT>(
    interrupt: &Interrupt,
    rx_queue: &mut Queue,
    mut tap: &mut T,
) -> result::Result<(), NetError> {
    let mut needs_interrupt = false;
    let mut exhausted_queue = false;

    // Read as many frames as possible.
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
                // No more to read from the tap.
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
            rx_queue.add_used(desc_chain, bytes_written);
            needs_interrupt = true;
        }
    }

    if needs_interrupt {
        rx_queue.trigger_interrupt(interrupt);
    }

    if exhausted_queue {
        Err(NetError::RxDescriptorsExhausted)
    } else {
        Ok(())
    }
}

pub fn process_tx<T: TapT>(interrupt: &Interrupt, tx_queue: &mut Queue, mut tap: &mut T) {
    while let Some(mut desc_chain) = tx_queue.pop() {
        let reader = &mut desc_chain.reader;
        let expected_count = reader.available_bytes();
        match reader.read_to(&mut tap, expected_count) {
            Ok(count) => {
                // Tap writes must be done in one call. If the entire frame was not
                // written, it's an error.
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

        tx_queue.add_used(desc_chain, 0);
    }

    tx_queue.trigger_interrupt(interrupt);
}

impl<T> Worker<T>
where
    T: TapT + ReadNotifier,
{
    pub(in crate::virtio) fn handle_rx_token(
        &mut self,
        wait_ctx: &WaitContext<Token>,
    ) -> result::Result<(), NetError> {
        match self.process_rx() {
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
    pub(super) fn process_rx(&mut self) -> result::Result<(), NetError> {
        process_rx(&self.interrupt, &mut self.rx_queue, &mut self.tap)
    }
}
