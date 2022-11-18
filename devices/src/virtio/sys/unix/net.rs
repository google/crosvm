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
use vm_memory::GuestMemory;

use super::super::super::net::NetError;
use super::super::super::net::Token;
use super::super::super::net::Worker;
use super::super::super::Queue;
use super::super::super::Reader;
use super::super::super::SignalableInterrupt;
use super::super::super::Writer;

pub fn process_rx<I: SignalableInterrupt, T: TapT>(
    interrupt: &I,
    rx_queue: &mut Queue,
    mem: &GuestMemory,
    mut tap: &mut T,
) -> result::Result<(), NetError> {
    let mut needs_interrupt = false;
    let mut exhausted_queue = false;

    // Read as many frames as possible.
    loop {
        let desc_chain = match rx_queue.peek(mem) {
            Some(desc) => desc,
            None => {
                exhausted_queue = true;
                break;
            }
        };

        let index = desc_chain.index;
        let bytes_written = match Writer::new(mem.clone(), desc_chain) {
            Ok(mut writer) => {
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

                writer.bytes_written() as u32
            }
            Err(e) => {
                error!("net: failed to create Writer: {}", e);
                0
            }
        };

        if bytes_written > 0 {
            rx_queue.pop_peeked(mem);
            rx_queue.add_used(mem, index, bytes_written);
            needs_interrupt = true;
        }
    }

    if needs_interrupt {
        rx_queue.trigger_interrupt(mem, interrupt);
    }

    if exhausted_queue {
        Err(NetError::RxDescriptorsExhausted)
    } else {
        Ok(())
    }
}

pub fn process_tx<I: SignalableInterrupt, T: TapT>(
    interrupt: &I,
    tx_queue: &mut Queue,
    mem: &GuestMemory,
    mut tap: &mut T,
) {
    while let Some(desc_chain) = tx_queue.pop(mem) {
        let index = desc_chain.index;

        match Reader::new(mem.clone(), desc_chain) {
            Ok(mut reader) => {
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
                    }
                    Err(e) => error!("net: tx: failed to write frame to tap: {}", e),
                }
            }
            Err(e) => error!("net: failed to create Reader: {}", e),
        }

        tx_queue.add_used(mem, index, 0);
    }

    tx_queue.trigger_interrupt(mem, interrupt);
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
        process_rx(
            &self.interrupt,
            &mut self.rx_queue,
            &self.mem,
            &mut self.tap,
        )
    }
}
