// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Read;
use std::io::Write;
use std::result;
use std::sync::Arc;
use std::sync::MutexGuard;

use base::error;
use base::named_pipes::OverlappedWrapper;
use base::warn;
use base::Event;
use base::ReadNotifier;
use base::WaitContext;
use libc::EEXIST;
use net_util::TapT;
use sync::Mutex;
use virtio_sys::virtio_net;
use vm_memory::GuestMemory;

use super::super::super::base_features;
use super::super::super::net::Net;
use super::super::super::net::NetError;
use super::super::super::net::Token;
use super::super::super::net::Worker;
use super::super::super::net::MAX_BUFFER_SIZE;
use super::super::super::Interrupt;
use super::super::super::ProtectionType;
use super::super::super::Queue;
use super::super::super::Reader;

// This file should not be included at virtio mod level if slirp is not include. In case it is,
// throw a user friendly message.
#[cfg(not(feature = "slirp"))]
compile_error!("Net device without slirp not supported on windows");

// Copies a single frame from `self.rx_buf` into the guest. Returns true
// if a buffer was used, and false if the frame must be deferred until a buffer
// is made available by the driver.
fn rx_single_frame(
    rx_queue: &mut MutexGuard<Queue>,
    mem: &GuestMemory,
    rx_buf: &mut [u8],
    rx_count: usize,
) -> bool {
    let mut desc_chain = match rx_queue.pop(mem) {
        Some(desc) => desc,
        None => return false,
    };

    match desc_chain.writer.write_all(&rx_buf[0..rx_count]) {
        Ok(()) => (),
        Err(ref e) if e.kind() == io::ErrorKind::WriteZero => {
            warn!(
                "net: rx: buffer is too small to hold frame of size {}",
                rx_count
            );
        }
        Err(e) => {
            warn!("net: rx: failed to write slice: {}", e);
        }
    };

    let bytes_written = desc_chain.writer.bytes_written() as u32;

    rx_queue.add_used(mem, desc_chain, bytes_written);

    true
}

pub fn process_rx<T: TapT>(
    interrupt: &Interrupt,
    rx_queue: &Arc<Mutex<Queue>>,
    mem: &GuestMemory,
    tap: &mut T,
    rx_buf: &mut [u8],
    deferred_rx: &mut bool,
    rx_count: &mut usize,
    overlapped_wrapper: &mut OverlappedWrapper,
) -> bool {
    let mut needs_interrupt = false;
    let mut first_frame = true;

    let mut rx_queue = rx_queue.try_lock().expect("Lock should not be unavailable");
    // Read as many frames as possible.
    loop {
        let res = if *deferred_rx {
            // The existing buffer still needs to be sent to the rx queue.
            Ok(*rx_count)
        } else {
            tap.try_read_result(overlapped_wrapper)
        };
        match res {
            Ok(count) => {
                *rx_count = count;
                if !rx_single_frame(&mut rx_queue, mem, rx_buf, *rx_count) {
                    *deferred_rx = true;
                    break;
                } else if first_frame {
                    interrupt.signal_used_queue(rx_queue.vector());
                    first_frame = false;
                } else {
                    needs_interrupt = true;
                }

                // SAFETY: safe because rx_buf & overlapped_wrapper live until
                // the overlapped operation completes and are not used in any
                // other operations until that time.
                match unsafe { tap.read_overlapped(rx_buf, overlapped_wrapper) } {
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                        warn!("net: rx: read_overlapped failed: {}", e);
                        break;
                    }
                    Err(e) => {
                        panic!("read_overlapped failed: {}", e);
                    }
                    _ => {}
                }

                // We were able to dispatch a frame to the guest, so we can resume normal RX
                // service.
                *deferred_rx = false;
            }
            Err(e) => {
                // `try_read_result()` shouldn't return any error other than
                // `ERROR_IO_INCOMPLETE`. If it does, we need to retry the
                // overlapped operation.
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    warn!("net: rx: failed to read tap: {}", e);
                    // SAFETY: safe because rx_buf & overlapped_wrapper live until
                    // the overlapped operation completes and are not used in any
                    // other operations until that time.
                    match unsafe { tap.read_overlapped(rx_buf, overlapped_wrapper) } {
                        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                            warn!("net: rx: read_overlapped failed: {}", e);
                            break;
                        }
                        Err(e) => {
                            panic!("read_overlapped failed: {}", e);
                        }
                        _ => {}
                    }
                }
                break;
            }
        }
    }

    needs_interrupt
}

pub fn process_tx<T: TapT>(
    interrupt: &Interrupt,
    tx_queue: &Arc<Mutex<Queue>>,
    mem: &GuestMemory,
    tap: &mut T,
) {
    // Reads up to `buf.len()` bytes or until there is no more data in `r`, whichever
    // is smaller.
    fn read_to_end(r: &mut Reader, buf: &mut [u8]) -> io::Result<usize> {
        let mut count = 0;
        while count < buf.len() {
            match r.read(&mut buf[count..]) {
                Ok(0) => break,
                Ok(n) => count += n,
                Err(e) => return Err(e),
            }
        }

        Ok(count)
    }

    let mut tx_queue = tx_queue.try_lock().expect("Lock should not be unavailable");
    while let Some(mut desc_chain) = tx_queue.pop(mem) {
        let mut frame = [0u8; MAX_BUFFER_SIZE];
        match read_to_end(&mut desc_chain.reader, &mut frame[..]) {
            Ok(len) => {
                // We need to copy frame into continuous buffer before writing it to
                // slirp because tap requires frame to complete in a single write.
                if let Err(err) = tap.write_all(&frame[..len]) {
                    error!("net: tx: failed to write to tap: {}", err);
                }
            }
            Err(e) => error!("net: tx: failed to read frame into buffer: {}", e),
        }

        tx_queue.add_used(mem, desc_chain, 0);
    }

    tx_queue.trigger_interrupt(mem, interrupt);
}

impl<T> Worker<T>
where
    T: TapT + ReadNotifier,
{
    pub(super) fn process_rx_slirp(&mut self) -> bool {
        process_rx(
            &self.interrupt,
            &self.rx_queue,
            &self.mem,
            &mut self.tap,
            &mut self.rx_buf,
            &mut self.deferred_rx,
            &mut self.rx_count,
            &mut self.overlapped_wrapper,
        )
    }

    pub(in crate::virtio) fn handle_rx_token(
        &mut self,
        wait_ctx: &WaitContext<Token>,
    ) -> result::Result<(), NetError> {
        let mut needs_interrupt = false;
        // Process a deferred frame first if available. Don't read from tap again
        // until we manage to receive this deferred frame.
        if self.deferred_rx {
            if rx_single_frame(
                &mut self
                    .rx_queue
                    .try_lock()
                    .expect("Lock should not be unavailable"),
                &self.mem,
                &mut self.rx_buf,
                self.rx_count,
            ) {
                self.deferred_rx = false;
                needs_interrupt = true;
            } else {
                // There is an outstanding deferred frame and the guest has not yet
                // made any buffers available. Remove the tapfd from the poll
                // context until more are made available.
                wait_ctx
                    .delete(&self.tap)
                    .map_err(NetError::EventRemoveTap)?;
                return Ok(());
            }
        }
        needs_interrupt |= self.process_rx_slirp();
        if needs_interrupt {
            self.interrupt.signal_used_queue(
                self.rx_queue
                    .try_lock()
                    .expect("Lock should not be unavailable")
                    .vector(),
            );
        }
        Ok(())
    }

    pub(in crate::virtio) fn handle_rx_queue(
        &mut self,
        wait_ctx: &WaitContext<Token>,
        _tap_polling_enabled: bool,
    ) -> result::Result<(), NetError> {
        let mut rx_queue = self
            .rx_queue
            .try_lock()
            .expect("Lock should not be unavailable");
        // There should be a buffer available now to receive the frame into.
        if self.deferred_rx
            && rx_single_frame(&mut rx_queue, &self.mem, &mut self.rx_buf, self.rx_count)
        {
            // The guest has made buffers available, so add the tap back to the
            // poll context in case it was removed.
            match wait_ctx.add(&self.tap, Token::RxTap) {
                Ok(_) => {}
                Err(e) if e.errno() == EEXIST => {}
                Err(e) => {
                    return Err(NetError::EventAddTap(e));
                }
            }
            self.deferred_rx = false;
            self.interrupt.signal_used_queue(rx_queue.vector());
        }
        Ok(())
    }
}
