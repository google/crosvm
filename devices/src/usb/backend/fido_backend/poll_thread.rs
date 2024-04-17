// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This file contains all functions and structs used to handle polling operations for the fido
//! backend device.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use base::debug;
use base::error;
use base::AsRawDescriptor;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::Timer;
use base::TimerTrait;
use base::WaitContext;
use sync::Mutex;
use usb_util::TransferStatus;

use crate::usb::backend::fido_backend::error::Error;
use crate::usb::backend::fido_backend::error::Result;
use crate::usb::backend::fido_backend::fido_device::FidoDevice;
use crate::usb::backend::fido_backend::transfer::FidoTransfer;
use crate::usb::backend::fido_backend::transfer::FidoTransferHandle;
use crate::usb::backend::transfer::BackendTransfer;
use crate::usb::backend::transfer::GenericTransferHandle;

#[derive(EventToken)]
enum Token {
    TransactionPollTimer,
    TransferPollTimer,
    PacketPollTimer,
    Kill,
}

/// PollTimer is a wrapper around the crosvm-provided `Timer` struct with a focus on maintaining a
/// regular interval with easy `arm()` and `clear()` methods to start and stop the timer
/// transparently from the interval.
pub struct PollTimer {
    name: String,
    timer: Timer,
    interval: Duration,
}

impl PollTimer {
    pub fn new(name: String, interval: Duration) -> Result<Self> {
        let timer = Timer::new().map_err(Error::CannotCreatePollTimer)?;
        Ok(PollTimer {
            name,
            timer,
            interval,
        })
    }

    /// Arms the timer with its initialized interval.
    pub fn arm(&mut self) -> Result<()> {
        self.timer
            .reset_oneshot(self.interval)
            .map_err(|error| Error::CannotArmPollTimer {
                name: self.name.clone(),
                error,
            })
    }

    /// Clears the timer, disarming it.
    pub fn clear(&mut self) -> Result<()> {
        self.timer
            .clear()
            .map_err(|error| Error::CannotClearPollTimer {
                name: self.name.clone(),
                error,
            })
    }
}

impl AsRawDescriptor for PollTimer {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.timer.as_raw_descriptor()
    }
}

/// This function is the main poll thread. It periodically wakes up to emulate a USB interrupt
/// (poll) device behavior. It takes care of three different poll timers:
/// - `PacketPollTimer`: periodically polls for available USB transfers waiting for data
/// - `TransferPollTimer`: times out USB transfers that stay pending for too long without data
/// - `TransactionPollTimer`: puts the security key device to sleep when transactions time out
pub fn poll_for_pending_packets(
    device: Arc<Mutex<FidoDevice>>,
    pending_in_transfers: Arc<
        Mutex<VecDeque<(FidoTransferHandle, Arc<Mutex<Option<FidoTransfer>>>)>>,
    >,
    kill_evt: Event,
) -> Result<()> {
    let device_lock = device.lock();
    let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
        (&device_lock.guest_key.lock().timer, Token::PacketPollTimer),
        (&device_lock.transfer_timer, Token::TransferPollTimer),
        (
            &device_lock.transaction_manager.lock().transaction_timer,
            Token::TransactionPollTimer,
        ),
        (&kill_evt, Token::Kill),
    ])
    .context("poll worker context failed")
    .map_err(Error::WaitContextFailed)?;
    drop(device_lock);

    loop {
        let events = wait_ctx
            .wait()
            .context("wait failed")
            .map_err(Error::WaitContextFailed)?;
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                // This timer checks that we have u2f host packets pending, waiting to be sent to
                // the guest, and that we have a valid USB transfer from the guest waiting for
                // data.
                Token::PacketPollTimer => {
                    handle_packet_poll(&device, &pending_in_transfers)?;
                    // If there are still transfers waiting in the queue we continue polling.
                    if packet_timer_needs_rearm(&device, &pending_in_transfers) {
                        device.lock().guest_key.lock().timer.arm()?;
                    }
                }
                // This timer takes care of expiring USB transfers from the guest as they time out
                // waiting for data from the host. It is the equivalent of a USB interrupt poll
                // thread.
                Token::TransferPollTimer => {
                    let mut transfers_lock = pending_in_transfers.lock();

                    transfers_lock.retain(process_pending_transfer);

                    // If the device has died, we need to tell the first pending transfer
                    // that the device has been lost at the xhci level, so we can safely detach the
                    // device from the guest.
                    if device.lock().is_device_lost {
                        let (_, transfer_opt) = match transfers_lock.pop_front() {
                            Some(tuple) => tuple,
                            None => {
                                // No pending transfers waiting for data, so we do nothing.
                                continue;
                            }
                        };
                        signal_device_lost(transfer_opt.lock().take());
                        return Ok(());
                    }

                    // If we still have pending transfers waiting, we keep polling, otherwise we
                    // stop.
                    if transfers_lock.len() > 0 {
                        device.lock().transfer_timer.arm()?;
                    } else {
                        device.lock().transfer_timer.clear()?;
                    }
                }
                // This timer takes care of timing out u2f transactions that haven't seen any
                // activity from either guest or host for a long-enough time.
                Token::TransactionPollTimer => {
                    // If transactions aren't expired, re-arm
                    if !device
                        .lock()
                        .transaction_manager
                        .lock()
                        .expire_transactions()
                    {
                        device
                            .lock()
                            .transaction_manager
                            .lock()
                            .transaction_timer
                            .arm()?;
                    }
                }
                Token::Kill => {
                    debug!("Fido poll thread exited succesfully.");
                    return Ok(());
                }
            }
        }
    }
}

/// Handles polling for available data to send back to the guest.
fn handle_packet_poll(
    device: &Arc<Mutex<FidoDevice>>,
    pending_in_transfers: &Arc<
        Mutex<VecDeque<(FidoTransferHandle, Arc<Mutex<Option<FidoTransfer>>>)>>,
    >,
) -> Result<()> {
    if device.lock().is_device_lost {
        // Rather than erroring here, we just return Ok as the case of a device being lost is
        // handled by the transfer timer.
        return Ok(());
    }
    let mut transfers_lock = pending_in_transfers.lock();

    // Process and remove expired or cancelled transfers
    transfers_lock.retain(process_pending_transfer);

    if transfers_lock.is_empty() {
        // We cannot do anything, the active transfers got pruned.
        // Return Ok() and let the poll thread handle the missing packets.
        return Ok(());
    }

    // Fetch first available transfer from the pending list and its fail handle.
    let (_, transfer_opt) = match transfers_lock.pop_front() {
        Some(tuple) => tuple,
        None => {
            // No pending transfers waiting for data, so we do nothing.
            return Ok(());
        }
    };
    drop(transfers_lock);

    let mut transfer_lock = transfer_opt.lock();
    let transfer = transfer_lock.take();

    // Obtain the next packet from the guest key and send it to the guest
    match device
        .lock()
        .guest_key
        .lock()
        .return_data_to_guest(transfer)?
    {
        None => {
            // The transfer was successful, nothing to do.
            Ok(())
        }
        transfer => {
            // We received our transfer back, it means there's no data available to return to the
            // guest.
            *transfer_lock = transfer;
            drop(transfer_lock);
            let cancel_handle = FidoTransferHandle {
                weak_transfer: Arc::downgrade(&transfer_opt),
            };

            // Put the transfer back into the pending queue, we can try again later.
            pending_in_transfers
                .lock()
                .push_front((cancel_handle, transfer_opt));
            Ok(())
        }
    }
}

/// Filter functions used to check for expired or canceled transfers. It is called over each
/// USB transfer waiting in the pending queue. Returns true if the given transfer is still valid,
/// otherwise false.
fn process_pending_transfer(
    transfer_handle_pair: &(FidoTransferHandle, Arc<Mutex<Option<FidoTransfer>>>),
) -> bool {
    let mut lock = transfer_handle_pair.1.lock();
    let transfer = match lock.take() {
        Some(t) => {
            // The transfer has already been cancelled. We report back to the xhci level and remove
            // it.
            if t.status() == TransferStatus::Cancelled {
                t.complete_transfer();
                return false;
            }
            // The transfer has expired, we cancel it and report back to the xhci level.
            if t.timeout_expired() {
                if let Err(e) = transfer_handle_pair.0.cancel() {
                    error!("Failed to properly cancel IN transfer, dropping the request: {e:#}");
                    return false;
                }
                t.complete_transfer();
                return false;
            }
            Some(t)
        }
        None => {
            // Transfer has already been removed so we can skip it.
            return false;
        }
    };
    *lock = transfer;

    true
}

/// Signals to the current transfer that the underlying device has been lost and the xhci layer
/// should recover by detaching the FIDO backend.
fn signal_device_lost(transfer_opt: Option<FidoTransfer>) {
    if let Some(mut transfer) = transfer_opt {
        transfer.signal_device_lost();
        transfer.complete_transfer();
    }
}

/// Checks whether we should re-arm the packet poll timer or not.
fn packet_timer_needs_rearm(
    device: &Arc<Mutex<FidoDevice>>,
    pending_in_transfers: &Arc<
        Mutex<VecDeque<(FidoTransferHandle, Arc<Mutex<Option<FidoTransfer>>>)>>,
    >,
) -> bool {
    let transfers_lock = pending_in_transfers.lock();
    if transfers_lock.is_empty() {
        // If there are no transfers pending, it means that some packet got stuck or lost,
        // so we just reset the entire device state since no one is waiting for a
        // response from the xhci level anyway.
        device.lock().guest_key.lock().reset();
        return false;
    }
    true
}
