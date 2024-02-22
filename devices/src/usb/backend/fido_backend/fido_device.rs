// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Error as IOError;
use std::io::ErrorKind;
use std::io::Write;
use std::sync::Arc;

use base::debug;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::EventType;
use base::RawDescriptor;
use sync::Mutex;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::usb::backend::fido_backend::constants;
use crate::usb::backend::fido_backend::error::Error;
use crate::usb::backend::fido_backend::error::Result;
use crate::usb::backend::fido_backend::fido_guest::FidoGuestKey;
use crate::usb::backend::fido_backend::fido_transaction::TransactionManager;
use crate::usb::backend::fido_backend::hid_utils::verify_is_fido_device;
use crate::usb::backend::fido_backend::poll_thread::PollTimer;
use crate::utils::EventLoop;

#[derive(FromZeroes, FromBytes, Debug)]
#[repr(C)]
pub struct InitPacket {
    cid: u32,
    cmd: u8,
    bcnth: u8,
    bcntl: u8,
    data: [u8; constants::PACKET_INIT_DATA_SIZE],
}

impl InitPacket {
    pub fn extract_cid(bytes: [u8; constants::U2FHID_PACKET_SIZE]) -> Result<u32> {
        // cid is the first 4 bytes so we don't need to worry about anything else in the bytes
        // buffer, we can just read from prefix.
        FromBytes::read_from_prefix(&bytes[..]).ok_or_else(|| Error::CannotExtractCidFromBytes)
    }

    fn is_valid(bytes: [u8; constants::U2FHID_PACKET_SIZE]) -> bool {
        (bytes[4] & constants::PACKET_INIT_VALID_CMD) != 0
    }

    pub fn from_bytes(bytes: [u8; constants::U2FHID_PACKET_SIZE]) -> Result<InitPacket> {
        if !InitPacket::is_valid(bytes) {
            return Err(Error::InvalidInitPacket);
        }

        InitPacket::read_from(&bytes[..]).ok_or_else(|| Error::CannotConvertInitPacketFromBytes)
    }

    pub fn bcnt(&self) -> u16 {
        (self.bcnth as u16) << 8 | (self.bcntl as u16)
    }
}

/// A virtual representation of a FidoDevice emulated on the Host.
pub struct FidoDevice {
    /// Guest representation of the virtual security key device
    pub guest_key: Arc<Mutex<FidoGuestKey>>,
    /// The `TransactionManager` which handles starting and stopping u2f transactions
    pub transaction_manager: Arc<Mutex<TransactionManager>>,
    /// Marks whether the current device is active in a transaction. If it is not active, the fd
    /// polling event loop does not handle the device fd monitoring.
    pub is_active: bool,
    /// Marks whether the device has been lost. In case the FD stops being responsive we signal
    /// that the device is lost and any further transaction will return a failure.
    pub is_device_lost: bool,
    /// Backend provider event loop to attach/detach the monitored fd.
    event_loop: Arc<EventLoop>,
    /// Timer to poll for active USB transfers
    pub transfer_timer: PollTimer,
    /// fd of the actual hidraw device
    pub fd: Arc<Mutex<File>>,
}

impl AsRawDescriptor for FidoDevice {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.fd.lock().as_raw_descriptor()
    }
}

impl FidoDevice {
    pub fn new(hidraw: File, event_loop: Arc<EventLoop>) -> Result<FidoDevice> {
        verify_is_fido_device(&hidraw)?;
        let timer = PollTimer::new(
            "USB transfer timer".to_string(),
            std::time::Duration::from_millis(constants::USB_POLL_RATE_MILLIS),
        )?;
        Ok(FidoDevice {
            guest_key: Arc::new(Mutex::new(FidoGuestKey::new()?)),
            transaction_manager: Arc::new(Mutex::new(TransactionManager::new()?)),
            is_active: false,
            is_device_lost: false,
            event_loop,
            transfer_timer: timer,
            fd: Arc::new(Mutex::new(hidraw)),
        })
    }

    /// Sets the device active state. If the device becomes active, it toggles polling on the file
    /// descriptor for the host hid device. If the devices becomes inactive, it stops polling.
    /// In case of error, it's not possible to recover so we just log the warning and continue.
    pub fn set_active(&mut self, active: bool) {
        if self.is_active && !active {
            if let Err(e) = self.event_loop.pause_event_for_descriptor(self) {
                error!("Could not deactivate polling of host device: {}", e);
            }
        } else if !self.is_active && active {
            if let Err(e) = self
                .event_loop
                .resume_event_for_descriptor(self, EventType::Read)
            {
                error!(
                    "Could not resume polling of host device, transactions will be lost: {}",
                    e
                );
            }
        }

        self.is_active = active;
    }

    /// Starts a new transaction from a given init packet.
    pub fn start_transaction(&mut self, packet: &InitPacket) -> Result<()> {
        let nonce = if packet.cid == constants::BROADCAST_CID {
            packet.data[..constants::NONCE_SIZE]
                .try_into()
                .map_err(|_| Error::InvalidNonceSize)?
        } else {
            constants::EMPTY_NONCE
        };

        // Start a transaction and the expiration timer if necessary
        if self
            .transaction_manager
            .lock()
            .start_transaction(packet.cid, nonce)
        {
            // Enable the timer that polls for transactions to expire
            self.transaction_manager.lock().transaction_timer.arm()?;
        }

        // Transition the low level device to active for a response from the host
        self.set_active(true);
        Ok(())
    }

    /// Receives a low-level request from the host device. It means we read data from the actual
    /// key on the host.
    pub fn recv_from_host(&mut self, packet: [u8; constants::U2FHID_PACKET_SIZE]) -> Result<()> {
        let cid = InitPacket::extract_cid(packet)?;
        let transaction_opt = if cid == constants::BROADCAST_CID {
            match InitPacket::from_bytes(packet) {
                Ok(packet) => {
                    // This is a special case, in case of an error message we return to the
                    // latest broadcast transaction without nonce checking.
                    if packet.cmd == constants::U2FHID_ERROR_CMD {
                        self.transaction_manager.lock().get_transaction(cid)
                    // Otherwise we verify that the nonce matches the right transaction.
                    } else {
                        let nonce = packet.data[..constants::NONCE_SIZE]
                            .try_into()
                            .map_err(|_| Error::InvalidNonceSize)?;
                        self.transaction_manager
                            .lock()
                            .get_transaction_from_nonce(nonce)
                    }
                }
                _ => {
                    // Drop init transaction with bad init packet
                    return Ok(());
                }
            }
        } else {
            self.transaction_manager.lock().get_transaction(cid)
        };

        let transaction = match transaction_opt {
            Some(t) => t,
            None => {
                debug!("Ignoring non-started transaction");
                return Ok(());
            }
        };

        match InitPacket::from_bytes(packet) {
            Ok(packet) => {
                if packet.cid == constants::BROADCAST_CID {
                    let nonce = &packet.data[..constants::NONCE_SIZE];
                    if transaction.nonce != nonce {
                        // In case of an error command we can let it through, otherwise we drop the
                        // response.
                        if packet.cmd != constants::U2FHID_ERROR_CMD {
                            warn!(
                                "u2f: received a broadcast transaction with mismatched nonce.\
                                Ignoring transaction."
                            );
                            return Ok(());
                        }
                    }
                }
                self.transaction_manager.lock().update_transaction(
                    cid,
                    packet.bcnt(),
                    constants::PACKET_INIT_DATA_SIZE as u16,
                );
            }
            // It's not an init packet, it means it's a continuation packet
            Err(Error::InvalidInitPacket) => {
                self.transaction_manager.lock().update_transaction(
                    cid,
                    transaction.resp_bcnt,
                    transaction.resp_size + constants::PACKET_CONT_DATA_SIZE as u16,
                );
            }
            Err(e) => {
                error!(
                    "u2f: received an invalid transaction state: {:?}. Ignoring transaction.",
                    e
                );
                return Ok(());
            }
        }

        // Fetch the transaction again to check if we are done processing it or if we should wait
        // for more continuation packets.
        let transaction = match self.transaction_manager.lock().get_transaction(cid) {
            Some(t) => t,
            None => {
                error!(
                    "We lost a transaction on the way. This is a bug. (cid: {})",
                    cid
                );
                return Ok(());
            }
        };
        // Check for the end of the transaction
        if transaction.resp_size >= transaction.resp_bcnt {
            if self
                .transaction_manager
                .lock()
                .close_transaction(transaction.cid)
            {
                // Resets the device as inactive, since we're not waiting for more data to come
                // from the host.
                self.set_active(false);
            }
        }

        let mut guest_key = self.guest_key.lock();
        if guest_key.pending_in_packets.is_empty() {
            // We start polling waiting to send the data back to the guest.
            if let Err(e) = guest_key.timer.arm() {
                error!(
                    "Unable to start U2F guest key timer. U2F packets may be lost. {}",
                    e
                );
            }
        }
        guest_key.pending_in_packets.push_back(packet);

        Ok(())
    }

    /// Receives a request from the guest device to write into the actual device on the host.
    pub fn recv_from_guest(
        &mut self,
        packet: [u8; constants::U2FHID_PACKET_SIZE],
    ) -> Result<usize> {
        // The first byte in the host packet request is the HID report request ID as required by
        // the Linux kernel. The real request data starts from the second byte, so we need to
        // allocate one extra byte in our write buffer.
        // See: https://docs.kernel.org/hid/hidraw.html#write
        let mut host_packet = vec![0; constants::U2FHID_PACKET_SIZE + 1];

        match InitPacket::from_bytes(packet) {
            Ok(init_packet) => {
                self.start_transaction(&init_packet)?;
            }
            Err(Error::InvalidInitPacket) => {
                // It's not an init packet, so we don't start a transaction.
            }
            Err(e) => {
                warn!("Received malformed or invalid u2f-hid init packet, request will be dropped");
                return Err(e);
            }
        }

        host_packet[1..].copy_from_slice(&packet);

        let written = self
            .fd
            .lock()
            .write(&host_packet)
            .map_err(Error::WriteHidrawDevice)?;

        if written != host_packet.len() {
            return Err(Error::WriteHidrawDevice(IOError::new(
                ErrorKind::Other,
                "Wrote too few bytes to hidraw device.",
            )));
        }

        // we subtract 1 because we added 1 extra byte to the host packet
        Ok(host_packet.len() - 1)
    }
}
