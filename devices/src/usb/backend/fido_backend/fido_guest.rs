// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;

use base::error;
use usb_util::TransferBuffer;

use crate::usb::backend::fido_backend::constants;
use crate::usb::backend::fido_backend::error::Error;
use crate::usb::backend::fido_backend::error::Result;
use crate::usb::backend::fido_backend::poll_thread::PollTimer;
use crate::usb::backend::fido_backend::transfer::FidoTransfer;

/// `FidoGuestKey` is the struct representation of a virtual fido device as seen by the guest VM.
/// It takes care of bubbling up transactions from the host into the guest and show a
/// representation of the device's state into the guest.
pub struct FidoGuestKey {
    /// Queue of packets already processed by the host that need to be sent to the guest.
    pub pending_in_packets: VecDeque<[u8; constants::U2FHID_PACKET_SIZE]>,
    /// HID Idle state of the security key.
    pub idle: u8,
    /// Timer used to poll to periodically send packets to pending USB transfers.
    pub timer: PollTimer,
}

impl FidoGuestKey {
    pub fn new() -> Result<Self> {
        let timer = PollTimer::new(
            "guest packet timer".to_string(),
            std::time::Duration::from_nanos(constants::PACKET_POLL_RATE_NANOS),
        )?;
        Ok(FidoGuestKey {
            pending_in_packets: VecDeque::with_capacity(constants::U2FHID_MAX_IN_PENDING),
            idle: 1,
            timer,
        })
    }

    /// Resets the guest key representation, stopping the poll and clearing the packet queue.
    pub fn reset(&mut self) {
        self.pending_in_packets.clear();
        if let Err(e) = self.timer.clear() {
            error!("Unable to clear guest key timer, silently failing. {}", e);
        }
    }

    /// Sends data to the guest by associating a given transfer to the oldest packet in the queue.
    /// If the data from the host hasn't been read yet (the packet queue is empty), it returns the
    /// same transfer back to the caller, unmodified.
    pub fn return_data_to_guest(
        &mut self,
        transfer_opt: Option<FidoTransfer>,
    ) -> Result<Option<FidoTransfer>> {
        // If this happens, it means we passed around an empty reference to a
        // non existing transfer that was already cancelled and removed.
        let mut transfer = transfer_opt.ok_or(Error::FidoTransferLost)?;
        match self.pending_in_packets.pop_front() {
            Some(packet) => {
                transfer.buffer = TransferBuffer::Vector(packet.to_vec());
                transfer.actual_length = packet.len();
                transfer.complete_transfer();
                Ok(None)
            }
            None => {
                // Pending queue is empty, nothing to do so we return the original transfer without
                // consuming it.
                Ok(Some(transfer))
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use sync::Mutex;
    use usb_util::TransferBuffer;
    use usb_util::TransferStatus;

    use crate::usb::backend::fido_backend::constants::U2FHID_PACKET_SIZE;
    use crate::usb::backend::fido_backend::fido_guest::FidoGuestKey;
    use crate::usb::backend::fido_backend::transfer::FidoTransfer;
    use crate::usb::backend::transfer::BackendTransfer;
    use crate::usb::backend::transfer::BackendTransferType;

    #[test]
    fn test_reset() {
        let mut fido_key = FidoGuestKey::new().unwrap();
        let fake_packet = [0; U2FHID_PACKET_SIZE];

        fido_key.pending_in_packets.push_back(fake_packet);
        assert_eq!(fido_key.pending_in_packets.len(), 1);
        fido_key.reset();
        assert_eq!(fido_key.pending_in_packets.len(), 0);
    }

    #[test]
    fn test_return_data_to_guest_no_packet_retry() {
        let mut fido_key = FidoGuestKey::new().unwrap();
        let transfer_buffer = TransferBuffer::Vector(vec![0u8; U2FHID_PACKET_SIZE]);
        let fake_transfer = FidoTransfer::new(1, transfer_buffer);

        let returned_transfer = fido_key.return_data_to_guest(Some(fake_transfer)).unwrap();
        assert!(returned_transfer.is_some());
    }

    #[test]
    fn test_return_data_to_guest_success() {
        let mut fido_key = FidoGuestKey::new().unwrap();
        let fake_packet = [5; U2FHID_PACKET_SIZE];
        let transfer_buffer = TransferBuffer::Vector(vec![0u8; U2FHID_PACKET_SIZE]);
        let mut fake_transfer = FidoTransfer::new(1, transfer_buffer);

        let callback_outer = Arc::new(Mutex::new(false));
        let callback_inner = callback_outer.clone();

        fake_transfer.set_callback(move |t: BackendTransferType| {
            assert_eq!(t.actual_length(), U2FHID_PACKET_SIZE);
            assert!(t.status() == TransferStatus::Completed);
            *callback_inner.lock() = true;
        });
        fido_key.pending_in_packets.push_back(fake_packet);

        let returned_transfer = fido_key.return_data_to_guest(Some(fake_transfer)).unwrap();
        assert!(returned_transfer.is_none());
        assert!(*callback_outer.lock());
    }
}
