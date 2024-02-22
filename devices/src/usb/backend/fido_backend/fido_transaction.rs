// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;

use base::error;
use base::warn;

use crate::usb::backend::fido_backend::constants;
use crate::usb::backend::fido_backend::error::Result;

/// Struct representation of a u2f-hid transaction according to the U2FHID protocol standard.
#[derive(Clone, Copy, Debug)]
pub struct FidoTransaction {
    /// Client ID of the transaction
    pub cid: u32,
    /// BCNT of the response.
    pub resp_bcnt: u16,
    /// Total size of the response.
    pub resp_size: u16,
    /// Unique nonce for broadcast transactions.
    /// The nonce size is 8 bytes, if no nonce is given it's empty
    pub nonce: [u8; constants::NONCE_SIZE],
}

/// Struct to keep track of all active transactions. It cycles through them, starts, stops and
/// removes outdated ones as they expire.
pub struct TransactionManager {
    transactions: VecDeque<FidoTransaction>,
    // TODO: Implement transaction timestamp and expiration timer
}

impl TransactionManager {
    pub fn new() -> Result<TransactionManager> {
        Ok(TransactionManager {
            transactions: VecDeque::new(),
        })
    }

    pub fn pop_transaction(&mut self) -> Option<FidoTransaction> {
        self.transactions.pop_front()
    }

    /// Attempts to close a transaction if it exists. Otherwise it silently drops it.
    /// It returns true to signal that there's no more transactions active and the device can
    /// return to an idle state.
    pub fn close_transaction(&mut self, cid: u32) -> bool {
        match self.transactions.iter().position(|t| t.cid == cid) {
            Some(index) => {
                self.transactions.remove(index);
            }
            None => {
                warn!(
                    "Tried to close a transaction that does not exist. Silently dropping request."
                );
            }
        };

        if self.transactions.is_empty() {
            return true;
        }
        false
    }

    /// Starts a new transaction in the queue. Returns true if it is the first transaction,
    /// signaling that the device would have to transition from idle to active state.
    pub fn start_transaction(&mut self, cid: u32, nonce: [u8; constants::NONCE_SIZE]) -> bool {
        let transaction = FidoTransaction {
            cid,
            resp_bcnt: 0,
            resp_size: 0,
            nonce,
        };

        // Remove the oldest transaction
        if self.transactions.len() >= constants::MAX_TRANSACTIONS {
            let _ = self.pop_transaction();
        }
        self.transactions.push_back(transaction);
        if self.transactions.len() == 1 {
            return true;
        }
        false
    }

    /// Resets the `TransactionManager`, dropping all pending transactions.
    pub fn reset(&mut self) {
        self.transactions = VecDeque::new();
    }

    /// Updates the bcnt and size of the first transaction that matches the given CID.
    pub fn update_transaction(&mut self, cid: u32, resp_bcnt: u16, resp_size: u16) {
        let index = match self
            .transactions
            .iter()
            .position(|t: &FidoTransaction| t.cid == cid)
        {
            Some(index) => index,
            None => {
                warn!(
                    "No u2f transaction found with (cid {}) in the list. Skipping.",
                    cid
                );
                return;
            }
        };
        match self.transactions.get_mut(index) {
            Some(t_ref) => {
                t_ref.resp_bcnt = resp_bcnt;
                t_ref.resp_size = resp_size;
            }
            None => {
                error!(
                    "A u2f transaction was found at index {} but now is gone. This is a bug.",
                    index
                );
            }
        };
    }

    /// Returns the first transaction that matches the given CID.
    pub fn get_transaction(&mut self, cid: u32) -> Option<FidoTransaction> {
        let index = match self
            .transactions
            .iter()
            .position(|t: &FidoTransaction| t.cid == cid)
        {
            Some(index) => index,
            None => {
                return None;
            }
        };
        match self.transactions.get(index) {
            Some(t_ref) => Some(*t_ref),
            None => {
                error!(
                    "A u2f transaction was found at index {} but now is gone. This is a bug.",
                    index
                );
                None
            }
        }
    }

    /// Returns the first broadcast transaction that matches the given nonce.
    pub fn get_transaction_from_nonce(
        &mut self,
        nonce: [u8; constants::NONCE_SIZE],
    ) -> Option<FidoTransaction> {
        let index =
            match self.transactions.iter().position(|t: &FidoTransaction| {
                t.cid == constants::BROADCAST_CID && t.nonce == nonce
            }) {
                Some(index) => index,
                None => {
                    return None;
                }
            };
        match self.transactions.get(index) {
            Some(t_ref) => Some(*t_ref),
            None => {
                error!(
                    "A u2f transaction was found at index {} but now is gone. This is a bug.",
                    index
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::usb::backend::fido_backend::constants::EMPTY_NONCE;
    use crate::usb::backend::fido_backend::constants::MAX_TRANSACTIONS;
    use crate::usb::backend::fido_backend::fido_transaction::TransactionManager;

    #[test]
    fn test_start_transaction() {
        let mut manager = TransactionManager::new().unwrap();
        let cid = 1234;

        assert!(manager.start_transaction(cid, EMPTY_NONCE));
        assert_eq!(manager.transactions.len(), 1);

        assert!(!manager.start_transaction(cid, EMPTY_NONCE));
        assert_eq!(manager.transactions.len(), 2);

        manager.reset();

        // We check that we silently drop old transactions once we go over the MAX_TRANSACTIONS
        // limit.
        for _ in 0..MAX_TRANSACTIONS + 1 {
            manager.start_transaction(cid, EMPTY_NONCE);
        }

        assert_eq!(manager.transactions.len(), MAX_TRANSACTIONS);
    }

    #[test]
    fn test_pop_transaction() {
        let mut manager = TransactionManager::new().unwrap();
        let cid1 = 1234;
        let cid2 = 5678;

        manager.start_transaction(cid1, EMPTY_NONCE);
        manager.start_transaction(cid2, EMPTY_NONCE);

        let popped_transaction = manager.pop_transaction().unwrap();

        assert_eq!(popped_transaction.cid, cid1);
    }

    #[test]
    fn test_close_transaction() {
        let mut manager = TransactionManager::new().unwrap();
        let cid1 = 1234;
        let cid2 = 5678;

        manager.start_transaction(cid1, EMPTY_NONCE);
        manager.start_transaction(cid2, EMPTY_NONCE);

        assert!(!manager.close_transaction(cid2));
        // We run this a second time to test it doesn't error out when closing already closed
        // transactions.
        assert!(!manager.close_transaction(cid2));
        assert_eq!(manager.transactions.len(), 1);
        assert!(manager.close_transaction(cid1));
    }

    #[test]
    fn test_update_transaction() {
        let mut manager = TransactionManager::new().unwrap();
        let cid = 1234;
        let bcnt = 17;
        let size = 56;

        manager.start_transaction(cid, EMPTY_NONCE);
        manager.update_transaction(cid, bcnt, size);

        let transaction = manager.get_transaction(cid).unwrap();

        assert_eq!(transaction.resp_bcnt, bcnt);
        assert_eq!(transaction.resp_size, size);
    }
}
