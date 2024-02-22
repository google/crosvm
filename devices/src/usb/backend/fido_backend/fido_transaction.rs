// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::time::Instant;

use base::error;
use base::warn;

cfg_if::cfg_if! {
    if #[cfg(test)] {
        use base::FakeClock as Clock;
    } else {
        use base::Clock;
    }
}

use crate::usb::backend::fido_backend::constants;
use crate::usb::backend::fido_backend::error::Result;
use crate::usb::backend::fido_backend::poll_thread::PollTimer;

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
    /// Timestamp of the transaction submission time.
    submission_time: Instant,
}

/// Struct to keep track of all active transactions. It cycles through them, starts, stops and
/// removes outdated ones as they expire.
pub struct TransactionManager {
    /// Sorted (by age) list of transactions.
    transactions: VecDeque<FidoTransaction>,
    /// Timestamp of the latest transaction.
    last_transaction_time: Instant,
    /// Timer used to poll for expired transactions.
    pub transaction_timer: PollTimer,
    /// Clock representation, overridden for testing.
    clock: Clock,
}

impl TransactionManager {
    pub fn new() -> Result<TransactionManager> {
        let timer = PollTimer::new(
            "transaction timer".to_string(),
            // Transactions expire after 120 seconds, polling a tenth of the time
            // sounds acceptable
            std::time::Duration::from_millis(constants::TRANSACTION_TIMEOUT_MILLIS / 10),
        )?;
        let clock = Clock::new();
        Ok(TransactionManager {
            transactions: VecDeque::new(),
            last_transaction_time: clock.now(),
            clock,
            transaction_timer: timer,
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
            submission_time: self.clock.now(),
        };

        // Remove the oldest transaction
        if self.transactions.len() >= constants::MAX_TRANSACTIONS {
            let _ = self.pop_transaction();
        }
        self.last_transaction_time = transaction.submission_time;
        self.transactions.push_back(transaction);
        if self.transactions.len() == 1 {
            return true;
        }
        false
    }

    /// Tests the transaction expiration time. If the latest transaction time is beyond the
    /// acceptable timeout, it removes all transactions and signals to reset the device (returns
    /// true).
    pub fn expire_transactions(&mut self) -> bool {
        // We have no transactions pending, so we can just return true
        if self.transactions.is_empty() {
            return true;
        }

        // The transaction manager resets if transactions took too long. We use duration_since
        // instead of elapsed so we can work with fake clocks in tests.
        if self
            .clock
            .now()
            .duration_since(self.last_transaction_time)
            .as_millis()
            >= constants::TRANSACTION_TIMEOUT_MILLIS.into()
        {
            self.reset();
            return true;
        }
        false
    }

    /// Resets the `TransactionManager`, dropping all pending transactions.
    pub fn reset(&mut self) {
        self.transactions = VecDeque::new();
        self.last_transaction_time = self.clock.now();
        if let Err(e) = self.transaction_timer.clear() {
            error!(
                "Unable to clear transaction manager timer, silently failing. {}",
                e
            );
        }
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
    use crate::usb::backend::fido_backend::constants::TRANSACTION_TIMEOUT_MILLIS;
    use crate::usb::backend::fido_backend::fido_transaction::TransactionManager;

    #[test]
    fn test_start_transaction() {
        let mut manager = TransactionManager::new().unwrap();
        let cid = 1234;

        assert!(manager.start_transaction(cid, EMPTY_NONCE));
        assert_eq!(manager.transactions.len(), 1);
        assert_eq!(manager.last_transaction_time, manager.clock.now());

        manager.clock.add_ns(100);

        assert!(!manager.start_transaction(cid, EMPTY_NONCE));
        assert_eq!(manager.transactions.len(), 2);
        assert_eq!(manager.last_transaction_time, manager.clock.now());

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

    #[test]
    fn test_expire_transactions() {
        let mut manager = TransactionManager::new().unwrap();
        let cid = 1234;

        // No transactions, so it defaults to true
        assert!(manager.expire_transactions());

        manager.start_transaction(cid, EMPTY_NONCE);
        assert!(!manager.expire_transactions());

        // Advance clock beyond expiration time, convert milliseconds to nanoseconds
        manager
            .clock
            .add_ns(TRANSACTION_TIMEOUT_MILLIS * 1000000 + 1);
        assert!(manager.expire_transactions());
        assert_eq!(manager.transactions.len(), 0);
    }
}
