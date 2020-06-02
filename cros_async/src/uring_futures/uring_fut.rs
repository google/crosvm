// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::task::Poll;

use crate::uring_executor::{PendingOperation, Result};

/// Helper to drive the state of a uring future forward.
/// This deals with keeping state across the initialize->submit->poll->complete lifecycle of a uring
/// operation. Use `UringFutState` to aid in adapting the uring model to the futures `poll`
/// interface.
/// Generic across two parameters: T is the initial data needed to start the operation and W is the
/// data returned from start that is used to poll and complete the operation.
#[derive(Debug)]
pub(crate) enum UringFutState<T, W> {
    Init(T),
    Wait((PendingOperation, W)),
    Done,
    Processing,
}

impl<T, W> UringFutState<T, W> {
    /// Create a new `UringFutState` with the given initial state.
    pub fn new(init_data: T) -> Self {
        UringFutState::Init(init_data)
    }

    /// Move to the next state if ready.
    /// `start` - the function used to get the operation started, returns the data that is needed
    /// for polling and completion of the operation.
    /// `poll` - the function used to check if the operaition is complete.
    pub fn advance<S, P>(self, start: S, poll: P) -> Result<(Self, Poll<(Result<u32>, W)>)>
    where
        S: FnOnce(T) -> Result<(PendingOperation, W)>,
        P: FnOnce(&mut PendingOperation) -> Poll<Result<u32>>,
    {
        use UringFutState::*;
        // First advance from init if that's the current state.
        let (mut op, wait_data) = match self {
            Init(init_data) => start(init_data)?,
            Wait(op_wait) => op_wait,
            Done | Processing => unreachable!("Invalid future state"),
        };

        match poll(&mut op) {
            Poll::Pending => Ok((Wait((op, wait_data)), Poll::Pending)),
            Poll::Ready(res) => Ok((Done, Poll::Ready((res, wait_data)))),
        }
    }
}
