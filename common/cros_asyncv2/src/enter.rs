// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::Cell;

use thiserror::Error as ThisError;

thread_local! (static EXECUTOR_ACTIVE: Cell<bool> = Cell::new(false));

#[derive(ThisError, Debug)]
#[error("Nested execution is not supported")]
struct NestedExecutionNotSupported;

#[derive(Debug)]
pub struct ExecutionGuard;

impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        EXECUTOR_ACTIVE.with(|active| {
            assert!(active.get());
            active.set(false);
        })
    }
}

pub fn enter() -> anyhow::Result<ExecutionGuard> {
    EXECUTOR_ACTIVE.with(|active| {
        if active.get() {
            Err(NestedExecutionNotSupported.into())
        } else {
            active.set(true);

            Ok(ExecutionGuard)
        }
    })
}

#[cfg(test)]
mod test {
    use crate::Executor;

    use super::NestedExecutionNotSupported;

    #[test]
    fn nested_execution() {
        Executor::new()
            .run_until(async {
                let e = Executor::new()
                    .run_until(async {})
                    .expect_err("nested execution successful");
                e.downcast::<NestedExecutionNotSupported>()
                    .expect("unexpected error type");
            })
            .unwrap();

        let ex = Executor::new();
        ex.run_until(async {
            let e = ex
                .run_until(async {})
                .expect_err("nested execution successful");
            e.downcast::<NestedExecutionNotSupported>()
                .expect("unexpected error type");
        })
        .unwrap();
    }
}
