// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Need non-snake case so the macro can re-use type names for variables.
#![allow(non_snake_case)]

use std::future::Future;
use std::pin::Pin;
use std::task::Context;

use futures::future::{maybe_done, FutureExt, MaybeDone};
use futures::task::waker_ref;

use crate::executor::{FutureList, FutureState, UnitFutures};

pub enum SelectResult<F: Future> {
    Pending(F),
    Finished(F::Output),
}

// Macro-generate future combinators to allow for running different numbers of top-level futures in
// this FutureList. Generates the implementation of `FutureList` for the select types. For an
// explicit example this is modeled after, see `UnitFutures`.
macro_rules! generate {
    ($(
        $(#[$doc:meta])*
        ($Select:ident, <$($Fut:ident),*>),
    )*) => ($(
        #[must_use = "Combinations of futures don't do anything unless run in an executor."]
        paste::item! {
            pub(crate) struct $Select<$($Fut: Future + Unpin),*> {
                added_futures: UnitFutures,
                $($Fut: MaybeDone<$Fut>,)*
                $([<$Fut _state>]: FutureState,)*
            }
        }

        impl<$($Fut: Future + Unpin),*> $Select<$($Fut),*> {
            paste::item! {
                pub(crate) fn new($($Fut: $Fut),*) -> $Select<$($Fut),*> {
                    $Select {
                        added_futures: UnitFutures::new(),
                        $($Fut: maybe_done($Fut),)*
                        $([<$Fut _state>]: FutureState::new(),)*
                    }
                }
            }
        }

        impl<$($Fut: Future + Unpin),*> FutureList for $Select<$($Fut),*> {
            type Output = ($(SelectResult<$Fut>),*);

            fn futures_mut(&mut self) -> &mut UnitFutures {
                &mut self.added_futures
            }

            paste::item! {
                fn poll_results(&mut self) -> Option<Self::Output> {
                    let _ = self.added_futures.poll_results();

                    let mut complete = false;
                    $(
                        let $Fut = Pin::new(&mut self.$Fut);
                        if self.[<$Fut _state>].needs_poll.swap(false) {
                            let waker = waker_ref(&self.[<$Fut _state>].needs_poll);
                            let mut ctx = Context::from_waker(&waker);
                            // The future impls `Unpin`, use `poll_unpin` to avoid wrapping it in
                            // `Pin` to call `poll`.
                            complete |= self.$Fut.poll_unpin(&mut ctx).is_ready();
                        }
                    )*

                    if complete {
                        Some(($(
                                    match std::mem::replace(&mut self.$Fut, MaybeDone::Gone) {
                                        MaybeDone::Future(f) => SelectResult::Pending(f),
                                        MaybeDone::Done(o) => SelectResult::Finished(o),
                                        MaybeDone::Gone=>unreachable!(),
                                    }
                               ), *))
                    } else {
                        None
                    }
                }

                fn any_ready(&self) -> bool {
                    let mut ready = self.added_futures.any_ready();
                    $(
                        ready |= self.[<$Fut _state>].needs_poll.get();
                    )*
                    ready
                }
            }
        }
    )*)
}

generate! {
    /// _Future for the [`select2`] function.
    (Select2, <_Fut1, _Fut2>),

    /// _Future for the [`select3`] function.
    (Select3, <_Fut1, _Fut2, _Fut3>),

    /// _Future for the [`select4`] function.
    (Select4, <_Fut1, _Fut2, _Fut3, _Fut4>),

    /// _Future for the [`select5`] function.
    (Select5, <_Fut1, _Fut2, _Fut3, _Fut4, _Fut5>),

    /// _Future for the [`select6`] function.
    (Select6, <_Fut1, _Fut2, _Fut3, _Fut4, _Fut5, _Fut6>),
}
