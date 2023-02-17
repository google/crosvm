// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Need non-snake case so the macro can re-use type names for variables.
#![allow(non_snake_case)]

use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use futures::future::maybe_done;
use futures::future::FutureExt;
use futures::future::MaybeDone;

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
        paste::item! {
            pub(crate) struct $Select<$($Fut: Future + Unpin),*> {
                $($Fut: MaybeDone<$Fut>,)*
            }
        }

        impl<$($Fut: Future + Unpin),*> $Select<$($Fut),*> {
            paste::item! {
                pub(crate) fn new($($Fut: $Fut),*) -> $Select<$($Fut),*> {
                    $Select {
                        $($Fut: maybe_done($Fut),)*
                    }
                }
            }
        }

        impl<$($Fut: Future + Unpin),*> Future for $Select<$($Fut),*> {
            type Output = ($(SelectResult<$Fut>),*);

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
                let mut complete = false;
                $(
                    let $Fut = Pin::new(&mut self.$Fut);
                    // The future impls `Unpin`, use `poll_unpin` to avoid wrapping it in
                    // `Pin` to call `poll`.
                    complete |= self.$Fut.poll_unpin(cx).is_ready();
                )*

                if complete {
                    Poll::Ready(($(
                        match std::mem::replace(&mut self.$Fut, MaybeDone::Gone) {
                            MaybeDone::Future(f) => SelectResult::Pending(f),
                            MaybeDone::Done(o) => SelectResult::Finished(o),
                            MaybeDone::Gone => unreachable!(),
                        }
                    ), *))
                } else {
                    Poll::Pending
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

    /// _Future for the [`select7`] function.
    (Select7, <_Fut1, _Fut2, _Fut3, _Fut4, _Fut5, _Fut6, _Fut7>),

    /// _Future for the [`select8`] function.
    (Select8, <_Fut1, _Fut2, _Fut3, _Fut4, _Fut5, _Fut6, _Fut7, _Fut8>),

    /// _Future for the [`select9`] function.
    (Select9, <_Fut1, _Fut2, _Fut3, _Fut4, _Fut5, _Fut6, _Fut7, _Fut8, _Fut9>),

    /// _Future for the [`select10`] function.
    (Select10, <_Fut1, _Fut2, _Fut3, _Fut4, _Fut5, _Fut6, _Fut7, _Fut8, _Fut9, _Fut10>),
}
