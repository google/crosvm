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
use futures::future::MaybeDone;
use pin_utils::unsafe_pinned;

// Macro-generate future combinators to allow for running different numbers of top-level futures in
// this FutureList. Generates the implementation of `FutureList` for the completion types. For an
// explicit example this is modeled after, see `UnitFutures`.
macro_rules! generate {
    ($(
        $(#[$doc:meta])*
        ($Complete:ident, <$($Fut:ident),*>),
    )*) => ($(
        #[must_use = "Combinations of futures don't do anything unless run in an executor."]
        pub(crate) struct $Complete<$($Fut: Future),*> {
            $($Fut: MaybeDone<$Fut>,)*
        }

        impl<$($Fut),*> $Complete<$($Fut),*>
        where $(
            $Fut: Future,
        )*
        {
            // Safety:
            // * No Drop impl
            // * No Unpin impl
            // * Not #[repr(packed)]
            $(
                unsafe_pinned!($Fut: MaybeDone<$Fut>);
            )*

            pub(crate) fn new($($Fut: $Fut),*) -> $Complete<$($Fut),*> {
                $(
                    let $Fut = maybe_done($Fut);
                )*
                $Complete {
                    $($Fut),*
                }
            }
        }

        impl<$($Fut),*> Future for $Complete<$($Fut),*>
        where $(
            $Fut: Future,
        )*
        {
            type Output = ($($Fut::Output),*);

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
                let mut complete = true;
                $(
                    complete &= self.as_mut().$Fut().poll(cx).is_ready();
                )*

                if complete {
                    $(
                        let $Fut = self.as_mut().$Fut().take_output().unwrap();
                    )*
                    Poll::Ready(($($Fut), *))
                } else {
                    Poll::Pending
                }
            }
        }
    )*)
}

generate! {
    /// _Future for the [`complete2`] function.
    (Complete2, <_Fut1, _Fut2>),

    /// _Future for the [`complete3`] function.
    (Complete3, <_Fut1, _Fut2, _Fut3>),

    /// _Future for the [`complete4`] function.
    (Complete4, <_Fut1, _Fut2, _Fut3, _Fut4>),

    /// _Future for the [`complete5`] function.
    (Complete5, <_Fut1, _Fut2, _Fut3, _Fut4, _Fut5>),
}
