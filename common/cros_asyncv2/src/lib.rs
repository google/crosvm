// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! An Executor and various primitives for running asynchronous code.
//!
//! This crate is meant to be used with the `futures-rs` crate that provides further combinators
//! and utility functions to combine and manage futures.
//!
//! # Running top-level futures.
//!
//! If there is only one top-level future to run, use the [`Executor::run_until`] method.
//!
//! # Implementations
//!
//! There are currently two paths for asynchronous IO: epoll and io_uring. The io_uring backend may
//! be disabled at compile time. When io_uring support is enabled, the framework performs a runtime
//! check to determine the backend to use.
//!
//! The backend selection should be transparent to the users of this crate.
//!
//! # Concrete async types
//!
//! This crate provides asynchronous versions of various IO types, like [`File`] and [`Event`].
//! Users should use these high-level types to perform asynchronous IO operations.
//!
//! # Thread pools
//!
//! The [`Executor`] supports driving futures simultaneously from multiple threads. To use a thread
//! pool, simply spawn the desired number of threads and call [`Executor::run`] or
//! [`Executor::run_until`] on each thread. Futures spawned via [`Executor::spawn`] may then run on
//! any of the threads in the thread pool.
//!
//! # Global executor
//!
//! This crate deliberately doesn't define a global executor. Instead all methods are implemented
//! directly on the [`Executor`] type. Users who want to use a single global executor for their
//! whole program can easily do so:
//!
//! ```
//! use cros_async::Executor;
//! use once_cell::sync::Lazy;
//! static GLOBAL_EXECUTOR: Lazy<Executor> = Lazy::new(Executor::new);
//!
//! let val = GLOBAL_EXECUTOR.run_until(async { 11 + 23 }).unwrap();
//! assert_eq!(val, 34);
//! ```
//!
//! # Dealing with `!Send` futures
//!
//! Almost all the functions of the async types in this crate are `!Send`. This status is
//! infectious: when one of these futures are `await`ed from another future, that future also
//! becomes `!Send`, which can be quite inconvenient. One way to isolate the `!Send` future is to
//! use [`Executor::spawn_local`] with a [`oneshot::channel`](futures::channel::oneshot::channel):
//!
//! ```
//! use std::mem::size_of;
//!
//! use futures::channel::oneshot::channel;
//! use cros_async::{Executor, File};
//!
//! async fn outer_future_implements_send(ex: Executor, f: File) -> u64 {
//!     let (tx, rx) = channel();
//!     let mut buf = 0x77u64.to_ne_bytes();
//!     ex.spawn_local(async move {
//!         let res = f.read(&mut buf, None).await;
//!         let _ = tx.send((res, buf));
//!     }).detach();
//!
//!     let (res, buf) = rx.await.expect("task canceled after detach()");
//!     assert_eq!(res.unwrap(), size_of::<u64>());
//!     u64::from_ne_bytes(buf)
//! }
//!
//! let ex = Executor::new();
//! let f = File::open("/dev/zero").unwrap();
//!
//! // `spawn` requires that the future implements `Send`.
//! let task = ex.spawn(outer_future_implements_send(ex.clone(), f));
//!
//! let val = ex.run_until(task).unwrap();
//! assert_eq!(val, 0);
//! ```
//!
//! A cancelable version of the inner future can be implemented using
//! [`abortable`](futures::future::abortable). However keep in mind that on backends like io_uring,
//! cancelling the future may not cancel the underlying IO operation.

#![cfg(unix)]

mod blocking;
mod enter;
mod event;
mod executor;
mod file;
mod iobuf;
pub mod sync;
mod timer;

#[cfg_attr(unix, path = "unix/mod.rs")]
mod sys;

pub use blocking::block_on;
pub use blocking::BlockingPool;
pub use event::Event;
pub use executor::Executor;
pub use file::File;
pub use iobuf::AsIoBufs;
pub use iobuf::OwnedIoBuf;
#[cfg(unix)]
pub use sys::Descriptor;
#[cfg(unix)]
pub use sys::SeqPacket as UnixSeqPacket;
#[cfg(unix)]
pub use sys::SeqPacketListener as UnixSeqPacketListener;
pub use timer::with_deadline;
pub use timer::TimedOut;
pub use timer::Timer;
