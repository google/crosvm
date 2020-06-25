// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Futures that implement `IoSource` using the UringExecutor.

mod fallocate;
mod fsync;
mod poll_fd;
mod read_mem;
mod read_vec;
mod uring_fut;
mod uring_source;
mod write_mem;
mod write_vec;

pub use fallocate::Fallocate;
pub use fsync::Fsync;
pub use poll_fd::PollFd;
pub use read_mem::ReadMem;
pub use read_vec::ReadVec;
pub use uring_source::UringSource;
pub use write_mem::WriteMem;
pub use write_vec::WriteVec;
