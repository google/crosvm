// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod descriptor;
pub mod file_traits;
#[macro_use]
pub mod handle_eintr;
mod fcntl;
mod file_flags;
mod iobuf;
pub mod net;
mod sock_ctrl_msg;
mod stream_channel;
pub mod system_info;
pub mod tube;

pub use descriptor::*;
pub use fcntl::*;
pub use file_flags::*;
pub use iobuf::IoBuf;
pub use sock_ctrl_msg::*;
pub use stream_channel::*;
pub use system_info::iov_max;
pub use system_info::number_of_logical_cores;
pub use system_info::pagesize;

/// Process identifier.
pub type Pid = libc::pid_t;

#[macro_export]
macro_rules! syscall {
    ($e:expr) => {{
        let res = $e;
        if res < 0 {
            $crate::errno_result()
        } else {
            Ok(res)
        }
    }};
}
