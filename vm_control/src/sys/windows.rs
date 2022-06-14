// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::Path;
use std::thread::JoinHandle;

use crate::{client::HandleRequestResult, VmRequest};

// TODO(b/145563346): Make this work on Windows
pub fn handle_request<T: AsRef<Path> + std::fmt::Debug>(
    _request: &VmRequest,
    _socket_path: T,
) -> HandleRequestResult {
    Err(())
}

pub(crate) fn kill_handle(_handle: &JoinHandle<()>) {}
