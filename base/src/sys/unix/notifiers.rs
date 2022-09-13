// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::net::UnixStream;

use crate::descriptor::AsRawDescriptor;
use crate::CloseNotifier;
use crate::ReadNotifier;

impl ReadNotifier for UnixStream {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self
    }
}

impl CloseNotifier for UnixStream {
    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
        self
    }
}
