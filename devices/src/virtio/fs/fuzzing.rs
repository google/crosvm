// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::virtio::fs::filesystem::FileSystem;
use crate::virtio::fs::server::Server;
use crate::virtio::{Reader, Writer};

// Use a file system that does nothing since we are fuzzing the server implementation.
struct NullFs;
impl FileSystem for NullFs {
    type Inode = u64;
    type Handle = u64;
}

/// Fuzz the server implementation.
pub fn fuzz_server(r: Reader, w: Writer) {
    let server = Server::new(NullFs);

    let _ = server.handle_message(r, w);
}
