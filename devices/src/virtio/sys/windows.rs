// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file should not be included at virtio mod level if slirp is not include. In case it is,
// throw a user friendly message.
#[cfg(not(feature = "slirp"))]
compile_error!("Net device without slirp not supported on windows");

pub(crate) mod net;
