// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use devices::virtio::vhost::user::device;

use argh::FromArgs;

#[derive(FromArgs)]
#[argh(subcommand)]
/// Unix Devices
pub enum DevicesSubcommand {
    Console(device::ConsoleOptions),
    #[cfg(feature = "audio_cras")]
    CrasSnd(device::CrasSndOptions),
    Fs(device::FsOptions),
    #[cfg(feature = "gpu")]
    Gpu(device::GpuOptions),
    Vsock(device::VsockOptions),
    Wl(device::WlOptions),
}
