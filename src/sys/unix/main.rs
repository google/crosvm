// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{thread::sleep, time::Duration};

use anyhow::anyhow;
use base::{kill_process_group, reap_child, syslog, syslog::LogConfig, warn};
#[cfg(feature = "audio_cras")]
use devices::virtio::vhost::user::device::run_cras_snd_device;
#[cfg(feature = "gpu")]
use devices::virtio::vhost::user::device::run_gpu_device;
use devices::virtio::vhost::user::device::{
    run_console_device, run_fs_device, run_vsock_device, run_wl_device,
};

use crate::{
    crosvm::sys::cmdline::{Commands, DevicesSubcommand},
    Config,
};

pub(crate) fn start_device(command: DevicesSubcommand) -> anyhow::Result<()> {
    match command {
        DevicesSubcommand::Console(cfg) => run_console_device(cfg),
        #[cfg(feature = "audio_cras")]
        DevicesSubcommand::CrasSnd(cfg) => run_cras_snd_device(cfg),
        DevicesSubcommand::Fs(cfg) => run_fs_device(cfg),
        #[cfg(feature = "gpu")]
        DevicesSubcommand::Gpu(cfg) => run_gpu_device(cfg),
        DevicesSubcommand::Vsock(cfg) => run_vsock_device(cfg),
        DevicesSubcommand::Wl(cfg) => run_wl_device(cfg),
    }
}

// Wait for all children to exit. Return true if they have all exited, false
// otherwise.
fn wait_all_children() -> bool {
    const CHILD_WAIT_MAX_ITER: isize = 100;
    const CHILD_WAIT_MS: u64 = 10;
    for _ in 0..CHILD_WAIT_MAX_ITER {
        loop {
            match reap_child() {
                Ok(0) => break,
                // We expect ECHILD which indicates that there were no children left.
                Err(e) if e.errno() == libc::ECHILD => return true,
                Err(e) => {
                    warn!("error while waiting for children: {}", e);
                    return false;
                }
                // We reaped one child, so continue reaping.
                _ => {}
            }
        }
        // There's no timeout option for waitpid which reap_child calls internally, so our only
        // recourse is to sleep while waiting for the children to exit.
        sleep(Duration::from_millis(CHILD_WAIT_MS));
    }

    // If we've made it to this point, not all of the children have exited.
    false
}

pub(crate) fn cleanup() {
    // Reap exit status from any child device processes. At this point, all devices should have been
    // dropped in the main process and told to shutdown. Try over a period of 100ms, since it may
    // take some time for the processes to shut down.
    if !wait_all_children() {
        // We gave them a chance, and it's too late.
        warn!("not all child processes have exited; sending SIGKILL");
        if let Err(e) = kill_process_group() {
            // We're now at the mercy of the OS to clean up after us.
            warn!("unable to kill all child processes: {}", e);
        }
    }
}

pub(crate) fn run_command(_cmd: Commands) -> anyhow::Result<()> {
    Err(anyhow::anyhow!("invalid command"))
}

pub(crate) fn init_log<F: 'static>(log_config: LogConfig<F>, _cfg: &Config) -> anyhow::Result<()>
where
    F: Fn(&mut syslog::fmt::Formatter, &log::Record<'_>) -> std::io::Result<()> + Sync + Send,
{
    if let Err(e) = syslog::init_with(LogConfig {
        proc_name: String::from("crosvm"),
        ..log_config
    }) {
        eprintln!("failed to initialize syslog: {}", e);
        return Err(anyhow!("failed to initialize syslog: {}", e));
    }
    Ok(())
}
