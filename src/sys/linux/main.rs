// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::thread::sleep;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Context;
use base::kill_process_group;
use base::reap_child;
use base::syslog;
use base::syslog::LogArgs;
use base::syslog::LogConfig;
use base::warn;
use devices::virtio::vhost::user::device::run_console_device;
use devices::virtio::vhost::user::device::run_fs_device;
use devices::virtio::vhost::user::device::run_vsock_device;
use devices::virtio::vhost::user::device::run_wl_device;

use crate::crosvm::sys::cmdline::Commands;
use crate::crosvm::sys::cmdline::DeviceSubcommand;
use crate::crosvm::sys::linux::start_devices;
use crate::CommandStatus;
use crate::Config;

pub(crate) fn start_device(command: DeviceSubcommand) -> anyhow::Result<()> {
    match command {
        DeviceSubcommand::Console(cfg) => run_console_device(cfg),
        DeviceSubcommand::Fs(cfg) => run_fs_device(cfg),
        DeviceSubcommand::Vsock(cfg) => run_vsock_device(cfg),
        DeviceSubcommand::Wl(cfg) => run_wl_device(cfg),
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

pub fn get_library_watcher() -> std::io::Result<()> {
    Ok(())
}

pub(crate) fn run_command(command: Commands, _log_args: LogArgs) -> anyhow::Result<()> {
    match command {
        Commands::Devices(cmd) => start_devices(cmd).context("start_devices subcommand failed"),
    }
}

pub(crate) fn init_log(log_config: LogConfig, _cfg: &Config) -> anyhow::Result<()> {
    if let Err(e) = syslog::init_with(log_config) {
        eprintln!("failed to initialize syslog: {}", e);
        return Err(anyhow!("failed to initialize syslog: {}", e));
    }
    Ok(())
}

pub(crate) fn error_to_exit_code(_res: &std::result::Result<CommandStatus, anyhow::Error>) -> i32 {
    1
}
