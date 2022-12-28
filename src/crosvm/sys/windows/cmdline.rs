// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use argh::CommandInfo;
use argh::EarlyExit;
use argh::FromArgs;
use argh::SubCommand;

use crate::crosvm::cmdline::RunCommand;
#[derive(Debug, FromArgs)]
#[argh(subcommand)]
/// Windows Devices
pub enum DeviceSubcommand {}

#[cfg(feature = "slirp")]
#[derive(FromArgs)]
#[argh(subcommand, name = "run-slirp")]
/// Start a new slirp instance
pub struct RunSlirpCommand {
    #[argh(option, arg_name = "TRANSPORT_TUBE_RD")]
    /// tube transporter descriptor used to bootstrap the Slirp process.
    pub bootstrap: usize,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "run-main")]
/// Start a new broker instance
pub struct RunMainCommand {
    #[argh(option, arg_name = "TRANSPORT_TUBE_RD")]
    /// tube transporter descriptor used to bootstrap the main process.
    pub bootstrap: usize,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "run-metrics")]
/// Start a new metrics instance
pub struct RunMetricsCommand {
    #[argh(option, arg_name = "TRANSPORT_TUBE_RD")]
    /// tube transporter descriptor used to bootstrap the metrics process.
    pub bootstrap: usize,
}

const RUN_MP_CMD_NAME: &str = "run-mp";

/// Start a new mp crosvm instance
pub struct RunMPCommand {
    pub run: RunCommand,
}

impl FromArgs for RunMPCommand {
    fn from_args(cmd_name: &[&str], args: &[&str]) -> std::result::Result<Self, EarlyExit> {
        Ok(Self {
            run: RunCommand::from_args(cmd_name, args)?,
        })
    }
    fn redact_arg_values(
        cmd_name: &[&str],
        args: &[&str],
    ) -> std::result::Result<Vec<String>, EarlyExit> {
        RunCommand::redact_arg_values(cmd_name, args)
    }
}

impl SubCommand for RunMPCommand {
    const COMMAND: &'static CommandInfo = &CommandInfo {
        name: RUN_MP_CMD_NAME,
        description: "Start a new mp crosvm instance",
    };
}

// Suppress complaint about RunMPCommand and RunMetricsCommand having a large size variation.
#[allow(clippy::large_enum_variant)]
#[derive(FromArgs)]
#[argh(subcommand)]
/// Windows Devices
pub enum Commands {
    RunMetrics(RunMetricsCommand),
    RunMP(RunMPCommand),
    #[cfg(feature = "slirp")]
    RunSlirp(RunSlirpCommand),
    RunMain(RunMainCommand),
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::crosvm::cmdline::RunCommand;

    fn get_args() -> Vec<&'static str> {
        let mut args = vec![
            "--bios",
            "C:\\src\\crosvm\\out\\image\\default\\images\\bios.rom",
            #[cfg(feature = "crash-report")]
            "--crash-pipe-name",
            "\\\\.\\pipe\\crashpad_27812_XGTCCTBYULHHLEJU",
            "--cpus",
            "4",
            "--mem",
            "8192",
            "--log-file",
            "C:\\tmp\\Emulator.log",
            "--kernel-log-file",
            "C:\\tmp\\Hypervisor.log",
            "--logs-directory",
            "C:\\tmp\\emulator_logs",
            "--serial",
            "hardware=serial,num=1,type=file,path=C:\\tmp\\AndroidSerial.log,earlycon=true",
            "--serial",
            "hardware=virtio-console,num=1,type=file,path=C:\\tmp\\AndroidSerial.log,console=true",
            "--rwdisk",
            "C:\\src\\crosvm\\out\\image\\default\\avd\\aggregate.img",
            "--rwdisk",
            "C:\\src\\crosvm\\out\\image\\default\\avd\\metadata.img",
            "--rwdisk",
            "C:\\src\\crosvm\\out\\image\\default\\avd\\userdata.img",
            "--rwdisk",
            "C:\\src\\crosvm\\out\\image\\default\\avd\\misc.img",
            "--host-guid",
            "09205719-879f-4324-8efc-3e362a4096f4",
            "--cid",
            "3",
            "--multi-touch",
            "nil",
            "--mouse",
            "nil",
            "--product-version",
            "99.9.9.9",
            "--product-channel",
            "Local",
            "--product-name",
            "Play Games",
            "--pstore",
            "path=C:\\tmp\\pstore,size=1048576",
            "--pvclock",
            "--params",
            "fake args",
        ];

        if cfg!(feature = "process-invariants") {
            args.extend(vec![
                "--process-invariants-handle",
                "7368",
                "--process-invariants-size",
                "568",
            ]);
        }
        if cfg!(all(feature = "gpu", feature = "gfxstream")) {
            args.extend(["--gpu", "angle=true,backend=gfxstream,egl=true,gles=false,glx=false,refresh_rate=60,surfaceless=false,vulkan=true,wsi=vk,display_mode=borderless_full_screen,hidden"]);
            args.extend([
                "--gpu-display",
                "mode=borderless_full_screen,hidden,refresh-rate=60",
            ]);
        }
        if cfg!(feature = "audio") {
            args.extend(["--ac97", "backend=win_audio"]);
        }
        args.extend([
            "--service-pipe-name",
            "service-ipc-8244a83a-ae3f-486f-9c50-3fc47b309d27",
        ]);
        args
    }

    #[test]
    fn parse_run_mp_test() {
        let _ = RunMPCommand::from_args(&["run-mp"], &get_args()).unwrap();
    }

    #[test]
    fn parse_run_test() {
        let _ = RunCommand::from_args(&["run-main"], &get_args()).unwrap();
    }
}
