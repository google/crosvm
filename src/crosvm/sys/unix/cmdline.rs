// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;

use argh::FromArgs;
use cros_async::ExecutorKind;
use devices::virtio::block::block::DiskOption;
use devices::virtio::vhost::user::device;
use devices::virtio::vhost::user::VhostUserParams;
use devices::SerialParameters;

use crate::crosvm::config::from_key_values;
use crate::crosvm::config::validate_serial_parameters;
use crate::crosvm::config::JailConfig;

#[derive(FromArgs)]
#[argh(subcommand)]
/// Unix Devices
pub enum DeviceSubcommand {
    Console(device::ConsoleOptions),
    #[cfg(feature = "audio")]
    Snd(device::SndOptions),
    Fs(device::FsOptions),
    #[cfg(feature = "gpu")]
    Gpu(device::GpuOptions),
    Vsock(device::VsockOptions),
    Wl(device::WlOptions),
}

fn parse_vu_serial_options(s: &str) -> Result<VhostUserParams<SerialParameters>, String> {
    let params: VhostUserParams<SerialParameters> = from_key_values(s)?;

    validate_serial_parameters(&params.device)?;

    Ok(params)
}

#[argh_helpers::pad_description_for_argh]
#[derive(FromArgs)]
#[argh(subcommand, name = "devices")]
/// Start one or several jailed device processes.
pub struct DevicesCommand {
    /// configure async executor backend to "uring" or "epoll" (default).
    #[argh(option, arg_name = "EXECUTOR")]
    pub async_executor: Option<ExecutorKind>,

    #[argh(switch)]
    /// disable sandboxing. Will nullify the --jail option if it was present.
    pub disable_sandbox: bool,

    #[argh(
        option,
        arg_name = "jail configuration",
        default = "Default::default()"
    )]
    /// set up the jail configuration.
    /// Possible key values:
    ///     pivot-root=/path - Path to empty directory to use for
    ///         sandbox pivot root.
    ///     seccomp-policy-dir=/path - Path to seccomp .policy files
    ///     seccomp-log-failures=(true|false) - Log seccomp filter
    ///         failures instead of them being fatal.
    pub jail: JailConfig,

    #[argh(
        option,
        arg_name = "vhost=PATH,type=TYPE,[hardware=HW,num=NUM,path=PATH,input=PATH,console,earlycon,stdin]",
        from_str_fn(parse_vu_serial_options)
    )]
    /// comma separated key=value pairs for setting up serial
    /// devices. Can be given more than once.
    /// Possible key values:
    ///     vhost=PATH - Path to a vhost-user endpoint to listen to.
    ///        This parameter must be given in first position.
    ///     type=(stdout,syslog,sink,file) - Where to route the
    ///        serial device
    ///     hardware=(serial,virtio-console) - Which type of serial
    ///        hardware to emulate. Defaults to 8250 UART (serial).
    ///     num=(1,2,3,4) - Serial Device Number. If not provided,
    ///        num will default to 1.
    ///     path=PATH - The path to the file to write to when
    ///        type=file
    ///     input=PATH - The path to the file to read from when not
    ///        stdin
    ///     console - Use this serial device as the guest console.
    ///        Can only be given once. Will default to first
    ///        serial port if not provided.
    ///     earlycon - Use this serial device as the early console.
    ///        Can only be given once.
    ///     stdin - Direct standard input to this serial device.
    ///        Can only be given once. Will default to first serial
    ///        port if not provided.
    pub serial: Vec<VhostUserParams<SerialParameters>>,

    #[argh(option, arg_name = "block options")]
    /// start a block device (see help from run command for options)
    pub block: Vec<VhostUserParams<DiskOption>>,

    #[argh(option, short = 's', arg_name = "PATH")]
    /// path to put the control socket.
    pub control_socket: Option<PathBuf>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
/// Unix Commands
pub enum Commands {
    #[cfg(unix)]
    Devices(DevicesCommand),
}
