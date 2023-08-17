// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Very crude interactive console to allow the test host to run shell commands
/// in the guest and receive the output.
mod wire_format;

use std::fs::File;
use std::io;
use std::io::prelude::*;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::str;

use serde_json::Deserializer;

use crate::wire_format::DelegateMessage;
use crate::wire_format::GuestToHostMessage;
use crate::wire_format::HostToGuestMessage;
use crate::wire_format::ProgramExit;

/// Device file to read from and write to.
const CONSOLE_FILE: &str = "/dev/ttyS1";

fn listen(
    input: &mut dyn Iterator<Item = Result<DelegateMessage, serde_json::Error>>,
    mut output: Box<dyn io::Write>,
) -> io::Result<()> {
    output.write_all(
        serde_json::to_string_pretty(&DelegateMessage::GuestToHost(GuestToHostMessage::Ready))
            .unwrap()
            .as_bytes(),
    )?;
    loop {
        if let Some(command) = input.next() {
            match command?.assume_host_to_guest() {
                HostToGuestMessage::Exit => {
                    break;
                }
                HostToGuestMessage::RunCommand {
                    command: command_string,
                } => {
                    println!("-> {}", &command_string);
                    let result = Command::new("/bin/sh")
                        .args(["-c", &command_string])
                        .output()
                        .unwrap();
                    let command_result = GuestToHostMessage::ProgramExit(ProgramExit {
                        stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
                        stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
                        exit_status: match result.status.code() {
                            Some(code) => wire_format::ExitStatus::Code(code),
                            #[cfg(unix)]
                            None => match result.status.signal() {
                                Some(signal) => wire_format::ExitStatus::Signal(signal),
                                None => wire_format::ExitStatus::None,
                            },
                            #[cfg(not(unix))]
                            _ => wire_format::ExitStatus::None,
                        },
                    });
                    println!(
                        "<- {}",
                        serde_json::to_string_pretty(&command_result).unwrap()
                    );
                    output.write_all(
                        serde_json::to_string_pretty(&DelegateMessage::GuestToHost(command_result))
                            .unwrap()
                            .as_bytes(),
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn main() {
    let path = Path::new(CONSOLE_FILE);

    let mut command_stream =
        Deserializer::from_reader(File::open(path).unwrap()).into_iter::<DelegateMessage>();

    listen(&mut command_stream, Box::new(File::create(path).unwrap())).unwrap();
}
