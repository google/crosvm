// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Very crude interactive console to allow the test host to run shell commands
/// in the guest and receive the output.
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::str;

/// Device file to read from and write to.
const CONSOLE_FILE: &'static str = "/dev/ttyS1";

/// Line sent when we are ready to receive a command.
/// \x05 is the ENQ (enquiry) character, which is rarely used and 'should'
/// not appear in command output.
const READY_LINE: &'static str = "\x05READY";

/// Line sent containing the exit code of the program
/// \x05 is the ENQ (enquiry) character, which is rarely used and 'should'
/// not appear in command output.
const EXIT_CODE_LINE: &'static str = "\x05EXIT_CODE";

/// When ready to receive a command, the `READY_LINE` is written to `input`.
/// The received command is executed via /bin/sh and it's stdout is written
/// back to `output`, terminated by `EXIT_CODE_LINE ${exit_code}`.
fn listen(input: Box<dyn io::Read>, mut output: Box<dyn io::Write>) -> io::Result<()> {
    let mut reader = io::BufReader::new(input);
    loop {
        writeln!(&mut output, "{}", READY_LINE).unwrap();

        let mut command = String::new();
        reader.read_line(&mut command)?;
        if command.trim() == "exit" {
            break;
        }

        println!("-> {:?}", command);
        let result = Command::new("/bin/sh")
            .args(&["-c", &command])
            .stderr(Stdio::inherit())
            .output()
            .unwrap();
        let exit_code = match result.status.code() {
            Some(code) => code,
            None => -result.status.signal().unwrap(),
        };

        output.write(&result.stdout)?;
        println!("<- {}", exit_code);
        writeln!(&mut output, "{EXIT_CODE_LINE} {exit_code}")?;
    }
    Ok(())
}

fn main() {
    let path = Path::new(CONSOLE_FILE);
    listen(
        Box::new(File::open(path).unwrap()),
        Box::new(File::create(path).unwrap()),
    )
    .unwrap();
}
