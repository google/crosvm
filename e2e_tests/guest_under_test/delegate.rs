// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Very crude interactive console to allow the test host to run shell commands
/// in the guest and receive the output.
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::str;

/// Device file to read from and write to.
const CONSOLE_FILE: &str = "/dev/ttyS1";

/// Magic line sent when we are ready to receive a command.
/// \x05 is the ENQ (enquiry) character, which is rarely used and 'should'
/// not appear in command output.
const MAGIC_LINE: &str = "\x05Ready";

/// When ready to receive a command, the `MAGIC_LINE` is written to `input`.
/// The received command is executed via /bin/sh/ and it's stdout is written
/// back to `output`, terminated by `MAGIC_LINE`.
fn listen(input: Box<dyn io::Read>, mut output: Box<dyn io::Write>) -> io::Result<()> {
    let mut reader = io::BufReader::new(input);
    loop {
        writeln!(&mut output, "{}", MAGIC_LINE).unwrap();

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

        output.write(&result.stdout)?;
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
