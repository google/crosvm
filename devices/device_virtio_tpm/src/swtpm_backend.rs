// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use base::error;
use base::AsRawDescriptor;
use base::RawDescriptor;

use crate::TpmBackend;
use crate::TPM_BUFSIZE;
use crate::TPM_RC_FAILURE_RESPONSE;

// Bound every socket operation so a stalled swtpm cannot hang the device worker, and
// with it Tpm::reset() and VM shutdown.  Matches the timeout VtpmProxy uses for D-Bus.
const SWTPM_IO_TIMEOUT: Duration = Duration::from_secs(300);

/// Backend that communicates with swtpm via Unix socket
pub struct SwtpmBackend {
    socket: UnixStream,
    response_buffer: Vec<u8>,
    broken: bool,
}

impl SwtpmBackend {
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Result<Self> {
        let socket = UnixStream::connect(socket_path.as_ref()).with_context(|| {
            format!(
                "failed to connect to swtpm socket at {}",
                socket_path.as_ref().display()
            )
        })?;

        socket
            .set_read_timeout(Some(SWTPM_IO_TIMEOUT))
            .context("failed to set swtpm socket read timeout")?;
        socket
            .set_write_timeout(Some(SWTPM_IO_TIMEOUT))
            .context("failed to set swtpm socket write timeout")?;

        Ok(Self {
            socket,
            response_buffer: vec![0u8; TPM_BUFSIZE],
            broken: false,
        })
    }
}

impl TpmBackend for SwtpmBackend {
    fn execute_command<'a>(&'a mut self, command: &[u8]) -> &'a [u8] {
        // A failed socket operation can leave a partial command or response in the
        // stream, so its framing is no longer trustworthy: refuse the socket from then
        // on rather than read one response as another.
        if self.broken {
            return TPM_RC_FAILURE_RESPONSE;
        }

        // swtpm takes its commands off a stream socket, so a command whose header
        // disagrees with the buffer it arrived in desynchronises that stream: swtpm waits
        // for bytes that never arrive, or the surplus is read as the next command.
        if command.len() < 10 {
            error!("swtpm command too short: {} bytes", command.len());
            return TPM_RC_FAILURE_RESPONSE;
        }
        let command_size =
            u32::from_be_bytes([command[2], command[3], command[4], command[5]]) as usize;
        if command_size != command.len() {
            error!(
                "swtpm command length mismatch: header says {}, buffer is {}",
                command_size,
                command.len()
            );
            return TPM_RC_FAILURE_RESPONSE;
        }

        if let Err(e) = self.socket.write_all(command) {
            error!("swtpm write error: {}", e);
            self.broken = true;
            return TPM_RC_FAILURE_RESPONSE;
        }

        let mut header = [0u8; 10];
        if let Err(e) = self.socket.read_exact(&mut header) {
            error!("swtpm read header error: {}", e);
            self.broken = true;
            return TPM_RC_FAILURE_RESPONSE;
        }

        // The length comes off the socket and is not trusted: a corrupt value would either
        // ask for far more than the device can ever return, or claim to be shorter than
        // the header just read.
        let response_size =
            u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        if !(10..=TPM_BUFSIZE).contains(&response_size) {
            error!("swtpm invalid response size: {}", response_size);
            self.broken = true;
            return TPM_RC_FAILURE_RESPONSE;
        }

        self.response_buffer[..10].copy_from_slice(&header);

        if response_size > 10 {
            if let Err(e) = self
                .socket
                .read_exact(&mut self.response_buffer[10..response_size])
            {
                error!("swtpm read body error: {}", e);
                self.broken = true;
                return TPM_RC_FAILURE_RESPONSE;
            }
        }

        &self.response_buffer[..response_size]
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        vec![self.socket.as_raw_descriptor()]
    }
}
