// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Write;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use base::error;
use base::named_pipes::PipeConnection;
use base::Event;
use base::EventToken;
use base::FileSync;
use base::RawDescriptor;
use base::Result;
use base::TimerTrait;
use base::WaitContext;
use hypervisor::ProtectionType;

use crate::bus::BusDevice;
use crate::serial_device::SerialInput;
use crate::sys::serial_device::SerialDevice;
use crate::Serial;

// TODO(b/234469655): Remove type alias once ReadNotifier is implemented for
// PipeConnection.
pub(crate) type InStreamType = Box<PipeConnection>;

/// Windows specific paramters for the serial device.
pub struct SystemSerialParams {
    pub in_stream: Option<InStreamType>,
    pub sync: Option<Box<dyn FileSync + Send>>,
    pub sync_thread: Option<JoinHandle<SyncWorker>>,
    pub kill_evt: Option<Event>,
}

impl Serial {
    // Spawn the worker thread if it hasn't been spawned yet.
    pub(in crate::serial) fn handle_sync_thread(&mut self) {
        if self.system_params.sync.is_some() {
            let sync = match self.system_params.sync.take() {
                Some(sync) => sync,
                None => return,
            };

            let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e)))
            {
                Ok(v) => v,
                Err(e) => {
                    error!("failed creating kill Event pair: {}", e);
                    return;
                }
            };
            self.system_params.kill_evt = Some(self_kill_evt);

            match thread::Builder::new()
                .name(format!("{} sync thread", self.debug_label()))
                .spawn(move || {
                    let mut worker = SyncWorker {
                        kill_evt,
                        file: sync,
                    };
                    worker.run();
                    worker
                }) {
                Err(e) => {
                    error!("failed to spawn sync thread: {}", e);
                }
                Ok(sync_thread) => self.system_params.sync_thread = Some(sync_thread),
            };
        }
    }
}

impl SerialDevice for Serial {
    /// Constructs a Serial device ready for input and output.
    ///
    /// The stream `input` should not block, instead returning 0 bytes if are no bytes available.
    fn new(
        _protection_type: ProtectionType,
        interrupt_evt: Event,
        input: Option<Box<dyn SerialInput>>,
        out: Option<Box<dyn io::Write + Send>>,
        sync: Option<Box<dyn FileSync + Send>>,
        out_timestamp: bool,
        _keep_rds: Vec<RawDescriptor>,
    ) -> Serial {
        let system_params = SystemSerialParams {
            in_stream: None,
            sync,
            sync_thread: None,
            kill_evt: None,
        };
        Serial::new_common(interrupt_evt, input, out, out_timestamp, system_params)
    }

    /// Constructs a Serial device connected to a named pipe for I/O
    ///
    /// pipe_in and pipe_out should both refer to the same end of the same pipe, but may have
    /// different underlying descriptors.
    fn new_with_pipe(
        _protection_type: ProtectionType,
        interrupt_evt: Event,
        pipe_in: PipeConnection,
        pipe_out: PipeConnection,
        _keep_rds: Vec<RawDescriptor>,
    ) -> Serial {
        let system_params = SystemSerialParams {
            in_stream: Some(Box::new(pipe_in)),
            sync: None,
            sync_thread: None,
            kill_evt: None,
        };
        let out_timestamp = false;
        Serial::new_common(
            interrupt_evt,
            None,
            Some(Box::new(pipe_out)),
            out_timestamp,
            system_params,
        )
    }
}

impl Drop for Serial {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.system_params.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.signal();
        }

        if let Some(sync_thread) = self.system_params.sync_thread.take() {
            let _ = sync_thread.join();
        }
    }
}

/// Worker to help with flusing contents of `file` to disk.
pub struct SyncWorker {
    kill_evt: Event,
    file: Box<dyn FileSync + Send>,
}

impl SyncWorker {
    pub(in crate::serial) fn run(&mut self) {
        let mut timer = match base::Timer::new() {
            Err(e) => {
                error!("failed to create timer for SyncWorker: {}", e);
                return;
            }
            Ok(timer) => timer,
        };

        if let Err(e) = timer.reset(Duration::from_secs(1), Some(Duration::from_secs(1))) {
            error!("failed to set timer for SyncWorker: {}", e);
            return;
        }

        #[derive(EventToken)]
        enum Token {
            Sync,
            Kill,
        }

        let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
            (&timer, Token::Sync),
            (&self.kill_evt, Token::Kill),
        ]) {
            Ok(ec) => ec,
            Err(e) => {
                error!("failed creating WaitContext: {}", e);
                return;
            }
        };
        loop {
            let events = match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    return;
                }
            };

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::Sync => {
                        if let Err(e) = self.file.fsync() {
                            error!("failed to fsync serial device, stopping sync thread: {}", e);
                            return;
                        }
                    }
                    Token::Kill => {
                        if let Err(e) = self.file.fsync() {
                            error!("failed to fsync serial device, stopping sync thread: {}", e);
                            return;
                        }
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serial::tests::*;
    use crate::serial::*;

    #[cfg(windows)]
    #[test]
    fn named_pipe() {
        use base::named_pipes;
        use base::named_pipes::BlockingMode;
        use base::named_pipes::FramingMode;
        use rand::Rng;

        let path_str = format!(r"\\.\pipe\crosvm_test_{}", rand::thread_rng().gen::<u64>());

        let pipe_in = named_pipes::create_server_pipe(
            &path_str,
            &FramingMode::Byte,
            &BlockingMode::NoWait,
            0, // default timeout
            named_pipes::DEFAULT_BUFFER_SIZE,
            false,
        )
        .unwrap();

        let pipe_out = pipe_in.try_clone().unwrap();
        let event = Event::new().unwrap();

        let mut device = Serial::new_with_pipe(
            ProtectionType::Unprotected,
            event,
            pipe_in,
            pipe_out,
            Vec::new(),
        );

        let client_pipe = named_pipes::create_client_pipe(
            &path_str,
            &FramingMode::Byte,
            &BlockingMode::Wait,
            false,
        )
        .unwrap();

        unsafe {
            // Check that serial output is sent to the pipe
            device.write(serial_bus_address(DATA), &[b'T']);
            device.write(serial_bus_address(DATA), &[b'D']);

            let mut read_buf: [u8; 2] = [0; 2];

            assert_eq!(client_pipe.read(&mut read_buf).unwrap(), 2);
            assert_eq!(read_buf, [b'T', b'D']);

            // Check that pipe_in is the other end of client_pipe. It's not actually wired up to
            // SerialInput in this file so we can't test the data flow
            client_pipe
                .write(&[1, 2])
                .expect("Failed to write to client pipe");
            assert_eq!(
                device
                    .system_params
                    .in_stream
                    .as_mut()
                    .unwrap()
                    .read(&mut read_buf)
                    .unwrap(),
                2
            );
            assert_eq!(read_buf, [1, 2]);
        }
    }
}
