// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the CrosVM control socket on Windows. Unlike on unix, this is a bit involved because
//! we can't process the raw named pipe in line inside `run_control` (named pipes aren't directly
//! waitable). In theory, AF_UNIX can be made waitable, but AF_UNIX is very slow, and we already
//! have significant prior art for using named pipes in a waitable fashion (`base::StreamChannel`).

use std::io;
use std::sync::mpsc;
use std::sync::Arc;

use base::named_pipes;
use base::named_pipes::OverlappedWrapper;
use base::named_pipes::PipeConnection;
use base::BlockingMode;
use base::Event;
use base::EventExt;
use base::EventToken;
use base::FlushOnDropTube;
use base::FramingMode;
use base::ReadNotifier;
use base::RecvTube;
use base::SendTube;
use base::StreamChannel;
use base::Tube;
use base::TubeError;
use base::WaitContext;
use base::WorkerThread;
use libc::EIO;
use log::error;
use log::info;
use log::warn;
use sync::Mutex;
use vm_control::VmRequest;
use vm_control::VmResponse;
use winapi::shared::winerror::ERROR_MORE_DATA;

/// Windows named pipes don't fit in well with the control loop (`run_control`) the way sockets do
/// on unix, so this struct provides a compatibility layer (named pipe server) that functions very
/// similarly to how a socket server would on unix.
///
/// Terminology:
///     * The `ControlServer` is a socket server compatibility layer.
///     * The "control loop" is the VMM's main loop (`run_control`). It uses the `ControlServer` to
///       accept & service connections from clients that want to control the VMM (e.g. press the
///       power button, etc).
pub struct ControlServer {
    server_listener_worker: WorkerThread<(io::Result<()>, ClientWorker)>,
    /// Signaled when a client has connected and can be accepted without blocking.
    client_waiting: Event,
    /// Provides the accepted Tube every time a client connects.
    client_tube_channel: mpsc::Receiver<FlushOnDropTube>,
}

#[derive(EventToken)]
enum Token {
    Exit,
    Readable,
}

impl ControlServer {
    /// Creates a named pipe server on `pipe_name` that forwards Tube messages between the connected
    /// client on that pipe, and the Tube returned by `ControlServer::accept`.
    pub fn new(pipe_name: &str) -> anyhow::Result<Self> {
        let client_pipe_read = named_pipes::create_server_pipe(
            pipe_name,
            &named_pipes::FramingMode::Message,
            &named_pipes::BlockingMode::Wait,
            /* timeout= */ 0,
            /* buffer_size= */ 1024 * 1024,
            /* overlapped= */ true,
        )?;
        let client_pipe_write = client_pipe_read.try_clone()?;
        let mut client_worker = ClientWorker::new(client_pipe_write);
        let client_waiting = Event::new_auto_reset()?;
        let client_waiting_for_worker = client_waiting.try_clone()?;
        let (client_tube_channel_send, client_tube_channel_recv) = mpsc::channel();

        Ok(Self {
            server_listener_worker: WorkerThread::start("ctrl_srv_listen_loop", move |exit_evt| {
                let res = Self::server_listener_loop(
                    exit_evt,
                    &mut client_worker,
                    client_waiting_for_worker,
                    client_tube_channel_send,
                    client_pipe_read,
                );
                if let Err(e) = res.as_ref() {
                    error!("server_listener_worker failed with error: {:?}", e)
                }
                (res, client_worker)
            }),
            client_waiting,
            client_tube_channel: client_tube_channel_recv,
        })
    }

    /// Gets the client waiting event. If a client is waiting, [ControlServer::accept] can be called
    /// and will return a [base::Tube] without blocking.
    pub fn client_waiting(&self) -> &Event {
        &self.client_waiting
    }

    /// Accepts a connection (if one is waiting), returning a [base::Tube] connected to the client.
    /// If [ControlServer::client_waiting] has not been signaled, this will block until a client
    /// connects.
    pub fn accept(&mut self) -> FlushOnDropTube {
        self.client_tube_channel
            .recv()
            .expect("client worker has done away")
    }

    /// Shuts down the control server, disconnecting any connected clients.
    pub fn shutdown(self) -> base::Result<()> {
        let (listen_res, client_worker) = self.server_listener_worker.stop();
        match listen_res {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(base::Error::from(e)),
            Ok(()) => (),
        };
        client_worker.shutdown()
    }

    /// Listen loop for the control server. Handles waiting for new connections, creates the
    /// forwarding thread for control loop -> client data, and forwards client -> control loop
    /// data.
    fn server_listener_loop(
        exit_evt: Event,
        client_worker: &mut ClientWorker,
        client_waiting: Event,
        client_tube_send_channel: mpsc::Sender<FlushOnDropTube>,
        mut client_pipe_read: PipeConnection,
    ) -> io::Result<()> {
        loop {
            info!("control server: started, waiting for clients.");
            client_pipe_read.wait_for_client_connection_overlapped_blocking(&exit_evt)?;

            let mut read_overlapped = OverlappedWrapper::new(true)?;
            let control_send = client_worker.connect_client(&client_tube_send_channel)?;
            client_waiting.signal()?;
            info!("control server: accepted client");

            loop {
                let recv_result = base::deserialize_and_recv::<VmRequest, _>(|buf| {
                    client_pipe_read.read_overlapped_blocking(
                        buf,
                        &mut read_overlapped,
                        &exit_evt,
                    )?;
                    Ok(buf.len())
                });

                match recv_result {
                    Ok(msg) => {
                        control_send.send(&msg).map_err(|e| {
                            error!("unexpected error in control server recv loop: {}", e);
                            io::Error::new(io::ErrorKind::Other, e)
                        })?;
                    }
                    Err(TubeError::Disconnected) => break,
                    Err(e) => {
                        error!("unexpected error in control server recv loop: {}", e);
                        return Err(io::Error::new(io::ErrorKind::Other, e));
                    }
                };
            }
            // Current client has disconnected. Now we can reuse the server pipe for a new client.
            match client_pipe_read.disconnect_clients() {
                Ok(()) => (),
                // If the pipe is already broken/closed, we'll get an error about trying to close
                // a pipe that has already been closed. Discard that error.
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => (),
                Err(e) => return Err(e),
            }
            client_worker.stop_control_to_client_worker()?;
            info!("control server: disconnected client");
        }
        unreachable!("loop exits by returning an error");
    }
}

/// Handles connecting clients & forwarding data from client -> control server.
struct ClientWorker {
    control_to_client_worker: Option<WorkerThread<(base::Result<()>, PipeConnection)>>,
    client_pipe_write: Option<PipeConnection>,
}

impl ClientWorker {
    fn new(client_pipe_write: PipeConnection) -> Self {
        Self {
            control_to_client_worker: None,
            client_pipe_write: Some(client_pipe_write),
        }
    }

    fn connect_client(
        &mut self,
        client_tube_send_channel: &mpsc::Sender<FlushOnDropTube>,
    ) -> base::Result<SendTube> {
        // It is critical that the server end of the pipe is returned as the Tube in
        // ControlServer::accept (tube_for_control_loop here). This way, we can ensure data is
        // flushed before the pipe is dropped. In short, the order of Tubes returned by the pair
        // matters.
        let (tube_for_control_loop, tube_to_control_loop) = Tube::pair().map_err(|e| match e {
            TubeError::Pair(io_err) => base::Error::from(io_err),
            _ => base::Error::new(EIO),
        })?;

        let (control_send, control_recv) =
            Tube::split_to_send_recv(tube_to_control_loop).map_err(|e| match e {
                TubeError::Clone(io_err) => base::Error::from(io_err),
                _ => base::Error::new(EIO),
            })?;

        let client_pipe_write = self.client_pipe_write.take().expect("loop already running");
        self.control_to_client_worker = Some(WorkerThread::start(
            "ctrl_srv_client_to_ctrl",
            move |exit_evt| {
                let res =
                    Self::control_to_client_worker(exit_evt, &client_pipe_write, control_recv);
                if let Err(e) = res.as_ref() {
                    error!("control_to_client_worker exited with error: {:?}", res);
                }
                (res, client_pipe_write)
            },
        ));
        client_tube_send_channel
            .send(FlushOnDropTube::from(tube_for_control_loop))
            .expect("control server has gone away");
        Ok(control_send)
    }

    fn stop_control_to_client_worker(&mut self) -> base::Result<()> {
        let (res, pipe) = self
            .control_to_client_worker
            .take()
            .expect("loop must be running")
            .stop();
        self.client_pipe_write = Some(pipe);
        res
    }

    fn shutdown(self) -> base::Result<()> {
        if let Some(worker) = self.control_to_client_worker {
            worker.stop().0
        } else {
            Ok(())
        }
    }

    /// Worker that forwards data from the control loop -> client pipe.
    fn control_to_client_worker(
        exit_evt: Event,
        client_pipe_write: &PipeConnection,
        control_recv: RecvTube,
    ) -> base::Result<()> {
        let wait_ctx = WaitContext::new()?;
        wait_ctx.add(&exit_evt, Token::Exit)?;
        wait_ctx.add(control_recv.get_read_notifier(), Token::Readable)?;

        'poll: loop {
            let events = wait_ctx.wait()?;
            for event in events {
                match event.token {
                    Token::Exit => {
                        break 'poll;
                    }
                    Token::Readable => {
                        let msg = match control_recv.recv::<VmResponse>() {
                            Ok(msg) => Ok(msg),
                            Err(TubeError::Disconnected) => {
                                return Ok(());
                            }
                            Err(TubeError::Recv(e)) => Err(base::Error::from(e)),
                            Err(tube_error) => {
                                error!(
                                    "unexpected error in control server recv loop: {}",
                                    tube_error
                                );
                                Err(base::Error::new(EIO))
                            }
                        }?;
                        base::serialize_and_send(|buf| client_pipe_write.write(buf), &msg, None)
                            .map_err(|e| match e {
                                TubeError::Send(e) => base::Error::from(e),
                                tube_error => {
                                    error!(
                                        "unexpected error in control server recv loop: {}",
                                        tube_error
                                    );
                                    base::Error::new(EIO)
                                }
                            })?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use base::PipeTube;
    use rand::Rng;

    use super::*;

    fn generate_pipe_name() -> String {
        format!(
            r"\\.\pipe\test-ipc-pipe-name.rand{}",
            rand::thread_rng().gen::<u64>(),
        )
    }

    #[track_caller]
    fn create_client(pipe_name: &str) -> PipeTube {
        let mut last_error: Option<io::Error> = None;
        for _ in 0..5 {
            match named_pipes::create_client_pipe(
                pipe_name,
                &named_pipes::FramingMode::Message,
                &named_pipes::BlockingMode::Wait,
                /* overlapped= */ false,
            ) {
                Ok(pipe) => return PipeTube::from(pipe, None),
                Err(e) => {
                    last_error = Some(e);
                    println!("failed client connection");
                    thread::sleep(Duration::from_millis(100))
                }
            }
        }
        panic!(
            "failed to connect to control server: {:?}",
            last_error.unwrap()
        )
    }

    #[test]
    fn test_smoke() {
        // There are several threads, so run many iterations to exercise any possible race
        // conditions.
        for i in 0..100 {
            println!("starting iteration {}", i);
            let pipe_name = generate_pipe_name();

            let mut control_server = ControlServer::new(&pipe_name).unwrap();
            let fake_control_loop = base::thread::spawn_with_timeout(move || {
                // First client.
                {
                    println!("server: starting client 1");
                    control_server.client_waiting().wait().unwrap();
                    let client1 = control_server.accept();
                    let req: VmRequest = client1.0.recv().unwrap();
                    assert!(matches!(req, VmRequest::Powerbtn));
                    client1.0.send(&VmResponse::Ok).unwrap();
                }
                println!("server: finished client 1");

                // Second client.
                {
                    println!("server: starting client 2");
                    control_server.client_waiting().wait().unwrap();
                    let client2 = control_server.accept();
                    let req: VmRequest = client2.0.recv().unwrap();
                    assert!(matches!(req, VmRequest::Exit));
                    client2
                        .0
                        .send(&VmResponse::ErrString("err".to_owned()))
                        .unwrap();
                }
                println!("server: finished client 2");
                control_server
            });

            {
                println!("client: starting client 1");
                let client1 = create_client(&pipe_name);
                client1.send(&VmRequest::Powerbtn).unwrap();
                assert!(matches!(client1.recv().unwrap(), VmResponse::Ok));
                println!("client: finished client 1");
            }

            {
                println!("client: starting client 2");
                let client2 = create_client(&pipe_name);
                client2.send(&VmRequest::Exit).unwrap();
                let resp = VmResponse::ErrString("err".to_owned());
                assert!(matches!(client2.recv::<VmResponse>().unwrap(), resp,));
                println!("client: finished client 2");
            }

            let control_server = fake_control_loop.try_join(Duration::from_secs(2)).unwrap();
            control_server.shutdown().unwrap();
            println!("completed iteration {}", i);
        }
    }
}
