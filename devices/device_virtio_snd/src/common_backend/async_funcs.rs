// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use audio_streams::capture::AsyncCaptureBuffer;
use audio_streams::AsyncPlaybackBuffer;
use audio_streams::BoxError;
use base::debug;
use base::error;
use base::info;
use cros_async::sync::Condvar;
use cros_async::sync::RwLock as AsyncRwLock;
use cros_async::AsyncTube;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::TimerAsync;
use devices::virtio::DescriptorChain;
use devices::virtio::Queue;
use devices::virtio::Reader;
use devices::virtio::Writer;
use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::pin_mut;
use futures::select;
use futures::FutureExt;
use futures::SinkExt;
use futures::StreamExt;
use thiserror::Error as ThisError;
use vm_control::SndControlCommand;
use vm_control::VmResponse;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

use super::validation::validate_query_info;
use super::validation::validate_set_params;
use super::Error;
use super::SndData;
use super::WorkerStatus;
use crate::common::*;
use crate::common_backend::stream_info::SetParams;
use crate::common_backend::stream_info::StreamInfo;
use crate::common_backend::DirectionalStream;
use crate::common_backend::PcmResponse;
use crate::constants::*;
use crate::layout::*;

/// Trait to wrap system specific helpers for reading from the start point capture buffer.
#[async_trait(?Send)]
pub trait CaptureBufferReader {
    async fn get_next_capture_period(
        &mut self,
        ex: &Executor,
    ) -> Result<AsyncCaptureBuffer, BoxError>;

    /// Starts the underlying capture stream. Default implementation is a no-op.
    ///
    /// Must return promptly; see `AsyncCaptureBufferStream::start()`.
    fn start(&mut self) -> Result<(), BoxError> {
        Ok(())
    }

    /// Stops the underlying capture stream. Default implementation is a no-op.
    ///
    /// Must return promptly; see `AsyncCaptureBufferStream::stop()`.
    fn stop(&mut self) -> Result<(), BoxError> {
        Ok(())
    }
}

/// Trait to wrap system specific helpers for writing to endpoint playback buffers.
#[async_trait(?Send)]
pub trait PlaybackBufferWriter {
    fn new(guest_period_bytes: usize) -> Self
    where
        Self: Sized;

    /// Returns the period of the endpoint device.
    fn endpoint_period_bytes(&self) -> usize;

    /// Read audio samples from the tx virtqueue.
    fn copy_to_buffer(
        &mut self,
        dst_buf: &mut AsyncPlaybackBuffer<'_>,
        reader: &mut Reader,
    ) -> Result<usize, Error> {
        dst_buf.copy_from(reader).map_err(Error::Io)
    }
}

#[derive(Debug)]
enum VirtioSndPcmCmd {
    SetParams { set_params: SetParams },
    Prepare,
    Start,
    Stop,
    Release,
}

impl fmt::Display for VirtioSndPcmCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cmd_code = match self {
            VirtioSndPcmCmd::SetParams { set_params: _ } => VIRTIO_SND_R_PCM_SET_PARAMS,
            VirtioSndPcmCmd::Prepare => VIRTIO_SND_R_PCM_PREPARE,
            VirtioSndPcmCmd::Start => VIRTIO_SND_R_PCM_START,
            VirtioSndPcmCmd::Stop => VIRTIO_SND_R_PCM_STOP,
            VirtioSndPcmCmd::Release => VIRTIO_SND_R_PCM_RELEASE,
        };
        f.write_str(get_virtio_snd_r_pcm_cmd_name(cmd_code))
    }
}

#[derive(ThisError, Debug)]
enum VirtioSndPcmCmdError {
    #[error("SetParams requires additional parameters")]
    SetParams,
    #[error("Invalid virtio snd command code")]
    InvalidCode,
}

impl TryFrom<u32> for VirtioSndPcmCmd {
    type Error = VirtioSndPcmCmdError;

    fn try_from(code: u32) -> Result<Self, Self::Error> {
        match code {
            VIRTIO_SND_R_PCM_PREPARE => Ok(VirtioSndPcmCmd::Prepare),
            VIRTIO_SND_R_PCM_START => Ok(VirtioSndPcmCmd::Start),
            VIRTIO_SND_R_PCM_STOP => Ok(VirtioSndPcmCmd::Stop),
            VIRTIO_SND_R_PCM_RELEASE => Ok(VirtioSndPcmCmd::Release),
            VIRTIO_SND_R_PCM_SET_PARAMS => Err(VirtioSndPcmCmdError::SetParams),
            _ => Err(VirtioSndPcmCmdError::InvalidCode),
        }
    }
}

// Returns true if the operation is successful. Returns error if there is
// a runtime/internal error
async fn process_pcm_ctrl(
    ex: &Executor,
    tx_send: &mpsc::UnboundedSender<PcmResponse>,
    rx_send: &mpsc::UnboundedSender<PcmResponse>,
    streams: &Rc<AsyncRwLock<Vec<AsyncRwLock<StreamInfo>>>>,
    cmd: VirtioSndPcmCmd,
    writer: &mut Writer,
    stream_id: usize,
    card_index: usize,
) -> Result<(), Error> {
    let streams = streams.read_lock().await;
    let mut stream = match streams.get(stream_id) {
        Some(stream_info) => stream_info.lock().await,
        None => {
            error!(
                "[Card {}] Stream id={} not found for {}. Error code: VIRTIO_SND_S_BAD_MSG",
                card_index, stream_id, cmd
            );
            return writer
                .write_obj(VIRTIO_SND_S_BAD_MSG)
                .map_err(Error::WriteResponse);
        }
    };

    debug!("[Card {}] {} for stream id={}", card_index, cmd, stream_id);

    let result = match cmd {
        VirtioSndPcmCmd::SetParams { set_params } => {
            let result = stream.set_params(set_params).await;
            if result.is_ok() {
                debug!(
                    "[Card {}] VIRTIO_SND_R_PCM_SET_PARAMS for stream id={}. Stream info: {:#?}",
                    card_index, stream_id, *stream
                );
            }
            result
        }
        VirtioSndPcmCmd::Prepare => stream.prepare(ex, tx_send, rx_send).await,
        VirtioSndPcmCmd::Start => stream.start().await,
        VirtioSndPcmCmd::Stop => stream.stop().await,
        VirtioSndPcmCmd::Release => stream.release().await,
    };
    match result {
        Ok(_) => writer
            .write_obj(VIRTIO_SND_S_OK)
            .map_err(Error::WriteResponse),
        Err(Error::OperationNotSupported) => {
            error!(
                "[Card {}] {} for stream id={} failed. Error code: VIRTIO_SND_S_NOT_SUPP.",
                card_index, cmd, stream_id
            );

            writer
                .write_obj(VIRTIO_SND_S_NOT_SUPP)
                .map_err(Error::WriteResponse)
        }
        Err(e) => {
            // Runtime/internal error would be more appropriate, but there's
            // no such error type
            error!(
                "[Card {}] {} for stream id={} failed. Error code: VIRTIO_SND_S_IO_ERR. Actual error: {}",
                card_index, cmd, stream_id, e
            );
            writer
                .write_obj(VIRTIO_SND_S_IO_ERR)
                .map_err(Error::WriteResponse)
        }
    }
}

async fn write_data(
    mut dst_buf: AsyncPlaybackBuffer<'_>,
    reader: Option<&mut Reader>,
    buffer_writer: &mut Box<dyn PlaybackBufferWriter>,
) -> Result<u32, Error> {
    let transferred = match reader {
        Some(reader) => buffer_writer.copy_to_buffer(&mut dst_buf, reader)?,
        None => dst_buf
            .copy_from(&mut io::repeat(0).take(buffer_writer.endpoint_period_bytes() as u64))
            .map_err(Error::Io)?,
    };

    if transferred != buffer_writer.endpoint_period_bytes() {
        error!(
            "Bytes written {} != period_bytes {}",
            transferred,
            buffer_writer.endpoint_period_bytes()
        );
        Err(Error::InvalidBufferSize)
    } else {
        dst_buf.commit().await;
        Ok(dst_buf.latency_bytes())
    }
}

async fn read_data(
    mut src_buf: AsyncCaptureBuffer<'_>,
    writer: Option<&mut Writer>,
    period_bytes: usize,
) -> Result<u32, Error> {
    let transferred = match writer {
        Some(writer) => src_buf.copy_to(writer),
        None => src_buf.copy_to(&mut io::sink()),
    }
    .map_err(Error::Io)?;
    if transferred != period_bytes {
        error!(
            "Bytes written {} != period_bytes {}",
            transferred, period_bytes
        );
        Err(Error::InvalidBufferSize)
    } else {
        src_buf.commit().await;
        Ok(src_buf.latency_bytes())
    }
}

impl From<Result<u32, Error>> for virtio_snd_pcm_status {
    fn from(res: Result<u32, Error>) -> Self {
        match res {
            Ok(latency_bytes) => virtio_snd_pcm_status::new(StatusCode::OK, latency_bytes),
            Err(e) => {
                error!("PCM I/O message failed: {}", e);
                virtio_snd_pcm_status::new(StatusCode::IoErr, 0)
            }
        }
    }
}

// Drain all DescriptorChain in desc_receiver during WorkerStatus::Quit process.
async fn drain_desc_receiver(
    desc_receiver: &mut mpsc::UnboundedReceiver<DescriptorChain>,
    sender: &mut mpsc::UnboundedSender<PcmResponse>,
) -> Result<(), Error> {
    let mut o_desc_chain = desc_receiver.next().await;
    while let Some(desc_chain) = o_desc_chain {
        // From the virtio-snd spec:
        // The device MUST complete all pending I/O messages for the specified stream ID.
        let status = virtio_snd_pcm_status::new(StatusCode::OK, 0);
        // Fetch next DescriptorChain to see if the current one is the last one.
        o_desc_chain = desc_receiver.next().await;
        let (done, future) = if o_desc_chain.is_none() {
            let (done, future) = oneshot::channel();
            (Some(done), Some(future))
        } else {
            (None, None)
        };
        sender
            .send(PcmResponse {
                desc_chain,
                status,
                done,
            })
            .await
            .map_err(Error::MpscSend)?;

        if let Some(f) = future {
            // From the virtio-snd spec:
            // The device MUST NOT complete the control request (VIRTIO_SND_R_PCM_RELEASE)
            // while there are pending I/O messages for the specified stream ID.
            f.await.map_err(Error::DoneNotTriggered)?;
        };
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureStreamState {
    Stopped,
    Started,
    StartFailed,
}

fn update_capture_stream_state(
    buffer_reader: &mut dyn CaptureBufferReader,
    stream_state: &mut CaptureStreamState,
    status: WorkerStatus,
    card_index: usize,
) {
    match status {
        WorkerStatus::Running if *stream_state == CaptureStreamState::Stopped => {
            match buffer_reader.start() {
                Ok(()) => *stream_state = CaptureStreamState::Started,
                Err(e) => {
                    error!(
                        "[Card {}] Failed to start capture stream: {}",
                        card_index, e
                    );
                    *stream_state = CaptureStreamState::StartFailed;
                }
            }
        }
        WorkerStatus::Pause | WorkerStatus::Quit => {
            if *stream_state == CaptureStreamState::Started {
                if let Err(e) = buffer_reader.stop() {
                    error!("[Card {}] Failed to stop capture stream: {}", card_index, e);
                }
            }
            *stream_state = CaptureStreamState::Stopped;
        }
        _ => {}
    }
}

/// Start a pcm worker that receives descriptors containing PCM frames (audio data) from the tx/rx
/// queue, and forward them to CRAS. One pcm worker per stream.
///
/// This worker is started when VIRTIO_SND_R_PCM_PREPARE is called, and returned before
/// VIRTIO_SND_R_PCM_RELEASE is completed for the stream.
pub async fn start_pcm_worker(
    ex: Executor,
    dstream: DirectionalStream,
    mut desc_receiver: mpsc::UnboundedReceiver<DescriptorChain>,
    status_mutex: Rc<AsyncRwLock<WorkerStatus>>,
    mut sender: mpsc::UnboundedSender<PcmResponse>,
    period_dur: Duration,
    card_index: usize,
    muted: Rc<AtomicBool>,
    release_signal: Rc<(AsyncRwLock<bool>, Condvar)>,
) -> Result<(), Error> {
    let res = pcm_worker_loop(
        ex,
        dstream,
        &mut desc_receiver,
        &status_mutex,
        &mut sender,
        period_dur,
        card_index,
        muted,
        release_signal,
    )
    .await;
    *status_mutex.lock().await = WorkerStatus::Quit;
    if res.is_err() {
        error!(
            "[Card {}] pcm_worker error: {:#?}. Draining desc_receiver",
            card_index,
            res.as_ref().err()
        );
        // On error, guaranteed that desc_receiver has not been drained, so drain it here.
        // Note that drain blocks until the stream is release.
        drain_desc_receiver(&mut desc_receiver, &mut sender).await?;
    }
    res
}

async fn pcm_worker_loop(
    ex: Executor,
    dstream: DirectionalStream,
    desc_receiver: &mut mpsc::UnboundedReceiver<DescriptorChain>,
    status_mutex: &Rc<AsyncRwLock<WorkerStatus>>,
    sender: &mut mpsc::UnboundedSender<PcmResponse>,
    period_dur: Duration,
    card_index: usize,
    muted: Rc<AtomicBool>,
    release_signal: Rc<(AsyncRwLock<bool>, Condvar)>,
) -> Result<(), Error> {
    let on_release = async {
        await_reset_signal(Some(&*release_signal)).await;
        // After receiving release signal, wait for up to 2 periods,
        // giving it a chance to respond to the last buffer.
        if let Err(e) = TimerAsync::sleep(&ex, period_dur * 2).await {
            error!(
                "[Card {}] Error on sleep after receiving reset signal: {}",
                card_index, e
            )
        }
    }
    .fuse();
    pin_mut!(on_release);

    match dstream {
        DirectionalStream::Output(mut sys_direction_output) => loop {
            #[cfg(windows)]
            #[allow(clippy::self_assignment)]
            {
                sys_direction_output = sys_direction_output; // unused_mut workaround
            }
            #[cfg(windows)]
            let (mut stream, mut buffer_writer_lock) = (
                sys_direction_output
                    .async_playback_buffer_stream
                    .lock()
                    .await,
                sys_direction_output.buffer_writer.lock().await,
            );
            #[cfg(windows)]
            let buffer_writer = &mut buffer_writer_lock;
            #[cfg(any(target_os = "android", target_os = "linux"))]
            let (stream, buffer_writer) = (
                &mut sys_direction_output.async_playback_buffer_stream,
                &mut sys_direction_output.buffer_writer,
            );

            let next_buf = stream.next_playback_buffer(&ex).fuse();
            pin_mut!(next_buf);

            let dst_buf = select! {
                _ = on_release => {
                    drain_desc_receiver(desc_receiver, sender).await?;
                    break Ok(());
                },
                buf = next_buf => buf.map_err(Error::FetchBuffer)?,
            };
            let worker_status = status_mutex.lock().await;
            match *worker_status {
                WorkerStatus::Quit => {
                    drain_desc_receiver(desc_receiver, sender).await?;
                    if let Err(e) = write_data(dst_buf, None, buffer_writer).await {
                        error!(
                            "[Card {}] Error on write_data after worker quit: {}",
                            card_index, e
                        )
                    }
                    break Ok(());
                }
                WorkerStatus::Pause => {
                    write_data(dst_buf, None, buffer_writer).await?;
                }
                WorkerStatus::Running => match desc_receiver.try_next() {
                    Err(e) => {
                        error!(
                            "[Card {}] Underrun. No new DescriptorChain while running: {}",
                            card_index, e
                        );
                        write_data(dst_buf, None, buffer_writer).await?;
                    }
                    Ok(None) => {
                        error!("[Card {}] Unreachable. status should be Quit when the channel is closed", card_index);
                        write_data(dst_buf, None, buffer_writer).await?;
                        return Err(Error::InvalidPCMWorkerState);
                    }
                    Ok(Some(mut desc_chain)) => {
                        let reader = if muted.load(Ordering::Relaxed) {
                            None
                        } else {
                            // stream_id was already read in handle_pcm_queue
                            Some(&mut desc_chain.reader)
                        };
                        let status = write_data(dst_buf, reader, buffer_writer).await.into();
                        sender
                            .send(PcmResponse {
                                desc_chain,
                                status,
                                done: None,
                            })
                            .await
                            .map_err(Error::MpscSend)?;
                    }
                },
            }
        },
        DirectionalStream::Input(period_bytes, mut buffer_reader) => {
            let mut stream_state = CaptureStreamState::Stopped;
            let res = async {
                loop {
                    let current_status = *status_mutex.lock().await;
                    update_capture_stream_state(
                        buffer_reader.as_mut(),
                        &mut stream_state,
                        current_status,
                        card_index,
                    );
                    if current_status == WorkerStatus::Quit {
                        drain_desc_receiver(desc_receiver, sender).await?;
                        break Ok(());
                    }
                    if current_status == WorkerStatus::Pause {
                        let sleep_fut = TimerAsync::sleep(&ex, period_dur).fuse();
                        pin_mut!(sleep_fut);
                        select! {
                            _ = on_release => {
                                drain_desc_receiver(desc_receiver, sender).await?;
                                break Ok(());
                            },
                            res = sleep_fut => {
                                if let Err(e) = res {
                                    error!(
                                        "[Card {}] Error on sleep while capture stream paused: {}",
                                        card_index, e
                                    );
                                }
                                continue;
                            },
                        };
                    }

                    let next_buf = buffer_reader.get_next_capture_period(&ex).fuse();
                    pin_mut!(next_buf);

                    let src_buf = select! {
                        _ = on_release => {
                            drain_desc_receiver(desc_receiver, sender).await?;
                            break Ok(());
                        },
                        buf = next_buf => buf.map_err(Error::FetchBuffer)?,
                    };

                    let worker_status = *status_mutex.lock().await;
                    match worker_status {
                        WorkerStatus::Quit => {
                            drain_desc_receiver(desc_receiver, sender).await?;
                            if let Err(e) = read_data(src_buf, None, period_bytes).await {
                                error!(
                                    "[Card {}] Error on read_data after worker quit: {}",
                                    card_index, e
                                )
                            }
                            break Ok(());
                        }
                        WorkerStatus::Pause => {
                            read_data(src_buf, None, period_bytes).await?;
                        }
                        WorkerStatus::Running => match desc_receiver.try_next() {
                            Err(e) => {
                                error!(
                                    "[Card {}] Overrun. No new DescriptorChain while running: {}",
                                    card_index, e
                                );
                                read_data(src_buf, None, period_bytes).await?;
                            }
                            Ok(None) => {
                                error!("[Card {}] Unreachable. status should be Quit when the channel is closed", card_index);
                                read_data(src_buf, None, period_bytes).await?;
                                return Err(Error::InvalidPCMWorkerState);
                            }
                            Ok(Some(mut desc_chain)) => {
                                let writer = if muted.load(Ordering::Relaxed) {
                                    None
                                } else {
                                    Some(&mut desc_chain.writer)
                                };
                                let status = read_data(src_buf, writer, period_bytes).await.into();
                                sender
                                    .send(PcmResponse {
                                        desc_chain,
                                        status,
                                        done: None,
                                    })
                                    .await
                                    .map_err(Error::MpscSend)?;
                            }
                        },
                    }
                }
            }
            .await;

            update_capture_stream_state(
                buffer_reader.as_mut(),
                &mut stream_state,
                WorkerStatus::Quit,
                card_index,
            );

            res
        }
    }
}

// Defer pcm message response to the pcm response worker
async fn defer_pcm_response_to_worker(
    desc_chain: DescriptorChain,
    status: virtio_snd_pcm_status,
    response_sender: &mut mpsc::UnboundedSender<PcmResponse>,
) -> Result<(), Error> {
    response_sender
        .send(PcmResponse {
            desc_chain,
            status,
            done: None,
        })
        .await
        .map_err(Error::MpscSend)
}

fn send_pcm_response(
    mut desc_chain: DescriptorChain,
    queue: &mut Queue,
    status: virtio_snd_pcm_status,
) -> Result<(), Error> {
    let writer = &mut desc_chain.writer;

    // For rx queue only. Fast forward the unused audio data buffer.
    if writer.available_bytes() > std::mem::size_of::<virtio_snd_pcm_status>() {
        writer
            .consume_bytes(writer.available_bytes() - std::mem::size_of::<virtio_snd_pcm_status>());
    }
    writer.write_obj(status).map_err(Error::WriteResponse)?;
    queue.add_used(desc_chain);
    queue.trigger_interrupt();
    Ok(())
}

// Await until reset_signal has been released
async fn await_reset_signal(reset_signal_option: Option<&(AsyncRwLock<bool>, Condvar)>) {
    match reset_signal_option {
        Some((lock, cvar)) => {
            let mut reset = lock.lock().await;
            while !*reset {
                reset = cvar.wait(reset).await;
            }
        }
        None => futures::future::pending().await,
    };
}

pub async fn send_pcm_response_worker(
    queue: Rc<AsyncRwLock<Queue>>,
    recv: &mut mpsc::UnboundedReceiver<PcmResponse>,
    reset_signal: Option<&(AsyncRwLock<bool>, Condvar)>,
) -> Result<(), Error> {
    let on_reset = await_reset_signal(reset_signal).fuse();
    pin_mut!(on_reset);

    loop {
        let next_async = recv.next().fuse();
        pin_mut!(next_async);

        let res = select! {
            _ = on_reset => break,
            res = next_async => res,
        };

        if let Some(r) = res {
            send_pcm_response(r.desc_chain, &mut *queue.lock().await, r.status)?;

            // Resume pcm_worker
            if let Some(done) = r.done {
                done.send(()).map_err(Error::OneshotSend)?;
            }
        } else {
            debug!("PcmResponse channel is closed.");
            break;
        }
    }
    Ok(())
}

/// Handle messages from the control tube. This one is not related to virtio spec.
pub async fn handle_ctrl_tube(
    streams: &Rc<AsyncRwLock<Vec<AsyncRwLock<StreamInfo>>>>,
    control_tube: &AsyncTube,
    reset_signal: Option<&(AsyncRwLock<bool>, Condvar)>,
) -> Result<(), Error> {
    let on_reset = await_reset_signal(reset_signal).fuse();
    pin_mut!(on_reset);

    loop {
        let next_async = control_tube.next().fuse();
        pin_mut!(next_async);

        let cmd = select! {
            _ = on_reset => break,
            res = next_async => res,
        };

        match cmd {
            Ok(cmd) => {
                let resp = match cmd {
                    SndControlCommand::MuteAll(muted) => {
                        let streams = streams.read_lock().await;
                        for stream in streams.iter() {
                            let stream_info = stream.lock().await;
                            stream_info.muted.store(muted, Ordering::Relaxed);
                            info!("Stream muted = {:?}", muted);
                        }
                        VmResponse::Ok
                    }
                };
                control_tube
                    .send(resp)
                    .await
                    .map_err(Error::ControlTubeError)?;
            }
            Err(e) => {
                error!("Failed to read the command: {}", e);
                return Err(Error::ControlTubeError(e));
            }
        }
    }

    Ok(())
}

/// Handle messages from the tx or the rx queue. One invocation is needed for
/// each queue.
pub async fn handle_pcm_queue(
    streams: &Rc<AsyncRwLock<Vec<AsyncRwLock<StreamInfo>>>>,
    mut response_sender: mpsc::UnboundedSender<PcmResponse>,
    queue: Rc<AsyncRwLock<Queue>>,
    queue_event: &EventAsync,
    card_index: usize,
    reset_signal: Option<&(AsyncRwLock<bool>, Condvar)>,
) -> Result<(), Error> {
    let on_reset = await_reset_signal(reset_signal).fuse();
    pin_mut!(on_reset);

    loop {
        // Manual queue.next_async() to avoid holding the mutex
        let next_async = async {
            loop {
                // Check if there are more descriptors available.
                if let Some(chain) = queue.lock().await.pop() {
                    return Ok(chain);
                }
                queue_event.next_val().await?;
            }
        }
        .fuse();
        pin_mut!(next_async);

        let mut desc_chain = select! {
            _ = on_reset => break,
            res = next_async => res.map_err(Error::Async)?,
        };

        let pcm_xfer: virtio_snd_pcm_xfer =
            desc_chain.reader.read_obj().map_err(Error::ReadMessage)?;
        let stream_id: usize = u32::from(pcm_xfer.stream_id) as usize;

        let streams = streams.read_lock().await;
        let stream_info = match streams.get(stream_id) {
            Some(stream_info) => stream_info.read_lock().await,
            None => {
                error!(
                    "[Card {}] stream_id ({}) >= num_streams ({})",
                    card_index,
                    stream_id,
                    streams.len()
                );
                defer_pcm_response_to_worker(
                    desc_chain,
                    virtio_snd_pcm_status::new(StatusCode::IoErr, 0),
                    &mut response_sender,
                )
                .await?;
                continue;
            }
        };

        match stream_info.sender.as_ref() {
            Some(mut s) => {
                s.send(desc_chain).await.map_err(Error::MpscSend)?;
                if *stream_info.status_mutex.lock().await == WorkerStatus::Quit {
                    // If sender channel is still intact but worker status is quit,
                    // the worker quitted unexpectedly. Return error to request a reset.
                    return Err(Error::PCMWorkerQuittedUnexpectedly);
                }
            }
            None => {
                if !stream_info.just_reset {
                    error!(
                        "[Card {}] stream {} is not ready. state: {}",
                        card_index,
                        stream_id,
                        get_virtio_snd_r_pcm_cmd_name(stream_info.state)
                    );
                }
                defer_pcm_response_to_worker(
                    desc_chain,
                    virtio_snd_pcm_status::new(StatusCode::IoErr, 0),
                    &mut response_sender,
                )
                .await?;
            }
        };
    }
    Ok(())
}

fn write_info_reply<T: IntoBytes + Immutable>(
    writer: &mut Writer,
    query_info: &virtio_snd_query_info,
    items: &[T],
    card_index: usize,
    what: &str,
) -> Result<(), Error> {
    match validate_query_info(query_info, items.len()) {
        Ok(range) => {
            writer
                .write_obj(VIRTIO_SND_S_OK)
                .map_err(Error::WriteResponse)?;
            for item in &items[range] {
                writer
                    .write_all(item.as_bytes())
                    .map_err(Error::WriteResponse)?;
            }
            Ok(())
        }
        Err(status) => {
            error!(
                "[Card {}] start_id({}) + count({}) must not exceed the number of {} ({})",
                card_index,
                u32::from(query_info.start_id),
                u32::from(query_info.count),
                what,
                items.len()
            );
            writer.write_obj(status).map_err(Error::WriteResponse)
        }
    }
}

/// Handle all the control messages from the ctrl queue.
pub async fn handle_ctrl_queue(
    ex: &Executor,
    streams: &Rc<AsyncRwLock<Vec<AsyncRwLock<StreamInfo>>>>,
    snd_data: &SndData,
    queue: Rc<AsyncRwLock<Queue>>,
    queue_event: &mut EventAsync,
    tx_send: mpsc::UnboundedSender<PcmResponse>,
    rx_send: mpsc::UnboundedSender<PcmResponse>,
    card_index: usize,
    reset_signal: Option<&(AsyncRwLock<bool>, Condvar)>,
) -> Result<(), Error> {
    let on_reset = await_reset_signal(reset_signal).fuse();
    pin_mut!(on_reset);

    let mut queue = queue.lock().await;
    loop {
        let mut desc_chain = {
            let next_async = queue.next_async(queue_event).fuse();
            pin_mut!(next_async);

            select! {
                _ = on_reset => break,
                res = next_async => res.map_err(Error::Async)?,
            }
        };

        let reader = &mut desc_chain.reader;
        let writer = &mut desc_chain.writer;
        // Don't advance the reader
        let code = reader
            .peek_obj::<virtio_snd_hdr>()
            .map_err(Error::ReadMessage)?
            .code
            .into();

        let handle_ctrl_msg = async {
            match code {
                VIRTIO_SND_R_JACK_INFO => {
                    let query_info: virtio_snd_query_info =
                        reader.read_obj().map_err(Error::ReadMessage)?;
                    write_info_reply(
                        writer,
                        &query_info,
                        &snd_data.jack_info,
                        card_index,
                        "jacks",
                    )
                }
                VIRTIO_SND_R_PCM_INFO => {
                    let query_info: virtio_snd_query_info =
                        reader.read_obj().map_err(Error::ReadMessage)?;
                    write_info_reply(
                        writer,
                        &query_info,
                        &snd_data.pcm_info,
                        card_index,
                        "streams",
                    )
                }
                VIRTIO_SND_R_CHMAP_INFO => {
                    let query_info: virtio_snd_query_info =
                        reader.read_obj().map_err(Error::ReadMessage)?;
                    write_info_reply(
                        writer,
                        &query_info,
                        &snd_data.chmap_info,
                        card_index,
                        "chmaps",
                    )
                }
                VIRTIO_SND_R_JACK_REMAP => {
                    // Jack remap is unsupported.
                    writer
                        .write_obj(VIRTIO_SND_S_NOT_SUPP)
                        .map_err(Error::WriteResponse)
                }
                VIRTIO_SND_R_PCM_SET_PARAMS => {
                    let set_params: virtio_snd_pcm_set_params =
                        reader.read_obj().map_err(Error::ReadMessage)?;
                    let stream_id: usize = u32::from(set_params.hdr.stream_id) as usize;
                    let Some(pcm_info) = snd_data.pcm_info.get(stream_id) else {
                        error!(
                            "[Card {}] stream_id {} < streams {}",
                            card_index,
                            stream_id,
                            snd_data.pcm_info.len()
                        );
                        return writer
                            .write_obj(VIRTIO_SND_S_BAD_MSG)
                            .map_err(Error::WriteResponse);
                    };

                    let set_params = match validate_set_params(&set_params, pcm_info) {
                        Ok(params) => params,
                        Err(err) => {
                            error!(
                                "[Card {}] Invalid PCM set_params for stream id={}: {}",
                                card_index, stream_id, err
                            );
                            return writer
                                .write_obj(err.status_code())
                                .map_err(Error::WriteResponse);
                        }
                    };

                    process_pcm_ctrl(
                        ex,
                        &tx_send,
                        &rx_send,
                        streams,
                        VirtioSndPcmCmd::SetParams { set_params },
                        writer,
                        stream_id,
                        card_index,
                    )
                    .await
                }
                VIRTIO_SND_R_PCM_PREPARE
                | VIRTIO_SND_R_PCM_START
                | VIRTIO_SND_R_PCM_STOP
                | VIRTIO_SND_R_PCM_RELEASE => {
                    let hdr: virtio_snd_pcm_hdr = reader.read_obj().map_err(Error::ReadMessage)?;
                    let stream_id: usize = u32::from(hdr.stream_id) as usize;
                    let cmd = match VirtioSndPcmCmd::try_from(code) {
                        Ok(cmd) => cmd,
                        Err(err) => {
                            error!(
                                "[Card {}] Error converting code to command: {}",
                                card_index, err
                            );
                            return writer
                                .write_obj(VIRTIO_SND_S_BAD_MSG)
                                .map_err(Error::WriteResponse);
                        }
                    };
                    process_pcm_ctrl(
                        ex, &tx_send, &rx_send, streams, cmd, writer, stream_id, card_index,
                    )
                    .await
                    .and(Ok(()))?;
                    Ok(())
                }
                c => {
                    error!("[Card {}] Unrecognized code: {}", card_index, c);
                    writer
                        .write_obj(VIRTIO_SND_S_BAD_MSG)
                        .map_err(Error::WriteResponse)
                }
            }
        };

        handle_ctrl_msg.await?;
        queue.add_used(desc_chain);
        queue.trigger_interrupt();
    }
    Ok(())
}

/// Send events to the audio driver.
pub async fn handle_event_queue(
    mut queue: Queue,
    mut queue_event: EventAsync,
) -> Result<(), Error> {
    loop {
        let desc_chain = queue
            .next_async(&mut queue_event)
            .await
            .map_err(Error::Async)?;

        // TODO(woodychow): Poll and forward events from cras asynchronously (API to be added)
        queue.add_used(desc_chain);
        queue.trigger_interrupt();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use audio_streams::NoopStreamSourceGenerator;
    use base::Tube;

    use super::*;
    use crate::common_backend::notify_reset_signal;

    #[test]
    fn test_handle_ctrl_tube_reset_signal() {
        let ex = Executor::new().expect("Failed to create an executor");
        let result = ex.run_until(async {
            let streams: Rc<AsyncRwLock<Vec<AsyncRwLock<StreamInfo>>>> = Default::default();
            let (t0, _t1) = Tube::pair().expect("Failed to create tube pairs");
            let t0 = AsyncTube::new(&ex, t0).expect("Failed to create async tube");
            let reset_signal = (AsyncRwLock::new(false), Condvar::new());

            let handle_future = handle_ctrl_tube(&streams, &t0, Some(&reset_signal));
            let notify_future = notify_reset_signal(&reset_signal);
            let (result, _) = futures::join!(handle_future, notify_future);

            assert!(
                result.is_ok(),
                "handle_ctrl_tube returns an error after reset signal"
            );
        });

        assert!(result.is_ok(), "ex.run_until returns an error");
    }

    fn new_stream() -> StreamInfo {
        let card_index = 0;
        StreamInfo::builder(
            Arc::new(Box::new(NoopStreamSourceGenerator::new())),
            card_index,
        )
        .build()
    }

    #[test]
    fn test_handle_ctrl_tube_receive_mute_cmd() {
        let ex = Executor::new().expect("Failed to create an executor");
        let result = ex.run_until(async {
            let streams: Vec<AsyncRwLock<StreamInfo>> = vec![AsyncRwLock::new(new_stream())];
            let streams = Rc::new(AsyncRwLock::new(streams));

            let (t0, t1) = Tube::pair().expect("Failed to create tube pairs");
            let t0 = AsyncTube::new(&ex, t0).expect("Failed to create an async tube");
            let t1 = AsyncTube::new(&ex, t1).expect("Failed to create an async tube");
            let reset_signal = (AsyncRwLock::new(false), Condvar::new());

            let handle_future = handle_ctrl_tube(&streams, &t0, Some(&reset_signal));
            let tube_future = async {
                let _ = t1.send(&SndControlCommand::MuteAll(true)).await;
                let recv_result = t1.next::<VmResponse>().await;
                notify_reset_signal(&reset_signal).await;
                recv_result
            };
            let (handle_result, tube_result) = futures::join!(handle_future, tube_future);

            assert!(
                handle_result.is_ok(),
                "handle_ctrl_tube returns an error after reset signal"
            );
            assert!(tube_result.is_ok(), "Failed to receive data from the tube");
            assert!(
                matches!(tube_result.unwrap(), VmResponse::Ok),
                "tube_result is not Ok",
            );

            let streams = streams.read_lock().await;
            let stream = streams.first().unwrap().lock().await;
            assert!(stream.muted.load(Ordering::Relaxed), "Stream is not muted");
        });

        assert!(result.is_ok(), "ex.run_until returns an error");
    }
}
