// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::io::{self, Read, Write};
use std::rc::Rc;

use audio_streams::{capture::AsyncCaptureBuffer, AsyncPlaybackBuffer};
use base::{debug, error};
use cros_async::{sync::Mutex as AsyncMutex, EventAsync, Executor};
use data_model::{DataInit, Le32};
use vm_memory::GuestMemory;

use crate::virtio::cras_backend::{Parameters, PcmResponse};
use crate::virtio::snd::common::*;
use crate::virtio::snd::constants::*;
use crate::virtio::snd::layout::*;
use crate::virtio::{DescriptorChain, Queue, Reader, SignalableInterrupt, Writer};

use super::{DirectionalStream, Error, SndData, StreamInfo, WorkerStatus};

// Returns true if the operation is successful. Returns error if there is
// a runtime/internal error
async fn process_pcm_ctrl(
    ex: &Executor,
    mem: &GuestMemory,
    tx_send: &mpsc::UnboundedSender<PcmResponse>,
    rx_send: &mpsc::UnboundedSender<PcmResponse>,
    streams: &Rc<AsyncMutex<Vec<AsyncMutex<StreamInfo<'_>>>>>,
    params: &Parameters,
    cmd_code: u32,
    writer: &mut Writer,
    stream_id: usize,
) -> Result<(), Error> {
    let streams = streams.read_lock().await;
    let mut stream = match streams.get(stream_id) {
        Some(stream_info) => stream_info.lock().await,
        None => {
            error!(
                "Stream id={} not found for {}. Error code: VIRTIO_SND_S_BAD_MSG",
                stream_id,
                get_virtio_snd_r_pcm_cmd_name(cmd_code)
            );
            return writer
                .write_obj(VIRTIO_SND_S_BAD_MSG)
                .map_err(Error::WriteResponse);
        }
    };

    debug!(
        "{} for stream id={}",
        get_virtio_snd_r_pcm_cmd_name(cmd_code),
        stream_id
    );

    let result = match cmd_code {
        VIRTIO_SND_R_PCM_PREPARE => {
            stream
                .prepare(ex, mem.clone(), tx_send, rx_send, params)
                .await
        }
        VIRTIO_SND_R_PCM_START => stream.start().await,
        VIRTIO_SND_R_PCM_STOP => stream.stop().await,
        VIRTIO_SND_R_PCM_RELEASE => stream.release().await,
        _ => unreachable!(),
    };
    match result {
        Ok(_) => {
            return writer
                .write_obj(VIRTIO_SND_S_OK)
                .map_err(Error::WriteResponse);
        }
        Err(Error::OperationNotSupported) => {
            error!(
                "{} for stream id={} failed. Error code: VIRTIO_SND_S_NOT_SUPP.",
                get_virtio_snd_r_pcm_cmd_name(cmd_code),
                stream_id
            );

            return writer
                .write_obj(VIRTIO_SND_S_NOT_SUPP)
                .map_err(Error::WriteResponse);
        }
        Err(e) => {
            // Runtime/internal error would be more appropriate, but there's
            // no such error type
            error!(
                "{} for stream id={} failed. Error code: VIRTIO_SND_S_IO_ERR. Actual error: {}",
                get_virtio_snd_r_pcm_cmd_name(cmd_code),
                stream_id,
                e
            );
            return writer
                .write_obj(VIRTIO_SND_S_IO_ERR)
                .map_err(Error::WriteResponse);
        }
    };
}

async fn write_data<'a>(
    mut dst_buf: AsyncPlaybackBuffer<'a>,
    reader: Option<Reader>,
    period_bytes: usize,
) -> Result<(), Error> {
    let transferred = match reader {
        Some(mut reader) => dst_buf.copy_from(&mut reader),
        None => dst_buf.copy_from(&mut io::repeat(0).take(period_bytes as u64)),
    }
    .map_err(Error::Io)?;
    if transferred as usize != period_bytes {
        error!(
            "Bytes written {} != period_bytes {}",
            transferred, period_bytes
        );
        Err(Error::InvalidBufferSize)
    } else {
        dst_buf.commit().await;
        Ok(())
    }
}

async fn read_data<'a>(
    mut src_buf: AsyncCaptureBuffer<'a>,
    writer: Option<&mut Writer>,
    period_bytes: usize,
) -> Result<(), Error> {
    let transferred = match writer {
        Some(writer) => src_buf.copy_to(writer),
        None => src_buf.copy_to(&mut io::sink()),
    }
    .map_err(Error::Io)?;
    if transferred as usize != period_bytes {
        error!(
            "Bytes written {} != period_bytes {}",
            transferred, period_bytes
        );
        Err(Error::InvalidBufferSize)
    } else {
        src_buf.commit().await;
        Ok(())
    }
}

impl From<Result<(), Error>> for virtio_snd_pcm_status {
    fn from(res: Result<(), Error>) -> Self {
        let status = match res {
            Ok(()) => VIRTIO_SND_S_OK,
            Err(e) => {
                error!("PCM I/O message failed: {}", e);
                VIRTIO_SND_S_IO_ERR
            }
        };

        // TODO(woodychow): Extend audio_streams API, and fetch latency_bytes from
        // `next_playback_buffer` or `next_capture_buffer`"
        Self {
            status: Le32::from(status),
            latency_bytes: Le32::from(0),
        }
    }
}

// Drain all DescriptorChain in desc_receiver during WorkerStatus::Quit process.
async fn drain_desc_receiver(
    desc_receiver: &mut mpsc::UnboundedReceiver<DescriptorChain>,
    mem: &GuestMemory,
    sender: &mut mpsc::UnboundedSender<PcmResponse>,
) -> Result<(), Error> {
    let mut o_desc_chain = desc_receiver.next().await;
    while let Some(desc_chain) = o_desc_chain {
        // From the virtio-snd spec:
        // The device MUST complete all pending I/O messages for the specified stream ID.
        let desc_index = desc_chain.index;
        let writer = Writer::new(mem.clone(), desc_chain).map_err(Error::DescriptorChain)?;
        let status = virtio_snd_pcm_status {
            status: Le32::from(VIRTIO_SND_S_OK),
            latency_bytes: Le32::from(0),
        };
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
                desc_index,
                status,
                writer,
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

/// Start a pcm worker that receives descriptors containing PCM frames (audio data) from the tx/rx
/// queue, and forward them to CRAS. One pcm worker per stream.
///
/// This worker is started when VIRTIO_SND_R_PCM_PREPARE is called, and returned before
/// VIRTIO_SND_R_PCM_RELEASE is completed for the stream.
pub async fn start_pcm_worker(
    ex: Executor,
    dstream: DirectionalStream,
    mut desc_receiver: mpsc::UnboundedReceiver<DescriptorChain>,
    status_mutex: Rc<AsyncMutex<WorkerStatus>>,
    mem: GuestMemory,
    mut sender: mpsc::UnboundedSender<PcmResponse>,
    period_bytes: usize,
) -> Result<(), Error> {
    match dstream {
        DirectionalStream::Output(mut stream) => {
            loop {
                let dst_buf = stream
                    .next_playback_buffer(&ex)
                    .await
                    .map_err(Error::FetchBuffer)?;
                let worker_status = status_mutex.lock().await;
                match *worker_status {
                    WorkerStatus::Quit => {
                        drain_desc_receiver(&mut desc_receiver, &mem, &mut sender).await?;
                        write_data(dst_buf, None, period_bytes).await?;
                        break Ok(());
                    }
                    WorkerStatus::Pause => {
                        write_data(dst_buf, None, period_bytes).await?;
                    }
                    WorkerStatus::Running => match desc_receiver.try_next() {
                        Err(e) => {
                            error!("Underrun. No new DescriptorChain while running: {}", e);
                            write_data(dst_buf, None, period_bytes).await?;
                        }
                        Ok(None) => {
                            error!("Unreachable. status should be Quit when the channel is closed");
                            write_data(dst_buf, None, period_bytes).await?;
                            return Err(Error::InvalidPCMWorkerState);
                        }
                        Ok(Some(desc_chain)) => {
                            let desc_index = desc_chain.index;
                            let mut reader = Reader::new(mem.clone(), desc_chain.clone())
                                .map_err(Error::DescriptorChain)?;
                            // stream_id was already read in handle_pcm_queue
                            reader.consume(std::mem::size_of::<virtio_snd_pcm_xfer>());
                            let writer = Writer::new(mem.clone(), desc_chain)
                                .map_err(Error::DescriptorChain)?;

                            sender
                                .send(PcmResponse {
                                    desc_index,
                                    status: write_data(dst_buf, Some(reader), period_bytes)
                                        .await
                                        .into(),
                                    writer,
                                    done: None,
                                })
                                .await
                                .map_err(Error::MpscSend)?;
                        }
                    },
                }
            }
        }
        DirectionalStream::Input(mut stream) => {
            loop {
                let src_buf = stream
                    .next_capture_buffer(&ex)
                    .await
                    .map_err(Error::FetchBuffer)?;

                let worker_status = status_mutex.lock().await;
                match *worker_status {
                    WorkerStatus::Quit => {
                        drain_desc_receiver(&mut desc_receiver, &mem, &mut sender).await?;
                        read_data(src_buf, None, period_bytes).await?;
                        break Ok(());
                    }
                    WorkerStatus::Pause => {
                        read_data(src_buf, None, period_bytes).await?;
                    }
                    WorkerStatus::Running => match desc_receiver.try_next() {
                        Err(e) => {
                            error!("Overrun. No new DescriptorChain while running: {}", e);
                            read_data(src_buf, None, period_bytes).await?;
                        }
                        Ok(None) => {
                            error!("Unreachable. status should be Quit when the channel is closed");
                            read_data(src_buf, None, period_bytes).await?;
                            return Err(Error::InvalidPCMWorkerState);
                        }
                        Ok(Some(desc_chain)) => {
                            let desc_index = desc_chain.index;
                            let mut reader = Reader::new(mem.clone(), desc_chain.clone())
                                .map_err(Error::DescriptorChain)?;
                            // stream_id was already read in handle_pcm_queue
                            reader.consume(std::mem::size_of::<virtio_snd_pcm_xfer>());
                            let mut writer = Writer::new(mem.clone(), desc_chain)
                                .map_err(Error::DescriptorChain)?;

                            sender
                                .send(PcmResponse {
                                    desc_index,
                                    status: read_data(src_buf, Some(&mut writer), period_bytes)
                                        .await
                                        .into(),
                                    writer,
                                    done: None,
                                })
                                .await
                                .map_err(Error::MpscSend)?;
                        }
                    },
                }
            }
        }
    }
}

// Defer pcm message response to the pcm response worker
async fn defer_pcm_response_to_worker(
    desc_chain: DescriptorChain,
    mem: &GuestMemory,
    status: virtio_snd_pcm_status,
    response_sender: &mut mpsc::UnboundedSender<PcmResponse>,
) -> Result<(), Error> {
    let desc_index = desc_chain.index;
    let writer = Writer::new(mem.clone(), desc_chain).map_err(Error::DescriptorChain)?;
    response_sender
        .send(PcmResponse {
            desc_index,
            status,
            writer,
            done: None,
        })
        .await
        .map_err(Error::MpscSend)
}

fn send_pcm_response_with_writer<I: SignalableInterrupt>(
    mut writer: Writer,
    desc_index: u16,
    mem: &GuestMemory,
    queue: &mut Queue,
    interrupt: &I,
    status: virtio_snd_pcm_status,
) -> Result<(), Error> {
    // For rx queue only. Fast forward the unused audio data buffer.
    if writer.available_bytes() > std::mem::size_of::<virtio_snd_pcm_status>() {
        writer
            .consume_bytes(writer.available_bytes() - std::mem::size_of::<virtio_snd_pcm_status>());
    }
    writer.write_obj(status).map_err(Error::WriteResponse)?;
    queue.add_used(mem, desc_index, writer.bytes_written() as u32);
    queue.trigger_interrupt(mem, interrupt);
    Ok(())
}

pub async fn send_pcm_response_worker<I: SignalableInterrupt>(
    mem: &GuestMemory,
    queue: &Rc<AsyncMutex<Queue>>,
    interrupt: &I,
    recv: &mut mpsc::UnboundedReceiver<PcmResponse>,
) -> Result<(), Error> {
    loop {
        if let Some(r) = recv.next().await {
            send_pcm_response_with_writer(
                r.writer,
                r.desc_index,
                &mem,
                &mut *queue.lock().await,
                interrupt,
                r.status,
            )?;

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

/// Handle messages from the tx or the rx queue. One invocation is needed for
/// each queue.
pub async fn handle_pcm_queue<'a>(
    mem: &GuestMemory,
    streams: &Rc<AsyncMutex<Vec<AsyncMutex<StreamInfo<'a>>>>>,
    mut response_sender: mpsc::UnboundedSender<PcmResponse>,
    queue: &Rc<AsyncMutex<Queue>>,
    queue_event: EventAsync,
) -> Result<(), Error> {
    loop {
        // Manual queue.next_async() to avoid holding the mutex
        let next_async = async {
            loop {
                // Check if there are more descriptors available.
                if let Some(chain) = queue.lock().await.pop(mem) {
                    return Ok(chain);
                }
                queue_event.next_val().await?;
            }
        };

        let desc_chain = next_async.await.map_err(Error::Async)?;
        let mut reader =
            Reader::new(mem.clone(), desc_chain.clone()).map_err(Error::DescriptorChain)?;

        let pcm_xfer: virtio_snd_pcm_xfer = reader.read_obj().map_err(Error::ReadMessage)?;
        let stream_id: usize = u32::from(pcm_xfer.stream_id) as usize;

        let streams = streams.read_lock().await;
        let stream_info = match streams.get(stream_id) {
            Some(stream_info) => stream_info.read_lock().await,
            None => {
                error!(
                    "stream_id ({}) >= num_streams ({})",
                    stream_id,
                    streams.len()
                );
                defer_pcm_response_to_worker(
                    desc_chain,
                    mem,
                    virtio_snd_pcm_status {
                        status: Le32::from(VIRTIO_SND_S_IO_ERR),
                        latency_bytes: Le32::from(0),
                    },
                    &mut response_sender,
                )
                .await?;
                continue;
            }
        };

        match stream_info.sender.as_ref() {
            Some(mut s) => {
                s.send(desc_chain).await.map_err(Error::MpscSend)?;
            }
            None => {
                error!(
                    "stream {} is not ready. state: {}",
                    stream_id,
                    get_virtio_snd_r_pcm_cmd_name(stream_info.state)
                );
                defer_pcm_response_to_worker(
                    desc_chain,
                    mem,
                    virtio_snd_pcm_status {
                        status: Le32::from(VIRTIO_SND_S_IO_ERR),
                        latency_bytes: Le32::from(0),
                    },
                    &mut response_sender,
                )
                .await?;
            }
        };
    }
}

/// Handle all the control messages from the ctrl queue.
pub async fn handle_ctrl_queue<I: SignalableInterrupt>(
    ex: &Executor,
    mem: &GuestMemory,
    streams: &Rc<AsyncMutex<Vec<AsyncMutex<StreamInfo<'_>>>>>,
    snd_data: &SndData,
    mut queue: Queue,
    mut queue_event: EventAsync,
    interrupt: &I,
    tx_send: mpsc::UnboundedSender<PcmResponse>,
    rx_send: mpsc::UnboundedSender<PcmResponse>,
    params: &Parameters,
) -> Result<(), Error> {
    loop {
        let desc_chain = queue
            .next_async(mem, &mut queue_event)
            .await
            .map_err(Error::Async)?;

        let index = desc_chain.index;

        let mut reader =
            Reader::new(mem.clone(), desc_chain.clone()).map_err(Error::DescriptorChain)?;
        let mut writer = Writer::new(mem.clone(), desc_chain).map_err(Error::DescriptorChain)?;
        // Don't advance the reader
        let code = reader
            .clone()
            .read_obj::<virtio_snd_hdr>()
            .map_err(Error::ReadMessage)?
            .code
            .into();

        let handle_ctrl_msg = async {
            return match code {
                VIRTIO_SND_R_JACK_INFO => {
                    let query_info: virtio_snd_query_info =
                        reader.read_obj().map_err(Error::ReadMessage)?;
                    let start_id: usize = u32::from(query_info.start_id) as usize;
                    let count: usize = u32::from(query_info.count) as usize;
                    if start_id + count > snd_data.jack_info.len() {
                        error!(
                            "start_id({}) + count({}) must be smaller than the number of jacks ({})",
                            start_id,
                            count,
                            snd_data.jack_info.len()
                        );
                        return writer
                            .write_obj(VIRTIO_SND_S_BAD_MSG)
                            .map_err(Error::WriteResponse);
                    }
                    // The response consists of the virtio_snd_hdr structure (contains the request
                    // status code), followed by the device-writable information structures of the
                    // item. Each information structure begins with the following common header
                    writer
                        .write_obj(VIRTIO_SND_S_OK)
                        .map_err(Error::WriteResponse)?;
                    for i in start_id..(start_id + count) {
                        writer
                            .write_all(snd_data.jack_info[i].as_slice())
                            .map_err(Error::WriteResponse)?;
                    }
                    Ok(())
                }
                VIRTIO_SND_R_PCM_INFO => {
                    let query_info: virtio_snd_query_info =
                        reader.read_obj().map_err(Error::ReadMessage)?;
                    let start_id: usize = u32::from(query_info.start_id) as usize;
                    let count: usize = u32::from(query_info.count) as usize;
                    if start_id + count > snd_data.pcm_info.len() {
                        error!(
                            "start_id({}) + count({}) must be smaller than the number of streams ({})",
                            start_id,
                            count,
                            snd_data.pcm_info.len()
                        );
                        return writer
                            .write_obj(VIRTIO_SND_S_BAD_MSG)
                            .map_err(Error::WriteResponse);
                    }
                    // The response consists of the virtio_snd_hdr structure (contains the request
                    // status code), followed by the device-writable information structures of the
                    // item. Each information structure begins with the following common header
                    writer
                        .write_obj(VIRTIO_SND_S_OK)
                        .map_err(Error::WriteResponse)?;
                    for i in start_id..(start_id + count) {
                        writer
                            .write_all(snd_data.pcm_info[i].as_slice())
                            .map_err(Error::WriteResponse)?;
                    }
                    Ok(())
                }
                VIRTIO_SND_R_CHMAP_INFO => {
                    let query_info: virtio_snd_query_info =
                        reader.read_obj().map_err(Error::ReadMessage)?;
                    let start_id: usize = u32::from(query_info.start_id) as usize;
                    let count: usize = u32::from(query_info.count) as usize;
                    if start_id + count > snd_data.chmap_info.len() {
                        error!(
                            "start_id({}) + count({}) must be smaller than the number of chmaps ({})",
                            start_id,
                            count,
                            snd_data.pcm_info.len()
                        );
                        return writer
                            .write_obj(VIRTIO_SND_S_BAD_MSG)
                            .map_err(Error::WriteResponse);
                    }
                    // The response consists of the virtio_snd_hdr structure (contains the request
                    // status code), followed by the device-writable information structures of the
                    // item. Each information structure begins with the following common header
                    writer
                        .write_obj(VIRTIO_SND_S_OK)
                        .map_err(Error::WriteResponse)?;
                    for i in start_id..(start_id + count) {
                        writer
                            .write_all(snd_data.chmap_info[i].as_slice())
                            .map_err(Error::WriteResponse)?;
                    }
                    Ok(())
                }
                VIRTIO_SND_R_JACK_REMAP => {
                    unreachable!("remap is unsupported");
                }
                VIRTIO_SND_R_PCM_SET_PARAMS => {
                    // Raise VIRTIO_SND_S_BAD_MSG or IO error?
                    let set_params: virtio_snd_pcm_set_params =
                        reader.read_obj().map_err(Error::ReadMessage)?;
                    let stream_id: usize = u32::from(set_params.hdr.stream_id) as usize;
                    let buffer_bytes: u32 = set_params.buffer_bytes.into();
                    let period_bytes: u32 = set_params.period_bytes.into();

                    let dir = match snd_data.pcm_info.get(stream_id) {
                        Some(pcm_info) => {
                            if set_params.channels < pcm_info.channels_min
                                || set_params.channels > pcm_info.channels_max
                            {
                                error!(
                                    "Number of channels ({}) must be between {} and {}",
                                    set_params.channels,
                                    pcm_info.channels_min,
                                    pcm_info.channels_max
                                );
                                return writer
                                    .write_obj(VIRTIO_SND_S_NOT_SUPP)
                                    .map_err(Error::WriteResponse);
                            }
                            if (u64::from(pcm_info.formats) & (1 << set_params.format)) == 0 {
                                error!("PCM format {} is not supported.", set_params.format);
                                return writer
                                    .write_obj(VIRTIO_SND_S_NOT_SUPP)
                                    .map_err(Error::WriteResponse);
                            }
                            if (u64::from(pcm_info.rates) & (1 << set_params.rate)) == 0 {
                                error!("PCM frame rate {} is not supported.", set_params.rate);
                                return writer
                                    .write_obj(VIRTIO_SND_S_NOT_SUPP)
                                    .map_err(Error::WriteResponse);
                            }

                            pcm_info.direction
                        }
                        None => {
                            error!(
                                "stream_id {} < streams {}",
                                stream_id,
                                snd_data.pcm_info.len()
                            );
                            return writer
                                .write_obj(VIRTIO_SND_S_BAD_MSG)
                                .map_err(Error::WriteResponse);
                        }
                    };

                    if set_params.features != 0 {
                        error!("No feature is supported");
                        return writer
                            .write_obj(VIRTIO_SND_S_NOT_SUPP)
                            .map_err(Error::WriteResponse);
                    }

                    if buffer_bytes % period_bytes != 0 {
                        error!(
                            "buffer_bytes({}) must be dividable by period_bytes({})",
                            buffer_bytes, period_bytes
                        );
                        return writer
                            .write_obj(VIRTIO_SND_S_BAD_MSG)
                            .map_err(Error::WriteResponse);
                    }

                    let streams = streams.read_lock().await;
                    let mut stream_info = match streams.get(stream_id) {
                        Some(stream_info) => stream_info.lock().await,
                        None => {
                            error!("stream_id {} < streams {}", stream_id, streams.len());
                            return writer
                                .write_obj(VIRTIO_SND_S_BAD_MSG)
                                .map_err(Error::WriteResponse);
                        }
                    };

                    if stream_info.state != 0
                        && stream_info.state != VIRTIO_SND_R_PCM_SET_PARAMS
                        && stream_info.state != VIRTIO_SND_R_PCM_PREPARE
                        && stream_info.state != VIRTIO_SND_R_PCM_RELEASE
                    {
                        error!(
                            "Invalid PCM state transition from {} to {}",
                            get_virtio_snd_r_pcm_cmd_name(stream_info.state),
                            get_virtio_snd_r_pcm_cmd_name(VIRTIO_SND_R_PCM_SET_PARAMS)
                        );
                        return writer
                            .write_obj(VIRTIO_SND_S_NOT_SUPP)
                            .map_err(Error::WriteResponse);
                    }

                    // Only required for PREPARE -> SET_PARAMS
                    stream_info.release_worker().await?;

                    stream_info.channels = set_params.channels;
                    stream_info.format = from_virtio_sample_format(set_params.format).unwrap();
                    stream_info.frame_rate = from_virtio_frame_rate(set_params.rate).unwrap();
                    stream_info.buffer_bytes = buffer_bytes as usize;
                    stream_info.period_bytes = period_bytes as usize;
                    stream_info.direction = dir;
                    stream_info.state = VIRTIO_SND_R_PCM_SET_PARAMS;

                    debug!(
                        "VIRTIO_SND_R_PCM_SET_PARAMS for stream id={}. Stream info: {:#?}",
                        stream_id, *stream_info
                    );

                    writer
                        .write_obj(VIRTIO_SND_S_OK)
                        .map_err(Error::WriteResponse)
                }
                VIRTIO_SND_R_PCM_PREPARE
                | VIRTIO_SND_R_PCM_START
                | VIRTIO_SND_R_PCM_STOP
                | VIRTIO_SND_R_PCM_RELEASE => {
                    let hdr: virtio_snd_pcm_hdr = reader.read_obj().map_err(Error::ReadMessage)?;
                    let stream_id: usize = u32::from(hdr.stream_id) as usize;
                    process_pcm_ctrl(
                        ex,
                        &mem.clone(),
                        &tx_send,
                        &rx_send,
                        streams,
                        params,
                        code,
                        &mut writer,
                        stream_id,
                    )
                    .await
                    .and(Ok(()))?;
                    Ok(())
                }
                c => {
                    error!("Unrecognized code: {}", c);
                    return writer
                        .write_obj(VIRTIO_SND_S_BAD_MSG)
                        .map_err(Error::WriteResponse);
                }
            };
        };

        handle_ctrl_msg.await?;
        queue.add_used(mem, index, writer.bytes_written() as u32);
        queue.trigger_interrupt(&mem, interrupt);
    }
}

/// Send events to the audio driver.
pub async fn handle_event_queue<I: SignalableInterrupt>(
    mem: &GuestMemory,
    mut queue: Queue,
    mut queue_event: EventAsync,
    interrupt: &I,
) -> Result<(), Error> {
    loop {
        let desc_chain = queue
            .next_async(mem, &mut queue_event)
            .await
            .map_err(Error::Async)?;

        // TODO(woodychow): Poll and forward events from cras asynchronously (API to be added)
        let index = desc_chain.index;
        queue.add_used(mem, index, 0);
        queue.trigger_interrupt(&mem, interrupt);
    }
}
