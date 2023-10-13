// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Read;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;

use base::error;
use base::warn;
use base::Event;
use base::EventToken;
use base::WaitContext;
use data_model::Le32;
use sync::Mutex;
use zerocopy::AsBytes;

use super::super::constants::*;
use super::super::layout::*;
use super::streams::*;
use super::Result;
use super::SoundError;
use super::*;
use crate::virtio::DescriptorChain;
use crate::virtio::Interrupt;
use crate::virtio::Queue;

pub struct Worker {
    // Lock order: Must never hold more than one queue lock at the same time.
    interrupt: Interrupt,
    pub control_queue: Arc<Mutex<Queue>>,
    pub event_queue: Option<Queue>,
    vios_client: Arc<Mutex<VioSClient>>,
    streams: Vec<StreamProxy>,
    pub tx_queue: Arc<Mutex<Queue>>,
    pub rx_queue: Arc<Mutex<Queue>>,
    io_thread: Option<thread::JoinHandle<Result<()>>>,
    io_kill: Event,
    // saved_stream_state holds the previous state of streams. When the sound device is newly
    // created, this will be empty. It will only contain state if the sound device is put to sleep
    // OR if we restore a VM.
    pub saved_stream_state: Vec<StreamSnapshot>,
}

impl Worker {
    /// Creates a new virtio-snd worker.
    pub fn try_new(
        vios_client: Arc<Mutex<VioSClient>>,
        interrupt: Interrupt,
        control_queue: Arc<Mutex<Queue>>,
        event_queue: Queue,
        tx_queue: Arc<Mutex<Queue>>,
        rx_queue: Arc<Mutex<Queue>>,
        saved_stream_state: Vec<StreamSnapshot>,
    ) -> Result<Worker> {
        let num_streams = vios_client.lock().num_streams();
        let mut streams: Vec<StreamProxy> = Vec::with_capacity(num_streams as usize);
        {
            for stream_id in 0..num_streams {
                let capture = vios_client
                    .lock()
                    .stream_info(stream_id)
                    .map(|i| i.direction == VIRTIO_SND_D_INPUT)
                    .unwrap_or(false);
                let io_queue = if capture { &rx_queue } else { &tx_queue };
                streams.push(Stream::try_new(
                    stream_id,
                    vios_client.clone(),
                    interrupt.clone(),
                    control_queue.clone(),
                    io_queue.clone(),
                    capture,
                    saved_stream_state.get(stream_id as usize).cloned(),
                )?);
            }
        }
        let (self_kill_io, kill_io) = Event::new()
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(SoundError::CreateEvent)?;

        let interrupt_clone = interrupt.clone();
        let senders: Vec<Sender<Box<StreamMsg>>> =
            streams.iter().map(|sp| sp.msg_sender().clone()).collect();
        let tx_queue_thread = tx_queue.clone();
        let rx_queue_thread = rx_queue.clone();
        let io_thread = thread::Builder::new()
            .name("v_snd_io".to_string())
            .spawn(move || {
                try_set_real_time_priority();

                io_loop(
                    interrupt_clone,
                    tx_queue_thread,
                    rx_queue_thread,
                    senders,
                    kill_io,
                )
            })
            .map_err(SoundError::CreateThread)?;
        Ok(Worker {
            interrupt,
            control_queue,
            event_queue: Some(event_queue),
            vios_client,
            streams,
            tx_queue,
            rx_queue,
            io_thread: Some(io_thread),
            io_kill: self_kill_io,
            saved_stream_state: Vec::new(),
        })
    }

    /// Emulates the virtio-snd device. It won't return until something is written to the kill_evt
    /// event or an unrecoverable error occurs.
    pub fn control_loop(&mut self, kill_evt: Event) -> Result<()> {
        let event_notifier = self
            .vios_client
            .lock()
            .get_event_notifier()
            .map_err(SoundError::ClientEventNotifier)?;
        #[derive(EventToken)]
        enum Token {
            ControlQAvailable,
            EventQAvailable,
            InterruptResample,
            EventTriggered,
            Kill,
        }
        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (self.control_queue.lock().event(), Token::ControlQAvailable),
            (
                self.event_queue.as_ref().expect("queue missing").event(),
                Token::EventQAvailable,
            ),
            (&event_notifier, Token::EventTriggered),
            (&kill_evt, Token::Kill),
        ])
        .map_err(SoundError::WaitCtx)?;

        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .map_err(SoundError::WaitCtx)?;
        }
        let mut event_queue = self.event_queue.take().expect("event_queue missing");
        'wait: loop {
            let wait_events = wait_ctx.wait().map_err(SoundError::WaitCtx)?;

            for wait_evt in wait_events.iter().filter(|e| e.is_readable) {
                match wait_evt.token {
                    Token::ControlQAvailable => {
                        self.control_queue
                            .lock()
                            .event()
                            .wait()
                            .map_err(SoundError::QueueEvt)?;
                        self.process_controlq_buffers()?;
                    }
                    Token::EventQAvailable => {
                        // Just read from the event object to make sure the producer of such events
                        // never blocks. The buffers will only be used when actual virtio-snd
                        // events are triggered.
                        event_queue.event().wait().map_err(SoundError::QueueEvt)?;
                    }
                    Token::EventTriggered => {
                        event_notifier.wait().map_err(SoundError::QueueEvt)?;
                        self.process_event_triggered(&mut event_queue)?;
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => {
                        let _ = kill_evt.wait();
                        break 'wait;
                    }
                }
            }
        }
        self.saved_stream_state = self
            .streams
            .drain(..)
            .map(|stream| stream.stop_thread())
            .collect();
        self.event_queue = Some(event_queue);
        Ok(())
    }

    fn stop_io_thread(&mut self) {
        if let Err(e) = self.io_kill.signal() {
            error!(
                "virtio-snd: Failed to send Break msg to stream thread: {}",
                e
            );
        }
        if let Some(th) = self.io_thread.take() {
            match th.join() {
                Err(e) => {
                    error!("virtio-snd: Panic detected on stream thread: {:?}", e);
                }
                Ok(r) => {
                    if let Err(e) = r {
                        error!("virtio-snd: IO thread exited with and error: {}", e);
                    }
                }
            }
        }
    }

    // Pops and handles all available ontrol queue buffers. Logs minor errors, but returns an
    // Err if it encounters an unrecoverable error.
    fn process_controlq_buffers(&mut self) -> Result<()> {
        while let Some(mut avail_desc) = lock_pop_unlock(&self.control_queue) {
            let reader = &mut avail_desc.reader;
            let available_bytes = reader.available_bytes();
            if available_bytes < std::mem::size_of::<virtio_snd_hdr>() {
                error!(
                    "virtio-snd: Message received on control queue is too small: {}",
                    available_bytes
                );
                return reply_control_op_status(
                    VIRTIO_SND_S_BAD_MSG,
                    avail_desc,
                    &self.control_queue,
                    &self.interrupt,
                );
            }
            let mut read_buf = vec![0u8; available_bytes];
            reader
                .read_exact(&mut read_buf)
                .map_err(SoundError::QueueIO)?;
            let mut code: Le32 = Default::default();
            // need to copy because the buffer may not be properly aligned
            code.as_bytes_mut()
                .copy_from_slice(&read_buf[..std::mem::size_of::<Le32>()]);
            let request_type = code.to_native();
            match request_type {
                VIRTIO_SND_R_JACK_INFO => {
                    let (code, info_vec) = {
                        match self.parse_info_query(&read_buf) {
                            None => (VIRTIO_SND_S_BAD_MSG, Vec::new()),
                            Some((start_id, count)) => {
                                let end_id = start_id.saturating_add(count);
                                if end_id > self.vios_client.lock().num_jacks() {
                                    error!(
                                        "virtio-snd: Requested info on invalid jacks ids: {}..{}",
                                        start_id,
                                        end_id - 1
                                    );
                                    (VIRTIO_SND_S_NOT_SUPP, Vec::new())
                                } else {
                                    (
                                        VIRTIO_SND_S_OK,
                                        // Safe to unwrap because we just ensured all the ids are valid
                                        (start_id..end_id)
                                            .map(|id| {
                                                self.vios_client.lock().jack_info(id).unwrap()
                                            })
                                            .collect(),
                                    )
                                }
                            }
                        }
                    };
                    self.send_info_reply(avail_desc, code, info_vec)?;
                }
                VIRTIO_SND_R_JACK_REMAP => {
                    let code = if read_buf.len() != std::mem::size_of::<virtio_snd_jack_remap>() {
                        error!(
                        "virtio-snd: The driver sent the wrong number bytes for a jack_remap struct: {}",
                        read_buf.len()
                        );
                        VIRTIO_SND_S_BAD_MSG
                    } else {
                        let mut request: virtio_snd_jack_remap = Default::default();
                        request.as_bytes_mut().copy_from_slice(&read_buf);
                        let jack_id = request.hdr.jack_id.to_native();
                        let association = request.association.to_native();
                        let sequence = request.sequence.to_native();
                        if let Err(e) =
                            self.vios_client
                                .lock()
                                .remap_jack(jack_id, association, sequence)
                        {
                            error!("virtio-snd: Failed to remap jack: {}", e);
                            vios_error_to_status_code(e)
                        } else {
                            VIRTIO_SND_S_OK
                        }
                    };
                    let writer = &mut avail_desc.writer;
                    writer
                        .write_obj(virtio_snd_hdr {
                            code: Le32::from(code),
                        })
                        .map_err(SoundError::QueueIO)?;
                    let len = writer.bytes_written() as u32;
                    {
                        let mut queue_lock = self.control_queue.lock();
                        queue_lock.add_used(avail_desc, len);
                        queue_lock.trigger_interrupt(&self.interrupt);
                    }
                }
                VIRTIO_SND_R_CHMAP_INFO => {
                    let (code, info_vec) = {
                        match self.parse_info_query(&read_buf) {
                            None => (VIRTIO_SND_S_BAD_MSG, Vec::new()),
                            Some((start_id, count)) => {
                                let end_id = start_id.saturating_add(count);
                                let num_chmaps = self.vios_client.lock().num_chmaps();
                                if end_id > num_chmaps {
                                    error!(
                                        "virtio-snd: Requested info on invalid chmaps ids: {}..{}",
                                        start_id,
                                        end_id - 1
                                    );
                                    (VIRTIO_SND_S_NOT_SUPP, Vec::new())
                                } else {
                                    (
                                        VIRTIO_SND_S_OK,
                                        // Safe to unwrap because we just ensured all the ids are valid
                                        (start_id..end_id)
                                            .map(|id| {
                                                self.vios_client.lock().chmap_info(id).unwrap()
                                            })
                                            .collect(),
                                    )
                                }
                            }
                        }
                    };
                    self.send_info_reply(avail_desc, code, info_vec)?;
                }
                VIRTIO_SND_R_PCM_INFO => {
                    let (code, info_vec) = {
                        match self.parse_info_query(&read_buf) {
                            None => (VIRTIO_SND_S_BAD_MSG, Vec::new()),
                            Some((start_id, count)) => {
                                let end_id = start_id.saturating_add(count);
                                if end_id > self.vios_client.lock().num_streams() {
                                    error!(
                                        "virtio-snd: Requested info on invalid stream ids: {}..{}",
                                        start_id,
                                        end_id - 1
                                    );
                                    (VIRTIO_SND_S_NOT_SUPP, Vec::new())
                                } else {
                                    (
                                        VIRTIO_SND_S_OK,
                                        // Safe to unwrap because we just ensured all the ids are valid
                                        (start_id..end_id)
                                            .map(|id| {
                                                self.vios_client.lock().stream_info(id).unwrap()
                                            })
                                            .collect(),
                                    )
                                }
                            }
                        }
                    };
                    self.send_info_reply(avail_desc, code, info_vec)?;
                }
                VIRTIO_SND_R_PCM_SET_PARAMS => self.process_set_params(avail_desc, &read_buf)?,
                VIRTIO_SND_R_PCM_PREPARE => {
                    self.try_parse_pcm_hdr_and_send_msg(&read_buf, StreamMsg::Prepare(avail_desc))?
                }
                VIRTIO_SND_R_PCM_RELEASE => {
                    self.try_parse_pcm_hdr_and_send_msg(&read_buf, StreamMsg::Release(avail_desc))?
                }
                VIRTIO_SND_R_PCM_START => {
                    self.try_parse_pcm_hdr_and_send_msg(&read_buf, StreamMsg::Start(avail_desc))?
                }
                VIRTIO_SND_R_PCM_STOP => {
                    self.try_parse_pcm_hdr_and_send_msg(&read_buf, StreamMsg::Stop(avail_desc))?
                }
                _ => {
                    error!(
                        "virtio-snd: Unknown control queue mesage code: {}",
                        request_type
                    );
                    reply_control_op_status(
                        VIRTIO_SND_S_NOT_SUPP,
                        avail_desc,
                        &self.control_queue,
                        &self.interrupt,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn process_event_triggered(&mut self, event_queue: &mut Queue) -> Result<()> {
        while let Some(evt) = self.vios_client.lock().pop_event() {
            if let Some(mut desc) = event_queue.pop() {
                let writer = &mut desc.writer;
                writer.write_obj(evt).map_err(SoundError::QueueIO)?;
                let len = writer.bytes_written() as u32;
                event_queue.add_used(desc, len);
                event_queue.trigger_interrupt(&self.interrupt);
            } else {
                warn!("virtio-snd: Dropping event because there are no buffers in virtqueue");
            }
        }
        Ok(())
    }

    fn parse_info_query(&mut self, read_buf: &[u8]) -> Option<(u32, u32)> {
        if read_buf.len() != std::mem::size_of::<virtio_snd_query_info>() {
            error!(
                "virtio-snd: The driver sent the wrong number bytes for a pcm_info struct: {}",
                read_buf.len()
            );
            return None;
        }
        let mut query: virtio_snd_query_info = Default::default();
        query.as_bytes_mut().copy_from_slice(read_buf);
        let start_id = query.start_id.to_native();
        let count = query.count.to_native();
        Some((start_id, count))
    }

    // Returns Err if it encounters an unrecoverable error, Ok otherwise
    fn process_set_params(&mut self, desc: DescriptorChain, read_buf: &[u8]) -> Result<()> {
        if read_buf.len() != std::mem::size_of::<virtio_snd_pcm_set_params>() {
            error!(
                "virtio-snd: The driver sent a buffer of the wrong size for a set_params struct: {}",
                read_buf.len()
                );
            return reply_control_op_status(
                VIRTIO_SND_S_BAD_MSG,
                desc,
                &self.control_queue,
                &self.interrupt,
            );
        }
        let mut params: virtio_snd_pcm_set_params = Default::default();
        params.as_bytes_mut().copy_from_slice(read_buf);
        let stream_id = params.hdr.stream_id.to_native();
        if stream_id < self.vios_client.lock().num_streams() {
            self.streams[stream_id as usize].send(StreamMsg::SetParams(desc, params))
        } else {
            error!(
                "virtio-snd: Driver requested operation on invalid stream: {}",
                stream_id
            );
            reply_control_op_status(
                VIRTIO_SND_S_BAD_MSG,
                desc,
                &self.control_queue,
                &self.interrupt,
            )
        }
    }

    // Returns Err if it encounters an unrecoverable error, Ok otherwise
    fn try_parse_pcm_hdr_and_send_msg(&mut self, read_buf: &[u8], msg: StreamMsg) -> Result<()> {
        if read_buf.len() != std::mem::size_of::<virtio_snd_pcm_hdr>() {
            error!(
                "virtio-snd: The driver sent a buffer too small to contain a header: {}",
                read_buf.len()
            );
            return reply_control_op_status(
                VIRTIO_SND_S_BAD_MSG,
                match msg {
                    StreamMsg::Prepare(d)
                    | StreamMsg::Start(d)
                    | StreamMsg::Stop(d)
                    | StreamMsg::Release(d) => d,
                    _ => panic!("virtio-snd: Can't handle message. This is a BUG!!"),
                },
                &self.control_queue,
                &self.interrupt,
            );
        }
        let mut pcm_hdr: virtio_snd_pcm_hdr = Default::default();
        pcm_hdr.as_bytes_mut().copy_from_slice(read_buf);
        let stream_id = pcm_hdr.stream_id.to_native();
        if stream_id < self.vios_client.lock().num_streams() {
            self.streams[stream_id as usize].send(msg)
        } else {
            error!(
                "virtio-snd: Driver requested operation on invalid stream: {}",
                stream_id
            );
            reply_control_op_status(
                VIRTIO_SND_S_BAD_MSG,
                match msg {
                    StreamMsg::Prepare(d)
                    | StreamMsg::Start(d)
                    | StreamMsg::Stop(d)
                    | StreamMsg::Release(d) => d,
                    _ => panic!("virtio-snd: Can't handle message. This is a BUG!!"),
                },
                &self.control_queue,
                &self.interrupt,
            )
        }
    }

    fn send_info_reply<T: AsBytes>(
        &mut self,
        mut desc: DescriptorChain,
        code: u32,
        info_vec: Vec<T>,
    ) -> Result<()> {
        let writer = &mut desc.writer;
        writer
            .write_obj(virtio_snd_hdr {
                code: Le32::from(code),
            })
            .map_err(SoundError::QueueIO)?;
        for info in info_vec {
            writer.write_obj(info).map_err(SoundError::QueueIO)?;
        }
        let len = writer.bytes_written() as u32;
        {
            let mut queue_lock = self.control_queue.lock();
            queue_lock.add_used(desc, len);
            queue_lock.trigger_interrupt(&self.interrupt);
        }
        Ok(())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop_io_thread();
    }
}

fn io_loop(
    interrupt: Interrupt,
    tx_queue: Arc<Mutex<Queue>>,
    rx_queue: Arc<Mutex<Queue>>,
    senders: Vec<Sender<Box<StreamMsg>>>,
    kill_evt: Event,
) -> Result<()> {
    #[derive(EventToken)]
    enum Token {
        TxQAvailable,
        RxQAvailable,
        Kill,
    }
    let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
        (tx_queue.lock().event(), Token::TxQAvailable),
        (rx_queue.lock().event(), Token::RxQAvailable),
        (&kill_evt, Token::Kill),
    ])
    .map_err(SoundError::WaitCtx)?;

    'wait: loop {
        let wait_events = wait_ctx.wait().map_err(SoundError::WaitCtx)?;
        for wait_evt in wait_events.iter().filter(|e| e.is_readable) {
            let queue = match wait_evt.token {
                Token::TxQAvailable => {
                    tx_queue
                        .lock()
                        .event()
                        .wait()
                        .map_err(SoundError::QueueEvt)?;
                    &tx_queue
                }
                Token::RxQAvailable => {
                    rx_queue
                        .lock()
                        .event()
                        .wait()
                        .map_err(SoundError::QueueEvt)?;
                    &rx_queue
                }
                Token::Kill => {
                    let _ = kill_evt.wait();
                    break 'wait;
                }
            };
            while let Some(mut avail_desc) = lock_pop_unlock(queue) {
                let reader = &mut avail_desc.reader;
                let xfer: virtio_snd_pcm_xfer = reader.read_obj().map_err(SoundError::QueueIO)?;
                let stream_id = xfer.stream_id.to_native();
                if stream_id as usize >= senders.len() {
                    error!(
                        "virtio-snd: Driver sent buffer for invalid stream: {}",
                        stream_id
                    );
                    reply_pcm_buffer_status(VIRTIO_SND_S_IO_ERR, 0, avail_desc, queue, &interrupt)?;
                } else {
                    StreamProxy::send_msg(
                        &senders[stream_id as usize],
                        StreamMsg::Buffer(avail_desc),
                    )?;
                }
            }
        }
    }
    Ok(())
}

// If queue.lock().pop() is used directly in the condition of a 'while' loop the lock is held over
// the entire loop block. Encapsulating it in this fuction guarantees that the lock is dropped
// immediately after pop() is called, which allows the code to remain somewhat simpler.
fn lock_pop_unlock(queue: &Arc<Mutex<Queue>>) -> Option<DescriptorChain> {
    queue.lock().pop()
}
