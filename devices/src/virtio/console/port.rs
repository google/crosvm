// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio console device per-port functionality.

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::Context;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Event;
use base::RawDescriptor;
use base::WorkerThread;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;

use crate::serial::sys::InStreamType;
use crate::virtio::console::sys::spawn_input_thread;

/// Each port info for multi-port virtio-console
#[derive(Clone, Debug)]
pub struct ConsolePortInfo {
    pub console: bool,
    pub name: Option<String>,
}

impl ConsolePortInfo {
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

pub struct ConsolePort {
    pub(crate) input: Option<InStreamType>,
    pub(crate) output: Option<Box<dyn std::io::Write + Send>>,

    info: Option<ConsolePortInfo>,

    // input_buffer is shared with the input_thread while it is running.
    input_buffer: Arc<Mutex<VecDeque<u8>>>,

    // `in_avail_evt` will be signaled by the input thread to notify the worker when new input is
    // available in `input_buffer`.
    in_avail_evt: Event,

    input_thread: Option<WorkerThread<InStreamType>>,

    keep_descriptors: Vec<Descriptor>,
}

#[derive(Serialize, Deserialize)]
pub struct ConsolePortSnapshot {
    input_buffer: Vec<u8>,
}

impl ConsolePort {
    pub fn new(
        input: Option<InStreamType>,
        output: Option<Box<dyn std::io::Write + Send>>,
        info: Option<ConsolePortInfo>,
        mut keep_rds: Vec<RawDescriptor>,
    ) -> Self {
        let input_buffer = Arc::new(Mutex::new(VecDeque::new()));
        let in_avail_evt = Event::new().expect("Event::new() failed");
        keep_rds.push(in_avail_evt.as_raw_descriptor());
        ConsolePort {
            input,
            output,
            info,
            input_buffer,
            in_avail_evt,
            input_thread: None,
            keep_descriptors: keep_rds.iter().map(|rd| Descriptor(*rd)).collect(),
        }
    }

    pub fn clone_in_avail_evt(&self) -> anyhow::Result<Event> {
        self.in_avail_evt
            .try_clone()
            .context("clone_in_avail_evt failed")
    }

    pub fn clone_input_buffer(&self) -> Arc<Mutex<VecDeque<u8>>> {
        self.input_buffer.clone()
    }

    pub fn take_output(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        self.output.take()
    }

    pub fn restore_output(&mut self, output: Box<dyn std::io::Write + Send>) {
        self.output = Some(output);
    }

    pub fn port_info(&self) -> Option<&ConsolePortInfo> {
        self.info.as_ref()
    }

    pub fn start_input_thread(&mut self) {
        // Spawn a separate thread to poll input.
        // A thread is used because io::Read only provides a blocking interface, and there is no
        // generic way to add an io::Read instance to a poll context (it may not be backed by a
        // file descriptor).  Moving the blocking read call to a separate thread and
        // sending data back to the main worker thread with an event for
        // notification bridges this gap.
        if let Some(input) = self.input.take() {
            assert!(self.input_thread.is_none());

            let thread_in_avail_evt = self
                .clone_in_avail_evt()
                .expect("failed creating input available Event pair");

            let thread = spawn_input_thread(input, thread_in_avail_evt, self.input_buffer.clone());
            self.input_thread = Some(thread);
        }
    }

    pub fn stop_input_thread(&mut self) {
        if let Some(input_thread) = self.input_thread.take() {
            let input = input_thread.stop();
            self.input = Some(input);
        }
    }

    pub fn snapshot(&mut self) -> ConsolePortSnapshot {
        // This is only guaranteed to return a consistent state while the input thread is stopped.
        self.stop_input_thread();
        let input_buffer = self.input_buffer.lock().iter().copied().collect();
        self.start_input_thread();
        ConsolePortSnapshot { input_buffer }
    }

    pub fn restore(&mut self, snap: &ConsolePortSnapshot) {
        self.stop_input_thread();

        // Set the input buffer, discarding any currently buffered data.
        let mut input_buffer = self.input_buffer.lock();
        input_buffer.clear();
        input_buffer.extend(snap.input_buffer.iter());
        drop(input_buffer);

        self.start_input_thread();
    }

    pub fn keep_rds(&self) -> Vec<RawDescriptor> {
        self.keep_descriptors
            .iter()
            .map(|descr| descr.as_raw_descriptor())
            .collect()
    }
}
