// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::marker::PhantomData;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::Event;
use base::EventToken;
use base::ReadNotifier;
use base::Tube;
use base::WaitContext;
use serde::de::DeserializeOwned;
use sync::Mutex;
use winapi::shared::minwindef::UINT;

use super::thread_message_util;

/// A trait implemented by all variants of `MessageRelayThread`.
pub(crate) trait MessageRelayThreadTrait {}

/// When receiving a message from the given tube, this thread posts a thread message to the WndProc
/// thread. A pointer to the message from the tube will be sent as the lParam, and the WndProc
/// thread is responsible for destructing it.
pub(crate) struct MessageRelayThread<T: DeserializeOwned + 'static> {
    thread: Option<JoinHandle<()>>,
    exit_event: Event,
    _marker: PhantomData<T>,
}

impl<T: DeserializeOwned + 'static> MessageRelayThread<T> {
    /// # Safety
    /// Since this class posts messages to the WndProc thread, the instance of it must not be
    /// created before the message queue is created on the WndProc thread, and must not outlive the
    /// WndProc thread.
    pub unsafe fn start_thread(
        vm_tube: Arc<Mutex<Tube>>,
        wndproc_thread_id: u32,
        thread_message_id: UINT,
    ) -> Result<Box<dyn MessageRelayThreadTrait>> {
        let exit_event = Event::new().unwrap();
        let exit_event_clone = exit_event
            .try_clone()
            .map_err(|e| anyhow!("Failed to clone exit_event: {}", e))?;
        let thread = thread::Builder::new()
            .name("gpu_display_message_relay".into())
            .spawn(move || {
                Self::run_poll_loop(
                    vm_tube,
                    wndproc_thread_id,
                    thread_message_id,
                    exit_event_clone,
                );
            })
            .context("When spawning message relay thread")?;

        Ok(Box::new(Self {
            thread: Some(thread),
            exit_event,
            _marker: PhantomData,
        }))
    }

    fn run_poll_loop(
        vm_tube: Arc<Mutex<Tube>>,
        wndproc_thread_id: u32,
        thread_message_id: UINT,
        exit_event: Event,
    ) {
        #[derive(EventToken)]
        enum Token {
            Message,
            Exit,
        }

        let wait_ctx = WaitContext::build_with(&[
            (vm_tube.lock().get_read_notifier(), Token::Message),
            (&exit_event, Token::Exit),
        ])
        .unwrap();

        info!("Message relay thread entering poll loop");
        'poll: loop {
            let events = {
                match wait_ctx.wait() {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Failed to wait: {:?}", e);
                        break;
                    }
                }
            };

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::Message => match vm_tube.lock().recv::<T>() {
                        Ok(message) => {
                            Self::relay_message(wndproc_thread_id, thread_message_id, message);
                        }
                        Err(e) => error!("Failed to receive message through the tube: {:?}", e),
                    },
                    Token::Exit => {
                        break 'poll;
                    }
                }
            }
        }
        info!("Message relay thread exiting poll loop");
    }

    fn relay_message(wndproc_thread_id: u32, thread_message_id: UINT, message: T) {
        // Safe because the user of this class guarantees that the WndProc thread is alive and has
        // created the message queue.
        if let Err(e) = unsafe {
            thread_message_util::post_message_carrying_object(
                wndproc_thread_id,
                thread_message_id,
                message,
            )
        } {
            error!("Failed to relay message: {:?}", e);
        }
    }
}

impl<T: DeserializeOwned + 'static> Drop for MessageRelayThread<T> {
    fn drop(&mut self) {
        if let Err(e) = self.exit_event.signal() {
            error!("Failed to inform message relay thread to exit: {:?}", e);
            return;
        }
        if let Err(e) = self.thread.take().unwrap().join() {
            error!("Failed to join with the message relay thread: {:?}", e);
            return;
        }
        info!("Message relay thread exited gracefully");
    }
}

impl<T: DeserializeOwned + 'static> MessageRelayThreadTrait for MessageRelayThread<T> {}
