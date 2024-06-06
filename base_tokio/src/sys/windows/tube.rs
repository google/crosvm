// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::warn;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Error;
use base::Event;
use base::Tube;
use base::TubeError;
use base::TubeResult;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use winapi::um::ioapiset::CancelIoEx;

/// An async version of `Tube`.
///
/// Implementation note: We don't trust `base::Tube::recv` to behave in a non-blocking manner even
/// when the read notifier is signalled, so we offload the actual `send` and `recv` calls onto a
/// blocking thread.
pub struct TubeTokio {
    worker: tokio::task::JoinHandle<Tube>,
    cmd_tx: mpsc::Sender<Box<dyn FnOnce(&Tube) + Send>>,
    // Clone of the tube's read notifier.
    read_notifier: Event,
    // Tube's RawDescriptor.
    tube_descriptor: Descriptor,
}

impl TubeTokio {
    pub fn new(mut tube: Tube) -> anyhow::Result<Self> {
        let read_notifier = tube.get_read_notifier_event().try_clone()?;
        let tube_descriptor = Descriptor(tube.as_raw_descriptor());

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Box<dyn FnOnce(&Tube) + Send>>(1);
        let worker = tokio::task::spawn_blocking(move || {
            while let Some(f) = cmd_rx.blocking_recv() {
                f(&mut tube)
            }
            tube
        });
        Ok(Self {
            worker,
            cmd_tx,
            read_notifier,
            tube_descriptor,
        })
    }

    pub async fn into_inner(self) -> Tube {
        drop(self.cmd_tx);

        // Attempt to cancel any blocking IO the worker thread is doing so that we don't get stuck
        // here if a `recv` call blocked. This is racy since we don't know if the queue'd up IO
        // requests have actually started yet.
        //
        // SAFETY: The descriptor should still be valid since we own the tube in the blocking task.
        if unsafe { CancelIoEx(self.tube_descriptor.0, std::ptr::null_mut()) } == 0 {
            warn!(
                "Cancel IO for handle:{:?} failed with {}",
                self.tube_descriptor.0,
                Error::last()
            );
        }

        self.worker.await.expect("failed to join tube worker")
    }

    pub async fn send<T: serde::Serialize + Send + 'static>(&mut self, msg: T) -> TubeResult<()> {
        // It is unlikely the tube is full given crosvm usage patterns, so request the blocking
        // send immediately.
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Box::new(move |tube| {
                let _ = tx.send(tube.send(&msg));
            }))
            .await
            .expect("worker missing");
        rx.await.map_err(|_| TubeError::OperationCancelled)??;
        Ok(())
    }

    pub async fn recv<T: serde::de::DeserializeOwned + Send + 'static>(&mut self) -> TubeResult<T> {
        // `Tube`'s read notifier event is a manual-reset event and `Tube::recv` wants to
        // handle the reset, so we bypass `EventAsync`.
        base::sys::windows::async_wait_for_single_object(&self.read_notifier)
            .await
            .map_err(TubeError::Recv)?;

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Box::new(move |tube| {
                let _ = tx.send(tube.recv());
            }))
            .await
            .expect("worker missing");
        rx.await.map_err(|_| TubeError::OperationCancelled)?
    }
}
