// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use base::info;
use base::warn;
#[cfg(windows)]
use base::CloseNotifier;
use base::Event;
use base::EventToken;
use base::EventType;
use base::ReadNotifier;
use base::WaitContext;
use sync::Mutex;
use vmm_vhost::BackendClient;
use vmm_vhost::Error as VhostError;

use crate::virtio::vhost_user_frontend::handler::BackendReqHandler;
use crate::virtio::Interrupt;
use crate::virtio::VIRTIO_MSI_NO_VECTOR;

pub struct Worker {
    pub kill_evt: Event,
    pub non_msix_evt: Event,
    pub backend_req_handler: Option<BackendReqHandler>,
    pub backend_client: Arc<Mutex<BackendClient>>,
}

impl Worker {
    pub fn run(&mut self, interrupt: Interrupt) -> anyhow::Result<()> {
        #[derive(EventToken)]
        enum Token {
            Kill,
            NonMsixEvt,
            Resample,
            ReqHandlerRead,
            ReqHandlerClose,
            // monitor whether backend_client_fd is broken
            BackendCloseNotify,
        }
        let wait_ctx = WaitContext::build_with(&[
            (&self.non_msix_evt, Token::NonMsixEvt),
            (&self.kill_evt, Token::Kill),
        ])
        .context("failed to build WaitContext")?;

        if let Some(resample_evt) = interrupt.get_resample_evt() {
            wait_ctx
                .add(resample_evt, Token::Resample)
                .context("failed to add resample event to WaitContext")?;
        }

        if let Some(backend_req_handler) = self.backend_req_handler.as_mut() {
            wait_ctx
                .add(
                    backend_req_handler.get_read_notifier(),
                    Token::ReqHandlerRead,
                )
                .context("failed to add backend req handler to WaitContext")?;

            #[cfg(any(target_os = "android", target_os = "linux"))]
            wait_ctx
                .add_for_event(
                    backend_req_handler.get_read_notifier(),
                    EventType::None, // only get hangup events from the close notifier
                    Token::ReqHandlerClose,
                )
                .context("failed to add backend req handler close notifier to WaitContext")?;
            #[cfg(target_os = "windows")]
            wait_ctx
                .add(
                    backend_req_handler.get_close_notifier(),
                    Token::ReqHandlerClose,
                )
                .context("failed to add backend req handler close notifier to WaitContext")?;
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        wait_ctx
            .add_for_event(
                self.backend_client.lock().get_read_notifier(),
                EventType::None,
                Token::BackendCloseNotify,
            )
            .context("failed to add backend client close notifier to WaitContext")?;
        #[cfg(target_os = "windows")]
        wait_ctx
            .add(
                self.backend_client.lock().get_close_notifier(),
                Token::BackendCloseNotify,
            )
            .context("failed to add backend client close notifier to WaitContext")?;

        'wait: loop {
            let events = wait_ctx.wait().context("WaitContext::wait() failed")?;
            for event in events {
                match event.token {
                    Token::Kill => {
                        break 'wait;
                    }
                    Token::NonMsixEvt => {
                        // The vhost-user protocol allows the backend to signal events, but for
                        // non-MSI-X devices, a device must also update the interrupt status mask.
                        // `non_msix_evt` proxies events from the vhost-user backend to update the
                        // status mask.
                        let _ = self.non_msix_evt.wait();

                        // The parameter vector of signal_used_queue is used only when msix is
                        // enabled.
                        interrupt.signal_used_queue(VIRTIO_MSI_NO_VECTOR);
                    }
                    Token::Resample => {
                        interrupt.interrupt_resample();
                    }
                    Token::ReqHandlerRead => {
                        let Some(backend_req_handler) = self.backend_req_handler.as_mut() else {
                            continue;
                        };

                        match backend_req_handler.handle_request() {
                            Ok(_) => (),
                            Err(VhostError::ClientExit) | Err(VhostError::Disconnect) => {
                                info!("backend req handler connection closed");
                                // Stop monitoring `backend_req_handler` as the client closed
                                // the connection.
                                let _ = wait_ctx.delete(backend_req_handler.get_read_notifier());
                                #[cfg(target_os = "windows")]
                                let _ = wait_ctx.delete(backend_req_handler.get_close_notifier());
                                self.backend_req_handler = None;
                            }
                            Err(e) => {
                                bail!("failed to handle a vhost-user request: {}", e);
                            }
                        }
                    }
                    Token::ReqHandlerClose => {
                        let Some(backend_req_handler) = self.backend_req_handler.as_mut() else {
                            continue;
                        };

                        info!("backend req handler connection closed");
                        let _ = wait_ctx.delete(backend_req_handler.get_read_notifier());
                        #[cfg(target_os = "windows")]
                        let _ = wait_ctx.delete(backend_req_handler.get_close_notifier());
                        self.backend_req_handler = None;
                    }
                    Token::BackendCloseNotify => {
                        // For linux domain socket, the close notifier fd is same with read/write
                        // notifier We need check whether the event is caused by socket broken.
                        #[cfg(any(target_os = "android", target_os = "linux"))]
                        if !event.is_hungup {
                            warn!("event besides hungup should not be notified");
                            continue;
                        }
                        panic!("Backend device disconnected");
                    }
                }
            }
        }

        Ok(())
    }
}
