// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap as Map;
use std::path::PathBuf;

use mesa3d_util::AsBorrowedDescriptor;
use mesa3d_util::Listener;
use mesa3d_util::MesaError;
use mesa3d_util::WaitContext;
use mesa3d_util::WaitTimeout;

use crate::kumquat_gpu::KumquatGpu;
use crate::kumquat_gpu::KumquatGpuConnection;
use crate::kumquat_gpu::KumquatGpuResult;

enum KumquatConnection {
    GpuListener,
    GpuConnection(KumquatGpuConnection),
}

pub struct Kumquat {
    connection_id: u64,
    wait_ctx: WaitContext,
    kumquat_gpu_opt: Option<KumquatGpu>,
    gpu_listener_opt: Option<Listener>,
    connections: Map<u64, KumquatConnection>,
}

impl Kumquat {
    pub fn run(&mut self) -> KumquatGpuResult<()> {
        let events = self.wait_ctx.wait(WaitTimeout::NoTimeout)?;
        for event in events {
            let mut hung_up = false;
            match self.connections.entry(event.connection_id) {
                Entry::Occupied(mut o) => {
                    let connection = o.get_mut();
                    match connection {
                        KumquatConnection::GpuListener => {
                            if let Some(ref listener) = self.gpu_listener_opt {
                                let stream = listener.accept()?;
                                self.connection_id += 1;
                                let new_gpu_conn = KumquatGpuConnection::new(stream);
                                self.wait_ctx.add(
                                    self.connection_id,
                                    new_gpu_conn.as_borrowed_descriptor(),
                                )?;
                                self.connections.insert(
                                    self.connection_id,
                                    KumquatConnection::GpuConnection(new_gpu_conn),
                                );
                            }
                        }
                        KumquatConnection::GpuConnection(ref mut gpu_conn) => {
                            if event.readable {
                                if let Some(ref mut kumquat_gpu) = self.kumquat_gpu_opt {
                                    hung_up =
                                        !gpu_conn.process_command(kumquat_gpu)? && event.hung_up;
                                }
                            }

                            if hung_up {
                                self.wait_ctx.delete(gpu_conn.as_borrowed_descriptor())?;
                                o.remove_entry();
                            }
                        }
                    }
                }
                Entry::Vacant(_) => {
                    return Err(MesaError::WithContext("no connection found").into())
                }
            }
        }

        Ok(())
    }
}

pub struct KumquatBuilder {
    capset_names_opt: Option<String>,
    gpu_socket_opt: Option<String>,
    renderer_features_opt: Option<String>,
}

impl KumquatBuilder {
    pub fn new() -> KumquatBuilder {
        KumquatBuilder {
            capset_names_opt: None,
            gpu_socket_opt: None,
            renderer_features_opt: None,
        }
    }

    pub fn set_capset_names(mut self, capset_names: String) -> KumquatBuilder {
        self.capset_names_opt = Some(capset_names);
        self
    }

    pub fn set_gpu_socket(mut self, gpu_socket_opt: Option<String>) -> KumquatBuilder {
        self.gpu_socket_opt = gpu_socket_opt;
        self
    }

    pub fn set_renderer_features(mut self, renderer_features: String) -> KumquatBuilder {
        self.renderer_features_opt = Some(renderer_features);
        self
    }

    pub fn build(self) -> KumquatGpuResult<Kumquat> {
        let connection_id: u64 = 0;
        let mut wait_ctx = WaitContext::new()?;
        let mut kumquat_gpu_opt: Option<KumquatGpu> = None;
        let mut gpu_listener_opt: Option<Listener> = None;
        let mut connections: Map<u64, KumquatConnection> = Default::default();

        if let Some(gpu_socket) = self.gpu_socket_opt {
            // Remove path if it exists
            let path = PathBuf::from(&gpu_socket);
            let _ = std::fs::remove_file(&path);

            // Should not panic, since main.rs always calls set_capset_names and
            // set_renderer_features, even with the empty string.
            kumquat_gpu_opt = Some(KumquatGpu::new(
                self.capset_names_opt.unwrap(),
                self.renderer_features_opt.unwrap(),
            )?);

            let gpu_listener = Listener::bind(path)?;
            wait_ctx.add(connection_id, gpu_listener.as_borrowed_descriptor())?;
            connections.insert(connection_id, KumquatConnection::GpuListener);
            gpu_listener_opt = Some(gpu_listener);
        }

        Ok(Kumquat {
            connection_id,
            wait_ctx,
            kumquat_gpu_opt,
            gpu_listener_opt,
            connections,
        })
    }
}
