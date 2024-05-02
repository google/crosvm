// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap as Map;

use rutabaga_gfx::RutabagaError;
use rutabaga_gfx::RutabagaResult;
use rutabaga_gfx::RutabagaWaitContext;

use crate::kumquat_gpu::KumquatGpu;
use crate::kumquat_gpu::KumquatGpuConnection;

pub struct Kumquat {
    kumquat_gpu: KumquatGpu,
    wait_ctx: RutabagaWaitContext,
    connections: Map<u64, KumquatGpuConnection>,
}

impl Kumquat {
    pub fn new(capset_names: String) -> RutabagaResult<Kumquat> {
        Ok(Kumquat {
            kumquat_gpu: KumquatGpu::new(capset_names)?,
            wait_ctx: RutabagaWaitContext::new()?,
            connections: Default::default(),
        })
    }

    pub fn add_connection(
        &mut self,
        connection_id: u64,
        connection: KumquatGpuConnection,
    ) -> RutabagaResult<()> {
        let _ = self.wait_ctx.add(connection_id, &connection);
        self.connections.insert(connection_id, connection);
        Ok(())
    }

    pub fn run(&mut self) -> RutabagaResult<()> {
        if self.connections.is_empty() {
            return Ok(());
        }

        let events = self.wait_ctx.wait()?;
        for event in events {
            let mut hung_up = false;
            match self.connections.entry(event.connection_id) {
                Entry::Occupied(mut o) => {
                    let connection = o.get_mut();
                    if event.readable {
                        hung_up =
                            !connection.process_command(&mut self.kumquat_gpu)? && event.hung_up;
                    }

                    if hung_up {
                        self.wait_ctx.delete(&connection)?;
                        o.remove_entry();
                    }
                }
                Entry::Vacant(_) => {
                    return Err(RutabagaError::SpecViolation("no connection found"))
                }
            }
        }

        Ok(())
    }
}
