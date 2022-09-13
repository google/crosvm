// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Result;
use base::CloseNotifier;
use base::ReadNotifier;
use base::WaitContext;

use crate::controller::MetricsController;
use crate::controller::MetricsControllerToken;

impl MetricsController {
    pub(crate) fn run_internal(&mut self) -> Result<()> {
        let wait_ctx: WaitContext<MetricsControllerToken> = WaitContext::new()?;
        self.closed_tubes = 0;

        for (agent_index, agent) in self.agents.iter().enumerate() {
            wait_ctx.add(
                agent.get_read_notifier(),
                MetricsControllerToken::Agent(agent_index),
            )?;
            wait_ctx.add(
                agent.get_close_notifier(),
                MetricsControllerToken::AgentExited(agent_index),
            )?;
        }

        'listen: loop {
            let events = wait_ctx.wait()?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    MetricsControllerToken::Agent(client_index) => {
                        self.on_tube_readable(&self.agents[client_index]);
                    }
                    MetricsControllerToken::AgentExited(client_index) => {
                        let client = &self.agents[client_index];
                        wait_ctx.delete(client.get_read_notifier())?;
                        wait_ctx.delete(client.get_close_notifier())?;
                        if self.on_connection_closed() {
                            break 'listen;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
