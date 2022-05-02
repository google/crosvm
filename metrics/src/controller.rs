// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Encapsulate the main runtime loop of a metrics process.

use crate::metrics_requests::MetricsRequest;
use crate::RequestHandler;
use anyhow::Result;
use base::{info, warn, CloseNotifier, PollToken, ReadNotifier, Tube, WaitContext};

/// Handles incoming requests to log metrics
pub(crate) trait MetricsRequestHandler {
    fn new() -> Self;
    fn handle_request(&self, request: MetricsRequest);
    fn shutdown(&self);
}

/// Runs the metrics controller.
pub struct MetricsController {
    agents: Vec<Tube>,
    handler: RequestHandler,
}

#[derive(PollToken)]
enum Token {
    /// Triggered when the agent's pipe is readable (e.g. read_notifier).
    Agent(usize),
    /// Triggered when the agent's pipe closes (e.g. close_notifier).
    AgentExited(usize),
}

impl MetricsController {
    pub fn new(agents: Vec<Tube>) -> Self {
        Self {
            agents,
            handler: RequestHandler::new(),
        }
    }

    /// Run the metrics controller until all clients exit & close their Tubes.
    pub fn run(&mut self) -> Result<()> {
        let wait_ctx: WaitContext<Token> = WaitContext::new()?;
        let mut closed_tubes = 0;

        for (agent_index, agent) in self.agents.iter().enumerate() {
            wait_ctx.add(agent.get_read_notifier(), Token::Agent(agent_index))?;
            wait_ctx.add(agent.get_close_notifier(), Token::AgentExited(agent_index))?;
        }

        'listen: loop {
            let events = wait_ctx.wait()?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::Agent(client_index) => {
                        let client = &self.agents[client_index];
                        match client.recv::<MetricsRequest>() {
                            Ok(req) => self.handler.handle_request(req),
                            Err(e) => {
                                warn!("unexpected error receiving agent metrics request: {}", e)
                            }
                        }
                    }
                    Token::AgentExited(client_index) => {
                        let client = &self.agents[client_index];
                        wait_ctx.delete(client.get_read_notifier())?;
                        wait_ctx.delete(client.get_close_notifier())?;
                        closed_tubes += 1;
                        info!(
                            "metrics tube closed: {} out of {} closed",
                            closed_tubes,
                            self.agents.len(),
                        );
                        if closed_tubes == self.agents.len() {
                            info!("metrics run loop exiting: all tubes closed");
                            break 'listen;
                        }
                    }
                }
            }
        }
        self.handler.shutdown();
        Ok(())
    }
}
