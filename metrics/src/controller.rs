// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Encapsulate the main runtime loop of a metrics process.

use anyhow::Result;
use base::info;
use base::warn;
use base::EventToken;
use base::Tube;

use crate::MetricsRequest;
use crate::RequestHandler;

/// Runs the metrics controller.
pub struct MetricsController {
    pub(crate) agents: Vec<Tube>,
    handler: RequestHandler,
    pub(crate) closed_tubes: usize,
}

#[derive(EventToken)]
pub(crate) enum MetricsControllerToken {
    /// Triggered when the agent's pipe is readable (e.g. read_notifier).
    Agent(usize),
    /// Triggered when the agent's pipe closes (e.g. close_notifier).
    #[cfg(windows)]
    AgentExited(usize),
}

impl MetricsController {
    pub fn new(agents: Vec<Tube>) -> Self {
        Self {
            agents,
            handler: RequestHandler::new(),
            closed_tubes: 0,
        }
    }

    /// Run the metrics controller until all clients exit & close their Tubes.
    pub fn run(&mut self) -> Result<()> {
        self.run_internal()?;
        self.handler.shutdown();
        Ok(())
    }

    /// Handles a tube that has indicated it has data ready to read.
    pub(crate) fn on_tube_readable(&self, client: &Tube) {
        match client.recv::<MetricsRequest>() {
            Ok(req) => self.handler.handle_request(req),
            Err(e) => {
                warn!("unexpected error receiving agent metrics request: {}", e)
            }
        }
    }

    /// Handles a closed connection, and returns a bool indicating
    /// whether the run loop itself should close.
    pub(crate) fn on_connection_closed(&mut self) -> bool {
        self.closed_tubes += 1;
        info!(
            "metrics tube closed: {} out of {} closed",
            self.closed_tubes,
            self.agents.len(),
        );
        if self.closed_tubes == self.agents.len() {
            info!("metrics run loop exiting: all tubes closed");
            return true;
        }

        false
    }
}
