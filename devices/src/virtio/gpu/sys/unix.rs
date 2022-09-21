// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Context;
use base::error;
use base::AsRawDescriptor;
use base::RawDescriptor;
use base::Tube;
use base::WaitContext;
use serde::Deserialize;
use serde::Serialize;

use crate::virtio::gpu::parameters::DisplayModeTrait;
use crate::virtio::gpu::Frontend;
use crate::virtio::gpu::ResourceBridgesTrait;
use crate::virtio::gpu::WorkerToken;
use crate::virtio::resource_bridge::ResourceRequest;
use crate::virtio::resource_bridge::ResourceResponse;

// This struct is only used for argument parsing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixDisplayModeArg {
    Windowed,
}

#[derive(Clone, Debug)]
pub enum UnixDisplayMode {
    Windowed { width: u32, height: u32 },
}

impl DisplayModeTrait for UnixDisplayMode {
    fn get_virtual_display_size(&self) -> (u32, u32) {
        match self {
            Self::Windowed { width, height, .. } => (*width, *height),
        }
    }
}

/// Trait for Unix-specific methods of `Frontend`.
pub trait UnixFrontendExt {
    /// Processes incoming requests on `resource_bridge`.
    fn process_resource_bridge(&mut self, _resource_bridge: &Tube) -> anyhow::Result<()>;
}

impl UnixFrontendExt for Frontend {
    fn process_resource_bridge(&mut self, resource_bridge: &Tube) -> anyhow::Result<()> {
        let response = match resource_bridge.recv() {
            Ok(ResourceRequest::GetBuffer { id }) => self.virtio_gpu.export_resource(id),
            Ok(ResourceRequest::GetFence { seqno }) => {
                // The seqno originated from self.backend, so it should fit in a u32.
                match u32::try_from(seqno) {
                    Ok(fence_id) => self.virtio_gpu.export_fence(fence_id),
                    Err(_) => ResourceResponse::Invalid,
                }
            }
            Err(e) => return Err(e).context("Error receiving resource bridge request"),
        };

        resource_bridge
            .send(&response)
            .context("Error sending resource bridge response")?;

        Ok(())
    }
}

/// This struct takes the ownership of resource bridges and tracks which ones should be processed.
pub(crate) struct UnixResourceBridges {
    resource_bridges: Vec<Tube>,
    should_process: Vec<bool>,
}

impl UnixResourceBridges {
    pub fn new(resource_bridges: Vec<Tube>) -> Self {
        let mut resource_bridges = Self {
            resource_bridges,
            should_process: Default::default(),
        };
        resource_bridges.reset_should_process();
        resource_bridges
    }

    fn reset_should_process(&mut self) {
        self.should_process.clear();
        self.should_process
            .resize(self.resource_bridges.len(), false);
    }
}

impl ResourceBridgesTrait for UnixResourceBridges {
    fn append_raw_descriptors(&self, rds: &mut Vec<RawDescriptor>) {
        for bridge in &self.resource_bridges {
            rds.push(bridge.as_raw_descriptor());
        }
    }

    fn add_to_wait_context(&self, wait_ctx: &mut WaitContext<WorkerToken>) {
        for (index, bridge) in self.resource_bridges.iter().enumerate() {
            if let Err(e) = wait_ctx.add(bridge, WorkerToken::ResourceBridge { index }) {
                error!("failed to add resource bridge to WaitContext: {}", e);
            }
        }
    }

    fn set_should_process(&mut self, index: usize) {
        self.should_process[index] = true;
    }

    fn process_resource_bridges(
        &mut self,
        state: &mut Frontend,
        wait_ctx: &mut WaitContext<WorkerToken>,
    ) {
        for (bridge, &should_process) in self.resource_bridges.iter().zip(&self.should_process) {
            if should_process {
                if let Err(e) = state.process_resource_bridge(bridge) {
                    error!("Failed to process resource bridge: {:#}", e);
                    error!("Removing that resource bridge from the wait context.");
                    wait_ctx.delete(bridge).unwrap_or_else(|e| {
                        error!("Failed to remove faulty resource bridge: {:#}", e)
                    });
                }
            }
        }
        self.reset_should_process();
    }
}
