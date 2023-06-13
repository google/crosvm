// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! vm_control API client for use within crosvm

use base::AsRawDescriptor;
use base::Event;
use base::Protection;
use base::RawDescriptor;
use base::Tube;
use base::TubeError;
use hypervisor::Datamatch;
use remain::sorted;
use resources::Alloc;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use vm_memory::GuestAddress;

use crate::IoEventUpdateRequest;
use crate::VmMemoryDestination;
use crate::VmMemoryRegionId;
use crate::VmMemoryRequest;
use crate::VmMemoryResponse;
use crate::VmMemorySource;

#[derive(Error, Debug)]
#[sorted]
pub enum ApiClientError {
    #[error("API client tube recv failed: {0}")]
    Recv(TubeError),
    #[error("Request failed: {0}")]
    RequestFailed(#[from] base::Error),
    #[error("API client tube send failed: {0}")]
    Send(TubeError),
    #[error("Unexpected tube response")]
    UnexpectedResponse,
}

pub type Result<T> = std::result::Result<T, ApiClientError>;

#[derive(Serialize, Deserialize)]
pub struct VmMemoryClient {
    tube: Tube,
}

impl VmMemoryClient {
    pub fn new(tube: Tube) -> Self {
        VmMemoryClient { tube }
    }

    fn request(&self, request: &VmMemoryRequest) -> Result<VmMemoryResponse> {
        self.tube.send(request).map_err(ApiClientError::Send)?;
        self.tube
            .recv::<VmMemoryResponse>()
            .map_err(ApiClientError::Recv)
    }

    fn request_unit(&self, request: &VmMemoryRequest) -> Result<()> {
        match self.request(request)? {
            VmMemoryResponse::Ok => Ok(()),
            VmMemoryResponse::Err(e) => Err(ApiClientError::RequestFailed(e)),
            _other => Err(ApiClientError::UnexpectedResponse),
        }
    }

    fn request_register_memory(&self, request: &VmMemoryRequest) -> Result<VmMemoryRegionId> {
        match self.request(request)? {
            VmMemoryResponse::Err(e) => Err(ApiClientError::RequestFailed(e)),
            VmMemoryResponse::RegisterMemory(region_id) => Ok(region_id),
            _other => Err(ApiClientError::UnexpectedResponse),
        }
    }

    /// Prepare a shared memory region to make later operations more efficient. This
    /// may be a no-op depending on underlying platform support.
    pub fn prepare_shared_memory_region(&self, alloc: Alloc) -> Result<()> {
        self.request_unit(&VmMemoryRequest::PrepareSharedMemoryRegion { alloc })
    }

    pub fn register_memory(
        &self,
        source: VmMemorySource,
        dest: VmMemoryDestination,
        prot: Protection,
    ) -> Result<VmMemoryRegionId> {
        self.request_register_memory(&VmMemoryRequest::RegisterMemory { source, dest, prot })
    }

    /// Call hypervisor to free the given memory range.
    pub fn dynamically_free_memory_range(
        &self,
        guest_address: GuestAddress,
        size: u64,
    ) -> Result<()> {
        self.request_unit(&VmMemoryRequest::DynamicallyFreeMemoryRange {
            guest_address,
            size,
        })
    }

    /// Call hypervisor to reclaim a priorly freed memory range.
    pub fn dynamically_reclaim_memory_range(
        &self,
        guest_address: GuestAddress,
        size: u64,
    ) -> Result<()> {
        self.request_unit(&VmMemoryRequest::DynamicallyReclaimMemoryRange {
            guest_address,
            size,
        })
    }

    /// Unregister the given memory slot that was previously registered with `RegisterMemory`.
    pub fn unregister_memory(&self, region: VmMemoryRegionId) -> Result<()> {
        self.request_unit(&VmMemoryRequest::UnregisterMemory(region))
    }

    /// Register an ioeventfd by looking up using Alloc info.
    pub fn register_io_event_with_alloc(
        &self,
        evt: Event,
        allocation: Alloc,
        offset: u64,
        datamatch: Datamatch,
    ) -> Result<()> {
        self.request_unit(&VmMemoryRequest::IoEventWithAlloc {
            evt,
            allocation,
            offset,
            datamatch,
            register: true,
        })
    }

    /// Unregister an eventfd by looking up using Alloc info.
    pub fn unregister_io_event_with_alloc(
        &self,
        evt: Event,
        allocation: Alloc,
        offset: u64,
        datamatch: Datamatch,
    ) -> Result<()> {
        self.request_unit(&VmMemoryRequest::IoEventWithAlloc {
            evt,
            allocation,
            offset,
            datamatch,
            register: false,
        })
    }

    /// Register an eventfd with raw guest memory address.
    pub fn register_io_event(&self, event: Event, addr: u64, datamatch: Datamatch) -> Result<()> {
        self.request_unit(&VmMemoryRequest::IoEventRaw(IoEventUpdateRequest {
            event,
            addr,
            datamatch,
            register: true,
        }))
    }

    /// Unregister an eventfd with raw guest memory address.
    pub fn unregister_io_event(&self, event: Event, addr: u64, datamatch: Datamatch) -> Result<()> {
        self.request_unit(&VmMemoryRequest::IoEventRaw(IoEventUpdateRequest {
            event,
            addr,
            datamatch,
            register: false,
        }))
    }

    pub fn balloon_target_reached(&self, size: u64) -> Result<()> {
        self.request_unit(&VmMemoryRequest::BalloonTargetReached { size })
    }
}

impl AsRawDescriptor for VmMemoryClient {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.tube.as_raw_descriptor()
    }
}
