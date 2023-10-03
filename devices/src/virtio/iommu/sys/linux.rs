// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod vfio_wrapper;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::rc::Rc;
use std::sync::Arc;

use base::error;
use base::MemoryMappingBuilder;
use base::TubeError;
use cros_async::AsyncTube;
use cros_async::Executor;
use hypervisor::MemSlot;
use sync::Mutex;
use vm_control::VirtioIOMMURequest;
use vm_control::VirtioIOMMUResponse;
use vm_control::VirtioIOMMUVfioCommand;
use vm_control::VirtioIOMMUVfioResult;

use self::vfio_wrapper::VfioWrapper;
use crate::virtio::iommu::ipc_memory_mapper::IommuRequest;
use crate::virtio::iommu::ipc_memory_mapper::IommuResponse;
use crate::virtio::iommu::DmabufRegionEntry;
use crate::virtio::iommu::Result;
use crate::virtio::iommu::State;
use crate::virtio::IommuError;
use crate::VfioContainer;

const VIRTIO_IOMMU_PAGE_SHIFT: u32 = 12;

impl State {
    pub(in crate::virtio::iommu) fn handle_add_vfio_device(
        &mut self,
        endpoint_addr: u32,
        wrapper: VfioWrapper,
    ) -> VirtioIOMMUVfioResult {
        let exists = |endpoint_addr: u32| -> bool {
            for endpoints_range in self.hp_endpoints_ranges.iter() {
                if endpoints_range.contains(&endpoint_addr) {
                    return true;
                }
            }
            false
        };

        if !exists(endpoint_addr) {
            return VirtioIOMMUVfioResult::NotInPCIRanges;
        }

        self.endpoints
            .insert(endpoint_addr, Arc::new(Mutex::new(Box::new(wrapper))));
        VirtioIOMMUVfioResult::Ok
    }

    pub(in crate::virtio::iommu) fn handle_del_vfio_device(
        &mut self,
        pci_address: u32,
    ) -> VirtioIOMMUVfioResult {
        if self.endpoints.remove(&pci_address).is_none() {
            error!("There is no vfio container of {}", pci_address);
            return VirtioIOMMUVfioResult::NoSuchDevice;
        }
        if let Some(domain) = self.endpoint_map.remove(&pci_address) {
            self.domain_map.remove(&domain);
        }
        VirtioIOMMUVfioResult::Ok
    }

    pub(in crate::virtio::iommu) fn handle_map_dmabuf(
        &mut self,
        mem_slot: MemSlot,
        gfn: u64,
        size: u64,
        dma_buf: File,
    ) -> VirtioIOMMUVfioResult {
        let mmap = match MemoryMappingBuilder::new(size as usize)
            .from_file(&dma_buf)
            .build()
        {
            Ok(v) => v,
            Err(_) => {
                error!("failed to mmap dma_buf");
                return VirtioIOMMUVfioResult::InvalidParam;
            }
        };
        self.dmabuf_mem.insert(
            gfn << VIRTIO_IOMMU_PAGE_SHIFT,
            DmabufRegionEntry {
                mmap,
                mem_slot,
                len: size,
            },
        );

        VirtioIOMMUVfioResult::Ok
    }

    pub(in crate::virtio::iommu) fn handle_unmap_dmabuf(
        &mut self,
        mem_slot: MemSlot,
    ) -> VirtioIOMMUVfioResult {
        if let Some(range) = self
            .dmabuf_mem
            .iter()
            .find(|(_, dmabuf_entry)| dmabuf_entry.mem_slot == mem_slot)
            .map(|entry| *entry.0)
        {
            self.dmabuf_mem.remove(&range);
            VirtioIOMMUVfioResult::Ok
        } else {
            VirtioIOMMUVfioResult::NoSuchMappedDmabuf
        }
    }

    pub(in crate::virtio::iommu) fn handle_vfio(
        &mut self,
        vfio_cmd: VirtioIOMMUVfioCommand,
    ) -> VirtioIOMMUResponse {
        use VirtioIOMMUVfioCommand::*;
        let vfio_result = match vfio_cmd {
            VfioDeviceAdd {
                wrapper_id,
                container,
                endpoint_addr,
            } => match VfioContainer::new_from_container(container) {
                Ok(vfio_container) => {
                    let wrapper =
                        VfioWrapper::new_with_id(vfio_container, wrapper_id, self.mem.clone());
                    self.handle_add_vfio_device(endpoint_addr, wrapper)
                }
                Err(e) => {
                    error!("failed to verify the new container: {}", e);
                    VirtioIOMMUVfioResult::NoAvailableContainer
                }
            },
            VfioDeviceDel { endpoint_addr } => self.handle_del_vfio_device(endpoint_addr),
            VfioDmabufMap {
                mem_slot,
                gfn,
                size,
                dma_buf,
            } => self.handle_map_dmabuf(mem_slot, gfn, size, File::from(dma_buf)),
            VfioDmabufUnmap(mem_slot) => self.handle_unmap_dmabuf(mem_slot),
        };
        VirtioIOMMUResponse::VfioResponse(vfio_result)
    }
}

pub(in crate::virtio::iommu) async fn handle_command_tube(
    state: &Rc<RefCell<State>>,
    command_tube: AsyncTube,
) -> Result<()> {
    loop {
        match command_tube.next::<VirtioIOMMURequest>().await {
            Ok(command) => {
                let response: VirtioIOMMUResponse = match command {
                    VirtioIOMMURequest::VfioCommand(vfio_cmd) => {
                        state.borrow_mut().handle_vfio(vfio_cmd)
                    }
                };
                if let Err(e) = command_tube.send(response).await {
                    error!("{}", IommuError::VirtioIOMMUResponseError(e));
                }
            }
            Err(e) => {
                return Err(IommuError::VirtioIOMMUReqError(e));
            }
        }
    }
}

pub(in crate::virtio::iommu) async fn handle_translate_request(
    ex: &Executor,
    state: &Rc<RefCell<State>>,
    request_tube: Option<AsyncTube>,
    response_tubes: Option<BTreeMap<u32, AsyncTube>>,
) -> Result<()> {
    let request_tube = match request_tube {
        Some(r) => r,
        None => {
            futures::future::pending::<()>().await;
            return Ok(());
        }
    };
    let response_tubes = response_tubes.unwrap();
    loop {
        let req: IommuRequest = match request_tube.next().await {
            Ok(req) => req,
            Err(TubeError::Disconnected) => {
                // This means the process on the other side of the tube went away. That's
                // not a problem with virtio-iommu itself, so just exit this callback
                // and wait for crosvm to exit.
                return Ok(());
            }
            Err(e) => {
                return Err(IommuError::Tube(e));
            }
        };
        let resp = if let Some(mapper) = state.borrow().endpoints.get(&req.get_endpoint_id()) {
            match req {
                IommuRequest::Export { iova, size, .. } => {
                    mapper.lock().export(iova, size).map(IommuResponse::Export)
                }
                IommuRequest::Release { iova, size, .. } => mapper
                    .lock()
                    .release(iova, size)
                    .map(|_| IommuResponse::Release),
                IommuRequest::StartExportSession { .. } => mapper
                    .lock()
                    .start_export_session(ex)
                    .map(IommuResponse::StartExportSession),
            }
        } else {
            error!("endpoint {} not found", req.get_endpoint_id());
            continue;
        };
        let resp: IommuResponse = match resp {
            Ok(resp) => resp,
            Err(e) => IommuResponse::Err(format!("{:?}", e)),
        };
        response_tubes
            .get(&req.get_endpoint_id())
            .unwrap()
            .send(resp)
            .await
            .map_err(IommuError::Tube)?;
    }
}
