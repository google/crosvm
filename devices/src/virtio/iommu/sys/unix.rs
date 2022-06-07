// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod vfio_wrapper;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use base::{error, TubeError};
use cros_async::AsyncTube;
use sync::Mutex;
use vm_control::{
    VirtioIOMMURequest, VirtioIOMMUResponse, VirtioIOMMUVfioCommand, VirtioIOMMUVfioResult,
};

use self::vfio_wrapper::VfioWrapper;

use crate::virtio::iommu::{MemRegion, Result, State, TranslateRequest};
use crate::virtio::IommuError;
use crate::VfioContainer;

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
    state: &Rc<RefCell<State>>,
    request_tube: Option<AsyncTube>,
    response_tubes: Option<BTreeMap<u32, AsyncTube>>,
) -> Result<()> {
    let request_tube = match request_tube {
        Some(r) => r,
        None => {
            let () = futures::future::pending().await;
            return Ok(());
        }
    };
    let response_tubes = response_tubes.unwrap();
    loop {
        let TranslateRequest {
            endpoint_id,
            iova,
            size,
        } = match request_tube.next().await {
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
        let translate_response: Option<Vec<MemRegion>> =
            if let Some(mapper) = state.borrow_mut().endpoints.get(&endpoint_id) {
                mapper
                    .lock()
                    .translate(iova, size)
                    .map_err(|e| {
                        error!("Failed to handle TranslateRequest: {}", e);
                        e
                    })
                    .ok()
            } else {
                error!("endpoint_id {} not found", endpoint_id);
                continue;
            };

        response_tubes
            .get(&endpoint_id)
            .unwrap()
            .send(translate_response)
            .await
            .map_err(IommuError::Tube)?;
    }
}
