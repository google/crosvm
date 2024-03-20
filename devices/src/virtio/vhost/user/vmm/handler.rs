// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub(super) mod sys;
pub(crate) mod worker;

use base::error;
use base::info;
use base::AsRawDescriptor;
use base::Protection;
use base::SafeDescriptor;
use hypervisor::MemCacheType;
use vm_control::VmMemorySource;
use vmm_vhost::message::VhostUserExternalMapMsg;
use vmm_vhost::message::VhostUserGpuMapMsg;
use vmm_vhost::message::VhostUserShmemMapMsg;
use vmm_vhost::message::VhostUserShmemUnmapMsg;
use vmm_vhost::Frontend;
use vmm_vhost::FrontendServer;
use vmm_vhost::HandlerResult;

use crate::virtio::Interrupt;
use crate::virtio::SharedMemoryMapper;

pub(crate) type BackendReqHandler = FrontendServer<BackendReqHandlerImpl>;

struct SharedMapperState {
    mapper: Box<dyn SharedMemoryMapper>,
    shmid: u8,
}

pub struct BackendReqHandlerImpl {
    interrupt: Option<Interrupt>,
    shared_mapper_state: Option<SharedMapperState>,
}

impl BackendReqHandlerImpl {
    pub(crate) fn new() -> Self {
        BackendReqHandlerImpl {
            interrupt: None,
            shared_mapper_state: None,
        }
    }

    pub(crate) fn set_interrupt(&mut self, interrupt: Interrupt) {
        self.interrupt = Some(interrupt);
    }

    pub(crate) fn set_shared_mapper_state(
        &mut self,
        mapper: Box<dyn SharedMemoryMapper>,
        shmid: u8,
    ) {
        self.shared_mapper_state = Some(SharedMapperState { mapper, shmid });
    }
}

impl Frontend for BackendReqHandlerImpl {
    fn shmem_map(
        &mut self,
        req: &VhostUserShmemMapMsg,
        fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        let shared_mapper_state = self
            .shared_mapper_state
            .as_mut()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        if req.shmid != shared_mapper_state.shmid {
            error!(
                "bad shmid {}, expected {}",
                req.shmid, shared_mapper_state.shmid
            );
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        match shared_mapper_state.mapper.add_mapping(
            VmMemorySource::Descriptor {
                descriptor: SafeDescriptor::try_from(fd)
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?,
                offset: req.fd_offset,
                size: req.len,
            },
            req.shm_offset,
            Protection::from(req.flags),
            MemCacheType::CacheCoherent,
        ) {
            Ok(()) => Ok(0),
            Err(e) => {
                error!("failed to create mapping {:?}", e);
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
        }
    }

    fn shmem_unmap(&mut self, req: &VhostUserShmemUnmapMsg) -> HandlerResult<u64> {
        let shared_mapper_state = self
            .shared_mapper_state
            .as_mut()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        if req.shmid != shared_mapper_state.shmid {
            error!(
                "bad shmid {}, expected {}",
                req.shmid, shared_mapper_state.shmid
            );
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        match shared_mapper_state.mapper.remove_mapping(req.shm_offset) {
            Ok(()) => Ok(0),
            Err(e) => {
                error!("failed to remove mapping {:?}", e);
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
        }
    }

    fn gpu_map(
        &mut self,
        req: &VhostUserGpuMapMsg,
        descriptor: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        let shared_mapper_state = self
            .shared_mapper_state
            .as_mut()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        if req.shmid != shared_mapper_state.shmid {
            error!(
                "bad shmid {}, expected {}",
                req.shmid, shared_mapper_state.shmid
            );
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        match shared_mapper_state.mapper.add_mapping(
            VmMemorySource::Vulkan {
                descriptor: SafeDescriptor::try_from(descriptor)
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?,
                handle_type: req.handle_type,
                memory_idx: req.memory_idx,
                device_uuid: req.device_uuid,
                driver_uuid: req.driver_uuid,
                size: req.len,
            },
            req.shm_offset,
            Protection::read_write(),
            MemCacheType::CacheCoherent,
        ) {
            Ok(()) => Ok(0),
            Err(e) => {
                error!("failed to create mapping {:?}", e);
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
        }
    }

    fn external_map(&mut self, req: &VhostUserExternalMapMsg) -> HandlerResult<u64> {
        let shared_mapper_state = self
            .shared_mapper_state
            .as_mut()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        if req.shmid != shared_mapper_state.shmid {
            error!(
                "bad shmid {}, expected {}",
                req.shmid, shared_mapper_state.shmid
            );
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        match shared_mapper_state.mapper.add_mapping(
            VmMemorySource::ExternalMapping {
                ptr: req.ptr,
                size: req.len,
            },
            req.shm_offset,
            Protection::read_write(),
            MemCacheType::CacheCoherent,
        ) {
            Ok(()) => Ok(0),
            Err(e) => {
                error!("failed to create mapping {:?}", e);
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
        }
    }

    fn handle_config_change(&mut self) -> HandlerResult<u64> {
        info!("Handle Config Change called");
        match &self.interrupt {
            Some(interrupt) => {
                interrupt.signal_config_changed();
                Ok(0)
            }
            None => {
                error!("cannot send interrupt");
                Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
            }
        }
    }
}
