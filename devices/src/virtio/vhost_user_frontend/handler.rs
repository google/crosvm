// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::bail;
use anyhow::Context;
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
    ) -> anyhow::Result<()> {
        let shared_mapper_state = self
            .shared_mapper_state
            .as_mut()
            .context("shared mapper state not set")?;
        if req.shmid != shared_mapper_state.shmid {
            bail!(
                "bad shmid {}, expected {}",
                req.shmid,
                shared_mapper_state.shmid
            );
        }
        shared_mapper_state
            .mapper
            .add_mapping(
                VmMemorySource::Descriptor {
                    descriptor: SafeDescriptor::try_from(fd)
                        .map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?,
                    offset: req.fd_offset,
                    size: req.len,
                },
                req.shm_offset,
                Protection::from(req.flags),
                MemCacheType::CacheCoherent,
            )
            .context("failed to add descriptor mapping")
    }

    fn shmem_unmap(&mut self, req: &VhostUserShmemUnmapMsg) -> anyhow::Result<()> {
        let shared_mapper_state = self
            .shared_mapper_state
            .as_mut()
            .context("shared mapper state not set")?;
        if req.shmid != shared_mapper_state.shmid {
            bail!(
                "bad shmid {}, expected {}",
                req.shmid,
                shared_mapper_state.shmid
            );
        }
        shared_mapper_state
            .mapper
            .remove_mapping(req.shm_offset)
            .context("failed to remove mapping based on shm offset")
    }

    fn gpu_map(
        &mut self,
        req: &VhostUserGpuMapMsg,
        descriptor: &dyn AsRawDescriptor,
    ) -> anyhow::Result<()> {
        let shared_mapper_state = self
            .shared_mapper_state
            .as_mut()
            .context("shared mapper state not set")?;
        if req.shmid != shared_mapper_state.shmid {
            bail!(
                "bad shmid {}, expected {}",
                req.shmid,
                shared_mapper_state.shmid
            );
        }
        shared_mapper_state
            .mapper
            .add_mapping(
                VmMemorySource::Vulkan {
                    descriptor: SafeDescriptor::try_from(descriptor)
                        .context("failed to clone descriptor")?,
                    handle_type: req.handle_type,
                    memory_idx: req.memory_idx,
                    device_uuid: req.device_uuid,
                    driver_uuid: req.driver_uuid,
                    size: req.len,
                },
                req.shm_offset,
                Protection::read_write(),
                MemCacheType::CacheCoherent,
            )
            .context("failed to add Vulkan source mapping")
    }

    fn external_map(&mut self, req: &VhostUserExternalMapMsg) -> anyhow::Result<()> {
        let shared_mapper_state = self
            .shared_mapper_state
            .as_mut()
            .context("shared mapper state not set")?;
        if req.shmid != shared_mapper_state.shmid {
            bail!(
                "bad shmid {}, expected {}",
                req.shmid,
                shared_mapper_state.shmid
            );
        }
        shared_mapper_state
            .mapper
            .add_mapping(
                VmMemorySource::ExternalMapping {
                    ptr: req.ptr,
                    size: req.len,
                },
                req.shm_offset,
                Protection::read_write(),
                MemCacheType::CacheCoherent,
            )
            .context("failed to add external mapping")
    }

    fn handle_config_change(&mut self) -> anyhow::Result<()> {
        info!("Handle Config Change called");
        match &self.interrupt {
            Some(interrupt) => {
                interrupt.signal_config_changed();
                Ok(())
            }
            None => bail!("cannot send interrupt"),
        }
    }
}
