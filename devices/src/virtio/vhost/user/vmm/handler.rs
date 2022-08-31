// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod sys;
mod worker;

use std::sync::Mutex;
use std::thread;

use base::error;
use base::AsRawDescriptor;
use base::Event;
use base::Protection;
use base::SafeDescriptor;
use vm_control::VmMemorySource;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserConfigFlags;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserShmemMapMsg;
use vmm_vhost::message::VhostUserShmemUnmapMsg;
use vmm_vhost::message::VhostUserVirtioFeatures;
use vmm_vhost::HandlerResult;
use vmm_vhost::MasterReqHandler;
use vmm_vhost::VhostBackend;
use vmm_vhost::VhostUserMaster;
use vmm_vhost::VhostUserMasterReqHandlerMut;
use vmm_vhost::VhostUserMemoryRegionInfo;
use vmm_vhost::VringConfigData;

use crate::virtio::vhost::user::vmm::handler::sys::SocketMaster;
use crate::virtio::vhost::user::vmm::Error;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::SharedMemoryMapper;
use crate::virtio::SharedMemoryRegion;

type BackendReqHandler = MasterReqHandler<Mutex<BackendReqHandlerImpl>>;

fn set_features(vu: &mut SocketMaster, avail_features: u64, ack_features: u64) -> Result<u64> {
    let features = avail_features & ack_features;
    vu.set_features(features).map_err(Error::SetFeatures)?;
    Ok(features)
}

pub struct VhostUserHandler {
    vu: SocketMaster,
    pub avail_features: u64,
    acked_features: u64,
    protocol_features: VhostUserProtocolFeatures,
    backend_req_handler: Option<BackendReqHandler>,
    // Shared memory region info. IPC result from backend is saved with outer Option.
    shmem_region: Option<Option<SharedMemoryRegion>>,
    // On Windows, we need a backend pid to support backend requests.
    #[cfg(windows)]
    backend_pid: Option<u32>,
}

impl VhostUserHandler {
    /// Creates a `VhostUserHandler` instance with features and protocol features initialized.
    fn new(
        mut vu: SocketMaster,
        allow_features: u64,
        init_features: u64,
        allow_protocol_features: VhostUserProtocolFeatures,
        #[cfg(windows)] backend_pid: Option<u32>,
    ) -> Result<Self> {
        vu.set_owner().map_err(Error::SetOwner)?;

        let avail_features = allow_features & vu.get_features().map_err(Error::GetFeatures)?;
        let acked_features = set_features(&mut vu, avail_features, init_features)?;

        let mut protocol_features = VhostUserProtocolFeatures::empty();
        if acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            let avail_protocol_features = vu
                .get_protocol_features()
                .map_err(Error::GetProtocolFeatures)?;
            protocol_features = allow_protocol_features & avail_protocol_features;
            vu.set_protocol_features(protocol_features)
                .map_err(Error::SetProtocolFeatures)?;
        }

        Ok(VhostUserHandler {
            vu,
            avail_features,
            acked_features,
            protocol_features,
            backend_req_handler: None,
            shmem_region: None,
            #[cfg(windows)]
            backend_pid,
        })
    }

    /// Returns a vector of sizes of each queue.
    pub fn queue_sizes(&mut self, queue_size: u16, default_queues_num: usize) -> Result<Vec<u16>> {
        let queues_num = if self
            .protocol_features
            .contains(VhostUserProtocolFeatures::MQ)
        {
            self.vu.get_queue_num().map_err(Error::GetQueueNum)? as usize
        } else {
            default_queues_num
        };
        Ok(vec![queue_size; queues_num])
    }

    /// Enables a set of features.
    pub fn ack_features(&mut self, ack_features: u64) -> Result<()> {
        let features = set_features(
            &mut self.vu,
            self.avail_features,
            self.acked_features | ack_features,
        )?;
        self.acked_features = features;
        Ok(())
    }

    /// Gets the device configuration space at `offset` and writes it into `data`.
    pub fn read_config(&mut self, offset: u64, data: &mut [u8]) -> Result<()> {
        let (_, config) = self
            .vu
            .get_config(
                offset
                    .try_into()
                    .map_err(|_| Error::InvalidConfigOffset(offset))?,
                data.len()
                    .try_into()
                    .map_err(|_| Error::InvalidConfigLen(data.len()))?,
                VhostUserConfigFlags::WRITABLE,
                data,
            )
            .map_err(Error::GetConfig)?;
        data.copy_from_slice(&config);
        Ok(())
    }

    /// Writes `data` into the device configuration space at `offset`.
    pub fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        self.vu
            .set_config(
                offset
                    .try_into()
                    .map_err(|_| Error::InvalidConfigOffset(offset))?,
                VhostUserConfigFlags::empty(),
                data,
            )
            .map_err(Error::SetConfig)
    }

    /// Sets the memory map regions so it can translate the vring addresses.
    pub fn set_mem_table(&mut self, mem: &GuestMemory) -> Result<()> {
        let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();
        mem.with_regions::<_, ()>(
            |_idx, guest_phys_addr, memory_size, userspace_addr, mmap, mmap_offset| {
                let region = VhostUserMemoryRegionInfo {
                    guest_phys_addr: guest_phys_addr.0,
                    memory_size: memory_size as u64,
                    userspace_addr: userspace_addr as u64,
                    mmap_offset,
                    mmap_handle: mmap.as_raw_descriptor(),
                };
                regions.push(region);
                Ok(())
            },
        )
        .unwrap(); // never fail

        self.vu
            .set_mem_table(regions.as_slice())
            .map_err(Error::SetMemTable)?;

        Ok(())
    }

    /// Activates a vring for the given `queue`.
    pub fn activate_vring(
        &mut self,
        mem: &GuestMemory,
        queue_index: usize,
        queue: &Queue,
        queue_evt: &Event,
        irqfd: &Event,
    ) -> Result<()> {
        self.vu
            .set_vring_num(queue_index, queue.actual_size())
            .map_err(Error::SetVringNum)?;

        let config_data = VringConfigData {
            queue_max_size: queue.max_size,
            queue_size: queue.actual_size(),
            flags: 0u32,
            desc_table_addr: mem
                .get_host_address(queue.desc_table())
                .map_err(Error::GetHostAddress)? as u64,
            used_ring_addr: mem
                .get_host_address(queue.used_ring())
                .map_err(Error::GetHostAddress)? as u64,
            avail_ring_addr: mem
                .get_host_address(queue.avail_ring())
                .map_err(Error::GetHostAddress)? as u64,
            log_addr: None,
        };
        self.vu
            .set_vring_addr(queue_index, &config_data)
            .map_err(Error::SetVringAddr)?;

        self.vu
            .set_vring_base(queue_index, 0)
            .map_err(Error::SetVringBase)?;

        self.vu
            .set_vring_call(queue_index, irqfd)
            .map_err(Error::SetVringCall)?;
        self.vu
            .set_vring_kick(queue_index, queue_evt)
            .map_err(Error::SetVringKick)?;
        self.vu
            .set_vring_enable(queue_index, true)
            .map_err(Error::SetVringEnable)?;

        Ok(())
    }

    /// Activates vrings.
    pub fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
        label: &str,
    ) -> Result<(thread::JoinHandle<()>, Event)> {
        self.set_mem_table(&mem)?;

        let msix_config_opt = interrupt
            .get_msix_config()
            .as_ref()
            .ok_or(Error::MsixConfigUnavailable)?;
        let msix_config = msix_config_opt.lock();

        for (queue_index, queue) in queues.iter().enumerate() {
            let queue_evt = &queue_evts[queue_index];
            let irqfd = msix_config
                .get_irqfd(queue.vector() as usize)
                .unwrap_or_else(|| interrupt.get_interrupt_evt());
            self.activate_vring(&mem, queue_index, queue, queue_evt, irqfd)?;
        }

        drop(msix_config);

        let label = format!("vhost_user_virtio_{}", label);
        let kill_evt = Event::new().map_err(Error::CreateEvent)?;
        let self_kill_evt = kill_evt.try_clone().map_err(Error::CreateEvent)?;
        let backend_req_handler = self.backend_req_handler.take();
        thread::Builder::new()
            .name(label.clone())
            .spawn(move || {
                let mut worker = worker::Worker {
                    queues,
                    mem,
                    kill_evt,
                    backend_req_handler,
                };

                if let Err(e) = worker.run(interrupt) {
                    error!("failed to start {} worker: {}", label, e);
                }
            })
            .map(|worker_result| (worker_result, self_kill_evt))
            .map_err(Error::SpawnWorker)
    }

    /// Deactivates all vrings.
    pub fn reset(&mut self, queues_num: usize) -> Result<()> {
        for queue_index in 0..queues_num {
            self.vu
                .set_vring_enable(queue_index, false)
                .map_err(Error::SetVringEnable)?;
            self.vu
                .get_vring_base(queue_index)
                .map_err(Error::GetVringBase)?;
        }
        Ok(())
    }

    pub fn get_shared_memory_region(&mut self) -> Result<Option<SharedMemoryRegion>> {
        if let Some(r) = self.shmem_region.as_ref() {
            return Ok(r.clone());
        }
        let regions = self
            .vu
            .get_shared_memory_regions()
            .map_err(Error::ShmemRegions)?;
        let region = match regions.len() {
            0 => None,
            1 => Some(SharedMemoryRegion {
                id: regions[0].id,
                length: regions[0].length,
            }),
            n => return Err(Error::TooManyShmemRegions(n)),
        };

        self.shmem_region = Some(region.clone());
        Ok(region)
    }

    pub fn set_shared_memory_mapper(&mut self, mapper: Box<dyn SharedMemoryMapper>) -> Result<()> {
        // The virtio framework will only call this if get_shared_memory_region returned a region
        let shmid = self
            .shmem_region
            .clone()
            .flatten()
            .expect("missing shmid")
            .id;
        self.initialize_backend_req_handler(BackendReqHandlerImpl { mapper, shmid })
    }
}

pub struct BackendReqHandlerImpl {
    mapper: Box<dyn SharedMemoryMapper>,
    shmid: u8,
}

impl VhostUserMasterReqHandlerMut for BackendReqHandlerImpl {
    fn shmem_map(
        &mut self,
        req: &VhostUserShmemMapMsg,
        fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        if req.shmid != self.shmid {
            error!("bad shmid {}, expected {}", req.shmid, self.shmid);
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        match self.mapper.add_mapping(
            VmMemorySource::Descriptor {
                descriptor: SafeDescriptor::try_from(fd)
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?,
                offset: req.fd_offset,
                size: req.len,
                gpu_blob: false,
            },
            req.shm_offset,
            Protection::from(req.flags),
        ) {
            Ok(()) => Ok(0),
            Err(e) => {
                error!("failed to create mapping {:?}", e);
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
        }
    }

    fn shmem_unmap(&mut self, req: &VhostUserShmemUnmapMsg) -> HandlerResult<u64> {
        if req.shmid != self.shmid {
            error!("bad shmid {}, expected {}", req.shmid, self.shmid);
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        match self.mapper.remove_mapping(req.shm_offset) {
            Ok(()) => Ok(0),
            Err(e) => {
                error!("failed to remove mapping {:?}", e);
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
        }
    }
}
