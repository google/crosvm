// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod sys;
pub(crate) mod worker;

use std::collections::BTreeMap;

use base::error;
use base::info;
use base::trace;
use base::AsRawDescriptor;
use base::Event;
use base::Protection;
use base::SafeDescriptor;
use base::WorkerThread;
use hypervisor::MemCacheType;
use vm_control::VmMemorySource;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserConfigFlags;
use vmm_vhost::message::VhostUserExternalMapMsg;
use vmm_vhost::message::VhostUserGpuMapMsg;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserShmemMapMsg;
use vmm_vhost::message::VhostUserShmemUnmapMsg;
use vmm_vhost::BackendClient;
use vmm_vhost::Frontend;
use vmm_vhost::FrontendServer;
use vmm_vhost::HandlerResult;
use vmm_vhost::VhostUserMemoryRegionInfo;
use vmm_vhost::VringConfigData;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;

use crate::virtio::vhost::user::vmm::handler::sys::create_backend_req_handler;
use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::Error;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::SharedMemoryMapper;
use crate::virtio::SharedMemoryRegion;

type BackendReqHandler = FrontendServer<BackendReqHandlerImpl>;

pub struct VhostUserHandler {
    backend_client: BackendClient,
    pub avail_features: u64,
    acked_features: u64,
    protocol_features: VhostUserProtocolFeatures,
    backend_req_handler: Option<BackendReqHandler>,
    // Shared memory region info. IPC result from backend is saved with outer Option.
    shmem_region: Option<Option<SharedMemoryRegion>>,
}

impl VhostUserHandler {
    /// Creates a `VhostUserHandler` instance with features and protocol features initialized.
    pub fn new(
        connection: Connection,
        allow_features: u64,
        allow_protocol_features: VhostUserProtocolFeatures,
    ) -> Result<Self> {
        #[cfg(windows)]
        let backend_pid = connection.target_pid();

        let mut backend_client = BackendClient::from_stream(connection);

        backend_client.set_owner().map_err(Error::SetOwner)?;

        let avail_features =
            allow_features & backend_client.get_features().map_err(Error::GetFeatures)?;
        let mut acked_features = 0;

        let mut protocol_features = VhostUserProtocolFeatures::empty();
        if avail_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES != 0 {
            // The vhost-user backend supports VHOST_USER_F_PROTOCOL_FEATURES; enable it.
            backend_client
                .set_features(1 << VHOST_USER_F_PROTOCOL_FEATURES)
                .map_err(Error::SetFeatures)?;
            acked_features |= 1 << VHOST_USER_F_PROTOCOL_FEATURES;

            let avail_protocol_features = backend_client
                .get_protocol_features()
                .map_err(Error::GetProtocolFeatures)?;
            protocol_features = allow_protocol_features & avail_protocol_features;
            backend_client
                .set_protocol_features(protocol_features)
                .map_err(Error::SetProtocolFeatures)?;
        }

        // if protocol feature `VhostUserProtocolFeatures::BACKEND_REQ` is negotiated.
        let backend_req_handler =
            if protocol_features.contains(VhostUserProtocolFeatures::BACKEND_REQ) {
                let (handler, tx_fd) = create_backend_req_handler(
                    BackendReqHandlerImpl {
                        interrupt: None,
                        shared_mapper_state: None,
                    },
                    #[cfg(windows)]
                    backend_pid,
                )?;
                backend_client
                    .set_backend_req_fd(&tx_fd)
                    .map_err(Error::SetDeviceRequestChannel)?;
                Some(handler)
            } else {
                None
            };

        Ok(VhostUserHandler {
            backend_client,
            avail_features,
            acked_features,
            protocol_features,
            backend_req_handler,
            shmem_region: None,
        })
    }

    /// Returns the maximum number of queues supported by the backend, or `None` if the MQ protocol
    /// feature was not negotiated.
    pub fn num_queues(&self) -> Result<Option<usize>> {
        if self
            .protocol_features
            .contains(VhostUserProtocolFeatures::MQ)
        {
            trace!("backend supports VHOST_USER_PROTOCOL_F_MQ");
            let num_queues = self
                .backend_client
                .get_queue_num()
                .map_err(Error::GetQueueNum)?;
            trace!("VHOST_USER_GET_QUEUE_NUM returned {num_queues}");
            Ok(Some(num_queues as usize))
        } else {
            trace!("backend does not support VHOST_USER_PROTOCOL_F_MQ");
            Ok(None)
        }
    }

    /// Enables a set of features.
    pub fn ack_features(&mut self, ack_features: u64) -> Result<()> {
        let features = (ack_features & self.avail_features) | self.acked_features;
        self.backend_client
            .set_features(features)
            .map_err(Error::SetFeatures)?;
        self.acked_features = features;
        Ok(())
    }

    /// Gets the device configuration space at `offset` and writes it into `data`.
    pub fn read_config(&mut self, offset: u64, data: &mut [u8]) -> Result<()> {
        let (_, config) = self
            .backend_client
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
        self.backend_client
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
        let regions: Vec<_> = mem
            .regions()
            .map(|region| VhostUserMemoryRegionInfo {
                guest_phys_addr: region.guest_addr.0,
                memory_size: region.size as u64,
                userspace_addr: region.host_addr as u64,
                mmap_offset: region.shm_offset,
                mmap_handle: region.shm.as_raw_descriptor(),
            })
            .collect();

        self.backend_client
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
        irqfd: &Event,
    ) -> Result<()> {
        self.backend_client
            .set_vring_num(queue_index, queue.size())
            .map_err(Error::SetVringNum)?;

        let config_data = VringConfigData {
            queue_size: queue.size(),
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
        self.backend_client
            .set_vring_addr(queue_index, &config_data)
            .map_err(Error::SetVringAddr)?;

        self.backend_client
            .set_vring_base(queue_index, 0)
            .map_err(Error::SetVringBase)?;

        self.backend_client
            .set_vring_call(queue_index, irqfd)
            .map_err(Error::SetVringCall)?;
        self.backend_client
            .set_vring_kick(queue_index, queue.event())
            .map_err(Error::SetVringKick)?;

        // Per protocol documentation, `VHOST_USER_SET_VRING_ENABLE` should be sent only when
        // `VHOST_USER_F_PROTOCOL_FEATURES` has been negotiated.
        if self.acked_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES != 0 {
            self.backend_client
                .set_vring_enable(queue_index, true)
                .map_err(Error::SetVringEnable)?;
        }

        Ok(())
    }

    /// Activates vrings.
    pub fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: BTreeMap<usize, Queue>,
        label: &str,
    ) -> Result<WorkerThread<()>> {
        self.set_mem_table(&mem)?;

        let msix_config_opt = interrupt
            .get_msix_config()
            .as_ref()
            .ok_or(Error::MsixConfigUnavailable)?;
        let msix_config = msix_config_opt.lock();

        let non_msix_evt = Event::new().map_err(Error::CreateEvent)?;
        for (&queue_index, queue) in queues.iter() {
            let irqfd = msix_config
                .get_irqfd(queue.vector() as usize)
                .unwrap_or(&non_msix_evt);
            self.activate_vring(&mem, queue_index, queue, irqfd)?;
        }

        drop(msix_config);

        self.start_worker(interrupt, label, mem, non_msix_evt)
    }

    /// Deactivates all vrings.
    pub fn reset(&mut self, queues_num: usize) -> Result<()> {
        for queue_index in 0..queues_num {
            if self.acked_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES != 0 {
                self.backend_client
                    .set_vring_enable(queue_index, false)
                    .map_err(Error::SetVringEnable)?;
            }
            self.backend_client
                .get_vring_base(queue_index)
                .map_err(Error::GetVringBase)?;
        }
        Ok(())
    }

    pub fn get_shared_memory_region(&mut self) -> Result<Option<SharedMemoryRegion>> {
        if !self
            .protocol_features
            .contains(VhostUserProtocolFeatures::SHARED_MEMORY_REGIONS)
        {
            return Ok(None);
        }
        if let Some(r) = self.shmem_region.as_ref() {
            return Ok(r.clone());
        }
        let regions = self
            .backend_client
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
        // Return error if backend request handler is not available. This indicates
        // that `VhostUserProtocolFeatures::BACKEND_REQ` is not negotiated.
        let backend_req_handler =
            self.backend_req_handler
                .as_mut()
                .ok_or(Error::ProtocolFeatureNotNegoiated(
                    VhostUserProtocolFeatures::BACKEND_REQ,
                ))?;

        // The virtio framework will only call this if get_shared_memory_region returned a region
        let shmid = self
            .shmem_region
            .clone()
            .flatten()
            .expect("missing shmid")
            .id;

        backend_req_handler
            .frontend_mut()
            .set_shared_mapper_state(SharedMapperState { mapper, shmid });
        Ok(())
    }

    /// Sends a message to the device process to stop worker futures/threads
    pub fn sleep(&mut self) -> Result<()> {
        self.backend_client.sleep().map_err(Error::Sleep)?;
        Ok(())
    }

    /// Sends a message to the device process to start up worker futures/threads.
    pub fn wake(&mut self) -> Result<()> {
        self.backend_client.wake().map_err(Error::Wake)
    }

    /// Sends a snapshot request to the device and it should respond with the device's serialized
    /// state.
    pub fn snapshot(&self) -> Result<serde_json::Value> {
        let snapshot_bytes = self.backend_client.snapshot().map_err(Error::Snapshot)?;
        serde_json::to_value(snapshot_bytes).map_err(Error::SliceToSerdeValue)
    }

    /// Sends a restore request with a payload of serialized snapshotted data and queue_evts to the
    /// device process so that it can revive its state and wire up the queue_evts again.
    pub fn restore(
        &mut self,
        data: serde_json::Value,
        queue_evts: Option<Vec<Event>>,
    ) -> Result<()> {
        let data_bytes: Vec<u8> = serde_json::from_value(data).map_err(Error::SerdeValueToSlice)?;
        self.backend_client
            .restore(data_bytes.as_slice(), queue_evts)
            .map_err(Error::Restore)
    }

    /// Rewire up irqfds. Meant to be called right before `restore` and should only be called
    /// if the device is asleep.
    pub fn restore_irqfd(&self, queue_index: usize, irqfd: &Event) -> Result<()> {
        self.backend_client
            .set_vring_call(queue_index, irqfd)
            .map_err(Error::SetVringCall)
    }

    /// Helper to start up the worker thread that will be used with handling interrupts and requests
    /// from the device process.
    pub fn start_worker(
        &mut self,
        interrupt: Interrupt,
        label: &str,
        mem: GuestMemory,
        non_msix_evt: Event,
    ) -> Result<WorkerThread<()>> {
        let label = format!("vhost_user_virtio_{}", label);

        let mut backend_req_handler = self.backend_req_handler.take();
        if let Some(handler) = &mut backend_req_handler {
            // Using unwrap here to get the mutex protected value
            handler.frontend_mut().set_interrupt(interrupt.clone());
        }

        Ok(WorkerThread::start(label.clone(), move |kill_evt| {
            let mut worker = worker::Worker {
                mem,
                kill_evt,
                non_msix_evt,
                backend_req_handler,
            };

            if let Err(e) = worker.run(interrupt) {
                error!("failed to start {} worker: {}", label, e);
            }
        }))
    }
}

struct SharedMapperState {
    mapper: Box<dyn SharedMemoryMapper>,
    shmid: u8,
}

pub struct BackendReqHandlerImpl {
    interrupt: Option<Interrupt>,
    shared_mapper_state: Option<SharedMapperState>,
}

impl BackendReqHandlerImpl {
    fn set_interrupt(&mut self, interrupt: Interrupt) {
        self.interrupt = Some(interrupt);
    }

    fn set_shared_mapper_state(&mut self, shared_mapper_state: SharedMapperState) {
        self.shared_mapper_state = Some(shared_mapper_state);
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
