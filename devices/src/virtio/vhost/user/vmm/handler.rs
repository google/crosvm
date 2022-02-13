// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;

use base::{AsRawDescriptor, Event, Tube};
use vm_memory::GuestMemory;
use vmm_vhost::message::{
    MasterReq, VhostUserConfigFlags, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vmm_vhost::{
    connection::socket::Endpoint as SocketEndpoint, Master, VhostBackend, VhostUserMaster,
    VhostUserMemoryRegionInfo, VringConfigData,
};

use crate::virtio::vhost::user::vmm::{Error, Result};
use crate::virtio::{Interrupt, Queue};

type SocketMaster = Master<SocketEndpoint<MasterReq>>;

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
}

impl VhostUserHandler {
    /// Creates a `VhostUserHandler` instance attached to the provided UDS path
    /// with features and protocol features initialized.
    pub fn new_from_path<P: AsRef<Path>>(
        path: P,
        max_queue_num: u64,
        allow_features: u64,
        init_features: u64,
        allow_protocol_features: VhostUserProtocolFeatures,
    ) -> Result<Self> {
        Self::new(
            SocketMaster::connect(path, max_queue_num)
                .map_err(Error::SocketConnectOnMasterCreate)?,
            allow_features,
            init_features,
            allow_protocol_features,
        )
    }

    /// Creates a `VhostUserHandler` instance attached to the provided
    /// UnixStream with features and protocol features initialized.
    pub fn new_from_stream(
        sock: UnixStream,
        max_queue_num: u64,
        allow_features: u64,
        init_features: u64,
        allow_protocol_features: VhostUserProtocolFeatures,
    ) -> Result<Self> {
        Self::new(
            SocketMaster::from_stream(sock, max_queue_num),
            allow_features,
            init_features,
            allow_protocol_features,
        )
    }

    /// Creates a `VhostUserHandler` instance with features and protocol features initialized.
    fn new(
        mut vu: SocketMaster,
        allow_features: u64,
        init_features: u64,
        allow_protocol_features: VhostUserProtocolFeatures,
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
    pub fn read_config<T>(&mut self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_len = std::mem::size_of::<T>() as u64;
        let data_len = data.len() as u64;
        offset
            .checked_add(data_len)
            .and_then(|l| if l <= config_len { Some(()) } else { None })
            .ok_or(Error::InvalidConfigOffset {
                data_len,
                offset,
                config_len,
            })?;

        let buf = vec![0u8; config_len as usize];
        let (_, config) = self
            .vu
            .get_config(0, config_len as u32, VhostUserConfigFlags::WRITABLE, &buf)
            .map_err(Error::GetConfig)?;

        data.write_all(
            &config[offset as usize..std::cmp::min(data_len + offset, config_len) as usize],
        )
        .map_err(Error::CopyConfig)
    }

    /// Writes `data` into the device configuration space at `offset`.
    pub fn write_config<T>(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let config_len = std::mem::size_of::<T>() as u64;
        let data_len = data.len() as u64;
        offset
            .checked_add(data_len)
            .and_then(|l| if l <= config_len { Some(()) } else { None })
            .ok_or(Error::InvalidConfigOffset {
                data_len,
                offset,
                config_len,
            })?;

        self.vu
            .set_config(offset as u32, VhostUserConfigFlags::empty(), data)
            .map_err(Error::SetConfig)
    }

    /// Sets the channel for device-specific messages.
    pub fn set_device_request_channel(&mut self, channel: Tube) -> Result<()> {
        self.vu
            .set_slave_request_fd(&channel)
            .map_err(Error::SetDeviceRequestChannel)
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
                .get_host_address(queue.desc_table)
                .map_err(Error::GetHostAddress)? as u64,
            used_ring_addr: mem
                .get_host_address(queue.used_ring)
                .map_err(Error::GetHostAddress)? as u64,
            avail_ring_addr: mem
                .get_host_address(queue.avail_ring)
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
        mem: &GuestMemory,
        interrupt: &Interrupt,
        queues: &[Queue],
        queue_evts: &[Event],
    ) -> Result<()> {
        self.set_mem_table(mem)?;

        let msix_config_opt = interrupt
            .get_msix_config()
            .as_ref()
            .ok_or(Error::MsixConfigUnavailable)?;
        let msix_config = msix_config_opt.lock();

        for (queue_index, queue) in queues.iter().enumerate() {
            let queue_evt = &queue_evts[queue_index];
            let irqfd = msix_config
                .get_irqfd(queue.vector as usize)
                .unwrap_or_else(|| interrupt.get_interrupt_evt());
            self.activate_vring(mem, queue_index, queue, queue_evt, irqfd)?;
        }

        Ok(())
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
}
