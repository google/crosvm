// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provide utility to communicate with an iommu in another process

use std::ops::Deref;
use std::result;

use base::{AsRawDescriptor, AsRawDescriptors, RawDescriptor, Tube};
use serde::{Deserialize, Serialize};

use crate::virtio::memory_mapper::{Error, MemRegion, Translate};

pub type Result<T> = result::Result<T, Error>;

#[derive(Serialize, Deserialize)]
pub struct TranslateRequest {
    pub endpoint_id: u32,
    pub iova: u64,
    pub size: u64,
}

/// Sends an addr translation request to another process using `Tube`, and
/// gets the translated addr from another `Tube`
pub struct IpcMemoryMapper {
    request_tx: Tube,
    response_rx: Tube,
    endpoint_id: u32,
}

impl IpcMemoryMapper {
    /// Returns a new `IpcMemoryMapper` instance.
    ///
    /// # Arguments
    ///
    /// * `request_tx` - A tube to send `TranslateRequest` to another process.
    /// * `response_rx` - A tube to receive `Option<Vec<MemRegion>>`
    /// * `endpoint_id` - For the remote iommu to identify the device/ipc mapper.
    pub fn new(request_tx: Tube, response_rx: Tube, endpoint_id: u32) -> Self {
        Self {
            request_tx,
            response_rx,
            endpoint_id,
        }
    }
}

impl Translate for IpcMemoryMapper {
    fn translate(&self, iova: u64, size: u64) -> Result<Vec<MemRegion>> {
        let req = TranslateRequest {
            endpoint_id: self.endpoint_id,
            iova,
            size,
        };
        self.request_tx.send(&req).map_err(Error::Tube)?;
        let res: Option<Vec<MemRegion>> = self.response_rx.recv().map_err(Error::Tube)?;
        res.ok_or(Error::InvalidIOVA(iova, size))
    }
}

impl AsRawDescriptors for IpcMemoryMapper {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![
            self.request_tx.as_raw_descriptor(),
            self.response_rx.as_raw_descriptor(),
        ]
    }
}

impl Translate for std::sync::MutexGuard<'_, IpcMemoryMapper> {
    fn translate(&self, iova: u64, size: u64) -> Result<Vec<MemRegion>> {
        self.deref().translate(iova, size)
    }
}

pub struct CreateIpcMapperRet {
    pub mapper: IpcMemoryMapper,
    pub response_tx: Tube,
}

/// Returns a new `IpcMemoryMapper` instance and a response_tx for the iommu
/// to respond to `TranslateRequest`s.
///
/// # Arguments
///
/// * `endpoint_id` - For the remote iommu to identify the device/ipc mapper.
/// * `request_tx` - A tube to send `TranslateRequest` to a remote iommu. This
///                  should be cloned and shared between different ipc mappers
///                  with different `endpoint_id`s.
pub fn create_ipc_mapper(endpoint_id: u32, request_tx: Tube) -> CreateIpcMapperRet {
    let (response_tx, response_rx) = Tube::pair().expect("failed to create tube pair");
    CreateIpcMapperRet {
        mapper: IpcMemoryMapper::new(request_tx, response_rx, endpoint_id),
        response_tx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::memory_mapper::Permission;
    use std::thread;
    use vm_memory::GuestAddress;

    #[test]
    fn test() {
        let (request_tx, request_rx) = Tube::pair().expect("failed to create tube pair");
        let CreateIpcMapperRet {
            mapper,
            response_tx,
        } = create_ipc_mapper(3, request_tx);
        let user_handle = thread::spawn(move || {
            assert!(mapper
                .translate(0x555, 1)
                .unwrap()
                .iter()
                .zip(&vec![MemRegion {
                    gpa: GuestAddress(0x777),
                    len: 1,
                    perm: Permission::RW,
                },])
                .all(|(a, b)| a == b));
        });
        let iommu_handle = thread::spawn(move || {
            let TranslateRequest {
                endpoint_id,
                iova,
                size,
            } = request_rx.recv().unwrap();
            assert_eq!(endpoint_id, 3);
            assert_eq!(iova, 0x555);
            assert_eq!(size, 1);
            response_tx
                .send(&Some(vec![MemRegion {
                    gpa: GuestAddress(0x777),
                    len: 1,
                    perm: Permission::RW,
                }]))
                .unwrap();
        });
        iommu_handle.join().unwrap();
        user_handle.join().unwrap();
    }
}
