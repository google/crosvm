// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provide utility to communicate with an iommu in another process

use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::Event;
use base::Protection;
use base::RawDescriptor;
use base::Tube;
use serde::Deserialize;
use serde::Serialize;
use smallvec::SmallVec;
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::virtio::memory_mapper::MemRegion;

#[derive(Serialize, Deserialize)]
pub(super) enum IommuRequest {
    Export {
        endpoint_id: u32,
        iova: u64,
        size: u64,
    },
    Release {
        endpoint_id: u32,
        iova: u64,
        size: u64,
    },
    StartExportSession {
        endpoint_id: u32,
    },
}

#[derive(Serialize, Deserialize)]
pub(super) enum IommuResponse {
    Export(Vec<MemRegion>),
    Release,
    StartExportSession(Event),
    Err(String),
}

impl IommuRequest {
    pub(super) fn get_endpoint_id(&self) -> u32 {
        match self {
            Self::Export { endpoint_id, .. } => *endpoint_id,
            Self::Release { endpoint_id, .. } => *endpoint_id,
            Self::StartExportSession { endpoint_id } => *endpoint_id,
        }
    }
}

/// Sends an addr translation request to another process using `Tube`, and
/// gets the translated addr from another `Tube`
pub struct IpcMemoryMapper {
    request_tx: Tube,
    response_rx: Tube,
    endpoint_id: u32,
}

fn map_bad_resp(resp: IommuResponse) -> anyhow::Error {
    match resp {
        IommuResponse::Err(e) => anyhow!("remote error {}", e),
        _ => anyhow!("response type mismatch"),
    }
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

    fn do_request(&self, req: IommuRequest) -> Result<IommuResponse> {
        self.request_tx
            .send(&req)
            .context("failed to send request")?;
        self.response_rx
            .recv::<IommuResponse>()
            .context("failed to get response")
    }

    /// See [crate::virtio::memory_mapper::MemoryMapper::export].
    pub fn export(&mut self, iova: u64, size: u64) -> Result<Vec<MemRegion>> {
        let req = IommuRequest::Export {
            endpoint_id: self.endpoint_id,
            iova,
            size,
        };
        match self.do_request(req)? {
            IommuResponse::Export(vec) => Ok(vec),
            e => Err(map_bad_resp(e)),
        }
    }

    /// See [crate::virtio::memory_mapper::MemoryMapper::release].
    pub fn release(&mut self, iova: u64, size: u64) -> Result<()> {
        let req = IommuRequest::Release {
            endpoint_id: self.endpoint_id,
            iova,
            size,
        };
        match self.do_request(req)? {
            IommuResponse::Release => Ok(()),
            e => Err(map_bad_resp(e)),
        }
    }

    /// See [crate::virtio::memory_mapper::MemoryMapper::start_export_session].
    pub fn start_export_session(&mut self) -> Result<Event> {
        let req = IommuRequest::StartExportSession {
            endpoint_id: self.endpoint_id,
        };
        match self.do_request(req)? {
            IommuResponse::StartExportSession(evt) => Ok(evt),
            e => Err(map_bad_resp(e)),
        }
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

struct ExportedRegionInner {
    regions: Vec<MemRegion>,
    iova: u64,
    size: u64,
    iommu: Arc<Mutex<IpcMemoryMapper>>,
}

impl Drop for ExportedRegionInner {
    fn drop(&mut self) {
        if let Err(e) = self.iommu.lock().release(self.iova, self.size) {
            error!("Error releasing region {:?}", e);
        }
    }
}

/// A region exported from the virtio-iommu.
#[derive(Clone)]
pub struct ExportedRegion {
    inner: Arc<Mutex<ExportedRegionInner>>,
}

impl ExportedRegion {
    /// Creates a new, fully initialized exported region.
    pub fn new(
        mem: &GuestMemory,
        iommu: Arc<Mutex<IpcMemoryMapper>>,
        iova: u64,
        size: u64,
    ) -> Result<Self> {
        let regions = iommu
            .lock()
            .export(iova, size)
            .context("failed to export")?;
        for r in &regions {
            if !mem.is_valid_range(r.gpa, r.len) {
                bail!("region not in memory range");
            }
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(ExportedRegionInner {
                regions,
                iova,
                size,
                iommu,
            })),
        })
    }

    // Helper function for copying to/from [iova, iova+remaining).
    fn do_copy<C>(
        &self,
        iova: u64,
        mut remaining: usize,
        prot: Protection,
        mut copy_fn: C,
    ) -> Result<()>
    where
        C: FnMut(usize /* offset */, GuestAddress, usize /* len */) -> Result<usize>,
    {
        let inner = self.inner.lock();
        let mut region_offset = iova.checked_sub(inner.iova).with_context(|| {
            format!(
                "out of bounds: src_iova={} region_iova={}",
                iova, inner.iova
            )
        })?;
        let mut offset = 0;
        for r in &inner.regions {
            if region_offset >= r.len {
                region_offset -= r.len;
                continue;
            }

            if !r.prot.allows(&prot) {
                bail!("gpa is not accessible");
            }

            let len = (r.len as usize).min(remaining);
            let copy_len = copy_fn(offset, r.gpa.unchecked_add(region_offset), len)?;
            if len != copy_len {
                bail!("incomplete copy: expected={}, actual={}", len, copy_len);
            }

            remaining -= len;
            offset += len;
            region_offset = 0;

            if remaining == 0 {
                return Ok(());
            }
        }

        Err(anyhow!("not enough data: remaining={}", remaining))
    }

    /// Reads an object from the given iova. Fails if the specified iova range does
    /// not lie within this region, or if part of the region isn't readable.
    pub fn read_obj_from_addr<T: FromBytes>(
        &self,
        mem: &GuestMemory,
        iova: u64,
    ) -> anyhow::Result<T> {
        let mut buf = vec![0u8; std::mem::size_of::<T>()];
        self.do_copy(iova, buf.len(), Protection::read(), |offset, gpa, len| {
            mem.read_at_addr(&mut buf[offset..(offset + len)], gpa)
                .context("failed to read from gpa")
        })?;
        T::read_from(buf.as_bytes()).context("failed to construct obj")
    }

    /// Writes an object at a given iova. Fails if the specified iova range does
    /// not lie within this region, or if part of the region isn't writable.
    pub fn write_obj_at_addr<T: AsBytes>(
        &self,
        mem: &GuestMemory,
        val: T,
        iova: u64,
    ) -> anyhow::Result<()> {
        let buf = val.as_bytes();
        self.do_copy(iova, buf.len(), Protection::write(), |offset, gpa, len| {
            mem.write_at_addr(&buf[offset..(offset + len)], gpa)
                .context("failed to write from gpa")
        })?;
        Ok(())
    }

    /// Validates that [iova, iova+size) lies within this region, and that
    /// the region is valid according to mem.
    pub fn is_valid(&self, mem: &GuestMemory, iova: u64, size: u64) -> bool {
        let inner = self.inner.lock();
        let iova_end = iova.checked_add(size);
        if iova_end.is_none() {
            return false;
        }
        if iova < inner.iova || iova_end.unwrap() > (inner.iova + inner.size) {
            return false;
        }
        self.inner
            .lock()
            .regions
            .iter()
            .all(|r| mem.range_overlap(r.gpa, r.gpa.unchecked_add(r.len as u64)))
    }

    /// Gets the list of guest physical regions for the exported region.
    pub fn get_mem_regions(&self) -> SmallVec<[MemRegion; 1]> {
        SmallVec::from_slice(&self.inner.lock().regions)
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use base::Protection;
    use vm_memory::GuestAddress;

    use super::*;

    #[test]
    fn test() {
        let (request_tx, request_rx) = Tube::pair().expect("failed to create tube pair");
        let CreateIpcMapperRet {
            mut mapper,
            response_tx,
        } = create_ipc_mapper(3, request_tx);
        let user_handle = thread::spawn(move || {
            assert!(mapper
                .export(0x555, 1)
                .unwrap()
                .iter()
                .zip(&vec![MemRegion {
                    gpa: GuestAddress(0x777),
                    len: 1,
                    prot: Protection::read_write(),
                },])
                .all(|(a, b)| a == b));
        });
        let iommu_handle = thread::spawn(move || {
            let (endpoint_id, iova, size) = match request_rx.recv().unwrap() {
                IommuRequest::Export {
                    endpoint_id,
                    iova,
                    size,
                } => (endpoint_id, iova, size),
                _ => unreachable!(),
            };
            assert_eq!(endpoint_id, 3);
            assert_eq!(iova, 0x555);
            assert_eq!(size, 1);
            response_tx
                .send(&IommuResponse::Export(vec![MemRegion {
                    gpa: GuestAddress(0x777),
                    len: 1,
                    prot: Protection::read_write(),
                }]))
                .unwrap();
            // This join needs to be here because on Windows, if `response_tx`
            // is dropped before `response_rx` can read, the connection will
            // be severed and this test will fail.
            user_handle.join().unwrap();
        });
        iommu_handle.join().unwrap();
    }
}
