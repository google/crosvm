// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Support for virtio-media devices in crosvm.
//!
//! This module provides implementation for the virtio-media traits required to make virtio-media
//! devices operate under crosvm. Sub-modules then integrate these devices with crosvm.

#[cfg(feature = "video-decoder")]
pub mod decoder_adapter;

use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::Context;
use base::error;
use base::Descriptor;
use base::Event;
use base::EventToken;
use base::EventType;
use base::MappedRegion;
use base::MemoryMappingArena;
use base::Protection;
use base::WaitContext;
use base::WorkerThread;
use resources::address_allocator::AddressAllocator;
use resources::AddressRange;
use resources::Alloc;
use sync::Mutex;
use virtio_media::io::WriteToDescriptorChain;
use virtio_media::poll::SessionPoller;
use virtio_media::protocol::SgEntry;
use virtio_media::protocol::V4l2Event;
use virtio_media::protocol::VirtioMediaDeviceConfig;
use virtio_media::GuestMemoryRange;
use virtio_media::VirtioMediaDevice;
use virtio_media::VirtioMediaDeviceRunner;
use virtio_media::VirtioMediaEventQueue;
use virtio_media::VirtioMediaGuestMemoryMapper;
use virtio_media::VirtioMediaHostMemoryMapper;
use vm_control::VmMemorySource;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::virtio::copy_config;
#[cfg(feature = "video-decoder")]
use crate::virtio::device_constants::media::QUEUE_SIZES;
#[cfg(feature = "video-decoder")]
use crate::virtio::device_constants::video::VideoBackendType;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::Reader;
use crate::virtio::SharedMemoryMapper;
use crate::virtio::SharedMemoryRegion;
use crate::virtio::VirtioDevice;
use crate::virtio::Writer;

/// Structure supporting the implementation of `VirtioMediaEventQueue` for sending events to the
/// driver.
struct EventQueue(Queue);

impl VirtioMediaEventQueue for EventQueue {
    /// Wait until an event descriptor becomes available and send `event` to the guest.
    fn send_event(&mut self, event: V4l2Event) {
        let mut desc;

        loop {
            match self.0.pop() {
                Some(d) => {
                    desc = d;
                    break;
                }
                None => {
                    if let Err(e) = self.0.event().wait() {
                        error!("could not obtain a descriptor to send event to: {:#}", e);
                        return;
                    }
                }
            }
        }

        if let Err(e) = match event {
            V4l2Event::Error(event) => WriteToDescriptorChain::write_obj(&mut desc.writer, event),
            V4l2Event::DequeueBuffer(event) => {
                WriteToDescriptorChain::write_obj(&mut desc.writer, event)
            }
            V4l2Event::Event(event) => WriteToDescriptorChain::write_obj(&mut desc.writer, event),
        } {
            error!("failed to write event: {}", e);
        }

        let written = desc.writer.bytes_written() as u32;
        self.0.add_used(desc, written);
        self.0.trigger_interrupt();
    }
}

/// A `SharedMemoryMapper` behind an `Arc`, allowing it to be shared.
///
/// This is required by the fact that devices can be activated several times, but the mapper is
/// only provided once. This might be a defect of the `VirtioDevice` interface.
#[derive(Clone)]
struct ArcedMemoryMapper(Arc<Mutex<Box<dyn SharedMemoryMapper>>>);

impl From<Box<dyn SharedMemoryMapper>> for ArcedMemoryMapper {
    fn from(mapper: Box<dyn SharedMemoryMapper>) -> Self {
        Self(Arc::new(Mutex::new(mapper)))
    }
}

impl SharedMemoryMapper for ArcedMemoryMapper {
    fn add_mapping(
        &mut self,
        source: VmMemorySource,
        offset: u64,
        prot: Protection,
        cache: hypervisor::MemCacheType,
    ) -> anyhow::Result<()> {
        self.0.lock().add_mapping(source, offset, prot, cache)
    }

    fn remove_mapping(&mut self, offset: u64) -> anyhow::Result<()> {
        self.0.lock().remove_mapping(offset)
    }

    fn as_raw_descriptor(&self) -> Option<base::RawDescriptor> {
        self.0.lock().as_raw_descriptor()
    }
}

/// Provides the ability to map host memory into the guest physical address space. Used to
/// implement `VirtioMediaHostMemoryMapper`.
struct HostMemoryMapper<M: SharedMemoryMapper> {
    /// Mapper.
    shm_mapper: M,
    /// Address allocator for the mapper.
    allocator: AddressAllocator,
}

impl<M: SharedMemoryMapper> VirtioMediaHostMemoryMapper for HostMemoryMapper<M> {
    fn add_mapping(
        &mut self,
        buffer: BorrowedFd,
        length: u64,
        offset: u64,
        rw: bool,
    ) -> Result<u64, i32> {
        // TODO: technically `offset` can be used twice if a buffer is deleted and some other takes
        // its place...
        let shm_offset = self
            .allocator
            .allocate(length, Alloc::FileBacked(offset), "".into())
            .map_err(|_| libc::ENOMEM)?;

        match self.shm_mapper.add_mapping(
            VmMemorySource::Descriptor {
                descriptor: buffer.try_clone_to_owned().map_err(|_| libc::EIO)?.into(),
                offset: 0,
                size: length,
            },
            shm_offset,
            if rw {
                Protection::read_write()
            } else {
                Protection::read()
            },
            hypervisor::MemCacheType::CacheCoherent,
        ) {
            Ok(()) => Ok(shm_offset),
            Err(e) => {
                base::error!("failed to map memory buffer: {:#}", e);
                Err(libc::EINVAL)
            }
        }
    }

    fn remove_mapping(&mut self, offset: u64) -> Result<(), i32> {
        let _ = self.allocator.release_containing(offset);

        self.shm_mapper
            .remove_mapping(offset)
            .map_err(|_| libc::EINVAL)
    }
}

/// Direct linear mapping of sparse guest memory.
///
/// A re-mapping of sparse guest memory into an arena that is linear to the host.
struct GuestMemoryMapping {
    arena: MemoryMappingArena,
    start_offset: usize,
}

impl GuestMemoryMapping {
    fn new(mem: &GuestMemory, sgs: &[SgEntry]) -> anyhow::Result<Self> {
        let page_size = base::pagesize() as u64;
        let page_mask = page_size - 1;

        // Validate the SGs.
        //
        // We can only map full pages and need to maintain a linear area. This means that the
        // following invariants must be withheld:
        //
        // - For all entries but the first, the start offset within the page must be 0.
        // - For all entries but the last, `start + len` must be a multiple of page size.
        for sg in sgs.iter().skip(1) {
            if sg.start & page_mask != 0 {
                anyhow::bail!("non-initial SG entry start offset is not 0");
            }
        }
        for sg in sgs.iter().take(sgs.len() - 1) {
            if (sg.start + sg.len as u64) & page_mask != 0 {
                anyhow::bail!("non-terminal SG entry with start + len != page_size");
            }
        }

        // Compute the arena size.
        let arena_size = sgs
            .iter()
            .fold(0, |size, sg| size + (sg.start & page_mask) + sg.len as u64)
            // Align to page size if the last entry did not cover a full page.
            .next_multiple_of(page_size);
        let mut arena = MemoryMappingArena::new(arena_size as usize)?;

        // Map all SG entries.
        let mut pos = 0;
        for region in sgs {
            // Address of the first page of the region.
            let region_first_page = region.start & !page_mask;
            let len = region.start - region_first_page + region.len as u64;
            // Make sure to map whole pages (only necessary for the last entry).
            let len = len.next_multiple_of(page_size) as usize;
            // TODO: find the offset from the region, this assumes a single
            // region starting at address 0.
            let fd = mem.offset_region(region_first_page)?;
            // Always map whole pages
            arena.add_fd_offset(pos, len, fd, region_first_page)?;

            pos += len;
        }

        let start_offset = sgs
            .first()
            .map(|region| region.start & page_mask)
            .unwrap_or(0) as usize;

        Ok(GuestMemoryMapping {
            arena,
            start_offset,
        })
    }
}

impl GuestMemoryRange for GuestMemoryMapping {
    fn as_ptr(&self) -> *const u8 {
        // SAFETY: the arena has a valid pointer that covers `start_offset + len`.
        unsafe { self.arena.as_ptr().add(self.start_offset) }
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        // SAFETY: the arena has a valid pointer that covers `start_offset + len`.
        unsafe { self.arena.as_ptr().add(self.start_offset) }
    }
}

/// Copy of sparse guest memory that is written back upon destruction.
///
/// Contrary to `GuestMemoryMapping` which re-maps guest memory to make it appear linear to the
/// host, this copies the sparse guest memory into a linear vector that is copied back upon
/// destruction. Doing so can be faster than a costly mapping operation if the guest area is small
/// enough.
struct GuestMemoryShadowMapping {
    /// Sparse data copied from the guest.
    data: Vec<u8>,
    /// Guest memory to read from.
    mem: GuestMemory,
    /// SG entries describing the sparse guest area.
    sgs: Vec<SgEntry>,
    /// Whether the data has potentially been modified and requires to be written back to the
    /// guest.
    dirty: bool,
}

impl GuestMemoryShadowMapping {
    fn new(mem: &GuestMemory, sgs: Vec<SgEntry>) -> anyhow::Result<Self> {
        let total_size = sgs.iter().fold(0, |total, sg| total + sg.len as usize);
        let mut data = vec![0u8; total_size];
        let mut pos = 0;
        for sg in &sgs {
            mem.read_exact_at_addr(
                &mut data[pos..pos + sg.len as usize],
                GuestAddress(sg.start),
            )?;
            pos += sg.len as usize;
        }

        Ok(Self {
            data,
            mem: mem.clone(),
            sgs,
            dirty: false,
        })
    }
}

impl GuestMemoryRange for GuestMemoryShadowMapping {
    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.dirty = true;
        self.data.as_mut_ptr()
    }
}

/// Write the potentially modified shadow buffer back into the guest memory.
impl Drop for GuestMemoryShadowMapping {
    fn drop(&mut self) {
        // No need to copy back if no modification has been done.
        if !self.dirty {
            return;
        }

        let mut pos = 0;
        for sg in &self.sgs {
            if let Err(e) = self.mem.write_all_at_addr(
                &self.data[pos..pos + sg.len as usize],
                GuestAddress(sg.start),
            ) {
                base::error!("failed to write back guest memory shadow mapping: {:#}", e);
            }
            pos += sg.len as usize;
        }
    }
}

/// A chunk of guest memory which can be either directly mapped, or copied into a shadow buffer.
enum GuestMemoryChunk {
    Mapping(GuestMemoryMapping),
    Shadow(GuestMemoryShadowMapping),
}

impl GuestMemoryRange for GuestMemoryChunk {
    fn as_ptr(&self) -> *const u8 {
        match self {
            GuestMemoryChunk::Mapping(m) => m.as_ptr(),
            GuestMemoryChunk::Shadow(s) => s.as_ptr(),
        }
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        match self {
            GuestMemoryChunk::Mapping(m) => m.as_mut_ptr(),
            GuestMemoryChunk::Shadow(s) => s.as_mut_ptr(),
        }
    }
}

/// Newtype to implement `VirtioMediaGuestMemoryMapper` on `GuestMemory`.
///
/// Whether to use a direct mapping or to copy the guest data into a shadow buffer is decided by
/// the size of the guest mapping. If it is below `MAPPING_THRESHOLD`, a shadow buffer is used ;
/// otherwise the area is mapped.
struct GuestMemoryMapper(GuestMemory);

impl VirtioMediaGuestMemoryMapper for GuestMemoryMapper {
    type GuestMemoryMapping = GuestMemoryChunk;

    fn new_mapping(&self, sgs: Vec<SgEntry>) -> anyhow::Result<Self::GuestMemoryMapping> {
        /// Threshold at which we perform a direct mapping of the guest memory into the host.
        /// Anything below that is copied into a shadow buffer and synced back to the guest when
        /// the memory chunk is destroyed.
        const MAPPING_THRESHOLD: usize = 0x400;
        let total_size = sgs.iter().fold(0, |total, sg| total + sg.len as usize);

        if total_size >= MAPPING_THRESHOLD {
            GuestMemoryMapping::new(&self.0, &sgs).map(GuestMemoryChunk::Mapping)
        } else {
            GuestMemoryShadowMapping::new(&self.0, sgs).map(GuestMemoryChunk::Shadow)
        }
    }
}

#[derive(EventToken, Debug)]
enum Token {
    CommandQueue,
    V4l2Session(u32),
    Kill,
    InterruptResample,
}

/// Newtype to implement `SessionPoller` on `Rc<WaitContext<Token>>`.
#[derive(Clone)]
struct WaitContextPoller(Rc<WaitContext<Token>>);

impl SessionPoller for WaitContextPoller {
    fn add_session(&self, session: BorrowedFd, session_id: u32) -> Result<(), i32> {
        self.0
            .add_for_event(
                &Descriptor(session.as_raw_fd()),
                EventType::Read,
                Token::V4l2Session(session_id),
            )
            .map_err(|e| e.errno())
    }

    fn remove_session(&self, session: BorrowedFd) {
        let _ = self.0.delete(&Descriptor(session.as_raw_fd()));
    }
}

/// Worker to operate a virtio-media device inside a worker thread.
struct Worker<D: VirtioMediaDevice<Reader, Writer>> {
    runner: VirtioMediaDeviceRunner<Reader, Writer, D, WaitContextPoller>,
    cmd_queue: (Queue, Interrupt),
    wait_ctx: Rc<WaitContext<Token>>,
}

impl<D> Worker<D>
where
    D: VirtioMediaDevice<Reader, Writer>,
{
    /// Create a new worker instance for `device`.
    fn new(
        device: D,
        cmd_queue: Queue,
        cmd_interrupt: Interrupt,
        kill_evt: Event,
        wait_ctx: Rc<WaitContext<Token>>,
    ) -> anyhow::Result<Self> {
        wait_ctx
            .add_many(&[
                (cmd_queue.event(), Token::CommandQueue),
                (&kill_evt, Token::Kill),
            ])
            .context("when adding worker events to wait context")?;

        Ok(Self {
            runner: VirtioMediaDeviceRunner::new(device, WaitContextPoller(Rc::clone(&wait_ctx))),
            cmd_queue: (cmd_queue, cmd_interrupt),
            wait_ctx,
        })
    }

    fn run(&mut self) -> anyhow::Result<()> {
        if let Some(resample_evt) = self.cmd_queue.1.get_resample_evt() {
            self.wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .context("failed adding resample event to WaitContext.")?;
        }

        loop {
            let wait_events = self.wait_ctx.wait().context("Wait error")?;

            for wait_event in wait_events.iter() {
                match wait_event.token {
                    Token::CommandQueue => {
                        let _ = self.cmd_queue.0.event().wait();
                        while let Some(mut desc) = self.cmd_queue.0.pop() {
                            self.runner
                                .handle_command(&mut desc.reader, &mut desc.writer);
                            // Return the descriptor to the guest.
                            let written = desc.writer.bytes_written() as u32;
                            self.cmd_queue.0.add_used(desc, written);
                            self.cmd_queue.0.trigger_interrupt();
                        }
                    }
                    Token::Kill => {
                        return Ok(());
                    }
                    Token::V4l2Session(session_id) => {
                        let session = match self.runner.sessions.get_mut(&session_id) {
                            Some(session) => session,
                            None => {
                                base::error!(
                                    "received event for non-registered session {}",
                                    session_id
                                );
                                continue;
                            }
                        };

                        if let Err(e) = self.runner.device.process_events(session) {
                            base::error!(
                                "error while processing events for session {}: {:#}",
                                session_id,
                                e
                            );
                            if let Some(session) = self.runner.sessions.remove(&session_id) {
                                self.runner.device.close_session(session);
                            }
                        }
                    }
                    Token::InterruptResample => {
                        self.cmd_queue.1.interrupt_resample();
                    }
                }
            }
        }
    }
}

/// Implements the required traits to operate a [`VirtioMediaDevice`] under crosvm.
struct CrosvmVirtioMediaDevice<
    D: VirtioMediaDevice<Reader, Writer>,
    F: Fn(EventQueue, GuestMemoryMapper, HostMemoryMapper<ArcedMemoryMapper>) -> anyhow::Result<D>,
> {
    /// Closure to create the device once all its resources are acquired.
    create_device: F,
    /// Virtio configuration area.
    config: VirtioMediaDeviceConfig,

    /// Virtio device features.
    base_features: u64,
    /// Mapper to make host video buffers visible to the guest.
    ///
    /// We unfortunately need to put it behind a `Arc` because the mapper is only passed once,
    /// whereas the device can be activated several times, so we need to keep a reference to it
    /// even after it is passed to the device.
    shm_mapper: Option<ArcedMemoryMapper>,
    /// Worker thread for the device.
    worker_thread: Option<WorkerThread<()>>,
}

impl<D, F> CrosvmVirtioMediaDevice<D, F>
where
    D: VirtioMediaDevice<Reader, Writer>,
    F: Fn(EventQueue, GuestMemoryMapper, HostMemoryMapper<ArcedMemoryMapper>) -> anyhow::Result<D>,
{
    fn new(base_features: u64, config: VirtioMediaDeviceConfig, create_device: F) -> Self {
        Self {
            base_features,
            config,
            shm_mapper: None,
            create_device,
            worker_thread: None,
        }
    }
}

const HOST_MAPPER_RANGE: u64 = 1 << 32;

impl<D, F> VirtioDevice for CrosvmVirtioMediaDevice<D, F>
where
    D: VirtioMediaDevice<Reader, Writer> + Send + 'static,
    F: Fn(EventQueue, GuestMemoryMapper, HostMemoryMapper<ArcedMemoryMapper>) -> anyhow::Result<D>
        + Send,
{
    fn keep_rds(&self) -> Vec<base::RawDescriptor> {
        let mut keep_rds = Vec::new();

        if let Some(fd) = self.shm_mapper.as_ref().and_then(|m| m.as_raw_descriptor()) {
            keep_rds.push(fd);
        }

        keep_rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Media
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.base_features
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.config.as_ref(), offset);
    }

    fn activate(
        &mut self,
        mem: vm_memory::GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        if queues.len() != QUEUE_SIZES.len() {
            anyhow::bail!(
                "wrong number of queues are passed: expected {}, actual {}",
                queues.len(),
                QUEUE_SIZES.len()
            );
        }

        let cmd_queue = queues.remove(&0).context("missing queue 0")?;
        let event_queue = EventQueue(queues.remove(&1).context("missing queue 1")?);

        let shm_mapper = self
            .shm_mapper
            .clone()
            .take()
            .context("shared memory mapper was not specified")?;

        let wait_ctx = WaitContext::new()?;
        let device = (self.create_device)(
            event_queue,
            GuestMemoryMapper(mem),
            HostMemoryMapper {
                shm_mapper,
                allocator: AddressAllocator::new(
                    AddressRange::from_start_and_end(0, HOST_MAPPER_RANGE - 1),
                    Some(base::pagesize() as u64),
                    None,
                )?,
            },
        )?;

        let worker_thread = WorkerThread::start("v_media_worker", move |e| {
            let wait_ctx = Rc::new(wait_ctx);
            let mut worker = match Worker::new(device, cmd_queue, interrupt, e, wait_ctx) {
                Ok(worker) => worker,
                Err(e) => {
                    error!("failed to create virtio-media worker: {:#}", e);
                    return;
                }
            };
            if let Err(e) = worker.run() {
                error!("virtio_media worker exited with error: {:#}", e);
            }
        });

        self.worker_thread = Some(worker_thread);
        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        if let Some(worker_thread) = self.worker_thread.take() {
            worker_thread.stop();
        }

        Ok(())
    }

    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
        Some(SharedMemoryRegion {
            id: 0,
            // We need a 32-bit address space as m2m devices start their CAPTURE buffers' offsets
            // at 2GB.
            length: HOST_MAPPER_RANGE,
        })
    }

    fn set_shared_memory_mapper(&mut self, mapper: Box<dyn SharedMemoryMapper>) {
        self.shm_mapper = Some(ArcedMemoryMapper::from(mapper));
    }
}

/// Create a simple media capture device.
///
/// This device can only generate a fixed pattern at a fixed resolution, and should only be used
/// for checking that the virtio-media pipeline is working properly.
pub fn create_virtio_media_simple_capture_device(features: u64) -> Box<dyn VirtioDevice> {
    use virtio_media::devices::SimpleCaptureDevice;
    use virtio_media::v4l2r::ioctl::Capabilities;

    let mut card = [0u8; 32];
    let card_name = "simple_device";
    card[0..card_name.len()].copy_from_slice(card_name.as_bytes());

    let device = CrosvmVirtioMediaDevice::new(
        features,
        VirtioMediaDeviceConfig {
            device_caps: (Capabilities::VIDEO_CAPTURE | Capabilities::STREAMING).bits(),
            // VFL_TYPE_VIDEO
            device_type: 0,
            card,
        },
        |event_queue, _, host_mapper| Ok(SimpleCaptureDevice::new(event_queue, host_mapper)),
    );

    Box::new(device)
}

/// Create a proxy device for a host V4L2 device.
///
/// Since V4L2 is a Linux-specific API, this is only available on Linux targets.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn create_virtio_media_v4l2_proxy_device<P: AsRef<Path>>(
    features: u64,
    device_path: P,
) -> anyhow::Result<Box<dyn VirtioDevice>> {
    use virtio_media::devices::V4l2ProxyDevice;
    use virtio_media::v4l2r;
    use virtio_media::v4l2r::ioctl::Capabilities;

    let device = v4l2r::device::Device::open(
        device_path.as_ref(),
        v4l2r::device::DeviceConfig::new().non_blocking_dqbuf(),
    )?;
    let mut device_caps = device.caps().device_caps();

    // We are only exposing one device worth of capabilities.
    device_caps.remove(Capabilities::DEVICE_CAPS);

    // Read-write is not supported by design.
    device_caps.remove(Capabilities::READWRITE);

    let mut config = VirtioMediaDeviceConfig {
        device_caps: device_caps.bits(),
        // VFL_TYPE_VIDEO
        device_type: 0,
        card: Default::default(),
    };
    let card = &device.caps().card;
    let name_slice = card[0..std::cmp::min(card.len(), config.card.len())].as_bytes();
    config.card.as_mut_slice()[0..name_slice.len()].copy_from_slice(name_slice);
    let device_path = PathBuf::from(device_path.as_ref());

    let device = CrosvmVirtioMediaDevice::new(
        features,
        config,
        move |event_queue, guest_mapper, host_mapper| {
            let device =
                V4l2ProxyDevice::new(device_path.clone(), event_queue, guest_mapper, host_mapper);

            Ok(device)
        },
    );

    Ok(Box::new(device))
}

/// Create a decoder adapter device.
///
/// This is a regular virtio-media decoder device leveraging the virtio-video decoder backends.
#[cfg(feature = "video-decoder")]
pub fn create_virtio_media_decoder_adapter_device(
    features: u64,
    _gpu_tube: base::Tube,
    backend: VideoBackendType,
) -> anyhow::Result<Box<dyn VirtioDevice>> {
    use decoder_adapter::VirtioVideoAdapter;
    use virtio_media::devices::video_decoder::VideoDecoder;
    use virtio_media::v4l2r::ioctl::Capabilities;

    #[cfg(feature = "ffmpeg")]
    use crate::virtio::video::decoder::backend::ffmpeg::FfmpegDecoder;
    #[cfg(feature = "vaapi")]
    use crate::virtio::video::decoder::backend::vaapi::VaapiDecoder;
    #[cfg(feature = "libvda")]
    use crate::virtio::video::decoder::backend::vda::LibvdaDecoder;
    use crate::virtio::video::decoder::DecoderBackend;

    let mut card = [0u8; 32];
    let card_name = format!("{:?} decoder adapter", backend).to_lowercase();
    card[0..card_name.len()].copy_from_slice(card_name.as_bytes());
    let config = VirtioMediaDeviceConfig {
        device_caps: (Capabilities::VIDEO_M2M_MPLANE | Capabilities::STREAMING).bits(),
        // VFL_TYPE_VIDEO
        device_type: 0,
        card,
    };

    let create_device = move |event_queue, _, host_mapper: HostMemoryMapper<ArcedMemoryMapper>| {
        let backend = match backend {
            #[cfg(feature = "libvda")]
            VideoBackendType::Libvda => {
                LibvdaDecoder::new(libvda::decode::VdaImplType::Gavda)?.into_trait_object()
            }
            #[cfg(feature = "libvda")]
            VideoBackendType::LibvdaVd => {
                LibvdaDecoder::new(libvda::decode::VdaImplType::Gavd)?.into_trait_object()
            }
            #[cfg(feature = "vaapi")]
            VideoBackendType::Vaapi => VaapiDecoder::new()?.into_trait_object(),
            #[cfg(feature = "ffmpeg")]
            VideoBackendType::Ffmpeg => FfmpegDecoder::new().into_trait_object(),
        };

        let adapter = VirtioVideoAdapter::new(backend);
        let decoder = VideoDecoder::new(adapter, event_queue, host_mapper);

        Ok(decoder)
    };

    Ok(Box::new(CrosvmVirtioMediaDevice::new(
        features,
        config,
        create_device,
    )))
}
