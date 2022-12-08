// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The cross-domain component type, specialized for allocating and sharing resources across domain
//! boundaries.

use std::collections::BTreeMap as Map;
use std::collections::VecDeque;
use std::convert::TryInto;
use std::fs::File;
use std::mem::size_of;
use std::ptr::copy_nonoverlapping;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::thread;

use base::error;
use base::Event;
use base::EventToken;
use base::FileReadWriteVolatile;
use base::SafeDescriptor;
use base::WaitContext;
use data_model::DataInit;
use data_model::VolatileSlice;

use super::sys::descriptor_analysis;
use super::sys::SystemStream;
use crate::cross_domain::cross_domain_protocol::*;
use crate::rutabaga_core::RutabagaComponent;
use crate::rutabaga_core::RutabagaContext;
use crate::rutabaga_core::RutabagaResource;
use crate::rutabaga_utils::*;
use crate::DrmFormat;
use crate::ImageAllocationInfo;
use crate::ImageMemoryRequirements;
use crate::RutabagaGralloc;
use crate::RutabagaGrallocFlags;

const CROSS_DOMAIN_DEFAULT_BUFFER_SIZE: usize = 4096;
const CROSS_DOMAIN_MAX_SEND_RECV_SIZE: usize =
    CROSS_DOMAIN_DEFAULT_BUFFER_SIZE - size_of::<CrossDomainSendReceive>();

#[derive(EventToken)]
enum CrossDomainToken {
    ContextChannel,
    WaylandReadPipe(u32),
    Resample,
    Kill,
}

pub(crate) enum CrossDomainItem {
    ImageRequirements(ImageMemoryRequirements),
    WaylandKeymap(SafeDescriptor),
    #[allow(dead_code)] // `WaylandReadPipe` is never constructed on Windows.
    WaylandReadPipe(File),
    WaylandWritePipe(File),
}

pub(crate) enum CrossDomainJob {
    HandleFence(RutabagaFence),
    #[allow(dead_code)] // `AddReadPipe` is never constructed on Windows.
    AddReadPipe(u32),
}

enum RingWrite<'a, T> {
    Write(T, Option<&'a [u8]>),
    WriteFromFile(CrossDomainReadWrite, &'a mut File, bool),
}

pub(crate) type CrossDomainResources = Arc<Mutex<Map<u32, CrossDomainResource>>>;
type CrossDomainJobs = Mutex<Option<VecDeque<CrossDomainJob>>>;
pub(crate) type CrossDomainItemState = Arc<Mutex<CrossDomainItems>>;

pub(crate) struct CrossDomainResource {
    #[allow(dead_code)] // `handle` is never used on Windows.
    pub handle: Option<Arc<RutabagaHandle>>,
    pub backing_iovecs: Option<Vec<RutabagaIovec>>,
}

pub(crate) struct CrossDomainItems {
    descriptor_id: u32,
    requirements_blob_id: u32,
    table: Map<u32, CrossDomainItem>,
}

pub(crate) struct CrossDomainState {
    context_resources: CrossDomainResources,
    ring_id: u32,
    #[allow(dead_code)] // `connection` is never used on Windows.
    pub(crate) connection: Option<SystemStream>,
    jobs: CrossDomainJobs,
    jobs_cvar: Condvar,
}

struct CrossDomainWorker {
    wait_ctx: WaitContext<CrossDomainToken>,
    state: Arc<CrossDomainState>,
    pub(crate) item_state: CrossDomainItemState,
    fence_handler: RutabagaFenceHandler,
}

pub(crate) struct CrossDomainContext {
    #[allow(dead_code)] // `channels` is unused on Windows.
    pub(crate) channels: Option<Vec<RutabagaChannel>>,
    gralloc: Arc<Mutex<RutabagaGralloc>>,
    pub(crate) state: Option<Arc<CrossDomainState>>,
    pub(crate) context_resources: CrossDomainResources,
    pub(crate) item_state: CrossDomainItemState,
    fence_handler: RutabagaFenceHandler,
    worker_thread: Option<thread::JoinHandle<RutabagaResult<()>>>,
    pub(crate) resample_evt: Option<Event>,
    kill_evt: Option<Event>,
}

/// The CrossDomain component contains a list of channels that the guest may connect to and the
/// ability to allocate memory.
pub struct CrossDomain {
    channels: Option<Vec<RutabagaChannel>>,
    gralloc: Arc<Mutex<RutabagaGralloc>>,
}

// TODO(gurchetansingh): optimize the item tracker.  Each requirements blob is long-lived and can
// be stored in a Slab or vector.  Descriptors received from the Wayland socket *seem* to come one
// at a time, and can be stored as options.  Need to confirm.
pub(crate) fn add_item(item_state: &CrossDomainItemState, item: CrossDomainItem) -> u32 {
    let mut items = item_state.lock().unwrap();

    let item_id = match item {
        CrossDomainItem::ImageRequirements(_) => {
            items.requirements_blob_id += 2;
            items.requirements_blob_id
        }
        _ => {
            items.descriptor_id += 2;
            items.descriptor_id
        }
    };

    items.table.insert(item_id, item);

    item_id
}

impl Default for CrossDomainItems {
    fn default() -> Self {
        // Odd for descriptors, and even for requirement blobs.
        CrossDomainItems {
            descriptor_id: 1,
            requirements_blob_id: 2,
            table: Default::default(),
        }
    }
}

impl CrossDomainState {
    fn new(
        ring_id: u32,
        context_resources: CrossDomainResources,
        connection: Option<SystemStream>,
    ) -> CrossDomainState {
        CrossDomainState {
            ring_id,
            context_resources,
            connection,
            jobs: Mutex::new(Some(VecDeque::new())),
            jobs_cvar: Condvar::new(),
        }
    }

    pub(crate) fn add_job(&self, job: CrossDomainJob) {
        let mut jobs = self.jobs.lock().unwrap();
        if let Some(queue) = jobs.as_mut() {
            queue.push_back(job);
            self.jobs_cvar.notify_one();
        }
    }

    fn end_jobs(&self) {
        let mut jobs = self.jobs.lock().unwrap();
        *jobs = None;
        // Only one worker thread in the current implementation.
        self.jobs_cvar.notify_one();
    }

    fn wait_for_job(&self) -> Option<CrossDomainJob> {
        let mut jobs = self.jobs.lock().unwrap();
        loop {
            match jobs.as_mut()?.pop_front() {
                Some(job) => return Some(job),
                None => jobs = self.jobs_cvar.wait(jobs).unwrap(),
            }
        }
    }

    fn write_to_ring<T>(&self, mut ring_write: RingWrite<T>) -> RutabagaResult<usize>
    where
        T: DataInit,
    {
        let mut context_resources = self.context_resources.lock().unwrap();
        let mut bytes_read: usize = 0;

        let resource = context_resources
            .get_mut(&self.ring_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        let iovecs = resource
            .backing_iovecs
            .as_mut()
            .ok_or(RutabagaError::InvalidIovec)?;

        // Safe because we've verified the iovecs are attached and owned only by this context.
        let slice =
            unsafe { VolatileSlice::from_raw_parts(iovecs[0].base as *mut u8, iovecs[0].len) };

        match ring_write {
            RingWrite::Write(cmd, opaque_data_opt) => {
                slice.copy_from(&[cmd]);
                if let Some(opaque_data) = opaque_data_opt {
                    let offset = size_of::<T>();
                    let sub_slice = slice.sub_slice(offset, opaque_data.len())?;
                    let dst_ptr = sub_slice.as_mut_ptr();
                    let src_ptr = opaque_data.as_ptr();

                    // Safe because:
                    //
                    // (1) The volatile slice has atleast `opaque_data.len()' bytes.
                    // (2) The both the destination and source are non-overlapping.
                    unsafe {
                        copy_nonoverlapping(src_ptr, dst_ptr, opaque_data.len());
                    }
                }
            }
            RingWrite::WriteFromFile(mut cmd_read, ref mut file, readable) => {
                let offset = size_of::<CrossDomainReadWrite>();
                let sub_slice = slice.offset(offset)?;

                if readable {
                    bytes_read = file.read_volatile(sub_slice)?;
                }

                if bytes_read == 0 {
                    cmd_read.hang_up = 1;
                }

                cmd_read.opaque_data_size = bytes_read.try_into()?;
                slice.copy_from(&[cmd_read]);
            }
        }

        Ok(bytes_read)
    }
}

impl CrossDomainWorker {
    fn new(
        wait_ctx: WaitContext<CrossDomainToken>,
        state: Arc<CrossDomainState>,
        item_state: CrossDomainItemState,
        fence_handler: RutabagaFenceHandler,
    ) -> CrossDomainWorker {
        CrossDomainWorker {
            wait_ctx,
            state,
            item_state,
            fence_handler,
        }
    }

    // Handles the fence according the the token according to the event token.  On success, a
    // boolean value indicating whether the worker thread should be stopped is returned.
    fn handle_fence(
        &mut self,
        fence: RutabagaFence,
        resample_evt: &Event,
        receive_buf: &mut [u8],
    ) -> RutabagaResult<bool> {
        let events = self.wait_ctx.wait()?;
        let mut stop_thread = false;

        for event in &events {
            match event.token {
                CrossDomainToken::ContextChannel => {
                    let mut descriptors = [0; CROSS_DOMAIN_MAX_IDENTIFIERS];

                    let (len, files) = self.state.receive_msg(receive_buf, &mut descriptors)?;
                    if len != 0 || files.len() != 0 {
                        let mut cmd_receive: CrossDomainSendReceive = Default::default();

                        let num_files = files.len();
                        cmd_receive.hdr.cmd = CROSS_DOMAIN_CMD_RECEIVE;
                        cmd_receive.num_identifiers = files.len().try_into()?;
                        cmd_receive.opaque_data_size = len.try_into()?;

                        let iter = cmd_receive
                            .identifiers
                            .iter_mut()
                            .zip(cmd_receive.identifier_types.iter_mut())
                            .zip(cmd_receive.identifier_sizes.iter_mut())
                            .zip(files.into_iter())
                            .take(num_files);

                        for (((identifier, identifier_type), identifier_size), mut file) in iter {
                            // Safe since the descriptors from receive_msg(..) are owned by us and valid.
                            descriptor_analysis(&mut file, identifier_type, identifier_size)?;

                            *identifier = match *identifier_type {
                                CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB => add_item(
                                    &self.item_state,
                                    CrossDomainItem::WaylandKeymap(file.into()),
                                ),
                                CROSS_DOMAIN_ID_TYPE_WRITE_PIPE => add_item(
                                    &self.item_state,
                                    CrossDomainItem::WaylandWritePipe(file),
                                ),
                                _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                            };
                        }

                        self.state.write_to_ring(RingWrite::Write(
                            cmd_receive,
                            Some(&receive_buf[0..len]),
                        ))?;
                        self.fence_handler.call(fence);
                    }
                }
                CrossDomainToken::Resample => {
                    // The resample event is triggered when the job queue is in the following state:
                    //
                    // [CrossDomain::AddReadPipe(..)] -> END
                    //
                    // After this event, the job queue will be the following state:
                    //
                    // [CrossDomain::AddReadPipe(..)] -> [CrossDomain::HandleFence(..)] -> END
                    //
                    // Fence handling is tied to some new data transfer across a pollable
                    // descriptor.  When we're adding new descriptors, we stop polling.
                    resample_evt.wait()?;
                    self.state.add_job(CrossDomainJob::HandleFence(fence));
                }
                CrossDomainToken::WaylandReadPipe(pipe_id) => {
                    let mut items = self.item_state.lock().unwrap();
                    let mut cmd_read: CrossDomainReadWrite = Default::default();
                    let bytes_read;

                    cmd_read.hdr.cmd = CROSS_DOMAIN_CMD_READ;
                    cmd_read.identifier = pipe_id;

                    let item = items
                        .table
                        .get_mut(&pipe_id)
                        .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

                    match item {
                        CrossDomainItem::WaylandReadPipe(ref mut file) => {
                            let ring_write =
                                RingWrite::WriteFromFile(cmd_read, file, event.is_readable);
                            bytes_read = self
                                .state
                                .write_to_ring::<CrossDomainReadWrite>(ring_write)?;

                            // Zero bytes read indicates end-of-file on POSIX.
                            if event.is_hungup && bytes_read == 0 {
                                self.wait_ctx.delete(file)?;
                            }
                        }
                        _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                    }

                    if event.is_hungup && bytes_read == 0 {
                        items.table.remove(&pipe_id);
                    }

                    self.fence_handler.call(fence);
                }
                CrossDomainToken::Kill => {
                    self.fence_handler.call(fence);
                    stop_thread = true;
                }
            }
        }

        Ok(stop_thread)
    }

    fn run(&mut self, kill_evt: Event, resample_evt: Event) -> RutabagaResult<()> {
        self.wait_ctx
            .add(&resample_evt, CrossDomainToken::Resample)?;
        self.wait_ctx.add(&kill_evt, CrossDomainToken::Kill)?;
        let mut receive_buf: Vec<u8> = vec![0; CROSS_DOMAIN_MAX_SEND_RECV_SIZE];

        while let Some(job) = self.state.wait_for_job() {
            match job {
                CrossDomainJob::HandleFence(fence) => {
                    match self.handle_fence(fence, &resample_evt, &mut receive_buf) {
                        Ok(true) => return Ok(()),
                        Ok(false) => (),
                        Err(e) => {
                            error!("Worker halting due to: {}", e);
                            return Err(e);
                        }
                    }
                }
                CrossDomainJob::AddReadPipe(read_pipe_id) => {
                    let items = self.item_state.lock().unwrap();
                    let item = items
                        .table
                        .get(&read_pipe_id)
                        .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

                    match item {
                        CrossDomainItem::WaylandReadPipe(file) => self
                            .wait_ctx
                            .add(file, CrossDomainToken::WaylandReadPipe(read_pipe_id))?,
                        _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                    }
                }
            }
        }

        Ok(())
    }
}

impl CrossDomain {
    /// Initializes the cross-domain component by taking the the rutabaga channels (if any) and
    /// initializing rutabaga gralloc.
    pub fn init(
        channels: Option<Vec<RutabagaChannel>>,
    ) -> RutabagaResult<Box<dyn RutabagaComponent>> {
        let gralloc = RutabagaGralloc::new()?;
        Ok(Box::new(CrossDomain {
            channels,
            gralloc: Arc::new(Mutex::new(gralloc)),
        }))
    }
}

impl CrossDomainContext {
    fn initialize(&mut self, cmd_init: &CrossDomainInit) -> RutabagaResult<()> {
        if !self
            .context_resources
            .lock()
            .unwrap()
            .contains_key(&cmd_init.ring_id)
        {
            return Err(RutabagaError::InvalidResourceId);
        }

        let ring_id = cmd_init.ring_id;
        let context_resources = self.context_resources.clone();

        // Zero means no requested channel.
        if cmd_init.channel_type != 0 {
            let connection = self.get_connection(cmd_init)?;

            let (kill_evt, thread_kill_evt) = Event::new().and_then(|e| Ok((e.try_clone()?, e)))?;
            let (resample_evt, thread_resample_evt) =
                Event::new().and_then(|e| Ok((e.try_clone()?, e)))?;

            let wait_ctx = match &connection {
                Some(connection) => {
                    WaitContext::build_with(&[(connection, CrossDomainToken::ContextChannel)])?
                }
                None => WaitContext::build_with(&[])?,
            };

            let state = Arc::new(CrossDomainState::new(
                ring_id,
                context_resources,
                connection,
            ));

            let thread_state = state.clone();
            let thread_items = self.item_state.clone();
            let thread_fence_handler = self.fence_handler.clone();

            let worker_result = thread::Builder::new()
                .name("cross domain".to_string())
                .spawn(move || -> RutabagaResult<()> {
                    CrossDomainWorker::new(
                        wait_ctx,
                        thread_state,
                        thread_items,
                        thread_fence_handler,
                    )
                    .run(thread_kill_evt, thread_resample_evt)
                });

            self.worker_thread = Some(worker_result.unwrap());
            self.state = Some(state);
            self.resample_evt = Some(resample_evt);
            self.kill_evt = Some(kill_evt);
        } else {
            self.state = Some(Arc::new(CrossDomainState::new(
                ring_id,
                context_resources,
                None,
            )));
        }

        Ok(())
    }

    fn get_image_requirements(
        &mut self,
        cmd_get_reqs: &CrossDomainGetImageRequirements,
    ) -> RutabagaResult<()> {
        let info = ImageAllocationInfo {
            width: cmd_get_reqs.width,
            height: cmd_get_reqs.height,
            drm_format: DrmFormat::from(cmd_get_reqs.drm_format),
            flags: RutabagaGrallocFlags::new(cmd_get_reqs.flags),
        };

        let reqs = self
            .gralloc
            .lock()
            .unwrap()
            .get_image_memory_requirements(info)?;

        let mut response = CrossDomainImageRequirements {
            strides: reqs.strides,
            offsets: reqs.offsets,
            modifier: reqs.modifier,
            size: reqs.size,
            blob_id: 0,
            map_info: reqs.map_info,
            memory_idx: -1,
            physical_device_idx: -1,
        };

        if let Some(ref vk_info) = reqs.vulkan_info {
            response.memory_idx = vk_info.memory_idx as i32;
            // We return -1 for now since physical_device_idx is deprecated. If this backend is
            // put back into action, it should be using device_id from the request instead.
            response.physical_device_idx = -1;
        }

        if let Some(state) = &self.state {
            response.blob_id = add_item(&self.item_state, CrossDomainItem::ImageRequirements(reqs));
            state.write_to_ring(RingWrite::Write(response, None))?;
            Ok(())
        } else {
            Err(RutabagaError::InvalidCrossDomainState)
        }
    }

    fn write(
        &self,
        cmd_write: &CrossDomainReadWrite,
        opaque_data: VolatileSlice,
    ) -> RutabagaResult<()> {
        let mut items = self.item_state.lock().unwrap();

        // Most of the time, hang-up and writing will be paired.  In lieu of this, remove the
        // item rather than getting a reference.  In case of an error, there's not much to do
        // besides reporting it.
        let item = items
            .table
            .remove(&cmd_write.identifier)
            .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

        let len: usize = cmd_write.opaque_data_size.try_into()?;
        match item {
            CrossDomainItem::WaylandWritePipe(mut file) => {
                if len != 0 {
                    file.write_all_volatile(opaque_data)?;
                }

                if cmd_write.hang_up == 0 {
                    items.table.insert(
                        cmd_write.identifier,
                        CrossDomainItem::WaylandWritePipe(file),
                    );
                }

                Ok(())
            }
            _ => Err(RutabagaError::InvalidCrossDomainItemType),
        }
    }
}

impl Drop for CrossDomainContext {
    fn drop(&mut self) {
        if let Some(state) = &self.state {
            state.end_jobs();
        }

        if let Some(kill_evt) = self.kill_evt.take() {
            // Don't join the the worker thread unless the write to `kill_evt` is successful.
            // Otherwise, this may block indefinitely.
            match kill_evt.signal() {
                Ok(_) => (),
                Err(e) => {
                    error!("failed to write cross domain kill event: {}", e);
                    return;
                }
            }

            if let Some(worker_thread) = self.worker_thread.take() {
                let _ = worker_thread.join();
            }
        }
    }
}

impl RutabagaContext for CrossDomainContext {
    fn context_create_blob(
        &mut self,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        handle_opt: Option<RutabagaHandle>,
    ) -> RutabagaResult<RutabagaResource> {
        let item_id = resource_create_blob.blob_id as u32;

        // We don't want to remove requirements blobs, since they can be used for subsequent
        // allocations.  We do want to remove Wayland keymaps, since they are mapped the guest
        // and then never used again.  The current protocol encodes this as divisiblity by 2.
        if item_id % 2 == 0 {
            let items = self.item_state.lock().unwrap();
            let item = items
                .table
                .get(&item_id)
                .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

            match item {
                CrossDomainItem::ImageRequirements(reqs) => {
                    if reqs.size != resource_create_blob.size {
                        return Err(RutabagaError::SpecViolation("blob size mismatch"));
                    }

                    // Strictly speaking, it's against the virtio-gpu spec to allocate memory in the context
                    // create blob function, which says "the actual allocation is done via
                    // VIRTIO_GPU_CMD_SUBMIT_3D."  However, atomic resource creation is easiest for the
                    // cross-domain use case, so whatever.
                    let hnd = match handle_opt {
                        Some(handle) => handle,
                        None => self.gralloc.lock().unwrap().allocate_memory(*reqs)?,
                    };

                    let info_3d = Resource3DInfo {
                        width: reqs.info.width,
                        height: reqs.info.height,
                        drm_fourcc: reqs.info.drm_format.into(),
                        strides: reqs.strides,
                        offsets: reqs.offsets,
                        modifier: reqs.modifier,
                    };

                    Ok(RutabagaResource {
                        resource_id,
                        handle: Some(Arc::new(hnd)),
                        blob: true,
                        blob_mem: resource_create_blob.blob_mem,
                        blob_flags: resource_create_blob.blob_flags,
                        map_info: Some(reqs.map_info),
                        info_2d: None,
                        info_3d: Some(info_3d),
                        vulkan_info: reqs.vulkan_info,
                        backing_iovecs: None,
                        import_mask: 0,
                    })
                }
                _ => Err(RutabagaError::InvalidCrossDomainItemType),
            }
        } else {
            let item = self
                .item_state
                .lock()
                .unwrap()
                .table
                .remove(&item_id)
                .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

            match item {
                CrossDomainItem::WaylandKeymap(descriptor) => {
                    let hnd = RutabagaHandle {
                        os_handle: descriptor,
                        handle_type: RUTABAGA_MEM_HANDLE_TYPE_SHM,
                    };

                    Ok(RutabagaResource {
                        resource_id,
                        handle: Some(Arc::new(hnd)),
                        blob: true,
                        blob_mem: resource_create_blob.blob_mem,
                        blob_flags: resource_create_blob.blob_flags,
                        map_info: Some(RUTABAGA_MAP_CACHE_CACHED),
                        info_2d: None,
                        info_3d: None,
                        vulkan_info: None,
                        backing_iovecs: None,
                        import_mask: 0,
                    })
                }
                _ => Err(RutabagaError::InvalidCrossDomainItemType),
            }
        }
    }

    fn submit_cmd(&mut self, mut commands: &mut [u8]) -> RutabagaResult<()> {
        while !commands.is_empty() {
            let hdr = CrossDomainHeader::read_from_prefix(commands)
                .ok_or(RutabagaError::InvalidCommandBuffer)?;

            match hdr.cmd {
                CROSS_DOMAIN_CMD_INIT => {
                    let cmd_init = CrossDomainInit::read_from_prefix(commands)
                        .ok_or(RutabagaError::InvalidCommandBuffer)?;

                    self.initialize(&cmd_init)?;
                }
                CROSS_DOMAIN_CMD_GET_IMAGE_REQUIREMENTS => {
                    let cmd_get_reqs = CrossDomainGetImageRequirements::read_from_prefix(commands)
                        .ok_or(RutabagaError::InvalidCommandBuffer)?;

                    self.get_image_requirements(&cmd_get_reqs)?;
                }
                CROSS_DOMAIN_CMD_SEND => {
                    let opaque_data_offset = size_of::<CrossDomainSendReceive>();
                    let cmd_send = CrossDomainSendReceive::read_from_prefix(commands)
                        .ok_or(RutabagaError::InvalidCommandBuffer)?;

                    let opaque_data = VolatileSlice::new(
                        commands
                            .get_mut(
                                opaque_data_offset
                                    ..opaque_data_offset + cmd_send.opaque_data_size as usize,
                            )
                            .ok_or(RutabagaError::InvalidCommandSize(
                                cmd_send.opaque_data_size as usize,
                            ))?,
                    );

                    self.send(&cmd_send, &[opaque_data])?;
                }
                CROSS_DOMAIN_CMD_POLL => {
                    // Actual polling is done in the subsequent when creating a fence.
                }
                CROSS_DOMAIN_CMD_WRITE => {
                    let opaque_data_offset = size_of::<CrossDomainReadWrite>();
                    let cmd_write = CrossDomainReadWrite::read_from_prefix(commands)
                        .ok_or(RutabagaError::InvalidCommandBuffer)?;

                    let opaque_data = VolatileSlice::new(
                        commands
                            .get_mut(
                                opaque_data_offset
                                    ..opaque_data_offset + cmd_write.opaque_data_size as usize,
                            )
                            .ok_or(RutabagaError::InvalidCommandSize(
                                cmd_write.opaque_data_size as usize,
                            ))?,
                    );

                    self.write(&cmd_write, opaque_data)?;
                }
                _ => return Err(RutabagaError::SpecViolation("invalid cross domain command")),
            }

            commands = commands
                .get_mut(hdr.cmd_size as usize..)
                .ok_or(RutabagaError::InvalidCommandSize(hdr.cmd_size as usize))?;
        }

        Ok(())
    }

    fn attach(&mut self, resource: &mut RutabagaResource) {
        if resource.blob_mem == RUTABAGA_BLOB_MEM_GUEST {
            self.context_resources.lock().unwrap().insert(
                resource.resource_id,
                CrossDomainResource {
                    handle: None,
                    backing_iovecs: resource.backing_iovecs.take(),
                },
            );
        } else if let Some(ref handle) = resource.handle {
            self.context_resources.lock().unwrap().insert(
                resource.resource_id,
                CrossDomainResource {
                    handle: Some(handle.clone()),
                    backing_iovecs: None,
                },
            );
        }
    }

    fn detach(&mut self, resource: &RutabagaResource) {
        self.context_resources
            .lock()
            .unwrap()
            .remove(&resource.resource_id);
    }

    fn context_create_fence(&mut self, fence: RutabagaFence) -> RutabagaResult<()> {
        match fence.ring_idx as u32 {
            CROSS_DOMAIN_QUERY_RING => self.fence_handler.call(fence),
            CROSS_DOMAIN_CHANNEL_RING => {
                if let Some(state) = &self.state {
                    state.add_job(CrossDomainJob::HandleFence(fence));
                }
            }
            _ => return Err(RutabagaError::SpecViolation("unexpected ring type")),
        }

        Ok(())
    }

    fn component_type(&self) -> RutabagaComponentType {
        RutabagaComponentType::CrossDomain
    }
}

impl RutabagaComponent for CrossDomain {
    fn get_capset_info(&self, _capset_id: u32) -> (u32, u32) {
        (0u32, size_of::<CrossDomainCapabilities>() as u32)
    }

    fn get_capset(&self, _capset_id: u32, _version: u32) -> Vec<u8> {
        let mut caps: CrossDomainCapabilities = Default::default();
        if let Some(ref channels) = self.channels {
            for channel in channels {
                caps.supported_channels = 1 << channel.channel_type;
            }
        }

        if self.gralloc.lock().unwrap().supports_dmabuf() {
            caps.supports_dmabuf = 1;
        }

        if self.gralloc.lock().unwrap().supports_external_gpu_memory() {
            caps.supports_external_gpu_memory = 1;
        }

        // Version 1 supports all commands up to and including CROSS_DOMAIN_CMD_WRITE.
        caps.version = 1;
        caps.as_slice().to_vec()
    }

    fn create_blob(
        &mut self,
        _ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        iovec_opt: Option<Vec<RutabagaIovec>>,
        _handle_opt: Option<RutabagaHandle>,
    ) -> RutabagaResult<RutabagaResource> {
        if resource_create_blob.blob_mem != RUTABAGA_BLOB_MEM_GUEST
            && resource_create_blob.blob_flags != RUTABAGA_BLOB_FLAG_USE_MAPPABLE
        {
            return Err(RutabagaError::SpecViolation(
                "expected only guest memory blobs",
            ));
        }

        Ok(RutabagaResource {
            resource_id,
            handle: None,
            blob: true,
            blob_mem: resource_create_blob.blob_mem,
            blob_flags: resource_create_blob.blob_flags,
            map_info: None,
            info_2d: None,
            info_3d: None,
            vulkan_info: None,
            backing_iovecs: iovec_opt,
            import_mask: 0,
        })
    }

    fn create_context(
        &self,
        _ctx_id: u32,
        _context_init: u32,
        _context_name: Option<&str>,
        fence_handler: RutabagaFenceHandler,
    ) -> RutabagaResult<Box<dyn RutabagaContext>> {
        Ok(Box::new(CrossDomainContext {
            channels: self.channels.clone(),
            gralloc: self.gralloc.clone(),
            state: None,
            context_resources: Arc::new(Mutex::new(Default::default())),
            item_state: Arc::new(Mutex::new(Default::default())),
            fence_handler,
            worker_thread: None,
            resample_evt: None,
            kill_evt: None,
        }))
    }
}
