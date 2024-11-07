// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The cross-domain component type, specialized for allocating and sharing resources across domain
//! boundaries.

use std::cmp::max;
use std::collections::BTreeMap as Map;
use std::collections::VecDeque;
use std::convert::TryInto;
use std::mem::size_of;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::thread;

use log::error;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::cross_domain::cross_domain_protocol::*;
use crate::rutabaga_core::RutabagaComponent;
use crate::rutabaga_core::RutabagaContext;
use crate::rutabaga_core::RutabagaResource;
use crate::rutabaga_os::create_pipe;
use crate::rutabaga_os::AsBorrowedDescriptor;
use crate::rutabaga_os::AsRawDescriptor;
use crate::rutabaga_os::DescriptorType;
use crate::rutabaga_os::Event;
use crate::rutabaga_os::IntoRawDescriptor;
use crate::rutabaga_os::OwnedDescriptor;
use crate::rutabaga_os::RawDescriptor;
use crate::rutabaga_os::ReadPipe;
use crate::rutabaga_os::Tube;
use crate::rutabaga_os::TubeType;
use crate::rutabaga_os::WaitContext;
use crate::rutabaga_os::WritePipe;
use crate::rutabaga_os::DEFAULT_RAW_DESCRIPTOR;
use crate::rutabaga_utils::*;
use crate::DrmFormat;
use crate::ImageAllocationInfo;
use crate::ImageMemoryRequirements;
use crate::RutabagaGralloc;
use crate::RutabagaGrallocBackendFlags;
use crate::RutabagaGrallocFlags;

mod cross_domain_protocol;

const CROSS_DOMAIN_CONTEXT_CHANNEL_ID: u64 = 1;
const CROSS_DOMAIN_RESAMPLE_ID: u64 = 2;
const CROSS_DOMAIN_KILL_ID: u64 = 3;

const CROSS_DOMAIN_DEFAULT_BUFFER_SIZE: usize = 4096;
const CROSS_DOMAIN_MAX_SEND_RECV_SIZE: usize =
    CROSS_DOMAIN_DEFAULT_BUFFER_SIZE - size_of::<CrossDomainSendReceive>();

enum CrossDomainItem {
    ImageRequirements(ImageMemoryRequirements),
    WaylandKeymap(OwnedDescriptor),
    WaylandReadPipe(ReadPipe),
    WaylandWritePipe(WritePipe),
}

enum CrossDomainJob {
    HandleFence(RutabagaFence),
    AddReadPipe(u32),
    Finish,
}

enum RingWrite<'a, T> {
    Write(T, Option<&'a [u8]>),
    WriteFromPipe(CrossDomainReadWrite, &'a mut ReadPipe, bool),
}

type CrossDomainResources = Arc<Mutex<Map<u32, CrossDomainResource>>>;
type CrossDomainJobs = Mutex<Option<VecDeque<CrossDomainJob>>>;
type CrossDomainItemState = Arc<Mutex<CrossDomainItems>>;

struct CrossDomainResource {
    handle: Option<Arc<RutabagaHandle>>,
    backing_iovecs: Option<Vec<RutabagaIovec>>,
}

struct CrossDomainItems {
    descriptor_id: u32,
    requirements_blob_id: u32,
    read_pipe_id: u32,
    table: Map<u32, CrossDomainItem>,
}

struct CrossDomainState {
    context_resources: CrossDomainResources,
    query_ring_id: u32,
    channel_ring_id: u32,
    connection: Option<Tube>,
    jobs: CrossDomainJobs,
    jobs_cvar: Condvar,
}

struct CrossDomainWorker {
    wait_ctx: WaitContext,
    state: Arc<CrossDomainState>,
    item_state: CrossDomainItemState,
    fence_handler: RutabagaFenceHandler,
}

struct CrossDomainContext {
    channels: Option<Vec<RutabagaChannel>>,
    gralloc: Arc<Mutex<RutabagaGralloc>>,
    state: Option<Arc<CrossDomainState>>,
    context_resources: CrossDomainResources,
    item_state: CrossDomainItemState,
    fence_handler: RutabagaFenceHandler,
    worker_thread: Option<thread::JoinHandle<RutabagaResult<()>>>,
    resample_evt: Option<Event>,
    kill_evt: Option<Event>,
}

/// The CrossDomain component contains a list of channels that the guest may connect to and the
/// ability to allocate memory.
pub struct CrossDomain {
    channels: Option<Vec<RutabagaChannel>>,
    gralloc: Arc<Mutex<RutabagaGralloc>>,
    fence_handler: RutabagaFenceHandler,
}

// TODO(gurchetansingh): optimize the item tracker.  Each requirements blob is long-lived and can
// be stored in a Slab or vector.  OwnedDescriptors received from the Wayland socket *seem* to come
// one at a time, and can be stored as options.  Need to confirm.
fn add_item(item_state: &CrossDomainItemState, item: CrossDomainItem) -> u32 {
    let mut items = item_state.lock().unwrap();

    let item_id = match item {
        CrossDomainItem::ImageRequirements(_) => {
            items.requirements_blob_id += 2;
            items.requirements_blob_id
        }
        CrossDomainItem::WaylandReadPipe(_) => {
            items.read_pipe_id += 1;
            max(items.read_pipe_id, CROSS_DOMAIN_PIPE_READ_START)
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
            read_pipe_id: CROSS_DOMAIN_PIPE_READ_START,
            table: Default::default(),
        }
    }
}

impl CrossDomainState {
    fn new(
        query_ring_id: u32,
        channel_ring_id: u32,
        context_resources: CrossDomainResources,
        connection: Option<Tube>,
    ) -> CrossDomainState {
        CrossDomainState {
            query_ring_id,
            channel_ring_id,
            context_resources,
            connection,
            jobs: Mutex::new(Some(VecDeque::new())),
            jobs_cvar: Condvar::new(),
        }
    }

    fn send_msg(&self, opaque_data: &[u8], descriptors: &[RawDescriptor]) -> RutabagaResult<usize> {
        match self.connection {
            Some(ref connection) => connection.send(opaque_data, descriptors),
            None => Err(RutabagaError::InvalidCrossDomainChannel),
        }
    }

    fn receive_msg(&self, opaque_data: &mut [u8]) -> RutabagaResult<(usize, Vec<OwnedDescriptor>)> {
        match self.connection {
            Some(ref connection) => connection.receive(opaque_data),
            None => Err(RutabagaError::InvalidCrossDomainChannel),
        }
    }

    fn add_job(&self, job: CrossDomainJob) {
        let mut jobs = self.jobs.lock().unwrap();
        if let Some(queue) = jobs.as_mut() {
            queue.push_back(job);
            self.jobs_cvar.notify_one();
        }
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

    fn write_to_ring<T>(&self, mut ring_write: RingWrite<T>, ring_id: u32) -> RutabagaResult<usize>
    where
        T: FromBytes + AsBytes,
    {
        let mut context_resources = self.context_resources.lock().unwrap();
        let mut bytes_read: usize = 0;

        let resource = context_resources
            .get_mut(&ring_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        let iovecs = resource
            .backing_iovecs
            .as_mut()
            .ok_or(RutabagaError::InvalidIovec)?;
        let slice =
            // SAFETY:
            // Safe because we've verified the iovecs are attached and owned only by this context.
            unsafe { std::slice::from_raw_parts_mut(iovecs[0].base as *mut u8, iovecs[0].len) };

        match ring_write {
            RingWrite::Write(cmd, opaque_data_opt) => {
                if slice.len() < size_of::<T>() {
                    return Err(RutabagaError::InvalidIovec);
                }
                let (cmd_slice, opaque_data_slice) = slice.split_at_mut(size_of::<T>());
                cmd_slice.copy_from_slice(cmd.as_bytes());
                if let Some(opaque_data) = opaque_data_opt {
                    if opaque_data_slice.len() < opaque_data.len() {
                        return Err(RutabagaError::InvalidIovec);
                    }
                    opaque_data_slice[..opaque_data.len()].copy_from_slice(opaque_data);
                }
            }
            RingWrite::WriteFromPipe(mut cmd_read, ref mut read_pipe, readable) => {
                if slice.len() < size_of::<CrossDomainReadWrite>() {
                    return Err(RutabagaError::InvalidIovec);
                }

                let (cmd_slice, opaque_data_slice) =
                    slice.split_at_mut(size_of::<CrossDomainReadWrite>());

                if readable {
                    bytes_read = read_pipe.read(opaque_data_slice)?;
                }

                if bytes_read == 0 {
                    cmd_read.hang_up = 1;
                }

                cmd_read.opaque_data_size = bytes_read.try_into()?;
                cmd_slice.copy_from_slice(cmd_read.as_bytes());
            }
        }

        Ok(bytes_read)
    }
}

impl CrossDomainWorker {
    fn new(
        wait_ctx: WaitContext,
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
        thread_resample_evt: &Event,
        receive_buf: &mut [u8],
    ) -> RutabagaResult<()> {
        let events = self.wait_ctx.wait(None)?;

        // The worker thread must:
        //
        // (1) Poll the ContextChannel (usually Wayland)
        // (2) Poll a number of WaylandReadPipes
        // (3) handle jobs from the virtio-gpu thread.
        //
        // We can only process one event at a time, because each `handle_fence` call is associated
        // with a guest virtio-gpu fence.  Signaling the fence means it's okay for the guest to
        // access ring data.  If two events are available at the same time (say a ContextChannel
        // event and a WaylandReadPipe event), and we write responses for both using the same guest
        // fence data, that will break the expected order of events.  We need the guest to generate
        // a new fence before we can resume polling.
        //
        // The CrossDomainJob queue gurantees a new fence has been generated before polling is
        // resumed.
        if let Some(event) = events.first() {
            match event.connection_id {
                CROSS_DOMAIN_CONTEXT_CHANNEL_ID => {
                    let (len, descriptors) = self.state.receive_msg(receive_buf)?;
                    if len != 0 || !descriptors.is_empty() {
                        let mut cmd_receive: CrossDomainSendReceive = Default::default();

                        let num_descriptors = descriptors.len();
                        cmd_receive.hdr.cmd = CROSS_DOMAIN_CMD_RECEIVE;
                        cmd_receive.num_identifiers = descriptors.len().try_into()?;
                        cmd_receive.opaque_data_size = len.try_into()?;

                        let iter = cmd_receive
                            .identifiers
                            .iter_mut()
                            .zip(cmd_receive.identifier_types.iter_mut())
                            .zip(cmd_receive.identifier_sizes.iter_mut())
                            .zip(descriptors)
                            .take(num_descriptors);

                        for (((identifier, identifier_type), identifier_size), descriptor) in iter {
                            *identifier = match descriptor.determine_type() {
                                Ok(DescriptorType::Memory(size)) => {
                                    *identifier_type = CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB;
                                    *identifier_size = size;
                                    add_item(
                                        &self.item_state,
                                        CrossDomainItem::WaylandKeymap(descriptor),
                                    )
                                }
                                Ok(DescriptorType::WritePipe) => {
                                    *identifier_type = CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB;
                                    add_item(
                                        &self.item_state,
                                        CrossDomainItem::WaylandWritePipe(WritePipe::new(
                                            descriptor.into_raw_descriptor(),
                                        )),
                                    )
                                }
                                _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                            };
                        }

                        self.state.write_to_ring(
                            RingWrite::Write(cmd_receive, Some(&receive_buf[0..len])),
                            self.state.channel_ring_id,
                        )?;
                        self.fence_handler.call(fence);
                    }
                }
                CROSS_DOMAIN_RESAMPLE_ID => {
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
                    thread_resample_evt.wait()?;
                    self.state.add_job(CrossDomainJob::HandleFence(fence));
                }
                CROSS_DOMAIN_KILL_ID => {
                    self.fence_handler.call(fence);
                }
                _ => {
                    let mut items = self.item_state.lock().unwrap();
                    let mut cmd_read: CrossDomainReadWrite = Default::default();
                    let pipe_id: u32 = event.connection_id.try_into()?;
                    let bytes_read;

                    cmd_read.hdr.cmd = CROSS_DOMAIN_CMD_READ;
                    cmd_read.identifier = pipe_id;

                    let item = items
                        .table
                        .get_mut(&pipe_id)
                        .ok_or(RutabagaError::InvalidCrossDomainItemId)?;

                    match item {
                        CrossDomainItem::WaylandReadPipe(ref mut readpipe) => {
                            let ring_write =
                                RingWrite::WriteFromPipe(cmd_read, readpipe, event.readable);
                            bytes_read = self.state.write_to_ring::<CrossDomainReadWrite>(
                                ring_write,
                                self.state.channel_ring_id,
                            )?;

                            // Zero bytes read indicates end-of-file on POSIX.
                            if event.hung_up && bytes_read == 0 {
                                self.wait_ctx.delete(readpipe.as_borrowed_descriptor())?;
                            }
                        }
                        _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                    }

                    if event.hung_up && bytes_read == 0 {
                        items.table.remove(&pipe_id);
                    }

                    self.fence_handler.call(fence);
                }
            }
        }

        Ok(())
    }

    fn run(&mut self, thread_kill_evt: Event, thread_resample_evt: Event) -> RutabagaResult<()> {
        self.wait_ctx.add(
            CROSS_DOMAIN_RESAMPLE_ID,
            thread_resample_evt.as_borrowed_descriptor(),
        )?;
        self.wait_ctx.add(
            CROSS_DOMAIN_KILL_ID,
            thread_kill_evt.as_borrowed_descriptor(),
        )?;
        let mut receive_buf: Vec<u8> = vec![0; CROSS_DOMAIN_MAX_SEND_RECV_SIZE];

        while let Some(job) = self.state.wait_for_job() {
            match job {
                CrossDomainJob::HandleFence(fence) => {
                    match self.handle_fence(fence, &thread_resample_evt, &mut receive_buf) {
                        Ok(()) => (),
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
                        CrossDomainItem::WaylandReadPipe(read_pipe) => self
                            .wait_ctx
                            .add(read_pipe_id as u64, read_pipe.as_borrowed_descriptor())?,
                        _ => return Err(RutabagaError::InvalidCrossDomainItemType),
                    }
                }
                CrossDomainJob::Finish => return Ok(()),
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
        fence_handler: RutabagaFenceHandler,
    ) -> RutabagaResult<Box<dyn RutabagaComponent>> {
        let gralloc = RutabagaGralloc::new(RutabagaGrallocBackendFlags::new())?;
        Ok(Box::new(CrossDomain {
            channels,
            gralloc: Arc::new(Mutex::new(gralloc)),
            fence_handler,
        }))
    }
}

impl CrossDomainContext {
    fn get_connection(&mut self, cmd_init: &CrossDomainInit) -> RutabagaResult<Tube> {
        let channels = self
            .channels
            .take()
            .ok_or(RutabagaError::InvalidCrossDomainChannel)?;
        let base_channel = &channels
            .iter()
            .find(|channel| channel.channel_type == cmd_init.channel_type)
            .ok_or(RutabagaError::InvalidCrossDomainChannel)?
            .base_channel;

        Tube::new(base_channel.clone(), TubeType::Stream)
    }

    fn initialize(&mut self, cmd_init: &CrossDomainInit) -> RutabagaResult<()> {
        if !self
            .context_resources
            .lock()
            .unwrap()
            .contains_key(&cmd_init.query_ring_id)
        {
            return Err(RutabagaError::InvalidResourceId);
        }

        let query_ring_id = cmd_init.query_ring_id;
        let channel_ring_id = cmd_init.channel_ring_id;
        let context_resources = self.context_resources.clone();

        // Zero means no requested channel.
        if cmd_init.channel_type != 0 {
            if !self
                .context_resources
                .lock()
                .unwrap()
                .contains_key(&cmd_init.channel_ring_id)
            {
                return Err(RutabagaError::InvalidResourceId);
            }

            let connection = self.get_connection(cmd_init)?;

            let kill_evt = Event::new()?;
            let thread_kill_evt = kill_evt.try_clone()?;

            let resample_evt = Event::new()?;
            let thread_resample_evt = resample_evt.try_clone()?;

            let mut wait_ctx = WaitContext::new()?;
            wait_ctx.add(
                CROSS_DOMAIN_CONTEXT_CHANNEL_ID,
                connection.as_borrowed_descriptor(),
            )?;

            let state = Arc::new(CrossDomainState::new(
                query_ring_id,
                channel_ring_id,
                context_resources,
                Some(connection),
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
                query_ring_id,
                channel_ring_id,
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
            state.write_to_ring(RingWrite::Write(response, None), state.query_ring_id)?;
            Ok(())
        } else {
            Err(RutabagaError::InvalidCrossDomainState)
        }
    }

    fn send(
        &mut self,
        cmd_send: &CrossDomainSendReceive,
        opaque_data: &[u8],
    ) -> RutabagaResult<()> {
        let mut descriptors: [RawDescriptor; CROSS_DOMAIN_MAX_IDENTIFIERS] =
            [DEFAULT_RAW_DESCRIPTOR; CROSS_DOMAIN_MAX_IDENTIFIERS];

        let mut write_pipe_opt: Option<WritePipe> = None;
        let mut read_pipe_id_opt: Option<u32> = None;

        let num_identifiers = cmd_send.num_identifiers.try_into()?;

        if num_identifiers > CROSS_DOMAIN_MAX_IDENTIFIERS {
            return Err(RutabagaError::SpecViolation(
                "max cross domain identifiers exceeded",
            ));
        }

        let iter = cmd_send
            .identifiers
            .iter()
            .zip(cmd_send.identifier_types.iter())
            .zip(descriptors.iter_mut())
            .take(num_identifiers);

        for ((identifier, identifier_type), descriptor) in iter {
            if *identifier_type == CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB {
                let context_resources = self.context_resources.lock().unwrap();

                let context_resource = context_resources
                    .get(identifier)
                    .ok_or(RutabagaError::InvalidResourceId)?;

                if let Some(ref handle) = context_resource.handle {
                    *descriptor = handle.os_handle.as_raw_descriptor();
                } else {
                    return Err(RutabagaError::InvalidRutabagaHandle);
                }
            } else if *identifier_type == CROSS_DOMAIN_ID_TYPE_READ_PIPE {
                // In practice, just 1 pipe pair per send is observed.  If we encounter
                // more, this can be changed later.
                if write_pipe_opt.is_some() {
                    return Err(RutabagaError::SpecViolation("expected just one pipe pair"));
                }

                let (read_pipe, write_pipe) = create_pipe()?;

                *descriptor = write_pipe.as_raw_descriptor();
                let read_pipe_id: u32 = add_item(
                    &self.item_state,
                    CrossDomainItem::WaylandReadPipe(read_pipe),
                );

                // For Wayland read pipes, the guest guesses which identifier the host will use to
                // avoid waiting for the host to generate one.  Validate guess here.  This works
                // because of the way Sommelier copy + paste works.  If the Sommelier sequence of
                // events changes, it's always possible to wait for the host
                // response.
                if read_pipe_id != *identifier {
                    return Err(RutabagaError::InvalidCrossDomainItemId);
                }

                // The write pipe needs to be dropped after the send_msg(..) call is complete, so
                // the read pipe can receive subsequent hang-up events.
                write_pipe_opt = Some(write_pipe);
                read_pipe_id_opt = Some(read_pipe_id);
            } else {
                // Don't know how to handle anything else yet.
                return Err(RutabagaError::InvalidCrossDomainItemType);
            }
        }

        if let (Some(state), Some(ref mut resample_evt)) = (&self.state, &mut self.resample_evt) {
            state.send_msg(opaque_data, &descriptors[..num_identifiers])?;

            if let Some(read_pipe_id) = read_pipe_id_opt {
                state.add_job(CrossDomainJob::AddReadPipe(read_pipe_id));
                resample_evt.signal()?;
            }
        } else {
            return Err(RutabagaError::InvalidCrossDomainState);
        }

        Ok(())
    }

    fn write(&self, cmd_write: &CrossDomainReadWrite, opaque_data: &[u8]) -> RutabagaResult<()> {
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
            CrossDomainItem::WaylandWritePipe(write_pipe) => {
                if len != 0 {
                    write_pipe.write(opaque_data)?;
                }

                if cmd_write.hang_up == 0 {
                    items.table.insert(
                        cmd_write.identifier,
                        CrossDomainItem::WaylandWritePipe(write_pipe),
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
            state.add_job(CrossDomainJob::Finish);
        }

        if let Some(mut kill_evt) = self.kill_evt.take() {
            // Log the error, but still try to join the worker thread
            match kill_evt.signal() {
                Ok(_) => (),
                Err(e) => {
                    error!("failed to write cross domain kill event: {}", e);
                }
            }

            if let Some(worker_thread) = self.worker_thread.take() {
                let _ = worker_thread.join();
            }
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default, AsBytes, FromZeroes, FromBytes)]
struct CrossDomainInitLegacy {
    hdr: CrossDomainHeader,
    query_ring_id: u32,
    channel_type: u32,
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

                    // Strictly speaking, it's against the virtio-gpu spec to allocate memory in the
                    // context create blob function, which says "the actual
                    // allocation is done via VIRTIO_GPU_CMD_SUBMIT_3D."
                    // However, atomic resource creation is easiest for the
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
                        guest_cpu_mappable: (resource_create_blob.blob_flags
                            & RUTABAGA_BLOB_FLAG_USE_MAPPABLE)
                            != 0,
                    };

                    Ok(RutabagaResource {
                        resource_id,
                        handle: Some(Arc::new(hnd)),
                        blob: true,
                        blob_mem: resource_create_blob.blob_mem,
                        blob_flags: resource_create_blob.blob_flags,
                        map_info: Some(reqs.map_info | RUTABAGA_MAP_ACCESS_RW),
                        info_2d: None,
                        info_3d: Some(info_3d),
                        vulkan_info: reqs.vulkan_info,
                        backing_iovecs: None,
                        component_mask: 1 << (RutabagaComponentType::CrossDomain as u8),
                        size: resource_create_blob.size,
                        mapping: None,
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
                        map_info: Some(RUTABAGA_MAP_CACHE_CACHED | RUTABAGA_MAP_ACCESS_READ),
                        info_2d: None,
                        info_3d: None,
                        vulkan_info: None,
                        backing_iovecs: None,
                        component_mask: 1 << (RutabagaComponentType::CrossDomain as u8),
                        size: resource_create_blob.size,
                        mapping: None,
                    })
                }
                _ => Err(RutabagaError::InvalidCrossDomainItemType),
            }
        }
    }

    fn submit_cmd(
        &mut self,
        mut commands: &mut [u8],
        _fence_ids: &[u64],
        _shareable_fences: Vec<RutabagaHandle>,
    ) -> RutabagaResult<()> {
        while !commands.is_empty() {
            let hdr = CrossDomainHeader::read_from_prefix(commands.as_bytes())
                .ok_or(RutabagaError::InvalidCommandBuffer)?;

            match hdr.cmd {
                CROSS_DOMAIN_CMD_INIT => {
                    let cmd_init = match CrossDomainInit::read_from_prefix(commands.as_bytes()) {
                        Some(cmd_init) => cmd_init,
                        None => {
                            if let Some(cmd_init) =
                                CrossDomainInitLegacy::read_from_prefix(commands.as_bytes())
                            {
                                CrossDomainInit {
                                    hdr: cmd_init.hdr,
                                    query_ring_id: cmd_init.query_ring_id,
                                    channel_ring_id: cmd_init.query_ring_id,
                                    channel_type: cmd_init.channel_type,
                                }
                            } else {
                                return Err(RutabagaError::InvalidCommandBuffer);
                            }
                        }
                    };

                    self.initialize(&cmd_init)?;
                }
                CROSS_DOMAIN_CMD_GET_IMAGE_REQUIREMENTS => {
                    let cmd_get_reqs =
                        CrossDomainGetImageRequirements::read_from_prefix(commands.as_bytes())
                            .ok_or(RutabagaError::InvalidCommandBuffer)?;

                    self.get_image_requirements(&cmd_get_reqs)?;
                }
                CROSS_DOMAIN_CMD_SEND => {
                    let opaque_data_offset = size_of::<CrossDomainSendReceive>();
                    let cmd_send = CrossDomainSendReceive::read_from_prefix(commands.as_bytes())
                        .ok_or(RutabagaError::InvalidCommandBuffer)?;

                    let opaque_data = commands
                        .get_mut(
                            opaque_data_offset
                                ..opaque_data_offset + cmd_send.opaque_data_size as usize,
                        )
                        .ok_or(RutabagaError::InvalidCommandSize(
                            cmd_send.opaque_data_size as usize,
                        ))?;

                    self.send(&cmd_send, opaque_data)?;
                }
                CROSS_DOMAIN_CMD_POLL => {
                    // Actual polling is done in the subsequent when creating a fence.
                }
                CROSS_DOMAIN_CMD_WRITE => {
                    let opaque_data_offset = size_of::<CrossDomainReadWrite>();
                    let cmd_write = CrossDomainReadWrite::read_from_prefix(commands.as_bytes())
                        .ok_or(RutabagaError::InvalidCommandBuffer)?;

                    let opaque_data = commands
                        .get_mut(
                            opaque_data_offset
                                ..opaque_data_offset + cmd_write.opaque_data_size as usize,
                        )
                        .ok_or(RutabagaError::InvalidCommandSize(
                            cmd_write.opaque_data_size as usize,
                        ))?;

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

    fn context_create_fence(
        &mut self,
        fence: RutabagaFence,
    ) -> RutabagaResult<Option<RutabagaHandle>> {
        match fence.ring_idx as u32 {
            CROSS_DOMAIN_QUERY_RING => self.fence_handler.call(fence),
            CROSS_DOMAIN_CHANNEL_RING => {
                if let Some(state) = &self.state {
                    state.add_job(CrossDomainJob::HandleFence(fence));
                }
            }
            _ => return Err(RutabagaError::SpecViolation("unexpected ring type")),
        }

        Ok(None)
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
                caps.supported_channels |= 1 << channel.channel_type;
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
        caps.as_bytes().to_vec()
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
            component_mask: 1 << (RutabagaComponentType::CrossDomain as u8),
            size: resource_create_blob.size,
            mapping: None,
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

    // With "drm/virtio: Conditionally allocate virtio_gpu_fence" in the kernel, global fences for
    // cross-domain aren't created.  However, that change is projected to land in the v6.6 kernel.
    // For older kernels, signal the fence immediately on creation.
    fn create_fence(&mut self, fence: RutabagaFence) -> RutabagaResult<()> {
        self.fence_handler.call(fence);
        Ok(())
    }
}
