// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod edid;
mod parameters;
mod protocol;
mod virtio_gpu;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use base::debug;
use base::error;
#[cfg(unix)]
use base::platform::move_task_to_cgroup;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
#[cfg(windows)]
use base::ReadNotifier;
#[cfg(windows)]
use base::RecvTube;
use base::Result;
use base::SafeDescriptor;
use base::SendTube;
use base::Tube;
use base::VmEventType;
use base::WaitContext;
use base::WorkerThread;
use data_model::*;
pub use gpu_display::EventDevice;
use gpu_display::*;
pub use parameters::GpuParameters;
use rutabaga_gfx::*;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
pub use vm_control::gpu::DisplayMode as GpuDisplayMode;
pub use vm_control::gpu::DisplayParameters as GpuDisplayParameters;
use vm_control::gpu::GpuControlCommand;
use vm_control::gpu::GpuControlResult;
pub use vm_control::gpu::DEFAULT_DISPLAY_HEIGHT;
pub use vm_control::gpu::DEFAULT_DISPLAY_WIDTH;
pub use vm_control::gpu::DEFAULT_REFRESH_RATE;
#[cfg(windows)]
use vm_control::ModifyWaitContext;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;

pub use self::protocol::virtio_gpu_config;
pub use self::protocol::VIRTIO_GPU_F_CONTEXT_INIT;
pub use self::protocol::VIRTIO_GPU_F_CREATE_GUEST_HANDLE;
pub use self::protocol::VIRTIO_GPU_F_EDID;
pub use self::protocol::VIRTIO_GPU_F_FENCE_PASSING;
pub use self::protocol::VIRTIO_GPU_F_RESOURCE_BLOB;
pub use self::protocol::VIRTIO_GPU_F_RESOURCE_UUID;
pub use self::protocol::VIRTIO_GPU_F_VIRGL;
pub use self::protocol::VIRTIO_GPU_SHM_ID_HOST_VISIBLE;
use self::protocol::*;
use self::virtio_gpu::to_rutabaga_descriptor;
pub use self::virtio_gpu::ProcessDisplayResult;
use self::virtio_gpu::VirtioGpu;
use self::virtio_gpu::VirtioGpuSnapshot;
use super::copy_config;
use super::resource_bridge::ResourceRequest;
use super::resource_bridge::ResourceResponse;
use super::DescriptorChain;
use super::DeviceType;
use super::Interrupt;
use super::Queue;
use super::Reader;
use super::SharedMemoryMapper;
use super::SharedMemoryRegion;
use super::VirtioDevice;
use super::Writer;
use crate::PciAddress;

// First queue is for virtio gpu commands. Second queue is for cursor commands, which we expect
// there to be fewer of.
const QUEUE_SIZES: &[u16] = &[512, 16];

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuMode {
    #[serde(rename = "2d", alias = "2D")]
    Mode2D,
    #[cfg(feature = "virgl_renderer")]
    #[serde(rename = "virglrenderer", alias = "3d", alias = "3D")]
    ModeVirglRenderer,
    #[cfg(feature = "gfxstream")]
    #[serde(rename = "gfxstream")]
    ModeGfxstream,
}

impl Default for GpuMode {
    fn default() -> Self {
        #[cfg(all(windows, feature = "gfxstream"))]
        return GpuMode::ModeGfxstream;

        #[cfg(all(unix, feature = "virgl_renderer"))]
        return GpuMode::ModeVirglRenderer;

        #[cfg(not(any(
            all(windows, feature = "gfxstream"),
            all(unix, feature = "virgl_renderer"),
        )))]
        return GpuMode::Mode2D;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GpuWsi {
    #[serde(alias = "vk")]
    Vulkan,
}

#[derive(Copy, Clone, Debug)]
pub struct VirtioScanoutBlobData {
    pub width: u32,
    pub height: u32,
    pub drm_format: DrmFormat,
    pub strides: [u32; 4],
    pub offsets: [u32; 4],
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum VirtioGpuRing {
    Global,
    ContextSpecific { ctx_id: u32, ring_idx: u8 },
}

struct FenceDescriptor {
    ring: VirtioGpuRing,
    fence_id: u64,
    desc_chain: DescriptorChain,
    len: u32,
}

#[derive(Default)]
pub struct FenceState {
    descs: Vec<FenceDescriptor>,
    completed_fences: BTreeMap<VirtioGpuRing, u64>,
}

#[derive(Serialize, Deserialize)]
struct FenceStateSnapshot {
    completed_fences: BTreeMap<VirtioGpuRing, u64>,
}

impl FenceState {
    fn snapshot(&self) -> FenceStateSnapshot {
        assert!(self.descs.is_empty(), "can't snapshot with pending fences");
        FenceStateSnapshot {
            completed_fences: self.completed_fences.clone(),
        }
    }

    fn restore(&mut self, snapshot: FenceStateSnapshot) {
        assert!(self.descs.is_empty(), "can't restore activated device");
        self.completed_fences = snapshot.completed_fences;
    }
}

pub trait QueueReader {
    fn pop(&self) -> Option<DescriptorChain>;
    fn add_used(&self, desc_chain: DescriptorChain, len: u32);
    fn signal_used(&self);
}

struct LocalQueueReader {
    queue: RefCell<Queue>,
    interrupt: Interrupt,
}

impl LocalQueueReader {
    fn new(queue: Queue, interrupt: Interrupt) -> Self {
        Self {
            queue: RefCell::new(queue),
            interrupt,
        }
    }
}

impl QueueReader for LocalQueueReader {
    fn pop(&self) -> Option<DescriptorChain> {
        self.queue.borrow_mut().pop()
    }

    fn add_used(&self, desc_chain: DescriptorChain, len: u32) {
        self.queue.borrow_mut().add_used(desc_chain, len)
    }

    fn signal_used(&self) {
        self.queue.borrow_mut().trigger_interrupt(&self.interrupt);
    }
}

#[derive(Clone)]
struct SharedQueueReader {
    queue: Arc<Mutex<Queue>>,
    interrupt: Interrupt,
}

impl SharedQueueReader {
    fn new(queue: Queue, interrupt: Interrupt) -> Self {
        Self {
            queue: Arc::new(Mutex::new(queue)),
            interrupt,
        }
    }
}

impl QueueReader for SharedQueueReader {
    fn pop(&self) -> Option<DescriptorChain> {
        self.queue.lock().pop()
    }

    fn add_used(&self, desc_chain: DescriptorChain, len: u32) {
        self.queue.lock().add_used(desc_chain, len)
    }

    fn signal_used(&self) {
        self.queue.lock().trigger_interrupt(&self.interrupt);
    }
}

/// Initializes the virtio_gpu state tracker.
fn build(
    display_backends: &[DisplayBackend],
    display_params: Vec<GpuDisplayParameters>,
    display_event: Arc<AtomicBool>,
    rutabaga: Rutabaga,
    mapper: Arc<Mutex<Option<Box<dyn SharedMemoryMapper>>>>,
    external_blob: bool,
    #[cfg(windows)] wndproc_thread: &mut Option<WindowProcedureThread>,
    udmabuf: bool,
    #[cfg(windows)] gpu_display_wait_descriptor_ctrl_wr: SendTube,
) -> Option<VirtioGpu> {
    let mut display_opt = None;
    for display_backend in display_backends {
        match display_backend.build(
            #[cfg(windows)]
            wndproc_thread,
            #[cfg(windows)]
            gpu_display_wait_descriptor_ctrl_wr
                .try_clone()
                .expect("failed to clone wait context ctrl channel"),
        ) {
            Ok(c) => {
                display_opt = Some(c);
                break;
            }
            Err(e) => error!("failed to open display: {}", e),
        };
    }

    let display = match display_opt {
        Some(d) => d,
        None => {
            error!("failed to open any displays");
            return None;
        }
    };

    VirtioGpu::new(
        display,
        display_params,
        display_event,
        rutabaga,
        mapper,
        external_blob,
        udmabuf,
    )
}

/// Resources used by the fence handler.
pub struct FenceHandlerActivationResources<Q>
where
    Q: QueueReader + Send + Clone + 'static,
{
    pub mem: GuestMemory,
    pub ctrl_queue: Q,
}

/// Create a handler that writes into the completed fence queue
pub fn create_fence_handler<Q>(
    fence_handler_resources: Arc<Mutex<Option<FenceHandlerActivationResources<Q>>>>,
    fence_state: Arc<Mutex<FenceState>>,
) -> RutabagaFenceHandler
where
    Q: QueueReader + Send + Clone + 'static,
{
    RutabagaFenceHandler::new(move |completed_fence: RutabagaFence| {
        let mut signal = false;

        if let Some(ref fence_handler_resources) = *fence_handler_resources.lock() {
            // Limits the lifetime of `fence_state`:
            {
                let ring = match completed_fence.flags & VIRTIO_GPU_FLAG_INFO_RING_IDX {
                    0 => VirtioGpuRing::Global,
                    _ => VirtioGpuRing::ContextSpecific {
                        ctx_id: completed_fence.ctx_id,
                        ring_idx: completed_fence.ring_idx,
                    },
                };

                let mut fence_state = fence_state.lock();
                // TODO(dverkamp): use `drain_filter()` when it is stabilized
                let mut i = 0;
                while i < fence_state.descs.len() {
                    if fence_state.descs[i].ring == ring
                        && fence_state.descs[i].fence_id <= completed_fence.fence_id
                    {
                        let completed_desc = fence_state.descs.remove(i);
                        fence_handler_resources
                            .ctrl_queue
                            .add_used(completed_desc.desc_chain, completed_desc.len);
                        signal = true;
                    } else {
                        i += 1;
                    }
                }

                // Update the last completed fence for this context
                fence_state
                    .completed_fences
                    .insert(ring, completed_fence.fence_id);
            }

            if signal {
                fence_handler_resources.ctrl_queue.signal_used();
            }
        }
    })
}

pub struct ReturnDescriptor {
    pub desc_chain: DescriptorChain,
    pub len: u32,
}

pub struct Frontend {
    fence_state: Arc<Mutex<FenceState>>,
    virtio_gpu: VirtioGpu,
}

impl Frontend {
    fn new(virtio_gpu: VirtioGpu, fence_state: Arc<Mutex<FenceState>>) -> Frontend {
        Frontend {
            fence_state,
            virtio_gpu,
        }
    }

    /// Returns the internal connection to the compositor and its associated state.
    pub fn display(&mut self) -> &Rc<RefCell<GpuDisplay>> {
        self.virtio_gpu.display()
    }

    /// Processes the internal `display` events and returns `true` if any display was closed.
    pub fn process_display(&mut self) -> ProcessDisplayResult {
        self.virtio_gpu.process_display()
    }

    /// Processes incoming requests on `resource_bridge`.
    pub fn process_resource_bridge(&mut self, resource_bridge: &Tube) -> anyhow::Result<()> {
        let response = match resource_bridge.recv() {
            Ok(ResourceRequest::GetBuffer { id }) => self.virtio_gpu.export_resource(id),
            Ok(ResourceRequest::GetFence { seqno }) => {
                // The seqno originated from self.backend, so it should fit in a u32.
                match u32::try_from(seqno) {
                    Ok(fence_id) => self.virtio_gpu.export_fence(fence_id),
                    Err(_) => ResourceResponse::Invalid,
                }
            }
            Err(e) => return Err(e).context("Error receiving resource bridge request"),
        };

        resource_bridge
            .send(&response)
            .context("Error sending resource bridge response")?;

        Ok(())
    }

    /// Processes the GPU control command and returns the result with a bool indicating if the
    /// GPU device's config needs to be updated.
    pub fn process_gpu_control_command(&mut self, cmd: GpuControlCommand) -> GpuControlResult {
        self.virtio_gpu.process_gpu_control_command(cmd)
    }

    fn process_gpu_command(
        &mut self,
        mem: &GuestMemory,
        cmd: GpuCommand,
        reader: &mut Reader,
    ) -> VirtioGpuResult {
        self.virtio_gpu.force_ctx_0();

        match cmd {
            GpuCommand::GetDisplayInfo(_) => Ok(GpuResponse::OkDisplayInfo(
                self.virtio_gpu.display_info().to_vec(),
            )),
            GpuCommand::ResourceCreate2d(info) => {
                let resource_id = info.resource_id.to_native();

                let resource_create_3d = ResourceCreate3D {
                    target: RUTABAGA_PIPE_TEXTURE_2D,
                    format: info.format.to_native(),
                    bind: RUTABAGA_PIPE_BIND_RENDER_TARGET,
                    width: info.width.to_native(),
                    height: info.height.to_native(),
                    depth: 1,
                    array_size: 1,
                    last_level: 0,
                    nr_samples: 0,
                    flags: 0,
                };

                self.virtio_gpu
                    .resource_create_3d(resource_id, resource_create_3d)
            }
            GpuCommand::ResourceUnref(info) => {
                self.virtio_gpu.unref_resource(info.resource_id.to_native())
            }
            GpuCommand::SetScanout(info) => self.virtio_gpu.set_scanout(
                info.scanout_id.to_native(),
                info.resource_id.to_native(),
                None,
            ),
            GpuCommand::ResourceFlush(info) => {
                self.virtio_gpu.flush_resource(info.resource_id.to_native())
            }
            GpuCommand::TransferToHost2d(info) => {
                let resource_id = info.resource_id.to_native();
                let transfer = Transfer3D::new_2d(
                    info.r.x.to_native(),
                    info.r.y.to_native(),
                    info.r.width.to_native(),
                    info.r.height.to_native(),
                );
                self.virtio_gpu.transfer_write(0, resource_id, transfer)
            }
            GpuCommand::ResourceAttachBacking(info) => {
                let available_bytes = reader.available_bytes();
                if available_bytes != 0 {
                    let entry_count = info.nr_entries.to_native() as usize;
                    let mut vecs = Vec::with_capacity(entry_count);
                    for _ in 0..entry_count {
                        match reader.read_obj::<virtio_gpu_mem_entry>() {
                            Ok(entry) => {
                                let addr = GuestAddress(entry.addr.to_native());
                                let len = entry.length.to_native() as usize;
                                vecs.push((addr, len))
                            }
                            Err(_) => return Err(GpuResponse::ErrUnspec),
                        }
                    }
                    self.virtio_gpu
                        .attach_backing(info.resource_id.to_native(), mem, vecs)
                } else {
                    error!("missing data for command {:?}", cmd);
                    Err(GpuResponse::ErrUnspec)
                }
            }
            GpuCommand::ResourceDetachBacking(info) => {
                self.virtio_gpu.detach_backing(info.resource_id.to_native())
            }
            GpuCommand::UpdateCursor(info) => self.virtio_gpu.update_cursor(
                info.resource_id.to_native(),
                info.pos.scanout_id.to_native(),
                info.pos.x.into(),
                info.pos.y.into(),
            ),
            GpuCommand::MoveCursor(info) => self.virtio_gpu.move_cursor(
                info.pos.scanout_id.to_native(),
                info.pos.x.into(),
                info.pos.y.into(),
            ),
            GpuCommand::ResourceAssignUuid(info) => {
                let resource_id = info.resource_id.to_native();
                self.virtio_gpu.resource_assign_uuid(resource_id)
            }
            GpuCommand::GetCapsetInfo(info) => self
                .virtio_gpu
                .get_capset_info(info.capset_index.to_native()),
            GpuCommand::GetCapset(info) => self
                .virtio_gpu
                .get_capset(info.capset_id.to_native(), info.capset_version.to_native()),
            GpuCommand::CtxCreate(info) => {
                let context_name: Option<String> = String::from_utf8(info.debug_name.to_vec()).ok();
                self.virtio_gpu.create_context(
                    info.hdr.ctx_id.to_native(),
                    info.context_init.to_native(),
                    context_name.as_deref(),
                )
            }
            GpuCommand::CtxDestroy(info) => {
                self.virtio_gpu.destroy_context(info.hdr.ctx_id.to_native())
            }
            GpuCommand::CtxAttachResource(info) => self
                .virtio_gpu
                .context_attach_resource(info.hdr.ctx_id.to_native(), info.resource_id.to_native()),
            GpuCommand::CtxDetachResource(info) => self
                .virtio_gpu
                .context_detach_resource(info.hdr.ctx_id.to_native(), info.resource_id.to_native()),
            GpuCommand::ResourceCreate3d(info) => {
                let resource_id = info.resource_id.to_native();
                let resource_create_3d = ResourceCreate3D {
                    target: info.target.to_native(),
                    format: info.format.to_native(),
                    bind: info.bind.to_native(),
                    width: info.width.to_native(),
                    height: info.height.to_native(),
                    depth: info.depth.to_native(),
                    array_size: info.array_size.to_native(),
                    last_level: info.last_level.to_native(),
                    nr_samples: info.nr_samples.to_native(),
                    flags: info.flags.to_native(),
                };

                self.virtio_gpu
                    .resource_create_3d(resource_id, resource_create_3d)
            }
            GpuCommand::TransferToHost3d(info) => {
                let ctx_id = info.hdr.ctx_id.to_native();
                let resource_id = info.resource_id.to_native();

                let transfer = Transfer3D {
                    x: info.box_.x.to_native(),
                    y: info.box_.y.to_native(),
                    z: info.box_.z.to_native(),
                    w: info.box_.w.to_native(),
                    h: info.box_.h.to_native(),
                    d: info.box_.d.to_native(),
                    level: info.level.to_native(),
                    stride: info.stride.to_native(),
                    layer_stride: info.layer_stride.to_native(),
                    offset: info.offset.to_native(),
                };

                self.virtio_gpu
                    .transfer_write(ctx_id, resource_id, transfer)
            }
            GpuCommand::TransferFromHost3d(info) => {
                let ctx_id = info.hdr.ctx_id.to_native();
                let resource_id = info.resource_id.to_native();

                let transfer = Transfer3D {
                    x: info.box_.x.to_native(),
                    y: info.box_.y.to_native(),
                    z: info.box_.z.to_native(),
                    w: info.box_.w.to_native(),
                    h: info.box_.h.to_native(),
                    d: info.box_.d.to_native(),
                    level: info.level.to_native(),
                    stride: info.stride.to_native(),
                    layer_stride: info.layer_stride.to_native(),
                    offset: info.offset.to_native(),
                };

                self.virtio_gpu
                    .transfer_read(ctx_id, resource_id, transfer, None)
            }
            GpuCommand::CmdSubmit3d(info) => {
                if reader.available_bytes() != 0 {
                    let num_in_fences = info.num_in_fences.to_native() as usize;
                    let cmd_size = info.size.to_native() as usize;
                    let mut cmd_buf = vec![0; cmd_size];
                    let mut fence_ids: Vec<u64> = Vec::with_capacity(num_in_fences);
                    let ctx_id = info.hdr.ctx_id.to_native();

                    for _ in 0..num_in_fences {
                        match reader.read_obj::<Le64>() {
                            Ok(fence_id) => {
                                fence_ids.push(fence_id.to_native());
                            }
                            Err(_) => return Err(GpuResponse::ErrUnspec),
                        }
                    }

                    if reader.read_exact(&mut cmd_buf[..]).is_ok() {
                        self.virtio_gpu
                            .submit_command(ctx_id, &mut cmd_buf[..], &fence_ids[..])
                    } else {
                        Err(GpuResponse::ErrInvalidParameter)
                    }
                } else {
                    // Silently accept empty command buffers to allow for
                    // benchmarking.
                    Ok(GpuResponse::OkNoData)
                }
            }
            GpuCommand::ResourceCreateBlob(info) => {
                let resource_id = info.resource_id.to_native();
                let ctx_id = info.hdr.ctx_id.to_native();

                let resource_create_blob = ResourceCreateBlob {
                    blob_mem: info.blob_mem.to_native(),
                    blob_flags: info.blob_flags.to_native(),
                    blob_id: info.blob_id.to_native(),
                    size: info.size.to_native(),
                };

                let entry_count = info.nr_entries.to_native();
                if reader.available_bytes() == 0 && entry_count > 0 {
                    return Err(GpuResponse::ErrUnspec);
                }

                let mut vecs = Vec::with_capacity(entry_count as usize);
                for _ in 0..entry_count {
                    match reader.read_obj::<virtio_gpu_mem_entry>() {
                        Ok(entry) => {
                            let addr = GuestAddress(entry.addr.to_native());
                            let len = entry.length.to_native() as usize;
                            vecs.push((addr, len))
                        }
                        Err(_) => return Err(GpuResponse::ErrUnspec),
                    }
                }

                self.virtio_gpu.resource_create_blob(
                    ctx_id,
                    resource_id,
                    resource_create_blob,
                    vecs,
                    mem,
                )
            }
            GpuCommand::SetScanoutBlob(info) => {
                let scanout_id = info.scanout_id.to_native();
                let resource_id = info.resource_id.to_native();
                let virtio_gpu_format = info.format.to_native();
                let width = info.width.to_native();
                let height = info.width.to_native();
                let mut strides: [u32; 4] = [0; 4];
                let mut offsets: [u32; 4] = [0; 4];

                // As of v4.19, virtio-gpu kms only really uses these formats.  If that changes,
                // the following may have to change too.
                let drm_format = match virtio_gpu_format {
                    VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM => DrmFormat::new(b'X', b'R', b'2', b'4'),
                    VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM => DrmFormat::new(b'A', b'R', b'2', b'4'),
                    _ => {
                        error!("unrecognized virtio-gpu format {}", virtio_gpu_format);
                        return Err(GpuResponse::ErrUnspec);
                    }
                };

                for plane_index in 0..PLANE_INFO_MAX_COUNT {
                    offsets[plane_index] = info.offsets[plane_index].to_native();
                    strides[plane_index] = info.strides[plane_index].to_native();
                }

                let scanout = VirtioScanoutBlobData {
                    width,
                    height,
                    drm_format,
                    strides,
                    offsets,
                };

                self.virtio_gpu
                    .set_scanout(scanout_id, resource_id, Some(scanout))
            }
            GpuCommand::ResourceMapBlob(info) => {
                let resource_id = info.resource_id.to_native();
                let offset = info.offset.to_native();
                self.virtio_gpu.resource_map_blob(resource_id, offset)
            }
            GpuCommand::ResourceUnmapBlob(info) => {
                let resource_id = info.resource_id.to_native();
                self.virtio_gpu.resource_unmap_blob(resource_id)
            }
            GpuCommand::GetEdid(info) => self.virtio_gpu.get_edid(info.scanout.to_native()),
        }
    }

    /// Processes virtio messages on `queue`.
    pub fn process_queue(&mut self, mem: &GuestMemory, queue: &dyn QueueReader) -> bool {
        let mut signal_used = false;
        while let Some(desc) = queue.pop() {
            if let Some(ret_desc) = self.process_descriptor(mem, desc) {
                queue.add_used(ret_desc.desc_chain, ret_desc.len);
                signal_used = true;
            }
        }

        signal_used
    }

    fn process_descriptor(
        &mut self,
        mem: &GuestMemory,
        mut desc_chain: DescriptorChain,
    ) -> Option<ReturnDescriptor> {
        let reader = &mut desc_chain.reader;
        let writer = &mut desc_chain.writer;
        let mut resp = Err(GpuResponse::ErrUnspec);
        let mut gpu_cmd = None;
        let mut len = 0;
        match GpuCommand::decode(reader) {
            Ok(cmd) => {
                resp = self.process_gpu_command(mem, cmd, reader);
                gpu_cmd = Some(cmd);
            }
            Err(e) => debug!("descriptor decode error: {}", e),
        }

        let mut gpu_response = match resp {
            Ok(gpu_response) => gpu_response,
            Err(gpu_response) => {
                debug!("{:?} -> {:?}", gpu_cmd, gpu_response);
                gpu_response
            }
        };

        if writer.available_bytes() != 0 {
            let mut fence_id = 0;
            let mut ctx_id = 0;
            let mut flags = 0;
            let mut ring_idx = 0;
            if let Some(cmd) = gpu_cmd {
                let ctrl_hdr = cmd.ctrl_hdr();
                if ctrl_hdr.flags.to_native() & VIRTIO_GPU_FLAG_FENCE != 0 {
                    flags = ctrl_hdr.flags.to_native();
                    fence_id = ctrl_hdr.fence_id.to_native();
                    ctx_id = ctrl_hdr.ctx_id.to_native();
                    ring_idx = ctrl_hdr.ring_idx;

                    let fence = RutabagaFence {
                        flags,
                        fence_id,
                        ctx_id,
                        ring_idx,
                    };
                    gpu_response = match self.virtio_gpu.create_fence(fence) {
                        Ok(_) => gpu_response,
                        Err(fence_resp) => {
                            warn!("create_fence {} -> {:?}", fence_id, fence_resp);
                            fence_resp
                        }
                    };
                }
            }

            // Prepare the response now, even if it is going to wait until
            // fence is complete.
            match gpu_response.encode(flags, fence_id, ctx_id, ring_idx, writer) {
                Ok(l) => len = l,
                Err(e) => debug!("ctrl queue response encode error: {}", e),
            }

            if flags & VIRTIO_GPU_FLAG_FENCE != 0 {
                let ring = match flags & VIRTIO_GPU_FLAG_INFO_RING_IDX {
                    0 => VirtioGpuRing::Global,
                    _ => VirtioGpuRing::ContextSpecific { ctx_id, ring_idx },
                };

                // In case the fence is signaled immediately after creation, don't add a return
                // FenceDescriptor.
                let mut fence_state = self.fence_state.lock();
                if fence_id > *fence_state.completed_fences.get(&ring).unwrap_or(&0) {
                    fence_state.descs.push(FenceDescriptor {
                        ring,
                        fence_id,
                        desc_chain,
                        len,
                    });

                    return None;
                }
            }

            // No fence (or already completed fence), respond now.
        }
        Some(ReturnDescriptor { desc_chain, len })
    }

    pub fn event_poll(&self) {
        self.virtio_gpu.event_poll();
    }
}

#[derive(EventToken, PartialEq, Eq, Clone, Copy, Debug)]
enum WorkerToken {
    CtrlQueue,
    CursorQueue,
    Display,
    #[cfg(unix)]
    GpuControl,
    InterruptResample,
    Kill,
    ResourceBridge {
        index: usize,
    },
    VirtioGpuPoll,
    #[cfg(windows)]
    DisplayDescriptorRequest,
}

struct EventManager<'a> {
    pub wait_ctx: WaitContext<WorkerToken>,
    events: Vec<(&'a dyn AsRawDescriptor, WorkerToken)>,
}

impl<'a> EventManager<'a> {
    pub fn new() -> Result<EventManager<'a>> {
        Ok(EventManager {
            wait_ctx: WaitContext::new()?,
            events: vec![],
        })
    }

    pub fn build_with(
        triggers: &[(&'a dyn AsRawDescriptor, WorkerToken)],
    ) -> Result<EventManager<'a>> {
        let mut manager = EventManager::new()?;
        manager.wait_ctx.add_many(triggers)?;

        for (descriptor, token) in triggers {
            manager.events.push((*descriptor, *token));
        }
        Ok(manager)
    }

    pub fn add(&mut self, descriptor: &'a dyn AsRawDescriptor, token: WorkerToken) -> Result<()> {
        self.wait_ctx.add(descriptor, token)?;
        self.events.push((descriptor, token));
        Ok(())
    }

    pub fn delete(&mut self, token: WorkerToken) {
        self.events.retain(|event| {
            if event.1 == token {
                self.wait_ctx.delete(event.0).ok();
                return false;
            }
            true
        });
    }
}

struct Worker {
    interrupt: Interrupt,
    exit_evt_wrtube: SendTube,
    #[cfg(unix)]
    gpu_control_tube: Tube,
    mem: GuestMemory,
    ctrl_queue: SharedQueueReader,
    cursor_queue: LocalQueueReader,
    resource_bridges: ResourceBridges,
    kill_evt: Event,
    state: Frontend,
    #[cfg(windows)]
    gpu_display_wait_descriptor_ctrl_rd: RecvTube,
}

struct WorkerReturn {
    #[cfg(unix)]
    gpu_control_tube: Tube,
    resource_bridges: ResourceBridges,
    event_devices: Vec<EventDevice>,
    // None if device not yet activated.
    activated_state: Option<(Vec<Queue>, WorkerSnapshot)>,
}

#[derive(Serialize, Deserialize)]
struct WorkerSnapshot {
    fence_state_snapshot: FenceStateSnapshot,
    virtio_gpu_snapshot: VirtioGpuSnapshot,
}

impl Worker {
    fn run(&mut self) {
        let display_desc =
            match SafeDescriptor::try_from(&*self.state.display().borrow() as &dyn AsRawDescriptor)
            {
                Ok(v) => v,
                Err(e) => {
                    error!("failed getting event descriptor for display: {}", e);
                    return;
                }
            };

        let ctrl_evt = self
            .ctrl_queue
            .queue
            .lock()
            .event()
            .try_clone()
            .expect("failed to clone queue event");
        let cursor_evt = self
            .cursor_queue
            .queue
            .borrow()
            .event()
            .try_clone()
            .expect("failed to clone queue event");

        let mut event_manager = match EventManager::build_with(&[
            (&ctrl_evt, WorkerToken::CtrlQueue),
            (&cursor_evt, WorkerToken::CursorQueue),
            (&display_desc, WorkerToken::Display),
            #[cfg(unix)]
            (&self.gpu_control_tube, WorkerToken::GpuControl),
            (&self.kill_evt, WorkerToken::Kill),
            #[cfg(windows)]
            (
                self.gpu_display_wait_descriptor_ctrl_rd.get_read_notifier(),
                WorkerToken::DisplayDescriptorRequest,
            ),
        ]) {
            Ok(v) => v,
            Err(e) => {
                error!("failed creating WaitContext: {}", e);
                return;
            }
        };

        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            if let Err(e) = event_manager.add(resample_evt, WorkerToken::InterruptResample) {
                error!(
                    "failed adding interrupt resample event to WaitContext: {}",
                    e
                );
                return;
            }
        }

        let poll_desc: SafeDescriptor;
        if let Some(desc) = self.state.virtio_gpu.poll_descriptor() {
            poll_desc = desc;
            if let Err(e) = event_manager.add(&poll_desc, WorkerToken::VirtioGpuPoll) {
                error!("failed adding poll event to WaitContext: {}", e);
                return;
            }
        }

        self.resource_bridges
            .add_to_wait_context(&mut event_manager.wait_ctx);

        // TODO(davidriley): The entire main loop processing is somewhat racey and incorrect with
        // respect to cursor vs control queue processing.  As both currently and originally
        // written, while the control queue is only processed/read from after the the cursor queue
        // is finished, the entire queue will be processed at that time.  The end effect of this
        // racyiness is that control queue descriptors that are issued after cursors descriptors
        // might be handled first instead of the other way around.  In practice, the cursor queue
        // isn't used so this isn't a huge issue.

        'wait: loop {
            let events = match event_manager.wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };
            let mut signal_used_cursor = false;
            let mut signal_used_ctrl = false;
            let mut ctrl_available = false;
            let mut display_available = false;
            let mut needs_config_interrupt = false;

            // Remove event triggers that have been hung-up to prevent unnecessary worker wake-ups
            // (see b/244486346#comment62 for context).
            for event in events.iter().filter(|e| e.is_hungup) {
                error!(
                    "unhandled virtio-gpu worker event hang-up detected: {:?}",
                    event.token
                );
                event_manager.delete(event.token);
            }

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    WorkerToken::CtrlQueue => {
                        let _ = ctrl_evt.wait();
                        // Set flag that control queue is available to be read, but defer reading
                        // until rest of the events are processed.
                        ctrl_available = true;
                    }
                    WorkerToken::CursorQueue => {
                        let _ = cursor_evt.wait();
                        if self.state.process_queue(&self.mem, &self.cursor_queue) {
                            signal_used_cursor = true;
                        }
                    }
                    WorkerToken::Display => {
                        // We only need to process_display once-per-wake, regardless of how many
                        // WorkerToken::Display events are received.
                        display_available = true;
                    }
                    #[cfg(windows)]
                    WorkerToken::DisplayDescriptorRequest => {
                        if let Ok(req) = self
                            .gpu_display_wait_descriptor_ctrl_rd
                            .recv::<ModifyWaitContext>()
                        {
                            match req {
                                ModifyWaitContext::Add(desc) => {
                                    if let Err(e) =
                                        event_manager.wait_ctx.add(&desc, WorkerToken::Display)
                                    {
                                        error!(
                                            "failed to add extra descriptor from display \
                                             to GPU worker wait context: {:?}",
                                            e
                                        )
                                    }
                                }
                            }
                        } else {
                            error!("failed to receive ModifyWaitContext request.")
                        }
                    }
                    #[cfg(unix)]
                    WorkerToken::GpuControl => {
                        let req = match self.gpu_control_tube.recv() {
                            Ok(req) => req,
                            Err(e) => {
                                error!("gpu control socket failed recv: {:?}", e);
                                break 'wait;
                            }
                        };

                        let resp = self.state.process_gpu_control_command(req);

                        if let GpuControlResult::DisplaysUpdated = resp {
                            needs_config_interrupt = true;
                        }

                        if let Err(e) = self.gpu_control_tube.send(&resp) {
                            error!("display control socket failed send: {}", e);
                            break 'wait;
                        }
                    }
                    WorkerToken::ResourceBridge { index } => {
                        self.resource_bridges.set_should_process(index);
                    }
                    WorkerToken::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    WorkerToken::VirtioGpuPoll => {
                        self.state.event_poll();
                    }
                    WorkerToken::Kill => {
                        break 'wait;
                    }
                }
            }

            if display_available {
                match self.state.process_display() {
                    ProcessDisplayResult::CloseRequested => {
                        let _ = self.exit_evt_wrtube.send::<VmEventType>(&VmEventType::Exit);
                    }
                    ProcessDisplayResult::Error(_e) => {
                        base::error!("Display processing failed, disabling display event handler.");
                        event_manager.delete(WorkerToken::Display);
                    }
                    ProcessDisplayResult::Success => (),
                };
            }

            if ctrl_available && self.state.process_queue(&self.mem, &self.ctrl_queue) {
                signal_used_ctrl = true;
            }

            // Process the entire control queue before the resource bridge in case a resource is
            // created or destroyed by the control queue. Processing the resource bridge first may
            // lead to a race condition.
            // TODO(davidriley): This is still inherently racey if both the control queue request
            // and the resource bridge request come in at the same time after the control queue is
            // processed above and before the corresponding bridge is processed below.
            self.resource_bridges
                .process_resource_bridges(&mut self.state, &mut event_manager.wait_ctx);

            if signal_used_ctrl {
                self.ctrl_queue.signal_used();
            }

            if signal_used_cursor {
                self.cursor_queue.signal_used();
            }

            if needs_config_interrupt {
                self.interrupt.signal_config_changed();
            }
        }
    }
}

/// Indicates a backend that should be tried for the gpu to use for display.
///
/// Several instances of this enum are used in an ordered list to give the gpu device many backends
/// to use as fallbacks in case some do not work.
#[derive(Clone)]
pub enum DisplayBackend {
    #[cfg(unix)]
    /// Use the wayland backend with the given socket path if given.
    Wayland(Option<PathBuf>),
    #[cfg(unix)]
    /// Open a connection to the X server at the given display if given.
    X(Option<String>),
    /// Emulate a display without actually displaying it.
    Stub,
    #[cfg(windows)]
    /// Open a window using WinAPI.
    WinApi(WinDisplayProperties),
}

impl DisplayBackend {
    fn build(
        &self,
        #[cfg(windows)] wndproc_thread: &mut Option<WindowProcedureThread>,
        #[cfg(windows)] gpu_display_wait_descriptor_ctrl: SendTube,
    ) -> std::result::Result<GpuDisplay, GpuDisplayError> {
        match self {
            #[cfg(unix)]
            DisplayBackend::Wayland(path) => GpuDisplay::open_wayland(path.as_ref()),
            #[cfg(unix)]
            DisplayBackend::X(display) => GpuDisplay::open_x(display.as_deref()),
            DisplayBackend::Stub => GpuDisplay::open_stub(),
            #[cfg(windows)]
            DisplayBackend::WinApi(display_properties) => match wndproc_thread.take() {
                Some(wndproc_thread) => GpuDisplay::open_winapi(
                    wndproc_thread,
                    /* win_metrics= */ None,
                    display_properties.clone(),
                    gpu_display_wait_descriptor_ctrl,
                ),
                None => {
                    error!("wndproc_thread is none");
                    Err(GpuDisplayError::Allocate)
                }
            },
        }
    }
}

/// Resources that are not available until the device is activated.
struct GpuActivationResources {
    mem: GuestMemory,
    interrupt: Interrupt,
    ctrl_queue: SharedQueueReader,
    cursor_queue: LocalQueueReader,
    worker_snapshot: Option<WorkerSnapshot>,
}

pub struct Gpu {
    exit_evt_wrtube: SendTube,
    #[cfg(unix)]
    gpu_control_tube: Option<Tube>,
    mapper: Arc<Mutex<Option<Box<dyn SharedMemoryMapper>>>>,
    resource_bridges: Option<ResourceBridges>,
    event_devices: Option<Vec<EventDevice>>,
    // The worker thread + a channel used to activate it.
    // NOTE: The worker thread doesn't respond to `WorkerThread::stop` when in the pre-activate
    // phase. You must drop the channel first. That is also why the channel is first in the tuple
    // (tuple members are dropped in order).
    worker_thread: Option<(
        mpsc::Sender<GpuActivationResources>,
        WorkerThread<WorkerReturn>,
    )>,
    display_backends: Vec<DisplayBackend>,
    display_params: Vec<GpuDisplayParameters>,
    display_event: Arc<AtomicBool>,
    rutabaga_builder: RutabagaBuilder,
    pci_address: Option<PciAddress>,
    pci_bar_size: u64,
    external_blob: bool,
    rutabaga_component: RutabagaComponentType,
    #[cfg(windows)]
    wndproc_thread: Option<WindowProcedureThread>,
    base_features: u64,
    udmabuf: bool,
    rutabaga_server_descriptor: Option<SafeDescriptor>,
    #[cfg(windows)]
    /// Because the Windows GpuDisplay can't expose an epollfd, it has to inform the GPU worker which
    /// descriptors to add to its wait context. That's what this Tube is used for (it is provided
    /// to each display backend.
    gpu_display_wait_descriptor_ctrl_wr: SendTube,
    #[cfg(windows)]
    /// The GPU worker uses this Tube to receive the descriptors that should be added to its wait
    /// context.
    gpu_display_wait_descriptor_ctrl_rd: Option<RecvTube>,
    capset_mask: u64,
    #[cfg(unix)]
    gpu_cgroup_path: Option<PathBuf>,
    /// Used to differentiate worker kill events that are for shutdown vs sleep. `virtio_sleep`
    /// sets this to true while stopping the worker.
    sleep_requested: Arc<AtomicBool>,
    worker_snapshot: Option<WorkerSnapshot>,
}

impl Gpu {
    pub fn new(
        exit_evt_wrtube: SendTube,
        #[cfg(unix)] gpu_control_tube: Tube,
        resource_bridges: Vec<Tube>,
        display_backends: Vec<DisplayBackend>,
        gpu_parameters: &GpuParameters,
        rutabaga_server_descriptor: Option<SafeDescriptor>,
        event_devices: Vec<EventDevice>,
        base_features: u64,
        channels: &BTreeMap<String, PathBuf>,
        #[cfg(windows)] wndproc_thread: WindowProcedureThread,
        #[cfg(unix)] gpu_cgroup_path: Option<&PathBuf>,
    ) -> Gpu {
        let mut display_params = gpu_parameters.display_params.clone();
        if display_params.is_empty() {
            display_params.push(Default::default());
        }
        let (display_width, display_height) = display_params[0].get_virtual_display_size();

        let mut rutabaga_channels: Vec<RutabagaChannel> = Vec::new();
        for (channel_name, path) in channels {
            match &channel_name[..] {
                "" => rutabaga_channels.push(RutabagaChannel {
                    base_channel: path.clone(),
                    channel_type: RUTABAGA_CHANNEL_TYPE_WAYLAND,
                }),
                "mojo" => rutabaga_channels.push(RutabagaChannel {
                    base_channel: path.clone(),
                    channel_type: RUTABAGA_CHANNEL_TYPE_CAMERA,
                }),
                _ => error!("unknown rutabaga channel"),
            }
        }

        let rutabaga_channels_opt = Some(rutabaga_channels);
        let component = match gpu_parameters.mode {
            GpuMode::Mode2D => RutabagaComponentType::Rutabaga2D,
            #[cfg(feature = "virgl_renderer")]
            GpuMode::ModeVirglRenderer => RutabagaComponentType::VirglRenderer,
            #[cfg(feature = "gfxstream")]
            GpuMode::ModeGfxstream => RutabagaComponentType::Gfxstream,
        };

        // Only allow virglrenderer to fork its own render server when explicitly requested.
        // Caller can enforce its own restrictions (e.g. not allowed when sandboxed) and set the
        // allow flag appropriately.
        let use_render_server = rutabaga_server_descriptor.is_some()
            || gpu_parameters.allow_implicit_render_server_exec;

        let rutabaga_wsi = match gpu_parameters.wsi {
            Some(GpuWsi::Vulkan) => RutabagaWsi::VulkanSwapchain,
            _ => RutabagaWsi::Surfaceless,
        };

        let rutabaga_builder = RutabagaBuilder::new(component, gpu_parameters.capset_mask)
            .set_display_width(display_width)
            .set_display_height(display_height)
            .set_rutabaga_channels(rutabaga_channels_opt)
            .set_use_egl(gpu_parameters.renderer_use_egl)
            .set_use_gles(gpu_parameters.renderer_use_gles)
            .set_use_glx(gpu_parameters.renderer_use_glx)
            .set_use_surfaceless(gpu_parameters.renderer_use_surfaceless)
            .set_use_vulkan(gpu_parameters.use_vulkan.unwrap_or_default())
            .set_wsi(rutabaga_wsi)
            .set_use_external_blob(gpu_parameters.external_blob)
            .set_use_system_blob(gpu_parameters.system_blob)
            .set_use_render_server(use_render_server);

        #[cfg(windows)]
        let (gpu_display_wait_descriptor_ctrl_wr, gpu_display_wait_descriptor_ctrl_rd) =
            Tube::directional_pair().expect("failed to create wait descriptor control pair.");

        Gpu {
            exit_evt_wrtube,
            #[cfg(unix)]
            gpu_control_tube: Some(gpu_control_tube),
            mapper: Arc::new(Mutex::new(None)),
            resource_bridges: Some(ResourceBridges::new(resource_bridges)),
            event_devices: Some(event_devices),
            worker_thread: None,
            display_backends,
            display_params,
            display_event: Arc::new(AtomicBool::new(false)),
            rutabaga_builder,
            pci_address: gpu_parameters.pci_address,
            pci_bar_size: gpu_parameters.pci_bar_size,
            external_blob: gpu_parameters.external_blob,
            rutabaga_component: component,
            #[cfg(windows)]
            wndproc_thread: Some(wndproc_thread),
            base_features,
            udmabuf: gpu_parameters.udmabuf,
            rutabaga_server_descriptor,
            #[cfg(windows)]
            gpu_display_wait_descriptor_ctrl_wr,
            #[cfg(windows)]
            gpu_display_wait_descriptor_ctrl_rd: Some(gpu_display_wait_descriptor_ctrl_rd),
            capset_mask: gpu_parameters.capset_mask,
            #[cfg(unix)]
            gpu_cgroup_path: gpu_cgroup_path.cloned(),
            sleep_requested: Arc::new(AtomicBool::new(false)),
            worker_snapshot: None,
        }
    }

    /// Initializes the internal device state so that it can begin processing virtqueues.
    ///
    /// Only used by vhost-user GPU.
    pub fn initialize_frontend(
        &mut self,
        fence_state: Arc<Mutex<FenceState>>,
        fence_handler: RutabagaFenceHandler,
        mapper: Arc<Mutex<Option<Box<dyn SharedMemoryMapper>>>>,
    ) -> Option<Frontend> {
        let rutabaga_server_descriptor = self.rutabaga_server_descriptor.as_ref().map(|d| {
            to_rutabaga_descriptor(d.try_clone().expect("failed to clone server descriptor"))
        });
        let rutabaga = self
            .rutabaga_builder
            .clone()
            .build(fence_handler, rutabaga_server_descriptor)
            .map_err(|e| error!("failed to build rutabaga {}", e))
            .ok()?;

        let mut virtio_gpu = build(
            &self.display_backends,
            self.display_params.clone(),
            self.display_event.clone(),
            rutabaga,
            mapper,
            self.external_blob,
            #[cfg(windows)]
            &mut self.wndproc_thread,
            self.udmabuf,
            #[cfg(windows)]
            self.gpu_display_wait_descriptor_ctrl_wr
                .try_clone()
                .expect("failed to clone wait context control channel"),
        )?;

        for event_device in self.event_devices.take().expect("missing event_devices") {
            virtio_gpu
                .import_event_device(event_device)
                // We lost the `EventDevice`, so fail hard.
                .expect("failed to import event device");
        }

        Some(Frontend::new(virtio_gpu, fence_state))
    }

    // This is not invoked when running with vhost-user GPU.
    fn start_worker_thread(&mut self) {
        let exit_evt_wrtube = self
            .exit_evt_wrtube
            .try_clone()
            .context("error cloning exit tube")
            .unwrap();

        #[cfg(unix)]
        let gpu_control_tube = self
            .gpu_control_tube
            .take()
            .context("gpu_control_tube is none")
            .unwrap();

        let resource_bridges = self
            .resource_bridges
            .take()
            .context("resource_bridges is none")
            .unwrap();

        let display_backends = self.display_backends.clone();
        let display_params = self.display_params.clone();
        let display_event = self.display_event.clone();
        let event_devices = self.event_devices.take().expect("missing event_devices");
        let external_blob = self.external_blob;
        let udmabuf = self.udmabuf;
        let fence_state = Arc::new(Mutex::new(Default::default()));

        #[cfg(windows)]
        let mut wndproc_thread = self.wndproc_thread.take();

        #[cfg(windows)]
        let gpu_display_wait_descriptor_ctrl_wr = self
            .gpu_display_wait_descriptor_ctrl_wr
            .try_clone()
            .expect("failed to clone wait context ctrl channel");

        #[cfg(windows)]
        let gpu_display_wait_descriptor_ctrl_rd = self
            .gpu_display_wait_descriptor_ctrl_rd
            .take()
            .expect("failed to take gpu_display_wait_descriptor_ctrl_rd");

        #[cfg(unix)]
        let gpu_cgroup_path = self.gpu_cgroup_path.clone();

        let mapper = Arc::clone(&self.mapper);

        let rutabaga_builder = self.rutabaga_builder.clone();
        let rutabaga_server_descriptor = self.rutabaga_server_descriptor.as_ref().map(|d| {
            to_rutabaga_descriptor(d.try_clone().expect("failed to clone server descriptor"))
        });

        let (init_finished_tx, init_finished_rx) = mpsc::channel();
        let (activate_tx, activate_rx) = mpsc::channel();
        let sleep_requested = self.sleep_requested.clone();

        let worker_thread = WorkerThread::start("v_gpu", move |kill_evt| {
            #[cfg(unix)]
            if let Some(cgroup_path) = gpu_cgroup_path {
                move_task_to_cgroup(cgroup_path, base::gettid())
                    .expect("Failed to move v_gpu into requested cgroup");
            }

            let rutabaga_fence_handler_resources = Arc::new(Mutex::new(None));
            let rutabaga_fence_handler = create_fence_handler(
                rutabaga_fence_handler_resources.clone(),
                fence_state.clone(),
            );
            let rutabaga =
                match rutabaga_builder.build(rutabaga_fence_handler, rutabaga_server_descriptor) {
                    Ok(rutabaga) => rutabaga,
                    Err(e) => {
                        error!("failed to build rutabaga {}", e);
                        return WorkerReturn {
                            #[cfg(unix)]
                            gpu_control_tube,
                            resource_bridges,
                            event_devices,
                            activated_state: None,
                        };
                    }
                };

            let mut virtio_gpu = match build(
                &display_backends,
                display_params,
                display_event,
                rutabaga,
                mapper,
                external_blob,
                #[cfg(windows)]
                &mut wndproc_thread,
                udmabuf,
                #[cfg(windows)]
                gpu_display_wait_descriptor_ctrl_wr,
            ) {
                Some(backend) => backend,
                None => {
                    return WorkerReturn {
                        #[cfg(unix)]
                        gpu_control_tube,
                        resource_bridges,
                        event_devices,
                        activated_state: None,
                    };
                }
            };

            for event_device in event_devices {
                virtio_gpu
                    .import_event_device(event_device)
                    // We lost the `EventDevice`, so fail hard.
                    .expect("failed to import event device");
            }

            // Tell the parent thread that the init phase is complete.
            let _ = init_finished_tx.send(());

            let activation_resources: GpuActivationResources = match activate_rx.recv() {
                Ok(x) => x,
                // Other half of channel was dropped.
                Err(mpsc::RecvError) => {
                    return WorkerReturn {
                        #[cfg(unix)]
                        gpu_control_tube,
                        resource_bridges,
                        event_devices: virtio_gpu.display().borrow_mut().take_event_devices(),
                        activated_state: None,
                    };
                }
            };

            rutabaga_fence_handler_resources
                .lock()
                .replace(FenceHandlerActivationResources {
                    mem: activation_resources.mem.clone(),
                    ctrl_queue: activation_resources.ctrl_queue.clone(),
                });
            // Drop so we don't hold extra refs on the queue's `Arc`.
            std::mem::drop(rutabaga_fence_handler_resources);

            let mut worker = Worker {
                interrupt: activation_resources.interrupt,
                exit_evt_wrtube,
                #[cfg(unix)]
                gpu_control_tube,
                mem: activation_resources.mem,
                ctrl_queue: activation_resources.ctrl_queue,
                cursor_queue: activation_resources.cursor_queue,
                resource_bridges,
                kill_evt,
                state: Frontend::new(virtio_gpu, fence_state),
                #[cfg(windows)]
                gpu_display_wait_descriptor_ctrl_rd,
            };

            // If a snapshot was provided, restore from it.
            if let Some(snapshot) = activation_resources.worker_snapshot {
                worker
                    .state
                    .fence_state
                    .lock()
                    .restore(snapshot.fence_state_snapshot);
                worker
                    .state
                    .virtio_gpu
                    .restore(snapshot.virtio_gpu_snapshot, &worker.mem)
                    .expect("failed to restore VirtioGpu");
            }

            worker.run();

            let event_devices = worker
                .state
                .virtio_gpu
                .display()
                .borrow_mut()
                .take_event_devices();
            // If we are stopping the worker because of a virtio_sleep request, then take a
            // snapshot and reclaim the queues.
            let activated_state = if sleep_requested.load(Ordering::SeqCst) {
                let worker_snapshot = WorkerSnapshot {
                    fence_state_snapshot: worker.state.fence_state.lock().snapshot(),
                    virtio_gpu_snapshot: worker
                        .state
                        .virtio_gpu
                        .snapshot()
                        .expect("failed to snapshot VirtioGpu"),
                };
                // Need to drop `Frontend` for the `Arc::try_unwrap` below to succeed.
                std::mem::drop(worker.state);
                Some((
                    vec![
                        match Arc::try_unwrap(worker.ctrl_queue.queue) {
                            Ok(x) => x.into_inner(),
                            Err(_) => panic!("too many refs on ctrl_queue"),
                        },
                        worker.cursor_queue.queue.into_inner(),
                    ],
                    worker_snapshot,
                ))
            } else {
                None
            };
            WorkerReturn {
                #[cfg(unix)]
                gpu_control_tube: worker.gpu_control_tube,
                resource_bridges: worker.resource_bridges,
                event_devices,
                activated_state,
            }
        });

        self.worker_thread = Some((activate_tx, worker_thread));

        match init_finished_rx.recv() {
            Ok(()) => {}
            Err(mpsc::RecvError) => error!("virtio-gpu worker thread init failed"),
        }
    }

    fn get_config(&self) -> virtio_gpu_config {
        let mut events_read = 0;

        if self.display_event.load(Ordering::Relaxed) {
            events_read |= VIRTIO_GPU_EVENT_DISPLAY;
        }

        let num_capsets = match self.capset_mask {
            0 => {
                match self.rutabaga_component {
                    RutabagaComponentType::Rutabaga2D => 0,
                    _ => {
                        #[allow(unused_mut)]
                        let mut num_capsets = 0;

                        // Three capsets for virgl_renderer
                        #[cfg(feature = "virgl_renderer")]
                        {
                            num_capsets += 3;
                        }

                        // One capset for gfxstream
                        #[cfg(feature = "gfxstream")]
                        {
                            num_capsets += 1;
                        }

                        num_capsets
                    }
                }
            }
            _ => self.capset_mask.count_ones(),
        };

        virtio_gpu_config {
            events_read: Le32::from(events_read),
            events_clear: Le32::from(0),
            num_scanouts: Le32::from(VIRTIO_GPU_MAX_SCANOUTS as u32),
            num_capsets: Le32::from(num_capsets),
        }
    }

    /// Send a request to exit the process to VMM.
    pub fn send_exit_evt(&self) -> anyhow::Result<()> {
        self.exit_evt_wrtube
            .send::<VmEventType>(&VmEventType::Exit)
            .context("failed to send exit event")
    }
}

impl VirtioDevice for Gpu {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = Vec::new();

        // To find the RawDescriptor associated with stdout and stderr on Windows is difficult.
        // Resource bridges are used only for Wayland displays. There is also no meaningful way
        // casting the underlying DMA buffer wrapped in File to a copyable RawDescriptor.
        // TODO(davidriley): Remove once virgl has another path to include
        // debugging logs.
        #[cfg(unix)]
        if cfg!(debug_assertions) {
            keep_rds.push(libc::STDOUT_FILENO);
            keep_rds.push(libc::STDERR_FILENO);
        }

        if let Some(ref mapper) = *self.mapper.lock() {
            if let Some(descriptor) = mapper.as_raw_descriptor() {
                keep_rds.push(descriptor);
            }
        }

        if let Some(ref rutabaga_server_descriptor) = self.rutabaga_server_descriptor {
            keep_rds.push(rutabaga_server_descriptor.as_raw_descriptor());
        }

        keep_rds.push(self.exit_evt_wrtube.as_raw_descriptor());

        #[cfg(unix)]
        if let Some(gpu_control_tube) = &self.gpu_control_tube {
            keep_rds.push(gpu_control_tube.as_raw_descriptor());
        }

        if let Some(resource_bridges) = &self.resource_bridges {
            resource_bridges.append_raw_descriptors(&mut keep_rds);
        }

        for event_device in self.event_devices.iter().flatten() {
            keep_rds.push(event_device.as_raw_descriptor());
        }

        keep_rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Gpu
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        let mut virtio_gpu_features = 1 << VIRTIO_GPU_F_EDID;

        // If a non-2D component is specified, enable 3D features.  It is possible to run display
        // contexts without 3D backend (i.e, gfxstream / virglrender), so check for that too.
        if self.rutabaga_component != RutabagaComponentType::Rutabaga2D || self.capset_mask != 0 {
            virtio_gpu_features |= 1 << VIRTIO_GPU_F_VIRGL
                | 1 << VIRTIO_GPU_F_RESOURCE_UUID
                | 1 << VIRTIO_GPU_F_RESOURCE_BLOB
                | 1 << VIRTIO_GPU_F_CONTEXT_INIT
                | 1 << VIRTIO_GPU_F_EDID;

            if self.udmabuf {
                virtio_gpu_features |= 1 << VIRTIO_GPU_F_CREATE_GUEST_HANDLE;
            }

            // New experimental/unstable feature, not upstreamed.
            // Safe to enable because guest must explicitly opt-in.
            virtio_gpu_features |= 1 << VIRTIO_GPU_F_FENCE_PASSING;
        }

        self.base_features | virtio_gpu_features
    }

    fn ack_features(&mut self, value: u64) {
        let _ = value;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.get_config().as_bytes(), offset);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let mut cfg = self.get_config();
        copy_config(cfg.as_bytes_mut(), offset, data, 0);
        if (cfg.events_clear.to_native() & VIRTIO_GPU_EVENT_DISPLAY) != 0 {
            self.display_event.store(false, Ordering::Relaxed);
        }
    }

    fn on_device_sandboxed(&mut self) {
        // Unlike most Virtio devices which start their worker thread in activate(),
        // the Gpu's worker thread is started earlier here so that rutabaga and the
        // underlying render server have a chance to initialize before the guest OS
        // starts. This is needed because the Virtio GPU kernel module has a timeout
        // for some calls during initialization and some host GPU drivers have been
        // observed to be extremely slow to initialize on fresh GCE instances. The
        // entire worker thread is started here (as opposed to just initializing
        // rutabaga and the underlying render server) as OpenGL based renderers may
        // expect to be initialized on the same thread that later processes commands.
        self.start_worker_thread();
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        if queues.len() != QUEUE_SIZES.len() {
            return Err(anyhow!(
                "expected {} queues, got {}",
                QUEUE_SIZES.len(),
                queues.len()
            ));
        }

        let ctrl_queue = SharedQueueReader::new(queues.remove(&0).unwrap(), interrupt.clone());
        let cursor_queue = LocalQueueReader::new(queues.remove(&1).unwrap(), interrupt.clone());

        self.worker_thread
            .as_mut()
            .expect("worker thread missing on activate")
            .0
            .send(GpuActivationResources {
                mem,
                interrupt,
                ctrl_queue,
                cursor_queue,
                worker_snapshot: self.worker_snapshot.take(),
            })
            .expect("failed to send activation resources to worker thread");

        Ok(())
    }

    fn pci_address(&self) -> Option<PciAddress> {
        self.pci_address
    }

    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
        Some(SharedMemoryRegion {
            id: VIRTIO_GPU_SHM_ID_HOST_VISIBLE,
            length: self.pci_bar_size,
        })
    }

    fn set_shared_memory_mapper(&mut self, mapper: Box<dyn SharedMemoryMapper>) {
        self.mapper.lock().replace(mapper);
    }

    fn expose_shmem_descriptors_with_viommu(&self) -> bool {
        true
    }

    // Notes on sleep/wake/snapshot/restore functionality.
    //
    //   * Only 2d mode is supported so far.
    //   * We only snapshot the state relevant to the virtio-gpu 2d mode protocol (i.e. scanouts,
    //     resources, fences).
    //   * The GpuDisplay is recreated from scratch, we don't want to snapshot the state of a
    //     Wayland socket (for example).
    //   * No state about pending virtio requests needs to be snapshotted because the 2d backend
    //     completes them synchronously.

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        if let Some((activate_tx, worker_thread)) = self.worker_thread.take() {
            self.sleep_requested.store(true, Ordering::SeqCst);
            drop(activate_tx);
            let WorkerReturn {
                #[cfg(unix)]
                gpu_control_tube,
                resource_bridges,
                event_devices,
                activated_state,
            } = worker_thread.stop();
            self.sleep_requested.store(false, Ordering::SeqCst);

            self.resource_bridges = Some(resource_bridges);
            #[cfg(unix)]
            {
                self.gpu_control_tube = Some(gpu_control_tube);
            }
            self.event_devices = Some(event_devices);

            match activated_state {
                Some((queues, worker_snapshot)) => {
                    self.worker_snapshot = Some(worker_snapshot);
                    return Ok(Some(queues.into_iter().enumerate().collect()));
                }
                // Device not activated yet.
                None => {
                    self.worker_snapshot = None;
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }

    fn virtio_wake(
        &mut self,
        queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        match queues_state {
            None => Ok(()),
            Some((mem, interrupt, queues)) => {
                assert!(self.worker_thread.is_none());
                self.start_worker_thread();
                // TODO(khei): activate is just what we want at the moment, but we should probably
                // move it into a "start workers" function to make it obvious that it isn't
                // strictly used for activate events.
                self.activate(mem, interrupt, queues)?;
                Ok(())
            }
        }
    }

    fn virtio_snapshot(&self) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::to_value(&self.worker_snapshot)?)
    }

    fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        self.worker_snapshot = serde_json::from_value(data)?;
        Ok(())
    }
}

/// This struct takes the ownership of resource bridges and tracks which ones should be processed.
struct ResourceBridges {
    resource_bridges: Vec<Tube>,
    should_process: Vec<bool>,
}

impl ResourceBridges {
    pub fn new(resource_bridges: Vec<Tube>) -> Self {
        #[cfg(windows)]
        assert!(
            resource_bridges.is_empty(),
            "resource bridges are not supported on Windows"
        );

        let mut resource_bridges = Self {
            resource_bridges,
            should_process: Default::default(),
        };
        resource_bridges.reset_should_process();
        resource_bridges
    }

    // Appends raw descriptors of all resource bridges to the given vector.
    pub fn append_raw_descriptors(&self, rds: &mut Vec<RawDescriptor>) {
        for bridge in &self.resource_bridges {
            rds.push(bridge.as_raw_descriptor());
        }
    }

    /// Adds all resource bridges to WaitContext.
    pub fn add_to_wait_context(&self, wait_ctx: &mut WaitContext<WorkerToken>) {
        for (index, bridge) in self.resource_bridges.iter().enumerate() {
            if let Err(e) = wait_ctx.add(bridge, WorkerToken::ResourceBridge { index }) {
                error!("failed to add resource bridge to WaitContext: {}", e);
            }
        }
    }

    /// Marks that the resource bridge at the given index should be processed when
    /// `process_resource_bridges()` is called.
    pub fn set_should_process(&mut self, index: usize) {
        self.should_process[index] = true;
    }

    /// Processes all resource bridges that have been marked as should be processed.  The markings
    /// will be cleared before returning. Faulty resource bridges will be removed from WaitContext.
    pub fn process_resource_bridges(
        &mut self,
        state: &mut Frontend,
        wait_ctx: &mut WaitContext<WorkerToken>,
    ) {
        for (bridge, &should_process) in self.resource_bridges.iter().zip(&self.should_process) {
            if should_process {
                if let Err(e) = state.process_resource_bridge(bridge) {
                    error!("Failed to process resource bridge: {:#}", e);
                    error!("Removing that resource bridge from the wait context.");
                    wait_ctx.delete(bridge).unwrap_or_else(|e| {
                        error!("Failed to remove faulty resource bridge: {:#}", e)
                    });
                }
            }
        }
        self.reset_should_process();
    }

    fn reset_should_process(&mut self) {
        self.should_process.clear();
        self.should_process
            .resize(self.resource_bridges.len(), false);
    }
}

/// This function creates the window procedure thread and windows.
///
/// We have seen third-party DLLs hooking into window creation. They may have deep call stack, and
/// they may not be well tested against late window creation, which may lead to stack overflow.
/// Hence, this should be called as early as possible when the VM is booting.
#[cfg(windows)]
#[inline]
pub fn start_wndproc_thread(
    #[cfg(feature = "kiwi")] gpu_main_display_tube: Option<Tube>,
) -> anyhow::Result<WindowProcedureThread> {
    WindowProcedureThread::start_thread(
        #[cfg(feature = "kiwi")]
        gpu_main_display_tube,
    )
}
