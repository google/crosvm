// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::fs::File;
use std::mem::size_of;
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::AsFd;
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::BorrowedFd;

use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::bytestream::Reader;
use crate::bytestream::Writer;
use crate::ipc::kumquat_gpu_protocol::*;
use crate::rutabaga_os::AsRawDescriptor;
use crate::rutabaga_os::FromRawDescriptor;
use crate::rutabaga_os::IntoRawDescriptor;
use crate::rutabaga_os::RawDescriptor;
use crate::rutabaga_os::SafeDescriptor;
use crate::rutabaga_os::Tube;
use crate::rutabaga_os::DEFAULT_RAW_DESCRIPTOR;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaHandle;
use crate::rutabaga_utils::RutabagaResult;
use crate::rutabaga_utils::RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD;

const MAX_DESCRIPTORS: usize = 1;
const MAX_COMMAND_SIZE: usize = 4096;

pub struct RutabagaStream {
    stream: Tube,
    write_buffer: [u8; MAX_COMMAND_SIZE],
    read_buffer: [u8; MAX_COMMAND_SIZE],
    descriptors: [RawDescriptor; MAX_DESCRIPTORS],
}

impl RutabagaStream {
    pub fn new(stream: Tube) -> RutabagaStream {
        RutabagaStream {
            stream,
            write_buffer: [0; MAX_COMMAND_SIZE],
            read_buffer: [0; MAX_COMMAND_SIZE],
            descriptors: [DEFAULT_RAW_DESCRIPTOR; MAX_DESCRIPTORS],
        }
    }

    pub fn write<T: FromBytes + AsBytes>(
        &mut self,
        encode: KumquatGpuProtocolWrite<T>,
    ) -> RutabagaResult<()> {
        let mut writer = Writer::new(&mut self.write_buffer);
        let mut num_descriptors = 0;

        let _handle_opt: Option<RutabagaHandle> = match encode {
            KumquatGpuProtocolWrite::Cmd(cmd) => {
                writer.write_obj(cmd)?;
                None
            }
            KumquatGpuProtocolWrite::CmdWithHandle(cmd, handle) => {
                writer.write_obj(cmd)?;
                num_descriptors = 1;
                self.descriptors[0] = handle.os_handle.as_raw_descriptor();
                Some(handle)
            }
            KumquatGpuProtocolWrite::CmdWithData(cmd, data) => {
                writer.write_obj(cmd)?;
                writer.write_all(&data)?;
                None
            }
        };

        let bytes_written = writer.bytes_written();
        self.stream.send(
            &self.write_buffer[0..bytes_written],
            &self.descriptors[0..num_descriptors],
        )?;
        Ok(())
    }

    pub fn read(&mut self) -> RutabagaResult<Vec<KumquatGpuProtocol>> {
        let mut vec: Vec<KumquatGpuProtocol> = Vec::new();
        let (bytes_read, files_vec) = self.stream.receive(&mut self.read_buffer)?;
        let mut files: VecDeque<File> = files_vec.into();

        if bytes_read == 0 {
            vec.push(KumquatGpuProtocol::OkNoData);
            return Ok(vec);
        }

        let mut reader = Reader::new(&self.read_buffer[0..bytes_read]);
        while reader.available_bytes() != 0 {
            let hdr = reader.peek_obj::<kumquat_gpu_protocol_ctrl_hdr>()?;
            let protocol = match hdr.type_ {
                KUMQUAT_GPU_PROTOCOL_GET_NUM_CAPSETS => {
                    reader.consume(size_of::<kumquat_gpu_protocol_ctrl_hdr>());
                    KumquatGpuProtocol::GetNumCapsets
                }
                KUMQUAT_GPU_PROTOCOL_GET_CAPSET_INFO => {
                    reader.consume(size_of::<kumquat_gpu_protocol_ctrl_hdr>());
                    KumquatGpuProtocol::GetCapsetInfo(hdr.payload)
                }
                KUMQUAT_GPU_PROTOCOL_GET_CAPSET => {
                    KumquatGpuProtocol::GetCapset(reader.read_obj()?)
                }
                KUMQUAT_GPU_PROTOCOL_CTX_CREATE => {
                    KumquatGpuProtocol::CtxCreate(reader.read_obj()?)
                }
                KUMQUAT_GPU_PROTOCOL_CTX_DESTROY => {
                    reader.consume(size_of::<kumquat_gpu_protocol_ctrl_hdr>());
                    KumquatGpuProtocol::CtxDestroy(hdr.payload)
                }
                KUMQUAT_GPU_PROTOCOL_CTX_ATTACH_RESOURCE => {
                    KumquatGpuProtocol::CtxAttachResource(reader.read_obj()?)
                }
                KUMQUAT_GPU_PROTOCOL_CTX_DETACH_RESOURCE => {
                    KumquatGpuProtocol::CtxDetachResource(reader.read_obj()?)
                }
                KUMQUAT_GPU_PROTOCOL_RESOURCE_CREATE_3D => {
                    KumquatGpuProtocol::ResourceCreate3d(reader.read_obj()?)
                }
                KUMQUAT_GPU_PROTOCOL_TRANSFER_TO_HOST_3D => {
                    let file = files.pop_front().ok_or(RutabagaError::InvalidResourceId)?;
                    let resp: kumquat_gpu_protocol_transfer_host_3d = reader.read_obj()?;

                    // SAFETY: Safe because we know the underlying OS descriptor is valid and
                    // owned by us.
                    let os_handle =
                        unsafe { SafeDescriptor::from_raw_descriptor(file.into_raw_descriptor()) };

                    let handle = RutabagaHandle {
                        os_handle,
                        handle_type: RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD,
                    };

                    KumquatGpuProtocol::TransferToHost3d(resp, handle)
                }
                KUMQUAT_GPU_PROTOCOL_TRANSFER_FROM_HOST_3D => {
                    let file = files.pop_front().ok_or(RutabagaError::InvalidResourceId)?;
                    let resp: kumquat_gpu_protocol_transfer_host_3d = reader.read_obj()?;

                    // SAFETY: Safe because we know the underlying OS descriptor is valid and
                    // owned by us.
                    let os_handle =
                        unsafe { SafeDescriptor::from_raw_descriptor(file.into_raw_descriptor()) };

                    let handle = RutabagaHandle {
                        os_handle,
                        handle_type: RUTABAGA_FENCE_HANDLE_TYPE_EVENT_FD,
                    };

                    KumquatGpuProtocol::TransferFromHost3d(resp, handle)
                }
                KUMQUAT_GPU_PROTOCOL_SUBMIT_3D => {
                    let cmd: kumquat_gpu_protocol_cmd_submit = reader.read_obj()?;
                    if reader.available_bytes() < cmd.size.try_into()? {
                        // Large command buffers should handled via shared memory.
                        return Err(RutabagaError::InvalidCommandBuffer);
                    } else if reader.available_bytes() != 0 {
                        let num_in_fences = cmd.num_in_fences as usize;
                        let cmd_size = cmd.size as usize;
                        let mut cmd_buf = vec![0; cmd_size];
                        let mut fence_ids: Vec<u64> = Vec::with_capacity(num_in_fences);
                        for _ in 0..num_in_fences {
                            match reader.read_obj::<u64>() {
                                Ok(fence_id) => {
                                    fence_ids.push(fence_id);
                                }
                                Err(_) => return Err(RutabagaError::InvalidIovec),
                            }
                        }
                        reader.read_exact(&mut cmd_buf[..])?;
                        KumquatGpuProtocol::CmdSubmit3d(cmd, cmd_buf, fence_ids)
                    } else {
                        KumquatGpuProtocol::CmdSubmit3d(cmd, Vec::new(), Vec::new())
                    }
                }
                KUMQUAT_GPU_PROTOCOL_RESOURCE_CREATE_BLOB => {
                    KumquatGpuProtocol::ResourceCreateBlob(reader.read_obj()?)
                }
                KUMQUAT_GPU_PROTOCOL_SNAPSHOT_SAVE => {
                    reader.consume(size_of::<kumquat_gpu_protocol_ctrl_hdr>());
                    KumquatGpuProtocol::SnapshotSave
                }
                KUMQUAT_GPU_PROTOCOL_SNAPSHOT_RESTORE => {
                    reader.consume(size_of::<kumquat_gpu_protocol_ctrl_hdr>());
                    KumquatGpuProtocol::SnapshotRestore
                }
                KUMQUAT_GPU_PROTOCOL_RESP_NUM_CAPSETS => {
                    reader.consume(size_of::<kumquat_gpu_protocol_ctrl_hdr>());
                    KumquatGpuProtocol::RespNumCapsets(hdr.payload)
                }
                KUMQUAT_GPU_PROTOCOL_RESP_CAPSET_INFO => {
                    KumquatGpuProtocol::RespCapsetInfo(reader.read_obj()?)
                }
                KUMQUAT_GPU_PROTOCOL_RESP_CAPSET => {
                    let len: usize = hdr.payload.try_into()?;
                    reader.consume(size_of::<kumquat_gpu_protocol_ctrl_hdr>());
                    let mut capset: Vec<u8> = vec![0; len];
                    reader.read_exact(&mut capset)?;
                    KumquatGpuProtocol::RespCapset(capset)
                }
                KUMQUAT_GPU_PROTOCOL_RESP_CONTEXT_CREATE => {
                    reader.consume(size_of::<kumquat_gpu_protocol_ctrl_hdr>());
                    KumquatGpuProtocol::RespContextCreate(hdr.payload)
                }
                KUMQUAT_GPU_PROTOCOL_RESP_RESOURCE_CREATE => {
                    let file = files.pop_front().ok_or(RutabagaError::InvalidResourceId)?;
                    let resp: kumquat_gpu_protocol_resp_resource_create = reader.read_obj()?;

                    // SAFETY: Safe because we know the underlying OS descriptor is valid and
                    // owned by us.
                    let os_handle =
                        unsafe { SafeDescriptor::from_raw_descriptor(file.into_raw_descriptor()) };

                    let handle = RutabagaHandle {
                        os_handle,
                        handle_type: resp.handle_type,
                    };

                    KumquatGpuProtocol::RespResourceCreate(resp, handle)
                }
                KUMQUAT_GPU_PROTOCOL_RESP_CMD_SUBMIT_3D => {
                    let file = files.pop_front().ok_or(RutabagaError::InvalidResourceId)?;
                    let resp: kumquat_gpu_protocol_resp_cmd_submit_3d = reader.read_obj()?;

                    // SAFETY: Safe because we know the underlying OS descriptor is valid and
                    // owned by us.
                    let os_handle =
                        unsafe { SafeDescriptor::from_raw_descriptor(file.into_raw_descriptor()) };

                    let handle = RutabagaHandle {
                        os_handle,
                        handle_type: resp.handle_type,
                    };

                    KumquatGpuProtocol::RespCmdSubmit3d(resp.fence_id, handle)
                }
                KUMQUAT_GPU_PROTOCOL_RESP_OK_SNAPSHOT => {
                    reader.consume(size_of::<kumquat_gpu_protocol_ctrl_hdr>());
                    KumquatGpuProtocol::RespOkSnapshot
                }
                _ => {
                    return Err(RutabagaError::Unsupported);
                }
            };

            vec.push(protocol);
        }

        Ok(vec)
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub fn as_borrowed_file(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}
