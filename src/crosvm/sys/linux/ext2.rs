// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides a function to lanunches a process of creating ext2 filesystem on memory region
//! asynchronously for pmem-ext2 device.
//!
//! The ext2 file system is created in the memory area for pmem by the following three processes:
//! (a). The main process
//! (b). ext2 process launched by the `launch()` below.
//! (c). The virtio-pmem process
//!
//! By executing mkfs in the multiple processes, mkfs won't block other initalization steps. Also,
//! we can use different seccopm poliy for (b) and (c).
//!
//! The overall workflow is like the followings:
//! 1. At (a): `launch()` is called from (a)
//! 2. At (a): (b) is foked from (a) in `launch()`
//! 3. At (b): The given directory is traversed and metadata is constructed.
//! 4. At (b): File descriptors are sent to (a) with `VmMemoryRequest::MmapAndRegisterMemory`.
//! 5. At (a): mmap() for the file descriptors are called. The reply is sent to (b).
//! 6. At (b): memory slot number is sent to (c).
//! 7. At (c): device activation finished.

use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use base::error;
use base::AsRawDescriptor;
use base::Pid;
use base::SharedMemory;
use base::Tube;
use jail::create_base_minijail;
use jail::create_sandbox_minijail;
use jail::fork_process;
use jail::JailConfig;
use jail::RunAsUser;
use jail::SandboxConfig;
use vm_control::api::VmMemoryClient;
use vm_control::VmMemoryFileMapping;
use vm_memory::GuestAddress;

/// Starts a process to create an ext2 filesystem on a given shared memory region.
pub fn launch(
    mapping_address: GuestAddress,
    vm_memory_client: VmMemoryClient,
    device_tube: Tube, // Connects to a virtio device to send a memory slot number.
    path: &Path,
    ugid: &(Option<u32>, Option<u32>),
    ugid_map: (&str, &str),
    builder: ext2::Builder,
    jail_config: &Option<JailConfig>,
) -> Result<Pid> {
    let max_open_files = base::linux::max_open_files()
        .context("failed to get max number of open files")?
        .rlim_max;

    let jail = if let Some(jail_config) = jail_config {
        let mut config = SandboxConfig::new(jail_config, "virtual_ext2");
        config.limit_caps = false;
        config.ugid_map = Some(ugid_map);
        // We want bind mounts from the parent namespaces to propagate into the mkfs's
        // namespace.
        config.remount_mode = Some(libc::MS_SLAVE);
        config.run_as = match *ugid {
            (None, None) => RunAsUser::Unspecified,
            (uid_opt, gid_opt) => RunAsUser::Specified(uid_opt.unwrap_or(0), gid_opt.unwrap_or(0)),
        };
        create_sandbox_minijail(path, max_open_files, &config)?
    } else {
        create_base_minijail(path, max_open_files)?
    };

    let shm = SharedMemory::new("pmem_ext2_shm", builder.size as u64)
        .context("failed to create shared memory")?;
    let mut keep_rds = vec![
        shm.as_raw_descriptor(),
        vm_memory_client.as_raw_descriptor(),
        device_tube.as_raw_descriptor(),
    ];
    base::syslog::push_descriptors(&mut keep_rds);

    let child_process = fork_process(jail, keep_rds, Some(String::from("mkfs process")), || {
        if let Err(e) = mkfs_callback(vm_memory_client, mapping_address, device_tube, builder, shm)
        {
            error!("failed to create file system: {:#}", e);
            // SAFETY: exit() is trivially safe.
            unsafe { libc::exit(1) };
        }
    })
    .context("failed to fork a process for mkfs")?;
    Ok(child_process.pid)
}

/// A callback to create a ext2 file system on `shm`.
/// This is supposed to be run in a jailed child process so operations are sandboxed and limited.
fn mkfs_callback(
    mem_client: VmMemoryClient,
    mapping_address: GuestAddress,
    device_tube: Tube, // Connects to a virtio device to send a memory slot number.
    builder: ext2::Builder,
    shm: SharedMemory,
) -> Result<()> {
    let jailed_root = Some(std::path::Path::new("/"));
    let file_mappings = builder
        .build_on_shm(&shm)
        .context("failed to build memory region")?
        .build_mmap_info(jailed_root)
        .context("failed to build ext2")?
        .mapping_info;

    let file_mapping_info: Vec<_> = file_mappings
        .into_iter()
        .map(|info| VmMemoryFileMapping {
            file: info.file,
            length: info.length,
            mem_offset: info.mem_offset,
            file_offset: info.file_offset as u64,
        })
        .collect();

    let slot = mem_client
        .mmap_and_register_memory(mapping_address, shm, file_mapping_info)
        .context("failed to request mmaping and registering memory")?;
    device_tube
        .send(&slot)
        .context("failed to send VmMemoryRequest::RegisterMemory")?;
    Ok(())
}
