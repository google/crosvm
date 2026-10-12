// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides a function to launches a process of creating ext2 filesystem on memory region
//! asynchronously for pmem-ext2 device.
//!
//! The ext2 file system is created in the memory area for pmem by the following three processes:
//! (a). The main process
//! (b). ext2 process launched by the `launch()` below.
//! (c). The virtio-pmem process
//!
//! By executing mkfs in the multiple processes, mkfs won't block other initialization steps. Also,
//! we can use different seccomp policy for (b) and (c).
//!
//! The overall workflow is like the followings:
//! 1. At (a): `launch()` is called from (a)
//! 2. At (a): (b) is forked from (a) in `launch()`
//! 3. At (b): The given directory is traversed and metadata is constructed.
//! 4. At (b): File descriptors are sent to (a) with `VmMemoryRequest::MmapAndRegisterMemory`.
//! 5. At (a): mmap() for the file descriptors are called. The reply is sent to (b).
//! 6. At (b): memory slot number is sent to (c).
//! 7. At (c): device activation finished.

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use base::error;
use base::AsRawDescriptor;
use base::Pid;
use base::SharedMemory;
use base::Tube;
use devices::virtio::VirtioDevice;
use devices::VirtioDeviceArgs;
use devices::VirtioDeviceModule;
use jail::create_base_minijail;
use jail::create_sandbox_minijail;
use jail::fork_process;
use jail::JailConfig;
use jail::RunAsUser;
use jail::SandboxConfig;
use minijail::Minijail;
use resources::Alloc;
use resources::AllocOptions;
use serde::Deserialize;
use serde::Serialize;
use vm_control::api::VmMemoryClient;
use vm_control::AnyControlTube;
use vm_control::VmMemoryFileMapping;
use vm_memory::GuestAddress;

use crate::MemSlotConfig;
use crate::Pmem;
use crate::PmemConfig;

/// Starts a process to create an ext2 filesystem on a given shared memory region.
fn launch(
    mapping_address: GuestAddress,
    vm_memory_client: VmMemoryClient,
    device_tube: Tube, // Connects to a virtio device to send a memory slot number.
    path: &Path,
    ugid: &(Option<u32>, Option<u32>),
    ugid_map: (&str, &str),
    mut builder: ext2::Builder,
    jail_config: Option<&JailConfig>,
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

    // Use "/" in the new mount namespace as the root for mkfs.
    builder.root_dir = Some(std::path::PathBuf::from("/"));

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
    let file_mappings = builder
        .build_on_shm(&shm)
        .context("failed to build memory region")?
        .build_mmap_info()
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PmemExt2Option {
    pub path: PathBuf,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub size: u32,
    pub ugid: (Option<u32>, Option<u32>),
    pub uid_map: String,
    pub gid_map: String,
}

impl Default for PmemExt2Option {
    fn default() -> Self {
        let blocks_per_group = 4096;
        let inodes_per_group = 1024;
        let size = ext2::BLOCK_SIZE as u32 * blocks_per_group; // only one block group
        Self {
            path: Default::default(),
            blocks_per_group,
            inodes_per_group,
            size,
            ugid: (None, None),
            // SAFETY: geteuid never fails.
            uid_map: format!("0 {} 1", unsafe { libc::geteuid() }),
            // SAFETY: getegid never fails.
            gid_map: format!("0 {} 1", unsafe { libc::getegid() }),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirtioPmemExt2Module {
    pub pmem_ext2_option: PmemExt2Option,
    pub index: usize,
}

impl VirtioDeviceModule for VirtioPmemExt2Module {
    fn sort_name(&self) -> &'static str {
        "pmem_ext2"
    }

    fn create(&self, cx: &mut VirtioDeviceArgs<'_>) -> Result<Box<dyn VirtioDevice>> {
        let (pmem_ext2_host_tube, pmem_ext2_device_tube) =
            Tube::pair().context("failed to create tube")?;
        let vm_memory_client = VmMemoryClient::new(pmem_ext2_device_tube);
        (cx.add_control_tube)(AnyControlTube::VmMemoryTube {
            tube: pmem_ext2_host_tube,
            expose_with_viommu: false,
            remote_peer: cx.jail_config.is_some(),
        });
        let (pmem_host_tube, pmem_device_tube) = Tube::pair().context("failed to create tube")?;
        (cx.add_control_tube)(AnyControlTube::VmMsync(pmem_host_tube));

        let mapping_size = self.pmem_ext2_option.size as u64;
        let builder = ext2::Builder {
            inodes_per_group: self.pmem_ext2_option.inodes_per_group,
            blocks_per_group: self.pmem_ext2_option.blocks_per_group,
            size: mapping_size as u32,
            ..Default::default()
        };

        let mapping_address = GuestAddress(
            cx.resources
                .allocate_mmio(
                    mapping_size,
                    Alloc::PmemDevice(self.index),
                    format!("pmem_ext2_image_{}", self.index),
                    AllocOptions::new()
                        .top_down(true)
                        .prefetchable(true)
                        // 2MB alignment for DAX
                        // cf. https://docs.pmem.io/persistent-memory/getting-started-guide/creating-development-environments/linux-environments/advanced-topics/i-o-alignment-considerations#verifying-io-alignment
                        .align(2 * 1024 * 1024),
                )
                .context("failed to allocate memory for pmem device")?,
        );

        let (mkfs_tube, mkfs_device_tube) = Tube::pair().context("failed to create tube")?;

        let ext2_proc_pid = launch(
            mapping_address,
            vm_memory_client,
            mkfs_tube,
            &self.pmem_ext2_option.path,
            &self.pmem_ext2_option.ugid,
            (
                &self.pmem_ext2_option.uid_map,
                &self.pmem_ext2_option.gid_map,
            ),
            builder,
            cx.jail_config,
        )
        .context("failed to spawn mkfs process")?;

        cx.worker_process_pids.insert(ext2_proc_pid);

        Ok(Box::new(
            Pmem::new(
                devices::virtio::base_features(cx.protection_type),
                PmemConfig {
                    disk_image: None,
                    mapping_address,
                    mem_slot: MemSlotConfig::LazyInit {
                        tube: mkfs_device_tube,
                    },
                    mapping_size,
                    pmem_device_tube,
                    swap_interval: None,
                    mapping_writable: false,
                },
            )
            .context("failed to create pmem device")?,
        ))
    }

    fn create_jail(&self, jail_config: Option<&JailConfig>) -> Result<Option<Minijail>> {
        let max_open_files = base::linux::max_open_files()
            .context("failed to get max number of open files")?
            .rlim_max;
        let jail = if let Some(jail_config) = jail_config {
            let mut config = SandboxConfig::new(jail_config, "pmem_device");
            config.limit_caps = false;
            create_sandbox_minijail(&self.pmem_ext2_option.path, max_open_files, &config)?
        } else {
            create_base_minijail(&self.pmem_ext2_option.path, max_open_files)?
        };
        Ok(Some(jail))
    }
}
