// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! crate for the vmm-swap feature.

#![deny(missing_docs)]

use std::fs::File;
use std::fs::OpenOptions;
use std::io::stderr;
use std::io::stdout;
use std::ops::Range;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::thread::Scope;
use std::thread::ScopedJoinHandle;
use std::time::Duration;
use std::time::Instant;

use anyhow::bail;
use anyhow::Context;
use base::debug;
use base::error;
use base::info;
use base::linux::FileDataIterator;
use base::syslog;
use base::warn;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::EventToken;
use base::RawDescriptor;
use base::SendTube;
use base::SharedMemory;
use base::Tube;
use base::TubeError;
use base::WaitContext;
use jail::create_base_minijail;
use jail::create_sandbox_minijail;
use jail::fork::fork_process;
use jail::fork::Child;
use jail::JailConfig;
use jail::SandboxConfig;
use jail::MAX_OPEN_FILES_DEFAULT;
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use vm_memory::GuestMemory;

use crate::file_truncator::FileTruncator;
use crate::page_handler::Error as PageHandlerError;
use crate::page_handler::MoveToStaging;
use crate::page_handler::PageHandler;
use crate::page_handler::MLOCK_BUDGET;
use crate::pagesize::bytes_to_pages;
use crate::pagesize::THP_SIZE;
use crate::processes::freeze_child_processes;
use crate::processes::ProcessesGuard;
use crate::uffd_list::Token as UffdListToken;
use crate::uffd_list::UffdList;
use crate::userfaultfd::register_regions;
use crate::userfaultfd::unregister_regions;
use crate::userfaultfd::DeadUffdCheckerImpl;
use crate::userfaultfd::Error as UffdError;
use crate::userfaultfd::Factory as UffdFactory;
use crate::userfaultfd::UffdEvent;
use crate::userfaultfd::Userfaultfd;
use crate::worker::BackgroundJobControl;
use crate::worker::Worker;
use crate::SwapMetrics;
use crate::SwapState;
use crate::SwapStateTransition;
use crate::SwapStatus;

/// The max size of chunks to swap out/in at once.
const MAX_SWAP_CHUNK_SIZE: usize = 2 * 1024 * 1024; // = 2MB
/// The max pages to trim at once.
const MAX_TRIM_PAGES: usize = 1024;

/// Returns count of pages active on the guest memory.
fn count_resident_pages(guest_memory: &GuestMemory) -> usize {
    let mut pages = 0;
    for region in guest_memory.regions() {
        let mut resident_bytes = 0u64;
        for range in FileDataIterator::new(region.shm, region.shm_offset, region.size as u64) {
            let range = match range {
                Ok(r) => r,
                Err(e) => {
                    error!("failed to iterate data ranges: {e:?}");
                    return 0;
                }
            };
            resident_bytes += range.end - range.start;
        }
        let resident_bytes = match resident_bytes.try_into() {
            Ok(n) => n,
            Err(e) => {
                error!("failed to load resident pages count: {:?}", e);
                return 0;
            }
        };

        pages += bytes_to_pages(resident_bytes);
    }
    pages
}

/// Commands used in vmm-swap feature internally sent to the monitor process from the main and other
/// processes.
///
/// This is mainly originated from the `crosvm swap <command>` command line.
#[derive(Serialize, Deserialize)]
enum Command {
    Enable,
    Trim,
    SwapOut,
    Disable {
        slow_file_cleanup: bool,
    },
    Exit,
    Status,
    ProcessForked {
        #[serde(with = "base::with_as_descriptor")]
        uffd: Userfaultfd,
        reply_tube: Tube,
    },
    StaticDeviceSetupComplete(u32),
}

/// [SwapController] provides APIs to control vmm-swap.
pub struct SwapController {
    child_process: Option<Child>,
    uffd_factory: UffdFactory,
    command_tube: Tube,
    num_static_devices: u32,
    // Keep 1 page dummy mmap in the main process to make it present in all the descendant
    // processes.
    _dead_uffd_checker: DeadUffdCheckerImpl,
    // Keep the cloned [GuestMemory] in the main process not to free it before the monitor process
    // exits.
    _guest_memory: GuestMemory,
}

impl SwapController {
    /// Launch a monitor process for vmm-swap and return a controller.
    ///
    /// Pages on the [GuestMemory] are registered to userfaultfd to track pagefault events.
    ///
    /// # Arguments
    ///
    /// * `guest_memory` - fresh new [GuestMemory]. Any pages on the [GuestMemory] must not be
    ///   touched.
    /// * `swap_dir` - directory to store swap files.
    pub fn launch(
        guest_memory: GuestMemory,
        swap_dir: &Path,
        jail_config: &Option<JailConfig>,
    ) -> anyhow::Result<Self> {
        info!("vmm-swap is enabled. launch monitor process.");

        let preserved_guest_memory = guest_memory.clone();

        let uffd_factory = UffdFactory::new();
        let uffd = uffd_factory.create().context("create userfaultfd")?;

        // The swap file is created as `O_TMPFILE` from the specified directory. As benefits:
        //
        // * it has no chance to conflict.
        // * it has a security benefit that no one (except root) can access the swap file.
        // * it will be automatically deleted by the kernel when crosvm exits/dies or on reboot if
        //   the device panics/hard-resets while crosvm is running.
        let swap_file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_TMPFILE | libc::O_EXCL)
            .mode(0o000) // other processes with the same uid can't open the file
            .open(swap_dir)?;
        // The internal tube in which [Command]s sent from other processes than the monitor process
        // to the monitor process. The response is `Status` only.
        let (command_tube_main, command_tube_monitor) =
            Tube::pair().context("create swap command tube")?;

        // Allocate eventfd before creating sandbox.
        let bg_job_control = BackgroundJobControl::new().context("create background job event")?;

        let dead_uffd_checker = DeadUffdCheckerImpl::new().context("create dead uffd checker")?;

        let mut keep_rds = vec![
            stdout().as_raw_descriptor(),
            stderr().as_raw_descriptor(),
            uffd.as_raw_descriptor(),
            swap_file.as_raw_descriptor(),
            command_tube_monitor.as_raw_descriptor(),
            bg_job_control.get_completion_event().as_raw_descriptor(),
        ];

        syslog::push_descriptors(&mut keep_rds);
        cros_tracing::push_descriptors!(&mut keep_rds);
        metrics::push_descriptors(&mut keep_rds);
        keep_rds.extend(guest_memory.as_raw_descriptors());

        keep_rds.extend(uffd_factory.as_raw_descriptors());

        // Load and cache transparent hugepage size from sysfs before jumping into sandbox.
        Lazy::force(&THP_SIZE);

        let mut jail = if let Some(jail_config) = jail_config {
            let config = SandboxConfig::new(jail_config, "swap_monitor");
            create_sandbox_minijail(&jail_config.pivot_root, MAX_OPEN_FILES_DEFAULT, &config)
                .context("create sandbox jail")?
        } else {
            create_base_minijail(Path::new("/"), MAX_OPEN_FILES_DEFAULT)
                .context("create minijail")?
        };
        jail.set_rlimit(
            libc::RLIMIT_MEMLOCK as libc::c_int,
            MLOCK_BUDGET as u64,
            MLOCK_BUDGET as u64,
        )
        .context("error setting RLIMIT_MEMLOCK")?;

        // Start a page fault monitoring process (this will be the first child process of the
        // current process)
        let child_process =
            fork_process(jail, keep_rds, Some(String::from("swap monitor")), || {
                if let Err(e) = monitor_process(
                    command_tube_monitor,
                    guest_memory,
                    uffd,
                    swap_file,
                    bg_job_control,
                    &dead_uffd_checker,
                ) {
                    if let Some(PageHandlerError::Userfaultfd(UffdError::UffdClosed)) =
                        e.downcast_ref::<PageHandlerError>()
                    {
                        // Userfaultfd can cause UffdError::UffdClosed if the main process
                        // unexpectedly while it is swapping in. This is not a bug of swap monitor,
                        // but the other feature on the main process.
                        // Note that UffdError::UffdClosed from other processes than the main
                        // process are derived from PageHandler::handle_page_fault() only and
                        // handled in the loop of handle_vmm_swap().
                        error!(
                            "page_fault_handler_thread exited with userfaultfd closed error: {:#}",
                            e
                        );
                    } else if e.is::<TubeError>() {
                        // Tube can cause TubeError if the main process unexpectedly dies. This is
                        // not a bug of swap monitor, but the other feature on the main process.
                        // Even if the tube itself is broken and the main process is alive, the main
                        // process catch that the swap monitor process exits unexpectedly and
                        // terminates itself.
                        error!("page_fault_handler_thread exited with tube error: {:#}", e);
                    } else {
                        panic!("page_fault_handler_thread exited with error: {:#}", e);
                    }
                }
            })
            .context("fork monitor process")?;

        // send first status request to the monitor process and wait for the response until setup on
        // the monitor process completes.
        command_tube_main.send(&Command::Status)?;
        match command_tube_main
            .recv::<SwapStatus>()
            .context("recv initial status")?
            .state
        {
            SwapState::Ready => {
                // The initial state of swap status is Ready and this is a signal that the
                // monitoring process completes setup and is running.
            }
            status => {
                bail!("initial state is not Ready, but {:?}", status);
            }
        };

        Ok(Self {
            child_process: Some(child_process),
            uffd_factory,
            command_tube: command_tube_main,
            num_static_devices: 0,
            _dead_uffd_checker: dead_uffd_checker,
            _guest_memory: preserved_guest_memory,
        })
    }

    /// Enable monitoring page faults and move guest memory to staging memory.
    ///
    /// The pages will be swapped in from the staging memory to the guest memory on page faults
    /// until pages are written into the swap file by [Self::swap_out()].
    ///
    /// This waits until enabling vmm-swap finishes on the monitor process.
    ///
    /// The caller must guarantee that any contents on the guest memory is not updated during
    /// enabling vmm-swap.
    ///
    /// # Note
    ///
    /// Enabling does not write pages to the swap file. User should call [Self::swap_out()]
    /// after a suitable time.
    ///
    /// Just after enabling vmm-swap, some amount of pages are swapped in as soon as guest resumes.
    /// By splitting the enable/swap_out operation and by delaying write to the swap file operation,
    /// it has a benefit of reducing file I/O for hot pages.
    pub fn enable(&self) -> anyhow::Result<()> {
        self.command_tube
            .send(&Command::Enable)
            .context("send swap enable request")?;

        let _ = self
            .command_tube
            .recv::<SwapStatus>()
            .context("receive swap status")?;
        Ok(())
    }

    /// Trim pages in the staging memory which are needless to be written back to the swap file.
    ///
    /// * zero pages
    /// * pages which are the same as the pages in the swap file.
    pub fn trim(&self) -> anyhow::Result<()> {
        self.command_tube
            .send(&Command::Trim)
            .context("send swap trim request")?;
        Ok(())
    }

    /// Swap out all the pages in the staging memory to the swap files.
    ///
    /// This returns as soon as it succeeds to send request to the monitor process.
    ///
    /// Users should call [Self::enable()] before this. See the comment of [Self::enable()] as well.
    pub fn swap_out(&self) -> anyhow::Result<()> {
        self.command_tube
            .send(&Command::SwapOut)
            .context("send swap out request")?;
        Ok(())
    }

    /// Swap in all the guest memory and disable monitoring page faults.
    ///
    /// This returns as soon as it succeeds to send request to the monitor process.
    pub fn disable(&self, slow_file_cleanup: bool) -> anyhow::Result<()> {
        self.command_tube
            .send(&Command::Disable { slow_file_cleanup })
            .context("send swap disable request")?;
        Ok(())
    }

    /// Return current swap status.
    ///
    /// This blocks until response from the monitor process arrives to the main process.
    pub fn status(&self) -> anyhow::Result<SwapStatus> {
        self.command_tube
            .send(&Command::Status)
            .context("send swap status request")?;
        let status = self.command_tube.recv().context("receive swap status")?;
        Ok(status)
    }

    /// Suspend device processes using `SIGSTOP` signal.
    ///
    /// When the returned `ProcessesGuard` is dropped, the devices resume.
    ///
    /// This must be called from the main process.
    pub fn suspend_devices(&self) -> anyhow::Result<ProcessesGuard> {
        // child_process become none on dropping SwapController.
        freeze_child_processes(
            self.child_process
                .as_ref()
                .expect("monitor process not exist")
                .pid,
        )
    }

    /// Notify the monitor process that all static devices are forked.
    ///
    /// Devices forked after this call are treated as dynamic devices which can die (e.g. hotplug
    /// devices).
    pub fn on_static_devices_setup_complete(&self) -> anyhow::Result<()> {
        // This sends the number of static devices counted on the main process because device
        // initializations are executed on child processes asynchronously.
        self.command_tube
            .send(&Command::StaticDeviceSetupComplete(self.num_static_devices))
            .context("send command")
    }

    /// Create [SwapDeviceHelper].
    pub fn create_device_helper(&self) -> anyhow::Result<SwapDeviceHelper> {
        let uffd_factory = self
            .uffd_factory
            .try_clone()
            .context("try clone uffd factory")?;
        let command_tube = self
            .command_tube
            .try_clone_send_tube()
            .context("try clone tube")?;
        Ok(SwapDeviceHelper {
            uffd_factory,
            command_tube,
        })
    }
}

impl Drop for SwapController {
    fn drop(&mut self) {
        // Shutdown the monitor process.
        // This blocks until the monitor process exits.
        if let Err(e) = self.command_tube.send(&Command::Exit) {
            error!(
                "failed to sent exit command to vmm-swap monitor process: {:#}",
                e
            );
            return;
        }
        if let Err(e) = self
            .child_process
            .take()
            .expect("monitor process not exist")
            .wait()
        {
            error!("failed to wait vmm-swap monitor process shutdown: {:#}", e);
        }
    }
}

/// Create a new [SwapDeviceUffdSender] which is passed to the forked child process.
pub trait PrepareFork {
    /// Create a new [SwapDeviceUffdSender].
    fn prepare_fork(&mut self) -> anyhow::Result<SwapDeviceUffdSender>;
}

impl PrepareFork for SwapController {
    /// Create a new [SwapDeviceUffdSender].
    ///
    /// This should be called from the main process because creating a [Tube]s requires seccomp
    /// policy.
    ///
    /// This also counts the number of static devices which are created before booting.
    fn prepare_fork(&mut self) -> anyhow::Result<SwapDeviceUffdSender> {
        let command_tube = self
            .command_tube
            .try_clone_send_tube()
            .context("try clone tube")?;
        self.num_static_devices += 1;
        SwapDeviceUffdSender::new(command_tube, &self.uffd_factory)
    }
}

/// Helper to create [SwapDeviceUffdSender] from child processes (e.g. JailWarden for hotplug
/// devices).
pub struct SwapDeviceHelper {
    uffd_factory: UffdFactory,
    command_tube: SendTube,
}

impl PrepareFork for SwapDeviceHelper {
    /// Create a new [SwapDeviceUffdSender].
    fn prepare_fork(&mut self) -> anyhow::Result<SwapDeviceUffdSender> {
        let command_tube = self.command_tube.try_clone().context("try clone tube")?;
        SwapDeviceUffdSender::new(command_tube, &self.uffd_factory)
    }
}

impl AsRawDescriptors for SwapDeviceHelper {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        let mut rds = self.uffd_factory.as_raw_descriptors();
        rds.push(self.command_tube.as_raw_descriptor());
        rds
    }
}

/// Create a new userfaultfd and send it to the monitor process.
pub struct SwapDeviceUffdSender {
    uffd_factory: UffdFactory,
    command_tube: SendTube,
    sender: Tube,
    receiver: Tube,
}

impl SwapDeviceUffdSender {
    fn new(command_tube: SendTube, uffd_factory: &UffdFactory) -> anyhow::Result<Self> {
        let uffd_factory = uffd_factory.try_clone().context("try clone uffd factory")?;
        let (sender, receiver) = Tube::pair().context("create tube")?;
        receiver
            .set_recv_timeout(Some(Duration::from_secs(60)))
            .context("set recv timeout")?;
        Ok(SwapDeviceUffdSender {
            uffd_factory,
            command_tube,
            sender,
            receiver,
        })
    }

    /// Create a new userfaultfd and send it to the monitor process.
    ///
    /// This must be called as soon as a child process which may touch the guest memory is forked.
    ///
    /// Userfaultfd(2) originally has `UFFD_FEATURE_EVENT_FORK`. But it is not applicable to crosvm
    /// since it does not support non-root user namespace.
    pub fn on_process_forked(self) -> anyhow::Result<()> {
        let uffd = self.uffd_factory.create().context("create userfaultfd")?;
        // The fd for Userfaultfd in this process is dropped when it is sent via Tube, but the
        // userfaultfd keeps alive in the monitor process which it is sent to.
        self.command_tube
            .send(&Command::ProcessForked {
                uffd,
                reply_tube: self.sender,
            })
            .context("send forked event")?;
        // Wait to proceeds the child process logic until the userfaultfd is set up.
        if !self.receiver.recv::<bool>().context("recv tube")? {
            bail!("failed to register a new userfaultfd");
        }
        Ok(())
    }
}

impl AsRawDescriptors for SwapDeviceUffdSender {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        let mut rds = self.uffd_factory.as_raw_descriptors();
        rds.push(self.command_tube.as_raw_descriptor());
        rds.push(self.sender.as_raw_descriptor());
        rds.push(self.receiver.as_raw_descriptor());
        rds
    }
}

#[derive(EventToken, Clone, Copy)]
enum Token {
    UffdEvents(u32),
    Command,
    BackgroundJobCompleted,
}

impl UffdListToken for Token {
    fn uffd_token(idx: u32) -> Self {
        Token::UffdEvents(idx)
    }
}

fn regions_from_guest_memory(guest_memory: &GuestMemory) -> Vec<Range<usize>> {
    guest_memory
        .regions()
        .map(|region| region.host_addr..(region.host_addr + region.size))
        .collect()
}

/// The main thread of the monitor process.
fn monitor_process(
    command_tube: Tube,
    guest_memory: GuestMemory,
    uffd: Userfaultfd,
    swap_file: File,
    bg_job_control: BackgroundJobControl,
    dead_uffd_checker: &DeadUffdCheckerImpl,
) -> anyhow::Result<()> {
    info!("monitor_process started");

    let wait_ctx = WaitContext::build_with(&[
        (&command_tube, Token::Command),
        (
            bg_job_control.get_completion_event(),
            Token::BackgroundJobCompleted,
        ),
    ])
    .context("create wait context")?;

    let mut swap_file_opt = Some(swap_file);
    let mut truncate_worker: Option<FileTruncator> = None;

    let n_worker = num_cpus::get();
    info!("start {} workers for staging memory move", n_worker);
    // The worker threads are killed when the main thread of the monitor process dies.
    let worker = Worker::new(n_worker, n_worker);

    let mut uffd_list =
        UffdList::new(uffd, dead_uffd_checker, &wait_ctx).context("create uffd list")?;
    let mut state_transition = SwapStateTransition::default();
    let mut try_gc_uffds = false;

    loop {
        let events = wait_ctx.wait().context("wait poll events")?;

        for event in events.iter() {
            match event.token {
                Token::UffdEvents(id_uffd) => {
                    let uffd = uffd_list
                        .get(id_uffd)
                        .with_context(|| format!("uffd is not found for idx: {}", id_uffd))?;
                    // Userfaultfd does not work as level triggered but as edge triggered. We need
                    // to read all the events in the userfaultfd here.
                    while let Some(event) = uffd.read_event().context("read userfaultfd event")? {
                        match event {
                            UffdEvent::Remove { .. } => {
                                // BUG(b/272620051): This is a bug of userfaultfd that
                                // UFFD_EVENT_REMOVE can be read even after unregistering memory
                                // from the userfaultfd.
                                warn!("page remove event while vmm-swap disabled");
                            }
                            event => {
                                bail!("unexpected uffd event: {:?}", event);
                            }
                        }
                    }
                }
                Token::Command => match command_tube
                    .recv::<Command>()
                    .context("recv swap command")?
                {
                    Command::ProcessForked { uffd, reply_tube } => {
                        debug!("new fork uffd: {:?}", uffd);
                        let result = match uffd_list.register(uffd) {
                            Ok(is_dynamic_uffd) => {
                                try_gc_uffds = is_dynamic_uffd;
                                true
                            }
                            Err(e) => {
                                error!("failed to register uffd to list: {:?}", e);
                                false
                            }
                        };
                        if let Err(e) = reply_tube.send(&result) {
                            error!("failed to response to new process: {:?}", e);
                        }
                    }
                    Command::StaticDeviceSetupComplete(num_static_devices) => {
                        info!("static device setup complete: n={}", num_static_devices);
                        if !uffd_list.set_num_static_devices(num_static_devices) {
                            bail!("failed to set num_static_devices");
                        }
                    }
                    Command::Enable => {
                        info!("enabling vmm-swap");

                        let staging_shmem =
                            SharedMemory::new("swap staging memory", guest_memory.memory_size())
                                .context("create staging shmem")?;

                        let regions = regions_from_guest_memory(&guest_memory);

                        let swap_file = match (swap_file_opt.take(), truncate_worker.take()) {
                            (Some(file), None) => file,
                            (None, Some(worker)) => {
                                worker.take_file().context("failed to get truncated swap")?
                            }
                            _ => bail!("Missing swap file"),
                        };

                        let page_handler = match PageHandler::create(
                            &swap_file,
                            &staging_shmem,
                            &regions,
                            worker.channel.clone(),
                        ) {
                            Ok(page_handler) => page_handler,
                            Err(e) => {
                                error!("failed to create swap handler: {:?}", e);
                                continue;
                            }
                        };

                        // TODO(b/272634283): Should just disable vmm-swap without crash.
                        // SAFETY:
                        // Safe because the regions are from guest memory and uffd_list contains all
                        // the processes of crosvm.
                        unsafe { register_regions(&regions, uffd_list.get_list()) }
                            .context("register regions")?;

                        // events may contain unprocessed entries, but those pending events will be
                        // immediately re-created when handle_vmm_swap checks wait_ctx because
                        // WaitContext is level triggered.
                        drop(events);

                        let mutex_transition = Mutex::new(state_transition);

                        bg_job_control.reset()?;
                        let swap_result = std::thread::scope(|scope| {
                            let result = handle_vmm_swap(
                                scope,
                                &wait_ctx,
                                &page_handler,
                                &mut uffd_list,
                                &guest_memory,
                                &regions,
                                &command_tube,
                                &worker,
                                &mutex_transition,
                                &bg_job_control,
                            );
                            // Abort background jobs to unblock ScopedJoinHandle eariler on a
                            // failure.
                            bg_job_control.abort();
                            result
                        })?;
                        if swap_result.should_exit {
                            return Ok(());
                        }
                        state_transition = mutex_transition.into_inner();

                        unregister_regions(&regions, uffd_list.get_list())
                            .context("unregister regions")?;

                        // Truncate the swap file to hold minimum resources while disabled.
                        if swap_result.slow_file_cleanup {
                            truncate_worker = Some(
                                FileTruncator::new(swap_file)
                                    .context("failed to start truncating")?,
                            );
                        } else {
                            if let Err(e) = swap_file.set_len(0) {
                                error!("failed to clear swap file: {:?}", e);
                            };
                            swap_file_opt = Some(swap_file);
                        }

                        info!("vmm-swap is disabled");
                        // events are obsolete. Run `WaitContext::wait()` again
                        break;
                    }
                    Command::Trim => {
                        warn!("swap trim while disabled");
                    }
                    Command::SwapOut => {
                        warn!("swap out while disabled");
                    }
                    Command::Disable { slow_file_cleanup } => {
                        if !slow_file_cleanup {
                            if let Some(worker) = truncate_worker.take() {
                                swap_file_opt =
                                    Some(worker.take_file().context("failed to truncate swap")?);
                            }
                        }
                    }
                    Command::Exit => {
                        return Ok(());
                    }
                    Command::Status => {
                        let metrics = SwapMetrics {
                            resident_pages: count_resident_pages(&guest_memory) as u64,
                            ..Default::default()
                        };
                        let status = SwapStatus {
                            state: SwapState::Ready,
                            metrics,
                            state_transition,
                        };
                        command_tube.send(&status).context("send status response")?;
                        debug!("swap status: {:?}", status);
                    }
                },
                Token::BackgroundJobCompleted => {
                    error!("unexpected background job completed event while swap is disabled");
                    bg_job_control.reset()?;
                }
            };
        }
        if try_gc_uffds {
            uffd_list.gc_dead_uffds().context("gc dead uffds")?;
            try_gc_uffds = false;
        }
    }
}

enum State<'scope> {
    SwapOutPending,
    Trim(ScopedJoinHandle<'scope, anyhow::Result<()>>),
    SwapOutInProgress {
        started_time: Instant,
    },
    SwapOutCompleted,
    SwapInInProgress {
        join_handle: ScopedJoinHandle<'scope, anyhow::Result<()>>,
        slow_file_cleanup: bool,
    },
    Failed,
}

impl From<&State<'_>> for SwapState {
    fn from(state: &State<'_>) -> Self {
        match state {
            State::SwapOutPending => SwapState::Pending,
            State::Trim(_) => SwapState::TrimInProgress,
            State::SwapOutInProgress { .. } => SwapState::SwapOutInProgress,
            State::SwapOutCompleted => SwapState::Active,
            State::SwapInInProgress { .. } => SwapState::SwapInInProgress,
            State::Failed => SwapState::Failed,
        }
    }
}

fn handle_enable_command<'scope>(
    state: State,
    bg_job_control: &BackgroundJobControl,
    page_handler: &PageHandler,
    guest_memory: &GuestMemory,
    worker: &Worker<MoveToStaging>,
    state_transition: &Mutex<SwapStateTransition>,
) -> anyhow::Result<State<'scope>> {
    match state {
        State::SwapInInProgress { join_handle, .. } => {
            info!("abort swap-in");
            abort_background_job(join_handle, bg_job_control).context("abort swap-in")?;
        }
        State::Trim(join_handle) => {
            info!("abort trim");
            abort_background_job(join_handle, bg_job_control).context("abort trim")?;
        }
        _ => {}
    }

    info!("start moving memory to staging");
    match move_guest_to_staging(page_handler, guest_memory, worker) {
        Ok(new_state_transition) => {
            info!(
                "move {} pages to staging in {} ms",
                new_state_transition.pages, new_state_transition.time_ms
            );
            *state_transition.lock() = new_state_transition;
            Ok(State::SwapOutPending)
        }
        Err(e) => {
            error!("failed to move memory to staging: {}", e);
            *state_transition.lock() = SwapStateTransition::default();
            Ok(State::Failed)
        }
    }
}

fn move_guest_to_staging(
    page_handler: &PageHandler,
    guest_memory: &GuestMemory,
    worker: &Worker<MoveToStaging>,
) -> anyhow::Result<SwapStateTransition> {
    let start_time = std::time::Instant::now();

    let mut pages = 0;

    let result = guest_memory.regions().try_for_each(|region| {
        // SAFETY:
        // safe because:
        // * all the regions are registered to all userfaultfd
        // * no process access the guest memory
        // * page fault events are handled by PageHandler
        // * wait for all the copy completed within _processes_guard
        pages += unsafe {
            page_handler.move_to_staging(region.host_addr, region.shm, region.shm_offset)
        }
        .context("move to staging")? as u64;
        Ok(())
    });
    worker.channel.wait_complete();

    match result {
        Ok(()) => {
            let resident_pages = count_resident_pages(guest_memory);
            if resident_pages > 0 {
                error!(
                    "active page is not zero just after swap out but {} pages",
                    resident_pages
                );
            }
            let time_ms = start_time.elapsed().as_millis().try_into()?;
            Ok(SwapStateTransition { pages, time_ms })
        }
        Err(e) => Err(e),
    }
}

fn abort_background_job<T>(
    join_handle: ScopedJoinHandle<'_, anyhow::Result<T>>,
    bg_job_control: &BackgroundJobControl,
) -> anyhow::Result<T> {
    bg_job_control.abort();
    // Wait until the background job is aborted and the thread finishes.
    let result = join_handle
        .join()
        .expect("panic on the background job thread");
    bg_job_control.reset().context("reset swap in event")?;
    result.context("failure on background job thread")
}

struct VmmSwapResult {
    should_exit: bool,
    slow_file_cleanup: bool,
}

fn handle_vmm_swap<'scope, 'env>(
    scope: &'scope Scope<'scope, 'env>,
    wait_ctx: &WaitContext<Token>,
    page_handler: &'env PageHandler<'env>,
    uffd_list: &'env mut UffdList<Token, DeadUffdCheckerImpl>,
    guest_memory: &GuestMemory,
    regions: &[Range<usize>],
    command_tube: &Tube,
    worker: &Worker<MoveToStaging>,
    state_transition: &'env Mutex<SwapStateTransition>,
    bg_job_control: &'env BackgroundJobControl,
) -> anyhow::Result<VmmSwapResult> {
    let mut state = match move_guest_to_staging(page_handler, guest_memory, worker) {
        Ok(transition) => {
            info!(
                "move {} pages to staging in {} ms",
                transition.pages, transition.time_ms
            );
            *state_transition.lock() = transition;
            State::SwapOutPending
        }
        Err(e) => {
            error!("failed to move memory to staging: {}", e);
            *state_transition.lock() = SwapStateTransition::default();
            State::Failed
        }
    };
    command_tube
        .send(&SwapStatus::dummy())
        .context("send enable finish signal")?;

    let mut try_gc_uffds = false;
    loop {
        let events = match &state {
            State::SwapOutInProgress { started_time } => {
                let events = wait_ctx
                    .wait_timeout(Duration::ZERO)
                    .context("wait poll events")?;

                // TODO(b/273129441): swap out on a background thread.
                // Proceed swap out only when there is no page fault (or other) events.
                if events.is_empty() {
                    match page_handler.swap_out(MAX_SWAP_CHUNK_SIZE) {
                        Ok(num_pages) => {
                            let mut state_transition = state_transition.lock();
                            state_transition.pages += num_pages as u64;
                            state_transition.time_ms =
                                started_time.elapsed().as_millis().try_into()?;
                            if num_pages == 0 {
                                info!(
                                    "swap out all {} pages to file in {} ms",
                                    state_transition.pages, state_transition.time_ms
                                );
                                state = State::SwapOutCompleted;
                            }
                        }
                        Err(e) => {
                            error!("failed to swap out: {:?}", e);
                            state = State::Failed;
                            *state_transition.lock() = SwapStateTransition::default();
                        }
                    }
                    continue;
                }

                events
            }
            _ => wait_ctx.wait().context("wait poll events")?,
        };

        for event in events.iter() {
            match event.token {
                Token::UffdEvents(id_uffd) => {
                    let uffd = uffd_list
                        .get(id_uffd)
                        .with_context(|| format!("uffd is not found for idx: {}", id_uffd))?;
                    // Userfaultfd does not work as level triggered but as edge triggered. We need
                    // to read all the events in the userfaultfd here.
                    // TODO(kawasin): Use [userfaultfd::Uffd::read_events()] for performance.
                    while let Some(event) = uffd.read_event().context("read userfaultfd event")? {
                        match event {
                            UffdEvent::Pagefault { addr, .. } => {
                                match page_handler.handle_page_fault(uffd, addr as usize) {
                                    Ok(()) => {}
                                    Err(PageHandlerError::Userfaultfd(UffdError::UffdClosed)) => {
                                        // Do nothing for the uffd. It will be garbage-collected
                                        // when a new uffd is registered.
                                        break;
                                    }
                                    Err(e) => {
                                        bail!("failed to handle page fault: {:?}", e);
                                    }
                                }
                            }
                            UffdEvent::Remove { start, end } => {
                                page_handler
                                    .handle_page_remove(start as usize, end as usize)
                                    .context("handle fault")?;
                            }
                            event => {
                                bail!("unsupported UffdEvent: {:?}", event);
                            }
                        }
                    }
                }
                Token::Command => match command_tube
                    .recv::<Command>()
                    .context("recv swap command")?
                {
                    Command::ProcessForked { uffd, reply_tube } => {
                        debug!("new fork uffd: {:?}", uffd);
                        let result = if let Err(e) = {
                            // SAFETY: regions is generated from the guest memory
                            // SAFETY: the uffd is from a new process.
                            unsafe { register_regions(regions, std::array::from_ref(&uffd)) }
                        } {
                            error!("failed to setup uffd: {:?}", e);
                            false
                        } else {
                            match uffd_list.register(uffd) {
                                Ok(is_dynamic_uffd) => {
                                    try_gc_uffds = is_dynamic_uffd;
                                    true
                                }
                                Err(e) => {
                                    error!("failed to register uffd to list: {:?}", e);
                                    false
                                }
                            }
                        };
                        if let Err(e) = reply_tube.send(&result) {
                            error!("failed to response to new process: {:?}", e);
                        }
                    }
                    Command::StaticDeviceSetupComplete(num_static_devices) => {
                        info!("static device setup complete: n={}", num_static_devices);
                        if !uffd_list.set_num_static_devices(num_static_devices) {
                            bail!("failed to set num_static_devices");
                        }
                    }
                    Command::Enable => {
                        let result = handle_enable_command(
                            state,
                            bg_job_control,
                            page_handler,
                            guest_memory,
                            worker,
                            state_transition,
                        );
                        command_tube
                            .send(&SwapStatus::dummy())
                            .context("send enable finish signal")?;
                        state = result?;
                    }
                    Command::Trim => match &state {
                        State::SwapOutPending => {
                            *state_transition.lock() = SwapStateTransition::default();
                            let join_handle = scope.spawn(|| {
                                let mut ctx = page_handler.start_trim();
                                let job = bg_job_control.new_job();
                                let start_time = std::time::Instant::now();

                                while !job.is_aborted() {
                                    if let Some(trimmed_pages) =
                                        ctx.trim_pages(MAX_TRIM_PAGES).context("trim pages")?
                                    {
                                        let mut state_transition = state_transition.lock();
                                        state_transition.pages += trimmed_pages as u64;
                                        state_transition.time_ms =
                                            start_time.elapsed().as_millis().try_into()?;
                                    } else {
                                        // Traversed all pages.
                                        break;
                                    }
                                }

                                if job.is_aborted() {
                                    info!("trim is aborted");
                                } else {
                                    info!(
                                        "trimmed {} clean pages and {} zero pages",
                                        ctx.trimmed_clean_pages(),
                                        ctx.trimmed_zero_pages()
                                    );
                                }
                                Ok(())
                            });

                            state = State::Trim(join_handle);
                            info!("start trimming staging memory");
                        }
                        state => {
                            warn!(
                                "swap trim is not ready. state: {:?}",
                                SwapState::from(state)
                            );
                        }
                    },
                    Command::SwapOut => match &state {
                        State::SwapOutPending => {
                            state = State::SwapOutInProgress {
                                started_time: std::time::Instant::now(),
                            };
                            *state_transition.lock() = SwapStateTransition::default();
                            info!("start swapping out");
                        }
                        state => {
                            warn!("swap out is not ready. state: {:?}", SwapState::from(state));
                        }
                    },
                    Command::Disable { slow_file_cleanup } => {
                        match state {
                            State::Trim(join_handle) => {
                                info!("abort trim");
                                abort_background_job(join_handle, bg_job_control)
                                    .context("abort trim")?;
                            }
                            State::SwapOutInProgress { .. } => {
                                info!("swap out is aborted");
                            }
                            State::SwapInInProgress { join_handle, .. } => {
                                info!("swap in is in progress");
                                state = State::SwapInInProgress {
                                    join_handle,
                                    slow_file_cleanup,
                                };
                                continue;
                            }
                            _ => {}
                        }
                        *state_transition.lock() = SwapStateTransition::default();

                        let uffd = uffd_list.clone_main_uffd().context("clone main uffd")?;
                        let join_handle = scope.spawn(move || {
                            let mut ctx = page_handler.start_swap_in();
                            let job = bg_job_control.new_job();
                            let start_time = std::time::Instant::now();
                            while !job.is_aborted() {
                                match ctx.swap_in(&uffd, MAX_SWAP_CHUNK_SIZE) {
                                    Ok(num_pages) => {
                                        if num_pages == 0 {
                                            break;
                                        }
                                        let mut state_transition = state_transition.lock();
                                        state_transition.pages += num_pages as u64;
                                        state_transition.time_ms =
                                            start_time.elapsed().as_millis().try_into()?;
                                    }
                                    Err(e) => {
                                        bail!("failed to swap in: {:?}", e);
                                    }
                                }
                            }
                            if job.is_aborted() {
                                info!("swap in is aborted");
                            }
                            Ok(())
                        });
                        state = State::SwapInInProgress {
                            join_handle,
                            slow_file_cleanup,
                        };

                        info!("start swapping in");
                    }
                    Command::Exit => {
                        match state {
                            State::SwapInInProgress { join_handle, .. } => {
                                // Wait until swap-in finishes.
                                if let Err(e) = join_handle.join() {
                                    bail!("failed to join swap in thread: {:?}", e);
                                }
                                return Ok(VmmSwapResult {
                                    should_exit: true,
                                    slow_file_cleanup: false,
                                });
                            }
                            State::Trim(join_handle) => {
                                abort_background_job(join_handle, bg_job_control)
                                    .context("abort trim")?;
                            }
                            _ => {}
                        }
                        let mut ctx = page_handler.start_swap_in();
                        // Swap-in all before exit.
                        while ctx
                            .swap_in(uffd_list.main_uffd(), MAX_SWAP_CHUNK_SIZE)
                            .context("swap in")?
                            > 0
                        {}
                        return Ok(VmmSwapResult {
                            should_exit: true,
                            slow_file_cleanup: false,
                        });
                    }
                    Command::Status => {
                        let mut metrics = SwapMetrics {
                            resident_pages: count_resident_pages(guest_memory) as u64,
                            ..Default::default()
                        };
                        page_handler.load_metrics(&mut metrics);
                        let status = SwapStatus {
                            state: (&state).into(),
                            metrics,
                            state_transition: *state_transition.lock(),
                        };
                        command_tube.send(&status).context("send status response")?;
                        debug!("swap status: {:?}", status);
                    }
                },
                Token::BackgroundJobCompleted => {
                    // Reset the completed event.
                    if !bg_job_control
                        .reset()
                        .context("reset background job event")?
                    {
                        // When the job is aborted and the event is comsumed by reset(), the token
                        // `Token::BackgroundJobCompleted` may remain in the `events`. Just ignore
                        // the obsolete token here.
                        continue;
                    }
                    match state {
                        State::SwapInInProgress {
                            join_handle,
                            slow_file_cleanup,
                        } => {
                            join_handle
                                .join()
                                .expect("panic on the background job thread")
                                .context("swap in finish")?;
                            let state_transition = state_transition.lock();
                            info!(
                                "swap in all {} pages in {} ms.",
                                state_transition.pages, state_transition.time_ms
                            );
                            return Ok(VmmSwapResult {
                                should_exit: false,
                                slow_file_cleanup,
                            });
                        }
                        State::Trim(join_handle) => {
                            join_handle
                                .join()
                                .expect("panic on the background job thread")
                                .context("trim finish")?;
                            let state_transition = state_transition.lock();
                            info!(
                                "trimmed {} pages in {} ms.",
                                state_transition.pages, state_transition.time_ms
                            );
                            state = State::SwapOutPending;
                        }
                        state => {
                            bail!(
                                "background job completed but the actual state is {:?}",
                                SwapState::from(&state)
                            );
                        }
                    }
                }
            };
        }
        if try_gc_uffds {
            uffd_list.gc_dead_uffds().context("gc dead uffds")?;
            try_gc_uffds = false;
        }
    }
}
