// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! crate for the vmm-swap feature.

#![cfg(unix)]
#![deny(missing_docs)]

mod file;
mod logger;
mod pagesize;
mod present_list;
// this is public only for integration tests.
pub mod page_handler;
mod processes;
mod staging;
// this is public only for integration tests.
pub mod userfaultfd;
// this is public only for integration tests.
pub mod worker;

use std::fs::File;
use std::fs::OpenOptions;
use std::io::stderr;
use std::io::stdout;
use std::ops::Range;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread::Scope;
use std::thread::ScopedJoinHandle;
use std::time::Duration;
use std::time::Instant;

use anyhow::bail;
use anyhow::Context;
use base::debug;
use base::error;
use base::info;
use base::syslog;
use base::unix::process::fork_process;
use base::unix::process::Child;
use base::warn;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::Event;
use base::EventToken;
use base::EventWaitResult;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::SharedMemory;
use base::Tube;
use base::WaitContext;
use jail::create_base_minijail;
use jail::create_sandbox_minijail;
use jail::JailConfig;
use jail::SandboxConfig;
use jail::MAX_OPEN_FILES_DEFAULT;
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use vm_memory::GuestMemory;

#[cfg(feature = "log_page_fault")]
use crate::logger::PageFaultEventLogger;
use crate::page_handler::MoveToStaging;
use crate::page_handler::PageHandler;
use crate::page_handler::MLOCK_BUDGET;
use crate::pagesize::THP_SIZE;
use crate::processes::freeze_child_processes;
use crate::processes::ProcessesGuard;
use crate::userfaultfd::register_regions;
use crate::userfaultfd::unregister_regions;
use crate::userfaultfd::Factory as UffdFactory;
use crate::userfaultfd::UffdEvent;
use crate::userfaultfd::Userfaultfd;
use crate::worker::Worker;

/// The max size of chunks to swap out/in at once.
const MAX_SWAP_CHUNK_SIZE: usize = 2 * 1024 * 1024; // = 2MB

/// Current state of vmm-swap.
///
/// This should not contain fields but be a plain enum because this will be displayed to user using
/// `serde_json` crate.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum State {
    /// vmm-swap is ready. userfaultfd is disabled until vmm-swap is enabled.
    Ready,
    /// Pages in guest memory are moved to the staging memory.
    Pending,
    /// swap-out is in progress.
    SwapOutInProgress,
    /// swap out succeeded.
    Active,
    /// swap-in is in progress.
    SwapInInProgress,
    /// swap out failed.
    Failed,
}

impl From<&SwapState<'_>> for State {
    fn from(state: &SwapState<'_>) -> Self {
        match state {
            SwapState::SwapOutPending => State::Pending,
            SwapState::SwapOutInProgress { .. } => State::SwapOutInProgress,
            SwapState::SwapOutCompleted => State::Active,
            SwapState::SwapInInProgress(_) => State::SwapInInProgress,
            SwapState::Failed => State::Failed,
        }
    }
}

/// Latency and number of pages of swap operations (move to staging, swap out, swap in).
///
/// The meaning of `StateTransition` depends on `State`.
///
/// | `State`             | `StateTransition`                            |
/// |---------------------|----------------------------------------------|
/// | `Ready`             | empty or transition record of `swap disable` |
/// | `Pending`           | transition record of `swap enable`           |
/// | `SwapOutInProgress` | transition record of `swap out`              |
/// | `Active`            | transition record of `swap out`              |
/// | `SwapInInProgress`  | transition record of `swap disable`          |
/// | `Failed`            | empty                                        |
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub struct StateTransition {
    /// The number of pages moved for the state transition.
    pages: usize,
    /// Time taken for the state transition.
    time_ms: u128,
}

/// Current metrics of vmm-swap.
///
/// This is only available while vmm-swap is enabled.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Metrics {
    /// count of pages on RAM.
    resident_pages: usize,
    /// count of pages copied from the vmm-swap file.
    copied_from_file_pages: usize,
    /// count of pages copied from the staging memory.
    copied_from_staging_pages: usize,
    /// count of pages initialized with zero.
    zeroed_pages: usize,
    /// count of pages which were already initialized on page faults. This can happen when several
    /// threads/processes access the uninitialized/removed page at the same time.
    redundant_pages: usize,
    /// count of pages in staging memory.
    staging_pages: usize,
    /// count of pages in swap files.
    swap_pages: usize,
}

impl Metrics {
    fn new(page_handler: &PageHandler) -> Self {
        Self {
            resident_pages: page_handler.compute_resident_pages(),
            copied_from_file_pages: page_handler.compute_copied_from_file_pages(),
            copied_from_staging_pages: page_handler.compute_copied_from_staging_pages(),
            zeroed_pages: page_handler.compute_zeroed_pages(),
            redundant_pages: page_handler.compute_redundant_pages(),
            staging_pages: page_handler.compute_staging_pages(),
            swap_pages: page_handler.compute_swap_pages(),
        }
    }
}

/// The response to `crosvm swap status` command.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Status {
    state: State,
    metrics: Metrics,
    state_transition: StateTransition,
}

impl Status {
    fn new(
        state: &SwapState,
        state_transition: StateTransition,
        page_handler: &PageHandler,
    ) -> Self {
        Status {
            state: state.into(),
            metrics: Metrics::new(page_handler),
            state_transition,
        }
    }

    fn disabled(state_transition: &StateTransition) -> Self {
        Status {
            state: State::Ready,
            metrics: Metrics::default(),
            state_transition: *state_transition,
        }
    }
}

/// Commands used in vmm-swap feature internally sent to the monitor process from the main and other
/// processes.
///
/// This is mainly originated from the `crosvm swap <command>` command line.
#[derive(Serialize, Deserialize, Debug)]
enum Command {
    Enable,
    SwapOut,
    Disable,
    Exit,
    Status,
    #[serde(with = "base::platform::with_raw_descriptor")]
    ProcessForked(RawDescriptor),
}

/// Commands sent from the monitor process to the main process.
#[derive(Serialize, Deserialize, Debug)]
pub enum VmSwapCommand {
    /// Suspend vCPUs and devices.
    Suspend,
    /// Resume vCPUs and devices.
    Resume,
}

/// Response from the main process to the monitor process.
#[derive(Serialize, Deserialize, Debug)]
pub enum VmSwapResponse {
    /// Suspend completes.
    SuspendCompleted,
    /// Failed to suspend vCPUs and devices.
    SuspendFailed,
}

/// [SwapController] provides APIs to control vmm-swap.
pub struct SwapController {
    child_process: Child,
    uffd_factory: UffdFactory,
    command_tube: Tube,
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
    ) -> anyhow::Result<(Self, Tube)> {
        info!("vmm-swap is enabled. launch monitor process.");

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
        // The tube in which `VmSwapCommand` is sent from the monitor process to the main process.
        // The response is `VmSwapResponse`.
        let (vm_tube_main, vm_tube_monitor) =
            Tube::pair().context("create swap vm-request tube")?;

        // Allocate eventfd before creating sandbox.
        let swap_in_event = Event::new().context("create event")?;

        #[cfg(feature = "log_page_fault")]
        let page_fault_logger = PageFaultEventLogger::create(&swap_dir, &guest_memory)
            .context("create page fault logger")?;

        let mut keep_rds = vec![
            stdout().as_raw_descriptor(),
            stderr().as_raw_descriptor(),
            uffd.as_raw_descriptor(),
            swap_file.as_raw_descriptor(),
            command_tube_monitor.as_raw_descriptor(),
            vm_tube_monitor.as_raw_descriptor(),
            swap_in_event.as_raw_descriptor(),
            #[cfg(feature = "log_page_fault")]
            page_fault_logger.as_raw_descriptor(),
        ];

        syslog::push_descriptors(&mut keep_rds);
        cros_tracing::push_descriptors!(&mut keep_rds);
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
                    vm_tube_monitor,
                    guest_memory,
                    uffd,
                    swap_file,
                    swap_in_event,
                    #[cfg(feature = "log_page_fault")]
                    page_fault_logger,
                ) {
                    panic!("page_fault_handler_thread exited with error: {:?}", e)
                }
            })
            .context("fork monitor process")?;

        // send first status request to the monitor process and wait for the response until setup on
        // the monitor process completes.
        command_tube_main.send(&Command::Status)?;
        match command_tube_main
            .recv::<Status>()
            .context("recv initial status")?
            .state
        {
            State::Ready => {
                // The initial state of swap status is Ready and this is a signal that the
                // monitoring process completes setup and is running.
            }
            status => {
                bail!("initial state is not Ready, but {:?}", status);
            }
        };

        Ok((
            Self {
                child_process,
                uffd_factory,
                command_tube: command_tube_main,
            },
            vm_tube_main,
        ))
    }

    /// Enable monitoring page faults and move guest memory to staging memory.
    ///
    /// The pages will be swapped in from the staging memory to the guest memory on page faults
    /// until pages are written into the swap file by [Self::swap_out()].
    ///
    /// This returns as soon as it succeeds to send request to the monitor process.
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
    pub fn disable(&self) -> anyhow::Result<()> {
        self.command_tube
            .send(&Command::Disable)
            .context("send swap disable request")?;
        Ok(())
    }

    /// Return current swap status.
    ///
    /// This blocks until response from the monitor process arrives to the main process.
    pub fn status(&self) -> anyhow::Result<Status> {
        self.command_tube
            .send(&Command::Status)
            .context("send swap status request")?;
        let status = self.command_tube.recv().context("receive swap status")?;
        Ok(status)
    }

    /// Shutdown the monitor process.
    ///
    /// This blocks until the monitor process exits.
    ///
    /// This should be called once.
    pub fn exit(self) -> anyhow::Result<()> {
        self.command_tube
            .send(&Command::Exit)
            .context("send exit command")?;
        self.child_process
            .wait()
            .context("wait monitor process shutdown")?;
        Ok(())
    }

    /// Create a new userfaultfd and send it to the monitor process.
    ///
    /// This must be called as soon as a child process which may touch the guest memory is forked.
    ///
    /// Userfaultfd(2) originally has `UFFD_FEATURE_EVENT_FORK`. But it is not applicable to crosvm
    /// since it does not support non-root user namespace.
    pub fn on_process_forked(&self) -> anyhow::Result<()> {
        let uffd = self.uffd_factory.create().context("create userfaultfd")?;
        self.command_tube
            .send(&Command::ProcessForked(uffd.as_raw_descriptor()))
            .context("send forked event")?;
        // The fd for Userfaultfd in this process is droped when this method exits, but the
        // userfaultfd keeps alive in the monitor process which it is sent to.
        Ok(())
    }

    /// Suspend device processes using `SIGSTOP` signal.
    ///
    /// When the returned `ProcessesGuard` is dropped, the devices resume.
    ///
    /// This must be called from the main process.
    pub fn suspend_devices(&self) -> anyhow::Result<ProcessesGuard> {
        freeze_child_processes(self.child_process.pid)
    }
}

impl AsRawDescriptors for SwapController {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        let mut rds = self.uffd_factory.as_raw_descriptors();
        rds.push(self.command_tube.as_raw_descriptor());
        rds
    }
}

#[derive(EventToken)]
enum Token {
    UffdEvents(u32),
    Command,
    SwapInCompleted,
}

struct UffdList<'a> {
    list: Vec<Userfaultfd>,
    wait_ctx: &'a WaitContext<Token>,
}

impl<'a> UffdList<'a> {
    const ID_MAIN_UFFD: u32 = 0;

    fn new(main_uffd: Userfaultfd, wait_ctx: &'a WaitContext<Token>) -> Self {
        Self {
            list: vec![main_uffd],
            wait_ctx,
        }
    }

    fn register(&mut self, uffd: Userfaultfd) -> anyhow::Result<()> {
        let id_uffd = self
            .list
            .len()
            .try_into()
            .context("too many userfaultfd forked")?;

        self.wait_ctx
            .add(&uffd, Token::UffdEvents(id_uffd))
            .context("add to wait context")?;
        self.list.push(uffd);

        Ok(())
    }

    fn get(&self, id: u32) -> Option<&Userfaultfd> {
        self.list.get(id as usize)
    }

    fn main_uffd(&self) -> &Userfaultfd {
        &self.list[Self::ID_MAIN_UFFD as usize]
    }

    fn get_list(&self) -> &[Userfaultfd] {
        &self.list
    }
}

fn regions_from_guest_memory(guest_memory: &GuestMemory) -> Vec<Range<usize>> {
    let mut regions = Vec::new();
    guest_memory
        .with_regions::<_, ()>(|_, _, region_size, host_addr, _, _| {
            regions.push(host_addr..(host_addr + region_size));
            Ok(())
        })
        .unwrap(); // the callback never return error.
    regions
}

/// The main thread of the monitor process.
fn monitor_process(
    command_tube: Tube,
    vm_tube: Tube,
    guest_memory: GuestMemory,
    uffd: Userfaultfd,
    swap_file: File,
    swap_in_event: Event,
    #[cfg(feature = "log_page_fault")] mut page_fault_logger: PageFaultEventLogger,
) -> anyhow::Result<()> {
    info!("monitor_process started");

    let wait_ctx = WaitContext::build_with(&[
        (&command_tube, Token::Command),
        // Even though swap isn't enabled until the enable command is received, it's necessary to
        // start waiting on the main uffd here so that uffd fork events can be processed, because
        // child processes will block until their corresponding uffd fork event is read.
        (&uffd, Token::UffdEvents(UffdList::ID_MAIN_UFFD)),
        (&swap_in_event, Token::SwapInCompleted),
    ])
    .context("create wait context")?;

    let n_worker = num_cpus::get();
    info!("start {} workers for staging memory move", n_worker);
    // The worker threads are killed when the main thread of the monitor process dies.
    let worker = Worker::new(n_worker, n_worker);

    let mut uffd_list = UffdList::new(uffd, &wait_ctx);
    let mut state_transition = StateTransition::default();

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
                    Command::ProcessForked(raw_descriptor) => {
                        debug!("new fork uffd: {:?}", raw_descriptor);
                        // Safe because the raw_descriptor is sent from another process via Tube and
                        // no one in this process owns it.
                        let uffd = unsafe { Userfaultfd::from_raw_descriptor(raw_descriptor) };
                        uffd_list.register(uffd).context("register forked uffd")?;
                    }
                    Command::Enable => {
                        info!("enabling vmm-swap");

                        let staging_shmem =
                            SharedMemory::new("swap staging memory", guest_memory.memory_size())
                                .context("create staging shmem")?;

                        let regions = regions_from_guest_memory(&guest_memory);

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
                        // Safe because the regions are from guest memory and uffd_list contains all
                        // the processes of crosvm.
                        unsafe { register_regions(&regions, uffd_list.get_list()) }
                            .context("register regions")?;

                        // events may contain unprocessed entries, but those pending events will be
                        // immediately re-created when handle_vmm_swap checks wait_ctx because
                        // WaitContext is level triggered.
                        drop(events);

                        let mutex_transition = Mutex::new(state_transition);
                        let abort_flag = AbortFlag::new();

                        let exit = std::thread::scope(|scope| {
                            let exit = handle_vmm_swap(
                                scope,
                                &wait_ctx,
                                &page_handler,
                                &uffd_list,
                                &guest_memory,
                                &command_tube,
                                &vm_tube,
                                &worker,
                                &mutex_transition,
                                &abort_flag,
                                &swap_in_event,
                                #[cfg(feature = "log_page_fault")]
                                &mut page_fault_logger,
                            );
                            // Abort background jobs to unblock ScopedJoinHandle eariler on a
                            // failure.
                            abort_flag.abort();
                            exit
                        })?;
                        if exit {
                            return Ok(());
                        }
                        state_transition = mutex_transition.into_inner();

                        unregister_regions(&regions, uffd_list.get_list())
                            .context("unregister regions")?;

                        // Truncate the swap file to hold minimum resources while disabled.
                        if let Err(e) = swap_file.set_len(0) {
                            error!("failed to clear swap file: {:?}", e);
                        };

                        info!("vmm-swap is disabled");
                        // events are obsolete. Run `WaitContext::wait()` again
                        break;
                    }
                    Command::SwapOut => {
                        warn!("swap out while disabled");
                    }
                    Command::Disable => {
                        warn!("swap is already disabled");
                    }
                    Command::Exit => {
                        return Ok(());
                    }
                    Command::Status => {
                        let status = Status::disabled(&state_transition);
                        command_tube.send(&status).context("send status response")?;
                        info!("swap status: {:?}", status);
                    }
                },
                Token::SwapInCompleted => {
                    error!("unexpected swap in completed event while swap is disabled");
                    swap_in_event.reset()?;
                }
            };
        }
    }
}

enum SwapState<'scope> {
    SwapOutPending,
    SwapOutInProgress { started_time: Instant },
    SwapOutCompleted,
    SwapInInProgress(ScopedJoinHandle<'scope, anyhow::Result<()>>),
    Failed,
}

struct AbortFlag {
    flag: AtomicBool,
}

impl AbortFlag {
    fn new() -> Self {
        Self {
            flag: AtomicBool::new(false),
        }
    }

    fn abort(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.flag.store(false, Ordering::Relaxed);
    }

    fn is_aborted(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

fn move_guest_to_staging(
    page_handler: &PageHandler,
    guest_memory: &GuestMemory,
    vm_tube: &Tube,
    worker: &Worker<MoveToStaging>,
) -> anyhow::Result<StateTransition> {
    let start_time = std::time::Instant::now();

    // Suspend vCPUs and devices from the main process.
    vm_tube
        .send(&VmSwapCommand::Suspend)
        .context("request suspend")?;

    let mut pages = 0;

    let result = match vm_tube.recv().context("recv suspend completed") {
        Ok(VmSwapResponse::SuspendCompleted) => {
            let result = guest_memory.with_regions::<_, anyhow::Error>(
                |_, _, _, host_addr, shm, shm_offset| {
                    // safe because:
                    // * all the regions are registered to all userfaultfd
                    // * no process access the guest memory
                    // * page fault events are handled by PageHandler
                    // * wait for all the copy completed within _processes_guard
                    pages += unsafe { page_handler.move_to_staging(host_addr, shm, shm_offset) }
                        .context("move to staging")?;
                    Ok(())
                },
            );
            worker.channel.wait_complete();
            result
        }
        Ok(VmSwapResponse::SuspendFailed) => Err(anyhow::anyhow!("failed to suspend vm")),
        // When failed to receive suspend response, try resume the vm.
        Err(e) => Err(e),
    };

    // Resume vCPUs and devices from the main process.
    if let Err(e) = vm_tube
        .send(&VmSwapCommand::Resume)
        .context("request resume")
    {
        if let Err(e) = result {
            error!("failed to move memory to staging: {:?}", e);
        }
        return Err(e);
    }

    match result {
        Ok(()) => {
            if page_handler.compute_resident_pages() > 0 {
                error!(
                    "active page is not zero just after swap out but {} pages",
                    page_handler.compute_resident_pages()
                );
            }
            let time_ms = start_time.elapsed().as_millis();
            Ok(StateTransition { pages, time_ms })
        }
        Err(e) => Err(e),
    }
}

fn handle_vmm_swap<'scope, 'env>(
    scope: &'scope Scope<'scope, 'env>,
    wait_ctx: &WaitContext<Token>,
    page_handler: &'env PageHandler<'env>,
    uffd_list: &'env UffdList,
    guest_memory: &GuestMemory,
    command_tube: &Tube,
    vm_tube: &Tube,
    worker: &Worker<MoveToStaging>,
    state_transition: &'env Mutex<StateTransition>,
    abort_flag: &'env AbortFlag,
    swap_in_event: &'env Event,
    #[cfg(feature = "log_page_fault")] page_fault_logger: &mut PageFaultEventLogger,
) -> anyhow::Result<bool> {
    let mut state = match move_guest_to_staging(page_handler, guest_memory, vm_tube, worker) {
        Ok(transition) => {
            info!(
                "move {} pages to staging in {} ms",
                transition.pages, transition.time_ms
            );
            *state_transition.lock() = transition;
            SwapState::SwapOutPending
        }
        Err(e) => {
            error!("failed to move memory to staging: {}", e);
            *state_transition.lock() = StateTransition::default();
            SwapState::Failed
        }
    };

    loop {
        let events = match &state {
            SwapState::SwapOutInProgress { started_time } => {
                let events = wait_ctx
                    .wait_timeout(Duration::ZERO)
                    .context("wait poll events")?;

                // TODO(b/273129441): swap out on a background thread.
                // Proceed swap out only when there is no page fault (or other) events.
                if events.is_empty() {
                    match page_handler.swap_out(MAX_SWAP_CHUNK_SIZE) {
                        Ok(num_pages) => {
                            let mut state_transition = state_transition.lock();
                            state_transition.pages += num_pages;
                            state_transition.time_ms = started_time.elapsed().as_millis();
                            if num_pages == 0 {
                                info!(
                                    "swap out all {} pages to file in {} ms",
                                    state_transition.pages, state_transition.time_ms
                                );
                                state = SwapState::SwapOutCompleted;
                            }
                        }
                        Err(e) => {
                            error!("failed to swap out: {:?}", e);
                            state = SwapState::Failed;
                            *state_transition.lock() = StateTransition::default();
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
                                #[cfg(feature = "log_page_fault")]
                                page_fault_logger.log_page_fault(addr as usize, id_uffd);
                                page_handler
                                    .handle_page_fault(uffd, addr as usize)
                                    .context("handle fault")?;
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
                    Command::ProcessForked(raw_descriptor) => {
                        debug!("new fork uffd: {:?}", raw_descriptor);
                        // TODO(b/266898615): The forked processes must wait running until the
                        // regions are registered to the new uffd if vmm-swap is already enabled.
                        // There are currently no use cases for swap + hotplug, so this is currently
                        // not implemented.
                        bail!("child process is forked while swap is enabled");
                    }
                    Command::Enable => {
                        if let SwapState::SwapInInProgress(join_handle) = state {
                            info!("abort swap-in");
                            abort_flag.abort();
                            // Wait until swap-in is aborted and the swap-in thread finishes.
                            if let Err(e) = join_handle.join() {
                                bail!("failed to join swap in thread: {:?}", e);
                            }
                            swap_in_event.reset().context("reset swap_in_event")?;
                            abort_flag.reset();
                        };

                        info!("start moving memory to staging");
                        match move_guest_to_staging(page_handler, guest_memory, vm_tube, worker) {
                            Ok(new_state_transition) => {
                                info!(
                                    "move {} pages to staging in {} ms",
                                    new_state_transition.pages, new_state_transition.time_ms
                                );
                                state = SwapState::SwapOutPending;
                                *state_transition.lock() = new_state_transition;
                            }
                            Err(e) => {
                                error!("failed to move memory to staging: {}", e);
                                state = SwapState::Failed;
                                *state_transition.lock() = StateTransition::default();
                            }
                        }
                    }
                    Command::SwapOut => match &state {
                        SwapState::SwapOutPending => {
                            state = SwapState::SwapOutInProgress {
                                started_time: std::time::Instant::now(),
                            };
                            *state_transition.lock() = StateTransition::default();
                            info!("start swapping out");
                        }
                        state => {
                            warn!("swap out is not ready. state: {:?}", State::from(state));
                        }
                    },
                    Command::Disable => {
                        match &state {
                            SwapState::SwapOutInProgress { .. } => {
                                info!("swap out is aborted");
                            }
                            SwapState::SwapInInProgress(_) => {
                                info!("swap in is in progress");
                                continue;
                            }
                            _ => {}
                        }
                        *state_transition.lock() = StateTransition::default();

                        let join_handle = scope.spawn(|| {
                            let mut ctx = page_handler.start_swap_in();
                            let uffd = uffd_list.main_uffd();
                            let start_time = std::time::Instant::now();
                            let success = loop {
                                if abort_flag.is_aborted() {
                                    info!("swap in aborted on the background thread");
                                    break Ok(());
                                }
                                match ctx.swap_in(uffd, MAX_SWAP_CHUNK_SIZE) {
                                    Ok(num_pages) => {
                                        if num_pages == 0 {
                                            break Ok(());
                                        }
                                        let mut state_transition = state_transition.lock();
                                        state_transition.pages += num_pages;
                                        state_transition.time_ms = start_time.elapsed().as_millis();
                                    }
                                    Err(e) => {
                                        break Err(anyhow::anyhow!("failed to swap in: {:?}", e));
                                    }
                                }
                            };
                            swap_in_event.signal().expect("sending signal");
                            success
                        });
                        state = SwapState::SwapInInProgress(join_handle);

                        info!("start swapping in");
                    }
                    Command::Exit => {
                        match state {
                            SwapState::SwapInInProgress(join_handle) => {
                                // Wait until swap-in finishes.
                                if let Err(e) = join_handle.join() {
                                    bail!("failed to join swap in thread: {:?}", e);
                                }
                            }
                            _ => {
                                let mut ctx = page_handler.start_swap_in();
                                let uffd = uffd_list.main_uffd();
                                // Swap-in all before exit.
                                while ctx.swap_in(uffd, MAX_SWAP_CHUNK_SIZE).context("swap in")? > 0
                                {
                                }
                            }
                        }
                        return Ok(true);
                    }
                    Command::Status => {
                        let status = Status::new(&state, *state_transition.lock(), page_handler);
                        command_tube.send(&status).context("send status response")?;
                        info!("swap status: {:?}", status);
                    }
                },
                Token::SwapInCompleted => {
                    // Reset the swap in complete event.
                    if matches!(
                        swap_in_event
                            .wait_timeout(Duration::ZERO)
                            .context("failed to get swapin complete event")?,
                        EventWaitResult::TimedOut
                    ) {
                        // On `Command::Enable`, it resets the event but the token
                        // `Token::SwapInCompleted` may remain in the `events`. Just ignore the
                        // obsolete token here.
                        continue;
                    }
                    if let SwapState::SwapInInProgress(join_handle) = state {
                        match join_handle.join() {
                            Ok(Ok(_)) => {
                                let state_transition = state_transition.lock();
                                info!(
                                    "swap in all {} pages in {} ms.",
                                    state_transition.pages, state_transition.time_ms
                                );
                                return Ok(false);
                            }
                            Ok(Err(e)) => {
                                bail!("swap in failed: {:?}", e)
                            }
                            Err(e) => {
                                bail!("failed to wait for the swap in thread: {:?}", e);
                            }
                        }
                    } else {
                        bail!(
                            "swap in completed but the actual state is {:?}",
                            State::from(&state)
                        );
                    }
                }
            };
        }
    }
}
