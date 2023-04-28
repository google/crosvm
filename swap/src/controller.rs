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
use base::syslog;
use base::unix::process::fork_process;
use base::unix::process::Child;
use base::warn;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::EventToken;
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
use vm_memory::MemoryRegionInformation;

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
use crate::worker::BackgroundJobControl;
use crate::worker::Worker;
use crate::Metrics;
use crate::State;
use crate::StateTransition;
use crate::Status;

/// The max size of chunks to swap out/in at once.
const MAX_SWAP_CHUNK_SIZE: usize = 2 * 1024 * 1024; // = 2MB
/// The max pages to trim at once.
const MAX_TRIM_PAGES: usize = 1024;

/// Commands used in vmm-swap feature internally sent to the monitor process from the main and other
/// processes.
///
/// This is mainly originated from the `crosvm swap <command>` command line.
#[derive(Serialize, Deserialize, Debug)]
enum Command {
    Enable,
    Trim,
    SwapOut,
    Disable,
    Exit,
    Status,
    #[serde(with = "base::platform::with_raw_descriptor")]
    ProcessForked(RawDescriptor),
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
    ) -> anyhow::Result<Self> {
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

        // Allocate eventfd before creating sandbox.
        let bg_job_control = BackgroundJobControl::new().context("create background job event")?;

        #[cfg(feature = "log_page_fault")]
        let page_fault_logger = PageFaultEventLogger::create(&swap_dir, &guest_memory)
            .context("create page fault logger")?;

        let mut keep_rds = vec![
            stdout().as_raw_descriptor(),
            stderr().as_raw_descriptor(),
            uffd.as_raw_descriptor(),
            swap_file.as_raw_descriptor(),
            command_tube_monitor.as_raw_descriptor(),
            bg_job_control.get_completion_event().as_raw_descriptor(),
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
                    guest_memory,
                    uffd,
                    swap_file,
                    bg_job_control,
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

        Ok(Self {
            child_process,
            uffd_factory,
            command_tube: command_tube_main,
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
            .recv::<Status>()
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
    BackgroundJobCompleted,
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
        .with_regions::<_, ()>(
            |MemoryRegionInformation {
                 size, host_addr, ..
             }| {
                regions.push(host_addr..(host_addr + size));
                Ok(())
            },
        )
        .unwrap(); // the callback never return error.
    regions
}

/// The main thread of the monitor process.
fn monitor_process(
    command_tube: Tube,
    guest_memory: GuestMemory,
    uffd: Userfaultfd,
    swap_file: File,
    bg_job_control: BackgroundJobControl,
    #[cfg(feature = "log_page_fault")] mut page_fault_logger: PageFaultEventLogger,
) -> anyhow::Result<()> {
    info!("monitor_process started");

    let wait_ctx = WaitContext::build_with(&[
        (&command_tube, Token::Command),
        // Even though swap isn't enabled until the enable command is received, it's necessary to
        // start waiting on the main uffd here so that uffd fork events can be processed, because
        // child processes will block until their corresponding uffd fork event is read.
        (&uffd, Token::UffdEvents(UffdList::ID_MAIN_UFFD)),
        (
            bg_job_control.get_completion_event(),
            Token::BackgroundJobCompleted,
        ),
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

                        bg_job_control.reset()?;
                        let exit = std::thread::scope(|scope| {
                            let exit = handle_vmm_swap(
                                scope,
                                &wait_ctx,
                                &page_handler,
                                &uffd_list,
                                &guest_memory,
                                &command_tube,
                                &worker,
                                &mutex_transition,
                                &bg_job_control,
                                #[cfg(feature = "log_page_fault")]
                                &mut page_fault_logger,
                            );
                            // Abort background jobs to unblock ScopedJoinHandle eariler on a
                            // failure.
                            bg_job_control.abort();
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
                    Command::Trim => {
                        warn!("swap trim while disabled");
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
                        let status = Status {
                            state: State::Ready,
                            metrics: Metrics::default(),
                            state_transition,
                        };
                        command_tube.send(&status).context("send status response")?;
                        info!("swap status: {:?}", status);
                    }
                },
                Token::BackgroundJobCompleted => {
                    error!("unexpected background job completed event while swap is disabled");
                    bg_job_control.reset()?;
                }
            };
        }
    }
}

enum SwapState<'scope> {
    SwapOutPending,
    Trim(ScopedJoinHandle<'scope, anyhow::Result<()>>),
    SwapOutInProgress { started_time: Instant },
    SwapOutCompleted,
    SwapInInProgress(ScopedJoinHandle<'scope, anyhow::Result<()>>),
    Failed,
}

impl From<&SwapState<'_>> for State {
    fn from(state: &SwapState<'_>) -> Self {
        match state {
            SwapState::SwapOutPending => State::Pending,
            SwapState::Trim(_) => State::TrimInProgress,
            SwapState::SwapOutInProgress { .. } => State::SwapOutInProgress,
            SwapState::SwapOutCompleted => State::Active,
            SwapState::SwapInInProgress(_) => State::SwapInInProgress,
            SwapState::Failed => State::Failed,
        }
    }
}

fn handle_enable_command<'scope>(
    state: SwapState,
    bg_job_control: &BackgroundJobControl,
    page_handler: &PageHandler,
    guest_memory: &GuestMemory,
    worker: &Worker<MoveToStaging>,
    state_transition: &Mutex<StateTransition>,
) -> anyhow::Result<SwapState<'scope>> {
    match state {
        SwapState::SwapInInProgress(join_handle) => {
            info!("abort swap-in");
            abort_background_job(join_handle, bg_job_control).context("abort swap-in")?;
        }
        SwapState::Trim(join_handle) => {
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
            Ok(SwapState::SwapOutPending)
        }
        Err(e) => {
            error!("failed to move memory to staging: {}", e);
            *state_transition.lock() = StateTransition::default();
            Ok(SwapState::Failed)
        }
    }
}

fn move_guest_to_staging(
    page_handler: &PageHandler,
    guest_memory: &GuestMemory,
    worker: &Worker<MoveToStaging>,
) -> anyhow::Result<StateTransition> {
    let start_time = std::time::Instant::now();

    let mut pages = 0;

    let result = guest_memory.with_regions::<_, anyhow::Error>(
        |MemoryRegionInformation {
             host_addr,
             shm,
             shm_offset,
             ..
         }| {
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

fn handle_vmm_swap<'scope, 'env>(
    scope: &'scope Scope<'scope, 'env>,
    wait_ctx: &WaitContext<Token>,
    page_handler: &'env PageHandler<'env>,
    uffd_list: &'env UffdList,
    guest_memory: &GuestMemory,
    command_tube: &Tube,
    worker: &Worker<MoveToStaging>,
    state_transition: &'env Mutex<StateTransition>,
    bg_job_control: &'env BackgroundJobControl,
    #[cfg(feature = "log_page_fault")] page_fault_logger: &mut PageFaultEventLogger,
) -> anyhow::Result<bool> {
    let mut state = match move_guest_to_staging(page_handler, guest_memory, worker) {
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
    command_tube
        .send(&Status::dummy())
        .context("send enable finish signal")?;

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
                        let result = handle_enable_command(
                            state,
                            bg_job_control,
                            page_handler,
                            guest_memory,
                            worker,
                            state_transition,
                        );
                        command_tube
                            .send(&Status::dummy())
                            .context("send enable finish signal")?;
                        state = result?;
                    }
                    Command::Trim => match &state {
                        SwapState::SwapOutPending => {
                            *state_transition.lock() = StateTransition::default();
                            let join_handle = scope.spawn(|| {
                                let mut ctx = page_handler.start_trim();
                                let job = bg_job_control.new_job();
                                let start_time = std::time::Instant::now();

                                while !job.is_aborted() {
                                    if let Some(trimmed_pages) =
                                        ctx.trim_pages(MAX_TRIM_PAGES).context("trim pages")?
                                    {
                                        let mut state_transition = state_transition.lock();
                                        state_transition.pages += trimmed_pages;
                                        state_transition.time_ms = start_time.elapsed().as_millis();
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

                            state = SwapState::Trim(join_handle);
                            info!("start trimming staging memory");
                        }
                        state => {
                            warn!("swap trim is not ready. state: {:?}", State::from(state));
                        }
                    },
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
                        match state {
                            SwapState::Trim(join_handle) => {
                                info!("abort trim");
                                abort_background_job(join_handle, bg_job_control)
                                    .context("abort trim")?;
                            }
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
                            let job = bg_job_control.new_job();
                            let start_time = std::time::Instant::now();
                            while !job.is_aborted() {
                                match ctx.swap_in(uffd, MAX_SWAP_CHUNK_SIZE) {
                                    Ok(num_pages) => {
                                        if num_pages == 0 {
                                            break;
                                        }
                                        let mut state_transition = state_transition.lock();
                                        state_transition.pages += num_pages;
                                        state_transition.time_ms = start_time.elapsed().as_millis();
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
                                return Ok(true);
                            }
                            SwapState::Trim(join_handle) => {
                                abort_background_job(join_handle, bg_job_control)
                                    .context("abort trim")?;
                            }
                            _ => {}
                        }
                        let mut ctx = page_handler.start_swap_in();
                        let uffd = uffd_list.main_uffd();
                        // Swap-in all before exit.
                        while ctx.swap_in(uffd, MAX_SWAP_CHUNK_SIZE).context("swap in")? > 0 {}
                        return Ok(true);
                    }
                    Command::Status => {
                        let status = Status {
                            state: (&state).into(),
                            metrics: page_handler.compute_metrics(),
                            state_transition: *state_transition.lock(),
                        };
                        command_tube.send(&status).context("send status response")?;
                        info!("swap status: {:?}", status);
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
                        SwapState::SwapInInProgress(join_handle) => {
                            join_handle
                                .join()
                                .expect("panic on the background job thread")
                                .context("swap in finish")?;
                            let state_transition = state_transition.lock();
                            info!(
                                "swap in all {} pages in {} ms.",
                                state_transition.pages, state_transition.time_ms
                            );
                            return Ok(false);
                        }
                        SwapState::Trim(join_handle) => {
                            join_handle
                                .join()
                                .expect("panic on the background job thread")
                                .context("trim finish")?;
                            let state_transition = state_transition.lock();
                            info!(
                                "trimmed {} pages in {} ms.",
                                state_transition.pages, state_transition.time_ms
                            );
                            state = SwapState::SwapOutPending;
                        }
                        state => {
                            bail!(
                                "background job completed but the actual state is {:?}",
                                State::from(&state)
                            );
                        }
                    }
                }
            };
        }
    }
}
