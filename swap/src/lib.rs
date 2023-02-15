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
use std::sync::Arc;
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
use base::Tube;
use base::WaitContext;
use minijail::Minijail;
use serde::Deserialize;
use serde::Serialize;
use vm_memory::GuestMemory;

#[cfg(feature = "log_page_fault")]
use crate::logger::PageFaultEventLogger;
use crate::page_handler::MoveToStaging;
use crate::page_handler::PageHandler;
use crate::processes::freeze_all_processes;
use crate::userfaultfd::register_regions;
use crate::userfaultfd::unregister_regions;
use crate::userfaultfd::Factory as UffdFactory;
use crate::userfaultfd::UffdEvent;
use crate::userfaultfd::Userfaultfd;
use crate::worker::Channel;
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

impl From<&SwapState> for State {
    fn from(state: &SwapState) -> Self {
        match state {
            SwapState::Disabled => State::Ready,
            SwapState::SwapOutPending => State::Pending,
            SwapState::InProgress {
                direction: SwapDirection::Out,
                ..
            } => State::SwapOutInProgress,
            SwapState::SwapOutCompleted => State::Active,
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
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
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
        state_transition: &StateTransition,
        page_handler: &Option<PageHandler>,
    ) -> Self {
        Status {
            state: state.into(),
            metrics: page_handler
                .as_ref()
                .map(Metrics::new)
                .unwrap_or_else(Metrics::default),
            state_transition: state_transition.clone(),
        }
    }
}

/// Commands used in vmm-swap feature internally between [SwapController] and [monitor_process].
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

/// [SwapController] provides APIs to control vmm-swap.
pub struct SwapController {
    child_process: Child,
    uffd_factory: UffdFactory,
    tube: Tube,
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
    pub fn launch(guest_memory: GuestMemory, swap_dir: &Path) -> anyhow::Result<Self> {
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

        let (tube_main_process, tube_monitor_process) = Tube::pair().context("create swap tube")?;

        #[cfg(feature = "log_page_fault")]
        let page_fault_logger = PageFaultEventLogger::create(&swap_dir, &guest_memory)
            .context("create page fault logger")?;

        let mut keep_rds = vec![
            stdout().as_raw_descriptor(),
            stderr().as_raw_descriptor(),
            uffd.as_raw_descriptor(),
            swap_file.as_raw_descriptor(),
            tube_monitor_process.as_raw_descriptor(),
            #[cfg(feature = "log_page_fault")]
            page_fault_logger.as_raw_descriptor(),
        ];

        syslog::push_descriptors(&mut keep_rds);
        cros_tracing::push_descriptors!(&mut keep_rds);
        keep_rds.extend(guest_memory.as_raw_descriptors());

        keep_rds.extend(uffd_factory.as_raw_descriptors());

        // TODO(b/258351526): setup minijail details
        let jail = Minijail::new().context("create minijail")?;

        // Start a page fault monitoring process (this will be the first child process of the
        // current process)
        let child_process =
            fork_process(jail, keep_rds, Some(String::from("swap monitor")), || {
                if let Err(e) = monitor_process(
                    tube_monitor_process,
                    guest_memory,
                    uffd,
                    swap_file,
                    #[cfg(feature = "log_page_fault")]
                    page_fault_logger,
                ) {
                    panic!("page_fault_handler_thread exited with error: {:?}", e)
                }
            })
            .context("fork monitor process")?;

        // send first status request to the monitor process and wait for the response until setup on
        // the monitor process completes.
        tube_main_process.send(&Command::Status)?;
        match tube_main_process
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
            tube: tube_main_process,
        })
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
        self.tube
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
        self.tube
            .send(&Command::SwapOut)
            .context("send swap out request")?;
        Ok(())
    }

    /// Swap in all the guest memory and disable monitoring page faults.
    ///
    /// This returns as soon as it succeeds to send request to the monitor process.
    pub fn disable(&self) -> anyhow::Result<()> {
        self.tube
            .send(&Command::Disable)
            .context("send swap disable request")?;
        Ok(())
    }

    /// Return current swap status.
    ///
    /// This blocks until response from the monitor process arrives to the main process.
    pub fn status(&self) -> anyhow::Result<Status> {
        self.tube
            .send(&Command::Status)
            .context("send swap status request")?;
        let status = self.tube.recv().context("receive swap status")?;
        Ok(status)
    }

    /// Shutdown the monitor process.
    ///
    /// This blocks until the monitor process exits.
    ///
    /// This should be called once.
    pub fn exit(self) -> anyhow::Result<()> {
        self.tube
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
        self.tube
            .send(&Command::ProcessForked(uffd.as_raw_descriptor()))
            .context("send forked event")?;
        // The fd for Userfaultfd in this process is droped when this method exits, but the
        // userfaultfd keeps alive in the monitor process which it is sent to.
        Ok(())
    }
}

impl AsRawDescriptors for SwapController {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        let mut rds = self.uffd_factory.as_raw_descriptors();
        rds.push(self.tube.as_raw_descriptor());
        rds
    }
}

#[derive(EventToken)]
enum Token {
    UffdEvents(u32),
    Command,
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

fn start_monitoring<'a>(
    uffd_list: &mut UffdList,
    guest_memory: &GuestMemory,
    swap_file: &'a File,
    channel: Arc<Channel<MoveToStaging>>,
) -> anyhow::Result<PageHandler<'a>> {
    // Drain the event queue to ensure that the uffds for all forked processes are being monitored.
    let mut new_uffds = Vec::new();
    for uffd in uffd_list.get_list() {
        while let Some(event) = uffd.read_event().context("read event")? {
            if let UffdEvent::Fork { uffd } = event {
                new_uffds.push(uffd.into());
            } else {
                bail!("unexpected uffd event before registering: {:?}", event);
            }
        }
    }
    for uffd in new_uffds {
        uffd_list.register(uffd).context("register uffd")?;
    }

    let regions = regions_from_guest_memory(guest_memory);

    let page_hander = PageHandler::create(swap_file, &regions, channel).context("enable swap")?;

    // safe because the regions are from guest memory and uffd_list contains all the processes of
    // crosvm.
    unsafe { register_regions(&regions, uffd_list.get_list()) }.context("register regions")?;

    Ok(page_hander)
}

fn disable_monitoring(
    mut page_handler: PageHandler,
    uffd_list: &UffdList,
    guest_memory: &GuestMemory,
) -> anyhow::Result<usize> {
    let mut num_pages = 0;
    loop {
        let pages = page_handler
            .swap_in(uffd_list.main_uffd(), MAX_SWAP_CHUNK_SIZE)
            .context("unregister all regions")?;
        if pages == 0 {
            break;
        }
        num_pages += pages;
    }
    let regions = regions_from_guest_memory(guest_memory);
    unregister_regions(&regions, uffd_list.get_list()).context("unregister regions")?;
    Ok(num_pages)
}

enum SwapDirection {
    Out,
    // TODO(b/265606668): Add `In` to swap-in concurrently.
}

enum SwapState {
    Disabled,
    SwapOutPending,
    InProgress {
        direction: SwapDirection,
        started_time: Instant,
    },
    SwapOutCompleted,
    Failed,
}

/// the main thread of the monitor process.
fn monitor_process(
    tube: Tube,
    guest_memory: GuestMemory,
    uffd: Userfaultfd,
    swap_file: File,
    #[cfg(feature = "log_page_fault")] mut page_fault_logger: PageFaultEventLogger,
) -> anyhow::Result<()> {
    info!("monitor_process started");

    let wait_ctx = WaitContext::build_with(&[
        (&tube, Token::Command),
        // Even though swap isn't enabled until the enable command is received, it's necessary to
        // start waiting on the main uffd here so that uffd fork events can be processed, because
        // child processes will block until their corresponding uffd fork event is read.
        (&uffd, Token::UffdEvents(UffdList::ID_MAIN_UFFD)),
    ])
    .context("create wait context")?;

    let n_worker = num_cpus::get();
    info!("start {} workers for staging memory move", n_worker);
    // The worker threads are killed when the main thread of the monitor process dies.
    let worker = Worker::new(n_worker, n_worker);

    let mut uffd_list = UffdList::new(uffd, &wait_ctx);
    let mut state: SwapState = SwapState::Disabled;
    let mut state_transition = StateTransition::default();
    let mut page_handler_opt: Option<PageHandler> = None;

    'wait: loop {
        let events = match &state {
            SwapState::InProgress {
                direction,
                started_time,
            } => {
                let events = wait_ctx
                    .wait_timeout(Duration::ZERO)
                    .context("wait poll events")?;

                // proceed swap out only when there is no page fault (or other) events.
                if events.is_empty() {
                    // page_handler must be present when state is InProgress.
                    let page_handler = page_handler_opt.as_mut().unwrap();
                    match direction {
                        SwapDirection::Out => {
                            let num_pages = page_handler
                                .swap_out(MAX_SWAP_CHUNK_SIZE)
                                .context("swap out")?;
                            state_transition.pages += num_pages;
                            state_transition.time_ms = started_time.elapsed().as_millis();
                            if num_pages == 0 {
                                info!(
                                    "swap out {} pages to file in {} ms",
                                    state_transition.pages, state_transition.time_ms
                                );
                                state = SwapState::SwapOutCompleted;
                            }
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
                    // userfaultfd does not work as level triggered but as edge triggered. We need
                    // to read all the events in the userfaultfd here.
                    while let Some((uffd, event)) = {
                        // get uffd on every loop because [UffdList::register()] called in this loop
                        // is mutable.
                        let uffd = uffd_list
                            .get(id_uffd)
                            .with_context(|| format!("uffd is not found for idx: {}", id_uffd))?;
                        // TODO(kawasin): Use [userfaultfd::Uffd::read_events()] for performance.
                        uffd.read_event()
                            .context("read userfaultfd event")?
                            .map(|event| (uffd, event))
                    } {
                        match event {
                            UffdEvent::Pagefault { addr, .. } => {
                                #[cfg(feature = "log_page_fault")]
                                page_fault_logger.log_page_fault(addr as usize, id_uffd);
                                if let Some(ref mut page_handler) = page_handler_opt {
                                    page_handler
                                        .handle_page_fault(uffd, addr as usize)
                                        .context("handle fault")?;
                                } else {
                                    bail!("page fault event while handler is none");
                                }
                            }
                            UffdEvent::Remove { start, end } => {
                                if let Some(ref mut page_handler) = page_handler_opt {
                                    page_handler
                                        .handle_page_remove(start as usize, end as usize)
                                        .context("handle fault")?;
                                } else {
                                    warn!("page remove event while handler is none");
                                }
                            }
                            event => {
                                bail!("unsupported UffdEvent: {:?}", event);
                            }
                        }
                    }
                }
                Token::Command => match tube.recv::<Command>().context("recv swap command")? {
                    Command::ProcessForked(raw_descriptor) => {
                        debug!("new fork uffd: {:?}", raw_descriptor);
                        // Safe because the raw_descriptor is sent from another process via Tube and
                        // no one in this process owns it.
                        let uffd = unsafe { Userfaultfd::from_raw_descriptor(raw_descriptor) };
                        if page_handler_opt.is_none() {
                            uffd_list.register(uffd).context("register forked uffd")?;
                        } else {
                            // TODO(b/266898615): The forked processes must wait running until the
                            // regions are registered to the new uffd if vmm-swap is already
                            // enabled. There are currently no use cases for swap + hotplug, so this
                            // is currently not implemented.
                            bail!("child process is forked while swap is enabled");
                        }
                    }
                    Command::Enable => {
                        if page_handler_opt.is_none() {
                            info!("enable monitoring page faults");
                            page_handler_opt = Some(start_monitoring(
                                &mut uffd_list,
                                &guest_memory,
                                &swap_file,
                                worker.channel.clone(),
                            )?);
                        }
                        let page_handler = page_handler_opt.as_mut().unwrap();

                        info!("start moving memory to staging");
                        let t0 = std::time::Instant::now();
                        state_transition = StateTransition::default();

                        let result = {
                            let _processes_guard =
                                freeze_all_processes().context("freeze processes")?;
                            let result = guest_memory.with_regions::<_, anyhow::Error>(
                                |_, _, _, host_addr, shm, shm_offset| {
                                    // safe because:
                                    // * all the regions are registered to all userfaultfd
                                    // * no process access the guest memory (freeze_all_processes())
                                    // * page fault events are handled by PageHandler.
                                    // * wait for all the copy completed within _processes_guard.
                                    state_transition.pages += unsafe {
                                        page_handler.move_to_staging(host_addr, shm, shm_offset)
                                    }
                                    .context("move to staging")?;
                                    Ok(())
                                },
                            );
                            worker.channel.wait_complete();
                            result
                        };
                        state_transition.time_ms = t0.elapsed().as_millis();

                        match result {
                            Ok(()) => {
                                info!(
                                    "move {} pages to staging in {} ms",
                                    state_transition.pages, state_transition.time_ms
                                );
                                if page_handler.compute_resident_pages() > 0 {
                                    error!(
                                        "active page is not zero just after swap out but {} pages",
                                        page_handler.compute_resident_pages()
                                    );
                                }
                                state = SwapState::SwapOutPending;
                            }
                            Err(e) => {
                                error!("failed to move memory to staging: {}", e);
                                state = SwapState::Failed;
                                state_transition = StateTransition::default();
                            }
                        }
                    }
                    Command::SwapOut => match &state {
                        SwapState::SwapOutPending => {
                            state = SwapState::InProgress {
                                direction: SwapDirection::Out,
                                started_time: std::time::Instant::now(),
                            };
                            state_transition = StateTransition::default();
                            info!("start swapping out.");
                        }
                        state => {
                            warn!("swap out is not ready. state: {:?}", State::from(state));
                        }
                    },
                    Command::Disable => {
                        match &state {
                            SwapState::Disabled => {
                                warn!("swap is already disabled.");
                                continue;
                            }
                            SwapState::InProgress {
                                direction: SwapDirection::Out,
                                ..
                            } => {
                                info!("swap out is aborted.");
                            }
                            _ => {}
                        }
                        if let Some(page_handler) = page_handler_opt.take() {
                            let t0 = std::time::Instant::now();
                            state_transition.pages =
                                disable_monitoring(page_handler, &uffd_list, &guest_memory)?;
                            state_transition.time_ms = t0.elapsed().as_millis();
                            info!(
                                "swap in all {} pages in {} ms. swap disabled.",
                                state_transition.pages, state_transition.time_ms
                            );
                            // Truncate the swap file to hold minimum resources while disabled.
                            swap_file.set_len(0).context("clear swap file")?;
                            state = SwapState::Disabled;
                        } else {
                            error!("swap is already disabled.");
                        }
                    }
                    Command::Exit => {
                        break 'wait;
                    }
                    Command::Status => {
                        let status = Status::new(&state, &state_transition, &page_handler_opt);
                        tube.send(&status).context("send status response")?;
                        info!("swap status: {:?}.", status);
                    }
                },
            };
        }
    }
    Ok(())
}
