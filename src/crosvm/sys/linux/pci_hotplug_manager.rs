// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A high-level manager for hotplug PCI devices.

// TODO(b/243767476): Support aarch64.
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Error;
use arch::RunnableLinuxVm;
use arch::VcpuArch;
use arch::VmArch;
use base::AsRawDescriptor;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::WaitContext;
use base::WorkerThread;
use devices::BusDevice;
use devices::HotPlugBus;
use devices::HotPlugKey;
use devices::IrqEventSource;
use devices::IrqLevelEvent;
use devices::PciAddress;
use devices::PciInterruptPin;
use devices::PciRootCommand;
use devices::ResourceCarrier;
use log::error;
use resources::SystemAllocator;
#[cfg(feature = "swap")]
use swap::SwapDeviceHelper;
use sync::Mutex;
use vm_memory::GuestMemory;

use crate::crosvm::sys::linux::JailWarden;
use crate::crosvm::sys::linux::JailWardenImpl;
use crate::crosvm::sys::linux::PermissiveJailWarden;
use crate::Config;

pub type Result<T> = std::result::Result<T, Error>;

/// PciHotPlugManager manages hotplug ports, and handles PCI device hot plug and hot removal.
pub struct PciHotPlugManager {
    /// map of ports managed
    port_stubs: BTreeMap<PciAddress, PortManagerStub>,
    /// map of downstream bus to upstream PCI address
    bus_address_map: BTreeMap<u8, PciAddress>,
    /// JailWarden for jailing hotplug devices
    jail_warden: Box<dyn JailWarden>,
    /// Client on Manager side of PciHotPlugWorker
    worker_client: Option<WorkerClient>,
}

/// WorkerClient is a wrapper of the worker methods.
struct WorkerClient {
    /// event to signal control command is sent
    control_evt: Event,
    /// control channel to worker
    command_sender: mpsc::Sender<WorkerCommand>,
    /// response channel from worker
    response_receiver: mpsc::Receiver<WorkerResponse>,
    _worker_thread: WorkerThread<Result<()>>,
}

impl WorkerClient {
    /// Constructs PciHotPlugWorker with its client.
    fn new(rootbus_controller: mpsc::Sender<PciRootCommand>) -> Result<Self> {
        let (command_sender, command_receiver) = mpsc::channel();
        let (response_sender, response_receiver) = mpsc::channel();
        let control_evt = Event::new()?;
        let control_evt_cpy = control_evt.try_clone()?;
        let worker_thread = WorkerThread::start("pcihp_mgr_workr", move |kill_evt| {
            let mut worker = PciHotPlugWorker::new(
                rootbus_controller,
                command_receiver,
                response_sender,
                control_evt_cpy,
                &kill_evt,
            )?;
            worker.run(kill_evt).map_err(|e| {
                error!("Worker exited with error: {:?}", &e);
                e
            })
        });
        Ok(WorkerClient {
            control_evt,
            command_sender,
            response_receiver,
            _worker_thread: worker_thread,
        })
    }

    /// Sends worker command, and wait for its response.
    fn send_worker_command(&self, command: WorkerCommand) -> Result<WorkerResponse> {
        self.command_sender.send(command)?;
        self.control_evt.signal()?;
        Ok(self.response_receiver.recv()?)
    }
}

/// PortManagerStub is the manager-side copy of a port.
struct PortManagerStub {
    /// index of downstream bus
    downstream_bus: u8,
    /// Map of hotplugged devices, and system resources that can be released when device is
    /// removed.
    devices: HashMap<PciAddress, RecoverableResource>,
}

/// System resources that can be released when a hotplugged device is removed.
struct RecoverableResource {
    irq_num: u32,
    irq_evt: IrqLevelEvent,
}

/// Control commands to worker.
enum WorkerCommand {
    /// Add port to the worker.
    AddPort(PciAddress, PortWorkerStub),
    /// Get the state of the port.
    GetPortState(PciAddress),
    /// Get an empty port for hotplug. Returns the least port sorted by PortKey.
    GetEmptyPort,
    /// Signals hot plug on port. Changes an empty port to occupied.
    SignalHotPlug(SignalHotPlugCommand),
    /// Signals hot unplug on port. Changes an occupied port to empty.
    SignalHotUnplug(PciAddress),
}

#[derive(Clone)]
struct GuestDeviceStub {
    pci_addr: PciAddress,
    key: HotPlugKey,
    device: Arc<Mutex<dyn BusDevice>>,
}

#[derive(Clone)]
struct SignalHotPlugCommand {
    /// the upstream address of hotplug port
    upstream_address: PciAddress,
    /// the array of guest devices on the port
    guest_devices: Vec<GuestDeviceStub>,
}

impl SignalHotPlugCommand {
    fn new(upstream_address: PciAddress, guest_devices: Vec<GuestDeviceStub>) -> Result<Self> {
        if guest_devices.is_empty() {
            bail!("No guest devices");
        }
        Ok(Self {
            upstream_address,
            guest_devices,
        })
    }
}

/// PortWorkerStub is the worker-side copy of a port.
#[derive(Clone)]
struct PortWorkerStub {
    /// The downstream base address of the port. Needed to send plug and unplug signal.
    base_address: PciAddress,
    /// Currently attached devices that should be removed.
    attached_devices: Vec<PciAddress>,
    /// Devices to be added each time send_hot_plug_signal is called.
    devices_to_add: VecDeque<Vec<GuestDeviceStub>>,
    /// hotplug port
    port: Arc<Mutex<dyn HotPlugBus>>,
}

impl PortWorkerStub {
    fn new(port: Arc<Mutex<dyn HotPlugBus>>, downstream_bus: u8) -> Result<Self> {
        let base_address = PciAddress::new(0, downstream_bus.into(), 0, 0)?;
        Ok(Self {
            base_address,
            devices_to_add: VecDeque::new(),
            attached_devices: Vec::new(),
            port,
        })
    }

    fn add_hotplug_devices(&mut self, devices: Vec<GuestDeviceStub>) -> Result<()> {
        if devices.is_empty() {
            bail!("No guest devices");
        }
        self.devices_to_add.push_back(devices);
        Ok(())
    }

    fn cancel_queued_add(&mut self) -> Result<()> {
        self.devices_to_add
            .pop_back()
            .context("No guest device add queued")?;
        Ok(())
    }

    fn send_hot_plug_signal(
        &mut self,
        rootbus_controller: &mpsc::Sender<PciRootCommand>,
    ) -> Result<Event> {
        let mut port_lock = self.port.lock();
        let devices = self
            .devices_to_add
            .pop_front()
            .context("Missing devices to add")?;
        for device in devices {
            rootbus_controller.send(PciRootCommand::Add(device.pci_addr, device.device))?;
            self.attached_devices.push(device.pci_addr);
            port_lock.add_hotplug_device(device.key, device.pci_addr);
        }
        port_lock
            .hot_plug(self.base_address)?
            .context("hotplug bus does not support command complete notification")
    }

    fn send_hot_unplug_signal(
        &mut self,
        rootbus_controller: &mpsc::Sender<PciRootCommand>,
    ) -> Result<Event> {
        for pci_addr in self.attached_devices.drain(..) {
            rootbus_controller.send(PciRootCommand::Remove(pci_addr))?;
        }
        self.port
            .lock()
            .hot_unplug(self.base_address)?
            .context("hotplug bus does not support command complete notification")
    }
}

/// Control response from worker.
#[derive(Debug)]
enum WorkerResponse {
    /// AddPort success.
    AddPortOk,
    /// GetEmptyPort success, use port at PciAddress.
    GetEmptyPortOk(PciAddress),
    /// GetPortState success. The "steps behind" field shall be considered expired, and the guest
    /// is "less than or equal to" n steps behind.
    GetPortStateOk(PortState),
    /// SignalHotPlug or SignalHotUnplug success.
    SignalOk,
    /// Command fail because it is not valid.
    InvalidCommand(Error),
}

impl PartialEq for WorkerResponse {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::GetEmptyPortOk(l0), Self::GetEmptyPortOk(r0)) => l0 == r0,
            (Self::GetPortStateOk(l0), Self::GetPortStateOk(r0)) => l0 == r0,
            (Self::InvalidCommand(_), Self::InvalidCommand(_)) => true,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

#[derive(Debug, EventToken)]
enum Token {
    Kill,
    ManagerCommand,
    PlugComplete(RawDescriptor),
    UnplugComplete(RawDescriptor),
}

/// PciHotPlugWorker is a worker that handles the asynchrony of slot states between crosvm and the
/// guest OS. It is responsible for scheduling the PCIe slot control signals and handle its result.
struct PciHotPlugWorker {
    event_map: BTreeMap<RawDescriptor, (Event, PciAddress)>,
    port_state_map: BTreeMap<PciAddress, PortState>,
    port_map: BTreeMap<PortKey, PortWorkerStub>,
    manager_evt: Event,
    wait_ctx: WaitContext<Token>,
    command_receiver: mpsc::Receiver<WorkerCommand>,
    response_sender: mpsc::Sender<WorkerResponse>,
    rootbus_controller: mpsc::Sender<PciRootCommand>,
}

impl PciHotPlugWorker {
    fn new(
        rootbus_controller: mpsc::Sender<PciRootCommand>,
        command_receiver: mpsc::Receiver<WorkerCommand>,
        response_sender: mpsc::Sender<WorkerResponse>,
        manager_evt: Event,
        kill_evt: &Event,
    ) -> Result<Self> {
        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (&manager_evt, Token::ManagerCommand),
            (kill_evt, Token::Kill),
        ])?;
        Ok(Self {
            event_map: BTreeMap::new(),
            port_state_map: BTreeMap::new(),
            port_map: BTreeMap::new(),
            manager_evt,
            wait_ctx,
            command_receiver,
            response_sender,
            rootbus_controller,
        })
    }

    /// Starts the worker. Runs until received kill request, or an error that the worker is in an
    /// invalid state.
    fn run(&mut self, kill_evt: Event) -> Result<()> {
        'wait: loop {
            let events = self.wait_ctx.wait()?;
            for triggered_event in events.iter().filter(|e| e.is_readable) {
                match triggered_event.token {
                    Token::ManagerCommand => {
                        self.manager_evt.wait()?;
                        self.handle_manager_command()?;
                    }
                    Token::PlugComplete(descriptor) => {
                        let (event, pci_address) = self
                            .event_map
                            .remove(&descriptor)
                            .context("Cannot find event")?;
                        self.wait_ctx.delete(&event)?;
                        self.handle_plug_complete(pci_address)?;
                    }
                    Token::UnplugComplete(descriptor) => {
                        let (event, pci_address) = self
                            .event_map
                            .remove(&descriptor)
                            .context("Cannot find event")?;
                        self.wait_ctx.delete(&event)?;
                        self.handle_unplug_complete(pci_address)?;
                    }
                    Token::Kill => {
                        let _ = kill_evt.wait();
                        break 'wait;
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_manager_command(&mut self) -> Result<()> {
        let response = match self.command_receiver.recv()? {
            WorkerCommand::AddPort(pci_address, port) => self.handle_add_port(pci_address, port),
            WorkerCommand::GetPortState(pci_address) => self.handle_get_port_state(pci_address),
            WorkerCommand::GetEmptyPort => self.handle_get_empty_port(),
            WorkerCommand::SignalHotPlug(hotplug_command) => {
                self.handle_plug_request(hotplug_command)
            }
            WorkerCommand::SignalHotUnplug(pci_address) => self.handle_unplug_request(pci_address),
        }?;
        Ok(self.response_sender.send(response)?)
    }

    /// Handles add port: Initiate port in Empty(0) state.
    fn handle_add_port(
        &mut self,
        pci_address: PciAddress,
        port: PortWorkerStub,
    ) -> Result<WorkerResponse> {
        if self.port_state_map.contains_key(&pci_address) {
            return Ok(WorkerResponse::InvalidCommand(anyhow!(
                "Conflicting upstream PCI address"
            )));
        }
        let port_state = PortState::Empty(0);
        self.port_state_map.insert(pci_address, port_state);
        self.port_map.insert(
            PortKey {
                port_state,
                pci_address,
            },
            port,
        );
        Ok(WorkerResponse::AddPortOk)
    }

    /// Handles get port state: returns the PortState.
    fn handle_get_port_state(&self, pci_address: PciAddress) -> Result<WorkerResponse> {
        match self.get_port_state(pci_address) {
            Ok(ps) => Ok(WorkerResponse::GetPortStateOk(ps)),
            Err(e) => Ok(WorkerResponse::InvalidCommand(e)),
        }
    }

    /// Handle getting empty port: Find the most empty port, or return error if all are occupied.
    fn handle_get_empty_port(&self) -> Result<WorkerResponse> {
        let most_empty_port = match self.port_map.first_key_value() {
            Some(p) => p.0,
            None => return Ok(WorkerResponse::InvalidCommand(anyhow!("No ports added"))),
        };
        match most_empty_port.port_state {
            PortState::Empty(_) => Ok(WorkerResponse::GetEmptyPortOk(most_empty_port.pci_address)),
            PortState::Occupied(_) => Ok(WorkerResponse::InvalidCommand(anyhow!("No empty port"))),
        }
    }

    /// Handles plug request: Moves PortState from Empty(n) to Occupied(n+1), and schedules the next
    /// plug event if n == 0.
    fn handle_plug_request(
        &mut self,
        hotplug_command: SignalHotPlugCommand,
    ) -> Result<WorkerResponse> {
        let pci_address = hotplug_command.upstream_address;
        let (n, next_state) = match self.get_port_state(pci_address) {
            Ok(PortState::Empty(n)) => (n, PortState::Occupied(n + 1)),
            Ok(PortState::Occupied(_)) => {
                return Ok(WorkerResponse::InvalidCommand(anyhow!(
                    "Attempt to plug into an occupied port"
                )))
            }
            Err(e) => return Ok(WorkerResponse::InvalidCommand(e)),
        };
        self.get_port_mut(pci_address)?
            .add_hotplug_devices(hotplug_command.guest_devices)?;
        if n == 0 {
            self.schedule_plug_event(pci_address)?;
        }
        self.set_port_state(pci_address, next_state)?;
        Ok(WorkerResponse::SignalOk)
    }

    /// Handles unplug request: Moves PortState from Occupied(n) to Empty(n % 2 + 1), and schedules
    /// the next unplug event if n == 0.
    ///
    /// n % 2 + 1: When unplug request is made, it either schedule the unplug event
    /// (n == 0 => 1 or n == 1 => 2), or cancels the corresponding plug event that has not started
    /// (n == 2 => 1 or n == 3 => 2). Staring at the mapping, it maps n to either 1 or 2 of opposite
    /// oddity. n % 2 + 1 is a good shorthand instead of the individual mappings.
    fn handle_unplug_request(&mut self, pci_address: PciAddress) -> Result<WorkerResponse> {
        let (n, next_state) = match self.get_port_state(pci_address) {
            Ok(PortState::Occupied(n)) => (n, PortState::Empty(n % 2 + 1)),
            Ok(PortState::Empty(_)) => {
                return Ok(WorkerResponse::InvalidCommand(anyhow!(
                    "Attempt to unplug from an empty port"
                )))
            }
            Err(e) => return Ok(WorkerResponse::InvalidCommand(e)),
        };
        if n >= 2 {
            self.get_port_mut(pci_address)?.cancel_queued_add()?;
        }
        if n == 0 {
            self.schedule_unplug_event(pci_address)?;
        }
        self.set_port_state(pci_address, next_state)?;
        Ok(WorkerResponse::SignalOk)
    }

    /// Handles plug complete: Moves PortState from Any(n) to Any(n-1), and schedules the next
    /// unplug event unless n == 1. (Any is either Empty or Occupied.)
    fn handle_plug_complete(&mut self, pci_address: PciAddress) -> Result<()> {
        let (n, next_state) = match self.get_port_state(pci_address)? {
            // Note: n - 1 >= 0 as otherwise there would be no pending events.
            PortState::Empty(n) => (n, PortState::Empty(n - 1)),
            PortState::Occupied(n) => (n, PortState::Occupied(n - 1)),
        };
        if n > 1 {
            self.schedule_unplug_event(pci_address)?;
        }
        self.set_port_state(pci_address, next_state)
    }

    /// Handles unplug complete: Moves PortState from Any(n) to Any(n-1), and schedules the next
    /// plug event unless n == 1. (Any is either Empty or Occupied.)
    fn handle_unplug_complete(&mut self, pci_address: PciAddress) -> Result<()> {
        let (n, next_state) = match self.get_port_state(pci_address)? {
            // Note: n - 1 >= 0 as otherwise there would be no pending events.
            PortState::Empty(n) => (n, PortState::Empty(n - 1)),
            PortState::Occupied(n) => (n, PortState::Occupied(n - 1)),
        };
        if n > 1 {
            self.schedule_plug_event(pci_address)?;
        }
        self.set_port_state(pci_address, next_state)
    }

    fn get_port_state(&self, pci_address: PciAddress) -> Result<PortState> {
        Ok(*self
            .port_state_map
            .get(&pci_address)
            .context(format!("Cannot find port state on {}", pci_address))?)
    }

    fn set_port_state(&mut self, pci_address: PciAddress, port_state: PortState) -> Result<()> {
        let old_port_state = self.get_port_state(pci_address)?;
        let port = self
            .port_map
            .remove(&PortKey {
                port_state: old_port_state,
                pci_address,
            })
            .context("Cannot find port")?;
        self.port_map.insert(
            PortKey {
                port_state,
                pci_address,
            },
            port,
        );
        self.port_state_map.insert(pci_address, port_state);
        Ok(())
    }

    fn schedule_plug_event(&mut self, pci_address: PciAddress) -> Result<()> {
        let rootbus_controller = self.rootbus_controller.clone();
        let plug_event = self
            .get_port_mut(pci_address)?
            .send_hot_plug_signal(&rootbus_controller)?;
        self.wait_ctx.add(
            &plug_event,
            Token::PlugComplete(plug_event.as_raw_descriptor()),
        )?;
        self.event_map
            .insert(plug_event.as_raw_descriptor(), (plug_event, pci_address));
        Ok(())
    }

    fn schedule_unplug_event(&mut self, pci_address: PciAddress) -> Result<()> {
        let rootbus_controller = self.rootbus_controller.clone();
        let unplug_event = self
            .get_port_mut(pci_address)?
            .send_hot_unplug_signal(&rootbus_controller)?;
        self.wait_ctx.add(
            &unplug_event,
            Token::UnplugComplete(unplug_event.as_raw_descriptor()),
        )?;
        self.event_map.insert(
            unplug_event.as_raw_descriptor(),
            (unplug_event, pci_address),
        );
        Ok(())
    }

    fn get_port_mut(&mut self, pci_address: PciAddress) -> Result<&mut PortWorkerStub> {
        let port_state = self.get_port_state(pci_address)?;
        self.port_map
            .get_mut(&PortKey {
                port_state,
                pci_address,
            })
            .context("PciHotPlugWorker is in invalid state")
    }
}

/// PortState indicates the state of the port.
///
/// The initial PortState is Empty(0). 7 PortStates are possible, and transition between the states
/// are only possible by the following 2 pairs of functions:
/// handle_plug_request(P) and handle_unplug_request(U): host initated requests.
/// handle_plug_complete(PC) and handle_unplug_complete(UC): guest notification of completion.
/// The state transition is as follows:
/// Emp0<-UC--Emp1<-PC--Emp2            |
///     \    ^    \^   ^    \^          |
///      P  /      P\ /      P\         |
///       \/        \\        \\        |
///       /\        /\\        \\       |
///      U  \      U  \U        \U      |
///     /    v    /    v\        v\     |
/// Occ0<-PC--Occ1<-UC--Occ2<-PC--Occ3  |

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PortState {
    /// Port is empty on crosvm. The state on the guest OS is n steps behind.
    Empty(u8),
    /// Port is occupied on crosvm. The state on the guest OS is n steps behind.
    Occupied(u8),
}

/// Ordering on PortState defined by "most empty".
impl Ord for PortState {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (PortState::Empty(lhs), PortState::Empty(rhs)) => lhs.cmp(rhs),
            (PortState::Empty(_), PortState::Occupied(_)) => Ordering::Less,
            (PortState::Occupied(_), PortState::Empty(_)) => Ordering::Greater,
            (PortState::Occupied(lhs), PortState::Occupied(rhs)) => lhs.cmp(rhs),
        }
    }
}

impl PartialOrd for PortState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// PortKey is a unique identifier of ports with an ordering defined on it.
///
/// Ports are ordered by whose downstream device would be discovered first by the guest OS.
/// Empty ports without pending events are ordered before those with pending events. When multiple
/// empty ports without pending events are available, they are ordered by PCI enumeration.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct PortKey {
    port_state: PortState,
    pci_address: PciAddress,
}

impl PciHotPlugManager {
    /// Constructs PciHotPlugManager.
    ///
    /// Constructor uses forking, therefore has to be called early, before crosvm enters a
    /// multi-threaded context.
    pub fn new(
        guest_memory: GuestMemory,
        config: &Config,
        #[cfg(feature = "swap")] swap_device_helper: Option<SwapDeviceHelper>,
    ) -> Result<Self> {
        let jail_warden: Box<dyn JailWarden> = match config.jail_config {
            Some(_) => Box::new(
                JailWardenImpl::new(
                    guest_memory,
                    config,
                    #[cfg(feature = "swap")]
                    swap_device_helper,
                )
                .context("jail warden construction")?,
            ),
            None => Box::new(
                PermissiveJailWarden::new(
                    guest_memory,
                    config,
                    #[cfg(feature = "swap")]
                    swap_device_helper,
                )
                .context("jail warden construction")?,
            ),
        };
        Ok(Self {
            jail_warden,
            port_stubs: BTreeMap::new(),
            bus_address_map: BTreeMap::new(),
            worker_client: None,
        })
    }

    /// Starts PciHotPlugManager. Required before any other commands.
    ///
    /// PciHotPlugManager::new must be called in a single-threaded context as it forks.
    /// However, rootbus_controller is only available after VM boots when crosvm is multi-threaded.
    ///
    /// TODO(293801301): Remove unused after aarch64 support
    #[allow(unused)]
    pub fn set_rootbus_controller(
        &mut self,
        rootbus_controller: mpsc::Sender<PciRootCommand>,
    ) -> Result<()> {
        // Spins the PciHotPlugWorker.
        self.worker_client = Some(WorkerClient::new(rootbus_controller)?);
        Ok(())
    }

    /// Adds a hotplug capable port to manage.
    ///
    /// PciHotPlugManager assumes exclusive control for adding and removing devices to this port.
    /// TODO(293801301): Remove unused_variables after aarch64 support
    #[allow(unused)]
    pub fn add_port(&mut self, port: Arc<Mutex<dyn HotPlugBus>>) -> Result<()> {
        let worker_client = self
            .worker_client
            .as_ref()
            .context("No worker thread. Is set_rootbus_controller not called?")?;
        let port_lock = port.lock();
        // Rejects hotplug bus with downstream devices.
        if !port_lock.is_empty() {
            bail!("invalid hotplug bus");
        }
        let pci_address = port_lock
            .get_address()
            .context("Hotplug bus PCI address missing")?;
        // Reject hotplug buses not on rootbus, since otherwise the order of enumeration depends on
        // the topology of PCI.
        if pci_address.bus != 0 {
            bail!("hotplug port on non-root bus not supported");
        }
        let downstream_bus = port_lock
            .get_secondary_bus_number()
            .context("cannot get downstream bus")?;
        drop(port_lock);
        if let Some(prev_address) = self.bus_address_map.insert(downstream_bus, pci_address) {
            bail!(
                "Downstream bus of new port is conflicting with previous port at {}",
                &prev_address
            );
        }
        self.port_stubs.insert(
            pci_address,
            PortManagerStub {
                downstream_bus,
                devices: HashMap::new(),
            },
        );
        match worker_client.send_worker_command(WorkerCommand::AddPort(
            pci_address,
            PortWorkerStub::new(port, downstream_bus)?,
        ))? {
            WorkerResponse::AddPortOk => Ok(()),
            WorkerResponse::InvalidCommand(e) => Err(e),
            r => bail!("Unexpected response from worker: {:?}", &r),
        }
    }

    /// hotplugs up to 8 PCI devices as "functions of a device" (in PCI Bus Device Function sense).
    ///
    /// returns the bus number of the bus on success.
    pub fn hotplug_device<V: VmArch, Vcpu: VcpuArch>(
        &mut self,
        resource_carriers: Vec<ResourceCarrier>,
        linux: &mut RunnableLinuxVm<V, Vcpu>,
        resources: &mut SystemAllocator,
    ) -> Result<u8> {
        let worker_client = self
            .worker_client
            .as_ref()
            .context("No worker thread. Is set_rootbus_controller not called?")?;
        if resource_carriers.len() > 8 || resource_carriers.is_empty() {
            bail!("PCI function count has to be 1 to 8 inclusive");
        }
        let pci_address = match worker_client.send_worker_command(WorkerCommand::GetEmptyPort)? {
            WorkerResponse::GetEmptyPortOk(p) => Ok(p),
            WorkerResponse::InvalidCommand(e) => Err(e),
            r => bail!("Unexpected response from worker: {:?}", &r),
        }?;
        let port_stub = self
            .port_stubs
            .get_mut(&pci_address)
            .context("Cannot find port")?;
        let downstream_bus = port_stub.downstream_bus;
        let mut devices = Vec::new();
        for (func_num, mut resource_carrier) in resource_carriers.into_iter().enumerate() {
            let device_address = PciAddress::new(0, downstream_bus as u32, 0, func_num as u32)?;
            let hotplug_key = HotPlugKey::GuestDevice {
                guest_addr: device_address,
            };
            resource_carrier.allocate_address(device_address, resources)?;
            let irq_evt = IrqLevelEvent::new()?;
            let (pin, irq_num) = match downstream_bus % 4 {
                0 => (PciInterruptPin::IntA, 0),
                1 => (PciInterruptPin::IntB, 1),
                2 => (PciInterruptPin::IntC, 2),
                _ => (PciInterruptPin::IntD, 3),
            };
            resource_carrier.assign_irq(irq_evt.try_clone()?, pin, irq_num);
            let (proxy_device, pid) = self
                .jail_warden
                .make_proxy_device(resource_carrier)
                .context("make proxy device")?;
            let device_id = proxy_device.lock().device_id();
            let device_name = proxy_device.lock().debug_label();
            linux.irq_chip.as_irq_chip_mut().register_level_irq_event(
                irq_num,
                &irq_evt,
                IrqEventSource {
                    device_id,
                    queue_id: 0,
                    device_name: device_name.clone(),
                },
            )?;
            let pid: u32 = pid.try_into().context("fork fail")?;
            if pid > 0 {
                linux.pid_debug_label_map.insert(pid, device_name);
            }
            devices.push(GuestDeviceStub {
                pci_addr: device_address,
                key: hotplug_key,
                device: proxy_device,
            });
            port_stub
                .devices
                .insert(device_address, RecoverableResource { irq_num, irq_evt });
        }
        // Ask worker to schedule hotplug signal.
        match worker_client.send_worker_command(WorkerCommand::SignalHotPlug(
            SignalHotPlugCommand::new(pci_address, devices)?,
        ))? {
            WorkerResponse::SignalOk => Ok(downstream_bus),
            WorkerResponse::InvalidCommand(e) => Err(e),
            r => bail!("Unexpected response from worker: {:?}", &r),
        }
    }

    /// Removes all hotplugged devices on the hotplug bus.
    pub fn remove_hotplug_device<V: VmArch, Vcpu: VcpuArch>(
        &mut self,
        bus: u8,
        linux: &mut RunnableLinuxVm<V, Vcpu>,
        resources: &mut SystemAllocator,
    ) -> Result<()> {
        let worker_client = self
            .worker_client
            .as_ref()
            .context("No worker thread. Is set_rootbus_controller not called?")?;
        let pci_address = self
            .bus_address_map
            .get(&bus)
            .context(format!("Port {} is not known", &bus))?;
        match worker_client.send_worker_command(WorkerCommand::GetPortState(*pci_address))? {
            WorkerResponse::GetPortStateOk(PortState::Occupied(_)) => {}
            WorkerResponse::GetPortStateOk(PortState::Empty(_)) => {
                bail!("Port {} is empty", &bus)
            }
            WorkerResponse::InvalidCommand(e) => {
                return Err(e);
            }
            wr => bail!("Unexpected response from worker: {:?}", &wr),
        };
        // Performs a surprise removal. That is, not waiting for hot removal completion before
        // deleting the resources.
        match worker_client.send_worker_command(WorkerCommand::SignalHotUnplug(*pci_address))? {
            WorkerResponse::SignalOk => {}
            WorkerResponse::InvalidCommand(e) => {
                return Err(e);
            }
            wr => bail!("Unexpected response from worker: {:?}", &wr),
        }
        // Remove all devices on the hotplug bus.
        let port_stub = self
            .port_stubs
            .get_mut(pci_address)
            .context(format!("Port {} is not known", &bus))?;
        for (downstream_address, recoverable_resource) in port_stub.devices.drain() {
            // port_stub.port does not have remove_hotplug_device method, as devices are removed
            // when hot_unplug is called.
            resources.release_pci(
                downstream_address.bus,
                downstream_address.dev,
                downstream_address.func,
            );
            linux.irq_chip.unregister_level_irq_event(
                recoverable_resource.irq_num,
                &recoverable_resource.irq_evt,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use devices::DeviceId;
    use devices::Suspendable;
    use serde::Deserialize;
    use serde::Serialize;

    use super::*;

    /// A MockPort that only supports hot_plug and hot_unplug commands, and signaling command
    /// complete manually, which is sufficient for PciHotPlugWorker unit test.
    struct MockPort {
        cc_event: Event,
        downstream_bus: u8,
    }

    impl MockPort {
        fn new(downstream_bus: u8) -> Self {
            Self {
                cc_event: Event::new().unwrap(),
                downstream_bus,
            }
        }

        fn signal_cc(&self) {
            self.cc_event.reset().unwrap();
            self.cc_event.signal().unwrap();
        }
    }

    #[derive(Copy, Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct MockDevice;

    impl Suspendable for MockDevice {
        fn snapshot(&mut self) -> anyhow::Result<serde_json::Value> {
            serde_json::to_value(self).context("error serializing")
        }

        fn restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
            *self = serde_json::from_value(data).context("error deserializing")?;
            Ok(())
        }

        fn sleep(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        fn wake(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    impl BusDevice for MockDevice {
        fn device_id(&self) -> DeviceId {
            DeviceId::try_from(0xdead_beef).unwrap()
        }
        fn debug_label(&self) -> String {
            "mock device".to_owned()
        }
    }

    impl HotPlugBus for MockPort {
        fn hot_plug(&mut self, _addr: PciAddress) -> anyhow::Result<Option<Event>> {
            self.cc_event = Event::new().unwrap();
            Ok(Some(self.cc_event.try_clone().unwrap()))
        }

        fn hot_unplug(&mut self, _addr: PciAddress) -> anyhow::Result<Option<Event>> {
            self.cc_event = Event::new().unwrap();
            Ok(Some(self.cc_event.try_clone().unwrap()))
        }

        fn is_match(&self, _host_addr: PciAddress) -> Option<u8> {
            None
        }

        fn get_address(&self) -> Option<PciAddress> {
            None
        }

        fn get_secondary_bus_number(&self) -> Option<u8> {
            Some(self.downstream_bus)
        }

        fn add_hotplug_device(&mut self, _hotplug_key: HotPlugKey, _guest_addr: PciAddress) {}

        fn get_hotplug_device(&self, _hotplug_key: HotPlugKey) -> Option<PciAddress> {
            None
        }

        fn is_empty(&self) -> bool {
            true
        }

        fn get_hotplug_key(&self) -> Option<HotPlugKey> {
            None
        }
    }

    fn new_port(downstream_bus: u8) -> Arc<Mutex<MockPort>> {
        Arc::new(Mutex::new(MockPort::new(downstream_bus)))
    }

    fn poll_until_with_timeout<F>(f: F, timeout: Duration) -> bool
    where
        F: Fn() -> bool,
    {
        for _ in 0..timeout.as_millis() {
            if f() {
                return true;
            }
            thread::sleep(Duration::from_millis(1));
        }
        false
    }

    #[test]
    fn worker_empty_port_ordering() {
        let (rootbus_controller, _rootbus_recvr) = mpsc::channel();
        let client = WorkerClient::new(rootbus_controller).unwrap();
        // Port A: upstream 00:01.1, downstream 2.
        let upstream_addr_a = PciAddress {
            bus: 0,
            dev: 1,
            func: 1,
        };
        let bus_a = 2;
        let downstream_addr_a = PciAddress {
            bus: bus_a,
            dev: 0,
            func: 0,
        };
        let hotplug_key_a = HotPlugKey::GuestDevice {
            guest_addr: downstream_addr_a,
        };
        let device_a = GuestDeviceStub {
            pci_addr: downstream_addr_a,
            key: hotplug_key_a,
            device: Arc::new(Mutex::new(MockDevice)),
        };
        let hotplug_command_a =
            SignalHotPlugCommand::new(upstream_addr_a, [device_a].to_vec()).unwrap();
        // Port B: upstream 00:01.0, downstream 3.
        let upstream_addr_b = PciAddress {
            bus: 0,
            dev: 1,
            func: 0,
        };
        let bus_b = 3;
        let downstream_addr_b = PciAddress {
            bus: bus_b,
            dev: 0,
            func: 0,
        };
        let hotplug_key_b = HotPlugKey::GuestDevice {
            guest_addr: downstream_addr_b,
        };
        let device_b = GuestDeviceStub {
            pci_addr: downstream_addr_b,
            key: hotplug_key_b,
            device: Arc::new(Mutex::new(MockDevice)),
        };
        let hotplug_command_b =
            SignalHotPlugCommand::new(upstream_addr_b, [device_b].to_vec()).unwrap();
        // Port C: upstream 00:02.0, downstream 4.
        let upstream_addr_c = PciAddress {
            bus: 0,
            dev: 2,
            func: 0,
        };
        let bus_c = 4;
        let downstream_addr_c = PciAddress {
            bus: bus_c,
            dev: 0,
            func: 0,
        };
        let hotplug_key_c = HotPlugKey::GuestDevice {
            guest_addr: downstream_addr_c,
        };
        let device_c = GuestDeviceStub {
            pci_addr: downstream_addr_c,
            key: hotplug_key_c,
            device: Arc::new(Mutex::new(MockDevice)),
        };
        let hotplug_command_c =
            SignalHotPlugCommand::new(upstream_addr_c, [device_c].to_vec()).unwrap();
        assert_eq!(
            WorkerResponse::AddPortOk,
            client
                .send_worker_command(WorkerCommand::AddPort(
                    upstream_addr_a,
                    PortWorkerStub::new(new_port(bus_a), bus_a).unwrap()
                ))
                .unwrap()
        );
        assert_eq!(
            WorkerResponse::AddPortOk,
            client
                .send_worker_command(WorkerCommand::AddPort(
                    upstream_addr_b,
                    PortWorkerStub::new(new_port(bus_b), bus_b).unwrap()
                ))
                .unwrap()
        );
        assert_eq!(
            WorkerResponse::AddPortOk,
            client
                .send_worker_command(WorkerCommand::AddPort(
                    upstream_addr_c,
                    PortWorkerStub::new(new_port(bus_c), bus_c).unwrap()
                ))
                .unwrap()
        );
        // All ports empty and in sync. Should get port B.
        assert_eq!(
            WorkerResponse::GetEmptyPortOk(upstream_addr_b),
            client
                .send_worker_command(WorkerCommand::GetEmptyPort)
                .unwrap()
        );
        assert_eq!(
            WorkerResponse::SignalOk,
            client
                .send_worker_command(WorkerCommand::SignalHotPlug(hotplug_command_b))
                .unwrap()
        );
        // Should get port A.
        assert_eq!(
            WorkerResponse::GetEmptyPortOk(upstream_addr_a),
            client
                .send_worker_command(WorkerCommand::GetEmptyPort)
                .unwrap()
        );
        assert_eq!(
            WorkerResponse::SignalOk,
            client
                .send_worker_command(WorkerCommand::SignalHotPlug(hotplug_command_a))
                .unwrap()
        );
        // Should get port C.
        assert_eq!(
            WorkerResponse::GetEmptyPortOk(upstream_addr_c),
            client
                .send_worker_command(WorkerCommand::GetEmptyPort)
                .unwrap()
        );
        assert_eq!(
            WorkerResponse::SignalOk,
            client
                .send_worker_command(WorkerCommand::SignalHotPlug(hotplug_command_c))
                .unwrap()
        );
        // Should get an error since no port is empty.
        if let WorkerResponse::InvalidCommand(_) = client
            .send_worker_command(WorkerCommand::GetEmptyPort)
            .unwrap()
        {
            // Assert result is of Error type.
        } else {
            unreachable!();
        }
        // Remove device from port A, immediately it should be available.
        assert_eq!(
            WorkerResponse::SignalOk,
            client
                .send_worker_command(WorkerCommand::SignalHotUnplug(upstream_addr_a))
                .unwrap()
        );
        assert_eq!(
            WorkerResponse::GetEmptyPortOk(upstream_addr_a),
            client
                .send_worker_command(WorkerCommand::GetEmptyPort)
                .unwrap()
        );
        // Moreover, it should be 2 steps behind.
        assert_eq!(
            WorkerResponse::GetPortStateOk(PortState::Empty(2)),
            client
                .send_worker_command(WorkerCommand::GetPortState(upstream_addr_a))
                .unwrap()
        );
    }

    #[test]
    fn worker_port_state_transitions() {
        let (rootbus_controller, _rootbus_recvr) = mpsc::channel();
        let client = WorkerClient::new(rootbus_controller).unwrap();
        let upstream_addr = PciAddress {
            bus: 0,
            dev: 1,
            func: 1,
        };
        let bus = 2;
        let downstream_addr = PciAddress {
            bus,
            dev: 0,
            func: 0,
        };
        let hotplug_key = HotPlugKey::GuestDevice {
            guest_addr: downstream_addr,
        };
        let device = GuestDeviceStub {
            pci_addr: downstream_addr,
            key: hotplug_key,
            device: Arc::new(Mutex::new(MockDevice)),
        };
        let hotplug_command = SignalHotPlugCommand::new(upstream_addr, [device].to_vec()).unwrap();
        let port = new_port(bus);
        assert_eq!(
            WorkerResponse::AddPortOk,
            client
                .send_worker_command(WorkerCommand::AddPort(
                    upstream_addr,
                    PortWorkerStub::new(port.clone(), bus).unwrap()
                ))
                .unwrap()
        );
        assert!(poll_until_with_timeout(
            || client
                .send_worker_command(WorkerCommand::GetPortState(upstream_addr))
                .unwrap()
                == WorkerResponse::GetPortStateOk(PortState::Empty(0)),
            Duration::from_millis(500)
        ));
        assert_eq!(
            WorkerResponse::SignalOk,
            client
                .send_worker_command(WorkerCommand::SignalHotPlug(hotplug_command.clone()))
                .unwrap()
        );
        assert!(poll_until_with_timeout(
            || client
                .send_worker_command(WorkerCommand::GetPortState(upstream_addr))
                .unwrap()
                == WorkerResponse::GetPortStateOk(PortState::Occupied(1)),
            Duration::from_millis(500)
        ));
        assert_eq!(
            WorkerResponse::SignalOk,
            client
                .send_worker_command(WorkerCommand::SignalHotUnplug(upstream_addr))
                .unwrap()
        );
        assert!(poll_until_with_timeout(
            || client
                .send_worker_command(WorkerCommand::GetPortState(upstream_addr))
                .unwrap()
                == WorkerResponse::GetPortStateOk(PortState::Empty(2)),
            Duration::from_millis(500)
        ));
        assert_eq!(
            WorkerResponse::SignalOk,
            client
                .send_worker_command(WorkerCommand::SignalHotPlug(hotplug_command.clone()))
                .unwrap()
        );
        assert!(poll_until_with_timeout(
            || client
                .send_worker_command(WorkerCommand::GetPortState(upstream_addr))
                .unwrap()
                == WorkerResponse::GetPortStateOk(PortState::Occupied(3)),
            Duration::from_millis(500)
        ));
        port.lock().signal_cc();
        assert!(poll_until_with_timeout(
            || client
                .send_worker_command(WorkerCommand::GetPortState(upstream_addr))
                .unwrap()
                == WorkerResponse::GetPortStateOk(PortState::Occupied(2)),
            Duration::from_millis(500)
        ));
        assert_eq!(
            WorkerResponse::SignalOk,
            client
                .send_worker_command(WorkerCommand::SignalHotUnplug(upstream_addr))
                .unwrap()
        );
        // Moves from Occupied(2) to Empty(1) since it is redundant to unplug a device that is yet
        // to be plugged in.
        assert!(poll_until_with_timeout(
            || client
                .send_worker_command(WorkerCommand::GetPortState(upstream_addr))
                .unwrap()
                == WorkerResponse::GetPortStateOk(PortState::Empty(1)),
            Duration::from_millis(500)
        ));
        port.lock().signal_cc();
        assert!(poll_until_with_timeout(
            || client
                .send_worker_command(WorkerCommand::GetPortState(upstream_addr))
                .unwrap()
                == WorkerResponse::GetPortStateOk(PortState::Empty(0)),
            Duration::from_millis(500)
        ));
    }
}
