// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
#[cfg(feature = "direct")]
use std::fs;
#[cfg(feature = "direct")]
use std::io::Error as IoError;
#[cfg(feature = "direct")]
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;

use acpi_tables::aml;
use acpi_tables::aml::Aml;
use anyhow::Context;
use base::error;
use base::warn;
use base::Error as SysError;
use base::Event;
use base::EventToken;
use base::SendTube;
use base::VmEventType;
use base::WaitContext;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use thiserror::Error;
use vm_control::GpeNotify;
use vm_control::PmResource;

use crate::pci::CrosvmDeviceId;
use crate::serialize_arc_mutex;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::BusResumeDevice;
use crate::DeviceId;
use crate::IrqLevelEvent;
use crate::Suspendable;

#[derive(Error, Debug)]
pub enum ACPIPMError {
    /// Creating WaitContext failed.
    #[error("failed to create wait context: {0}")]
    CreateWaitContext(SysError),
    /// Error while waiting for events.
    #[error("failed to wait for events: {0}")]
    WaitError(SysError),
    #[error("Did not find group_id corresponding to acpi_mc_group")]
    AcpiMcGroupError,
    #[error("Failed to create and bind NETLINK_GENERIC socket for acpi_mc_group: {0}")]
    AcpiEventSockError(base::Error),
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum ACPIPMFixedEvent {
    GlobalLock,
    PowerButton,
    SleepButton,
    RTC,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Pm1Resource {
    pub(crate) status: u16,
    enable: u16,
    control: u16,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct GpeResource {
    pub(crate) status: [u8; ACPIPM_RESOURCE_GPE0_BLK_LEN as usize / 2],
    enable: [u8; ACPIPM_RESOURCE_GPE0_BLK_LEN as usize / 2],
    #[serde(skip_serializing, skip_deserializing)]
    pub(crate) gpe_notify: BTreeMap<u32, Vec<Arc<Mutex<dyn GpeNotify>>>>,
}

#[cfg(feature = "direct")]
struct DirectGpe {
    num: u32,
    path: PathBuf,
    ready: bool,
    enabled: bool,
}

#[cfg(feature = "direct")]
struct DirectFixedEvent {
    evt: ACPIPMFixedEvent,
    bitshift: u16,
    path: PathBuf,
    enabled: bool,
}

/// ACPI PM resource for handling OS suspend/resume request
#[allow(dead_code)]
#[derive(Serialize)]
pub struct ACPIPMResource {
    // This is SCI interrupt that will be raised in the VM.
    #[serde(skip_serializing)]
    sci_evt: IrqLevelEvent,
    // This is the host SCI that is being handled by crosvm.
    #[cfg(feature = "direct")]
    #[serde(skip_serializing)]
    sci_direct_evt: Option<IrqLevelEvent>,
    #[cfg(feature = "direct")]
    #[serde(skip_serializing)]
    direct_gpe: Vec<DirectGpe>,
    #[cfg(feature = "direct")]
    #[serde(skip_serializing)]
    direct_fixed_evts: Vec<DirectFixedEvent>,
    #[serde(skip_serializing)]
    kill_evt: Option<Event>,
    #[serde(skip_serializing)]
    worker_thread: Option<thread::JoinHandle<()>>,
    #[serde(skip_serializing)]
    suspend_evt: Event,
    #[serde(skip_serializing)]
    exit_evt_wrtube: SendTube,
    #[serde(serialize_with = "serialize_arc_mutex")]
    pm1: Arc<Mutex<Pm1Resource>>,
    #[serde(serialize_with = "serialize_arc_mutex")]
    gpe0: Arc<Mutex<GpeResource>>,
}

#[derive(Deserialize)]
struct ACPIPMResrourceSerializable {
    pm1: Pm1Resource,
    gpe0: GpeResource,
}

impl ACPIPMResource {
    /// Constructs ACPI Power Management Resouce.
    ///
    /// `direct_evt_info` - tuple of:
    ///     1. host SCI trigger and resample events
    ///     2. list of direct GPEs
    ///     3. list of direct fixed events
    #[allow(dead_code)]
    pub fn new(
        sci_evt: IrqLevelEvent,
        #[cfg(feature = "direct")] direct_evt_info: Option<(
            IrqLevelEvent,
            &[u32],
            &[ACPIPMFixedEvent],
        )>,
        suspend_evt: Event,
        exit_evt_wrtube: SendTube,
    ) -> ACPIPMResource {
        let pm1 = Pm1Resource {
            status: 0,
            enable: 0,
            control: 0,
        };
        let gpe0 = GpeResource {
            status: Default::default(),
            enable: Default::default(),
            gpe_notify: BTreeMap::new(),
        };

        #[cfg(feature = "direct")]
        let (sci_direct_evt, direct_gpe, direct_fixed_evts) = if let Some(info) = direct_evt_info {
            let (evt, gpes, fixed_evts) = info;
            let gpe_vec = gpes.iter().map(|gpe| DirectGpe::new(*gpe)).collect();
            let fixed_evt_vec = fixed_evts
                .iter()
                .map(|evt| DirectFixedEvent::new(*evt))
                .collect();
            (Some(evt), gpe_vec, fixed_evt_vec)
        } else {
            (None, Vec::new(), Vec::new())
        };

        ACPIPMResource {
            sci_evt,
            #[cfg(feature = "direct")]
            sci_direct_evt,
            #[cfg(feature = "direct")]
            direct_gpe,
            #[cfg(feature = "direct")]
            direct_fixed_evts,
            kill_evt: None,
            worker_thread: None,
            suspend_evt,
            exit_evt_wrtube,
            pm1: Arc::new(Mutex::new(pm1)),
            gpe0: Arc::new(Mutex::new(gpe0)),
        }
    }

    pub fn start(&mut self) {
        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed to create kill Event pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let sci_evt = self.sci_evt.try_clone().expect("failed to clone event");
        let pm1 = self.pm1.clone();
        let gpe0 = self.gpe0.clone();

        #[cfg(feature = "direct")]
        let sci_direct_evt = self.sci_direct_evt.take();

        #[cfg(feature = "direct")]
        // ACPI event listener is currently used only for notifying gpe_notify
        // notifiers when a GPE is fired in the host. For direct forwarded GPEs,
        // we notify gpe_notify in a different way, ensuring that the notifier
        // completes synchronously before we inject the GPE into the guest.
        // So tell ACPI event listener to ignore direct GPEs.
        let acpi_event_ignored_gpe = self.direct_gpe.iter().map(|gpe| gpe.num).collect();

        #[cfg(not(feature = "direct"))]
        let acpi_event_ignored_gpe = Vec::new();

        let worker_result = thread::Builder::new()
            .name("ACPI PM worker".to_string())
            .spawn(move || {
                if let Err(e) = run_worker(
                    sci_evt,
                    kill_evt,
                    pm1,
                    gpe0,
                    acpi_event_ignored_gpe,
                    #[cfg(feature = "direct")]
                    sci_direct_evt,
                ) {
                    error!("{}", e);
                }
            });

        match worker_result {
            Err(e) => error!("failed to spawn ACPI PM worker thread: {}", e),
            Ok(join_handle) => self.worker_thread = Some(join_handle),
        }
    }
}

impl Suspendable for ACPIPMResource {
    fn snapshot(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(self)
            .with_context(|| format!("error serializing {}", self.debug_label()))
    }

    fn restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let acpi_snapshot: ACPIPMResrourceSerializable = serde_json::from_value(data)
            .with_context(|| format!("error deserializing {}", self.debug_label()))?;
        {
            let mut pm1 = self.pm1.lock();
            *pm1 = acpi_snapshot.pm1;
        }
        {
            let mut gpe0 = self.gpe0.lock();
            gpe0.status = acpi_snapshot.gpe0.status;
            gpe0.enable = acpi_snapshot.gpe0.enable;
        }
        Ok(())
    }

    fn sleep(&mut self) -> anyhow::Result<()> {
        if let Some(kill_evt) = self.kill_evt.take() {
            let _ = kill_evt.signal();
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        self.start();
        Ok(())
    }
}

fn run_worker(
    sci_evt: IrqLevelEvent,
    kill_evt: Event,
    pm1: Arc<Mutex<Pm1Resource>>,
    gpe0: Arc<Mutex<GpeResource>>,
    acpi_event_ignored_gpe: Vec<u32>,
    #[cfg(feature = "direct")] sci_direct_evt: Option<IrqLevelEvent>,
) -> Result<(), ACPIPMError> {
    let acpi_event_sock = crate::sys::get_acpi_event_sock()?;
    #[derive(EventToken)]
    enum Token {
        AcpiEvent,
        InterruptResample,
        #[cfg(feature = "direct")]
        InterruptTriggerDirect,
        Kill,
    }

    let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
        (sci_evt.get_resample(), Token::InterruptResample),
        (&kill_evt, Token::Kill),
    ])
    .map_err(ACPIPMError::CreateWaitContext)?;
    if let Some(acpi_event_sock) = &acpi_event_sock {
        wait_ctx
            .add(acpi_event_sock, Token::AcpiEvent)
            .map_err(ACPIPMError::CreateWaitContext)?;
    }

    #[cfg(feature = "direct")]
    if let Some(ref evt) = sci_direct_evt {
        wait_ctx
            .add(evt.get_trigger(), Token::InterruptTriggerDirect)
            .map_err(ACPIPMError::CreateWaitContext)?;
    }

    #[cfg(feature = "direct")]
    let mut pending_sci_direct: Option<&IrqLevelEvent> = None;

    loop {
        let events = wait_ctx.wait().map_err(ACPIPMError::WaitError)?;
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::AcpiEvent => {
                    crate::sys::acpi_event_run(&acpi_event_sock, &gpe0, &acpi_event_ignored_gpe);
                }
                Token::InterruptResample => {
                    sci_evt.clear_resample();

                    #[cfg(feature = "direct")]
                    if let Some(evt) = pending_sci_direct.take() {
                        if let Err(e) = evt.trigger_resample() {
                            error!("ACPIPM: failed to resample sci event: {}", e);
                        }
                    }

                    // Re-trigger SCI if PM1 or GPE status is still not cleared.
                    pm1.lock().trigger_sci(&sci_evt);
                    gpe0.lock().trigger_sci(&sci_evt);
                }
                #[cfg(feature = "direct")]
                Token::InterruptTriggerDirect => {
                    if let Some(ref evt) = sci_direct_evt {
                        evt.clear_trigger();

                        for (gpe, devs) in &gpe0.lock().gpe_notify {
                            if DirectGpe::is_gpe_trigger(*gpe).unwrap_or(false) {
                                for dev in devs {
                                    dev.lock().notify();
                                }
                            }
                        }

                        if let Err(e) = sci_evt.trigger() {
                            error!("ACPIPM: failed to trigger sci event: {}", e);
                        }
                        pending_sci_direct = Some(evt);
                    }
                }
                Token::Kill => return Ok(()),
            }
        }
    }
}

impl Drop for ACPIPMResource {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            let _ = kill_evt.signal();
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

impl Pm1Resource {
    fn trigger_sci(&self, sci_evt: &IrqLevelEvent) {
        if self.status & self.enable & ACPIPMFixedEvent::bitmask_all() != 0 {
            if let Err(e) = sci_evt.trigger() {
                error!("ACPIPM: failed to trigger sci event for pm1: {}", e);
            }
        }
    }
}

impl GpeResource {
    fn trigger_sci(&self, sci_evt: &IrqLevelEvent) {
        if (0..self.status.len()).any(|i| self.status[i] & self.enable[i] != 0) {
            if let Err(e) = sci_evt.trigger() {
                error!("ACPIPM: failed to trigger sci event for gpe: {}", e);
            }
        }
    }
}

#[cfg(feature = "direct")]
impl DirectGpe {
    fn new(gpe: u32) -> DirectGpe {
        DirectGpe {
            num: gpe,
            path: PathBuf::from("/sys/firmware/acpi/interrupts").join(format!("gpe{:02X}", gpe)),
            ready: false,
            enabled: false,
        }
    }

    fn is_status_set(&self) -> Result<bool, IoError> {
        match fs::read_to_string(&self.path) {
            Err(e) => {
                error!("ACPIPM: failed to read gpe {} STS: {}", self.num, e);
                Err(e)
            }
            Ok(s) => Ok(s.split_whitespace().any(|s| s == "STS")),
        }
    }

    fn is_enabled(&self) -> Result<bool, IoError> {
        match fs::read_to_string(&self.path) {
            Err(e) => {
                error!("ACPIPM: failed to read gpe {} EN: {}", self.num, e);
                Err(e)
            }
            Ok(s) => Ok(s.split_whitespace().any(|s| s == "EN")),
        }
    }

    fn clear(&self) {
        if !self.is_status_set().unwrap_or(false) {
            // Just to avoid harmless error messages due to clearing an already cleared GPE.
            return;
        }

        if let Err(e) = fs::write(&self.path, "clear\n") {
            error!("ACPIPM: failed to clear gpe {}: {}", self.num, e);
        }
    }

    fn enable(&mut self) {
        if self.enabled {
            // Just to avoid harmless error messages due to enabling an already enabled GPE.
            return;
        }

        if !self.ready {
            // The GPE is being enabled for the first time.
            // Use "enable" to ensure the ACPICA's reference count for this GPE is > 0.
            match fs::write(&self.path, "enable\n") {
                Err(e) => error!("ACPIPM: failed to enable gpe {}: {}", self.num, e),
                Ok(()) => {
                    self.ready = true;
                    self.enabled = true;
                }
            }
        } else {
            // Use "unmask" instead of "enable", to bypass ACPICA's reference counting.
            match fs::write(&self.path, "unmask\n") {
                Err(e) => error!("ACPIPM: failed to unmask gpe {}: {}", self.num, e),
                Ok(()) => {
                    self.enabled = true;
                }
            }
        }
    }

    fn disable(&mut self) {
        if !self.enabled {
            // Just to avoid harmless error messages due to disabling an already disabled GPE.
            return;
        }

        // Use "mask" instead of "disable", to bypass ACPICA's reference counting.
        match fs::write(&self.path, "mask\n") {
            Err(e) => error!("ACPIPM: failed to mask gpe {}: {}", self.num, e),
            Ok(()) => {
                self.enabled = false;
            }
        }
    }

    fn is_gpe_trigger(gpe: u32) -> Result<bool, IoError> {
        let path = PathBuf::from("/sys/firmware/acpi/interrupts").join(format!("gpe{:02X}", gpe));
        let s = fs::read_to_string(&path)?;
        let mut enable = false;
        let mut status = false;
        for itr in s.split_whitespace() {
            match itr {
                "EN" => enable = true,
                "STS" => status = true,
                _ => (),
            }
        }

        Ok(enable && status)
    }
}

#[cfg(feature = "direct")]
impl DirectFixedEvent {
    fn new(evt: ACPIPMFixedEvent) -> DirectFixedEvent {
        DirectFixedEvent {
            evt,
            bitshift: evt.bitshift(),
            path: PathBuf::from("/sys/firmware/acpi/interrupts").join(match evt {
                ACPIPMFixedEvent::GlobalLock => "ff_gbl_lock",
                ACPIPMFixedEvent::PowerButton => "ff_pwr_btn",
                ACPIPMFixedEvent::SleepButton => "ff_slp_btn",
                ACPIPMFixedEvent::RTC => "ff_rt_clk",
            }),
            enabled: false,
        }
    }

    fn is_status_set(&self) -> Result<bool, IoError> {
        match fs::read_to_string(&self.path) {
            Err(e) => {
                error!("ACPIPM: failed to read {:?} event STS: {}", self.evt, e);
                Err(e)
            }
            Ok(s) => Ok(s.split_whitespace().any(|s| s == "STS")),
        }
    }

    fn is_enabled(&self) -> Result<bool, IoError> {
        match fs::read_to_string(&self.path) {
            Err(e) => {
                error!("ACPIPM: failed to read {:?} event EN: {}", self.evt, e);
                Err(e)
            }
            Ok(s) => Ok(s.split_whitespace().any(|s| s == "EN")),
        }
    }

    fn clear(&self) {
        if !self.is_status_set().unwrap_or(false) {
            // Just to avoid harmless error messages due to clearing an already cleared event.
            return;
        }

        if let Err(e) = fs::write(&self.path, "clear\n") {
            error!("ACPIPM: failed to clear {:?} event: {}", self.evt, e);
        }
    }

    fn enable(&mut self) {
        if self.enabled {
            // Just to avoid harmless error messages due to enabling an already enabled event.
            return;
        }

        match fs::write(&self.path, "enable\n") {
            Err(e) => error!("ACPIPM: failed to enable {:?} event: {}", self.evt, e),
            Ok(()) => {
                self.enabled = true;
            }
        }
    }

    fn disable(&mut self) {
        if !self.enabled {
            // Just to avoid harmless error messages due to disabling an already disabled event.
            return;
        }

        match fs::write(&self.path, "disable\n") {
            Err(e) => error!("ACPIPM: failed to disable {:?} event: {}", self.evt, e),
            Ok(()) => {
                self.enabled = false;
            }
        }
    }
}

/// the ACPI PM register length.
pub const ACPIPM_RESOURCE_EVENTBLK_LEN: u8 = 4;
pub const ACPIPM_RESOURCE_CONTROLBLK_LEN: u8 = 2;
pub const ACPIPM_RESOURCE_GPE0_BLK_LEN: u8 = 64;
pub const ACPIPM_RESOURCE_LEN: u8 = ACPIPM_RESOURCE_EVENTBLK_LEN + 4 + ACPIPM_RESOURCE_GPE0_BLK_LEN;

/// ACPI PM register value definitions

/// 4.8.4.1.1 PM1 Status Registers, ACPI Spec Version 6.4
/// Register Location: <PM1a_EVT_BLK / PM1b_EVT_BLK> System I/O or Memory Space (defined in FADT)
/// Size: PM1_EVT_LEN / 2 (defined in FADT)
const PM1_STATUS: u16 = 0;

/// 4.8.4.1.2 PM1Enable Registers, ACPI Spec Version 6.4
/// Register Location: <<PM1a_EVT_BLK / PM1b_EVT_BLK> + PM1_EVT_LEN / 2 System I/O or Memory Space
/// (defined in FADT)
/// Size: PM1_EVT_LEN / 2 (defined in FADT)
const PM1_ENABLE: u16 = PM1_STATUS + (ACPIPM_RESOURCE_EVENTBLK_LEN as u16 / 2);

/// 4.8.4.2.1 PM1 Control Registers, ACPI Spec Version 6.4
/// Register Location: <PM1a_CNT_BLK / PM1b_CNT_BLK> System I/O or Memory Space (defined in FADT)
/// Size: PM1_CNT_LEN (defined in FADT)
const PM1_CONTROL: u16 = PM1_STATUS + ACPIPM_RESOURCE_EVENTBLK_LEN as u16;

/// 4.8.5.1 General-Purpose Event Register Blocks, ACPI Spec Version 6.4
/// - Each register block contains two registers: an enable and a status register.
/// - Each register block is 32-bit aligned.
/// - Each register in the block is accessed as a byte.

/// 4.8.5.1.1 General-Purpose Event 0 Register Block, ACPI Spec Version 6.4
/// This register block consists of two registers: The GPE0_STS and the GPE0_EN registers. Each
/// register’s length is defined to be half the length of the GPE0 register block, and is described
/// in the ACPI FADT’s GPE0_BLK and GPE0_BLK_LEN operators.

/// 4.8.5.1.1.1 General-Purpose Event 0 Status Register, ACPI Spec Version 6.4
/// Register Location: <GPE0_STS> System I/O or System Memory Space (defined in FADT)
/// Size: GPE0_BLK_LEN/2 (defined in FADT)
const GPE0_STATUS: u16 = PM1_STATUS + ACPIPM_RESOURCE_EVENTBLK_LEN as u16 + 4; // ensure alignment

/// 4.8.5.1.1.2 General-Purpose Event 0 Enable Register, ACPI Spec Version 6.4
/// Register Location: <GPE0_EN> System I/O or System Memory Space (defined in FADT)
/// Size: GPE0_BLK_LEN/2 (defined in FADT)
const GPE0_ENABLE: u16 = GPE0_STATUS + (ACPIPM_RESOURCE_GPE0_BLK_LEN as u16 / 2);

/// 4.8.4.1.1, 4.8.4.1.2 Fixed event bits in both PM1 Status and PM1 Enable registers.
const BITSHIFT_PM1_GBL: u16 = 5;
const BITSHIFT_PM1_PWRBTN: u16 = 8;
const BITSHIFT_PM1_SLPBTN: u16 = 9;
const BITSHIFT_PM1_RTC: u16 = 10;

const BITMASK_PM1CNT_SLEEP_ENABLE: u16 = 0x2000;
const BITMASK_PM1CNT_WAKE_STATUS: u16 = 0x8000;

#[cfg(not(feature = "direct"))]
const BITMASK_PM1CNT_SLEEP_TYPE: u16 = 0x1C00;
#[cfg(not(feature = "direct"))]
const SLEEP_TYPE_S1: u16 = 1 << 10;
#[cfg(not(feature = "direct"))]
const SLEEP_TYPE_S5: u16 = 0 << 10;

impl ACPIPMFixedEvent {
    fn bitshift(self) -> u16 {
        match self {
            ACPIPMFixedEvent::GlobalLock => BITSHIFT_PM1_GBL,
            ACPIPMFixedEvent::PowerButton => BITSHIFT_PM1_PWRBTN,
            ACPIPMFixedEvent::SleepButton => BITSHIFT_PM1_SLPBTN,
            ACPIPMFixedEvent::RTC => BITSHIFT_PM1_RTC,
        }
    }

    pub(crate) fn bitmask(self) -> u16 {
        1 << self.bitshift()
    }

    fn bitmask_all() -> u16 {
        (1 << BITSHIFT_PM1_GBL)
            | (1 << BITSHIFT_PM1_PWRBTN)
            | (1 << BITSHIFT_PM1_SLPBTN)
            | (1 << BITSHIFT_PM1_RTC)
    }
}

impl FromStr for ACPIPMFixedEvent {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gbllock" => Ok(ACPIPMFixedEvent::GlobalLock),
            "powerbtn" => Ok(ACPIPMFixedEvent::PowerButton),
            "sleepbtn" => Ok(ACPIPMFixedEvent::SleepButton),
            "rtc" => Ok(ACPIPMFixedEvent::RTC),
            _ => Err("unknown event, must be: gbllock|powerbtn|sleepbtn|rtc"),
        }
    }
}

impl PmResource for ACPIPMResource {
    fn pwrbtn_evt(&mut self) {
        let mut pm1 = self.pm1.lock();

        pm1.status |= ACPIPMFixedEvent::PowerButton.bitmask();
        pm1.trigger_sci(&self.sci_evt);
    }

    fn slpbtn_evt(&mut self) {
        let mut pm1 = self.pm1.lock();

        pm1.status |= ACPIPMFixedEvent::SleepButton.bitmask();
        pm1.trigger_sci(&self.sci_evt);
    }

    fn gpe_evt(&mut self, gpe: u32) {
        let mut gpe0 = self.gpe0.lock();

        let byte = gpe as usize / 8;
        if byte >= gpe0.status.len() {
            error!("gpe_evt: GPE register {} does not exist", byte);
            return;
        }
        gpe0.status[byte] |= 1 << (gpe % 8);
        gpe0.trigger_sci(&self.sci_evt);
    }

    fn register_gpe_notify_dev(&mut self, gpe: u32, notify_dev: Arc<Mutex<dyn GpeNotify>>) {
        let mut gpe0 = self.gpe0.lock();
        match gpe0.gpe_notify.get_mut(&gpe) {
            Some(v) => v.push(notify_dev),
            None => {
                gpe0.gpe_notify.insert(gpe, vec![notify_dev]);
            }
        }
    }
}

const PM1_STATUS_LAST: u16 = PM1_STATUS + (ACPIPM_RESOURCE_EVENTBLK_LEN as u16 / 2) - 1;
const PM1_ENABLE_LAST: u16 = PM1_ENABLE + (ACPIPM_RESOURCE_EVENTBLK_LEN as u16 / 2) - 1;
const PM1_CONTROL_LAST: u16 = PM1_CONTROL + ACPIPM_RESOURCE_CONTROLBLK_LEN as u16 - 1;
const GPE0_STATUS_LAST: u16 = GPE0_STATUS + (ACPIPM_RESOURCE_GPE0_BLK_LEN as u16 / 2) - 1;
const GPE0_ENABLE_LAST: u16 = GPE0_ENABLE + (ACPIPM_RESOURCE_GPE0_BLK_LEN as u16 / 2) - 1;

impl BusDevice for ACPIPMResource {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::ACPIPMResource.into()
    }

    fn debug_label(&self) -> String {
        "ACPIPMResource".to_owned()
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        match info.offset as u16 {
            // Accesses to the PM1 registers are done through byte or word accesses
            PM1_STATUS..=PM1_STATUS_LAST => {
                if data.len() > std::mem::size_of::<u16>()
                    || info.offset + data.len() as u64 > (PM1_STATUS_LAST + 1).into()
                {
                    warn!("ACPIPM: bad read size: {}", data.len());
                    return;
                }
                let offset = (info.offset - PM1_STATUS as u64) as usize;

                let v = self.pm1.lock().status.to_ne_bytes();
                for (i, j) in (offset..offset + data.len()).enumerate() {
                    data[i] = v[j];

                    #[cfg(feature = "direct")]
                    for evt in self
                        .direct_fixed_evts
                        .iter()
                        .filter(|evt| evt.bitshift / 8 == j as u16)
                    {
                        data[i] &= !(1 << (evt.bitshift % 8));
                        if evt.is_status_set().unwrap_or(false) {
                            data[i] |= 1 << (evt.bitshift % 8);
                        }
                    }
                }
            }
            PM1_ENABLE..=PM1_ENABLE_LAST => {
                if data.len() > std::mem::size_of::<u16>()
                    || info.offset + data.len() as u64 > (PM1_ENABLE_LAST + 1).into()
                {
                    warn!("ACPIPM: bad read size: {}", data.len());
                    return;
                }
                let offset = (info.offset - PM1_ENABLE as u64) as usize;

                let v = self.pm1.lock().enable.to_ne_bytes();
                for (i, j) in (offset..offset + data.len()).enumerate() {
                    data[i] = v[j];

                    #[cfg(feature = "direct")]
                    for evt in self
                        .direct_fixed_evts
                        .iter()
                        .filter(|evt| evt.bitshift / 8 == j as u16)
                    {
                        data[i] &= !(1 << (evt.bitshift % 8));
                        if evt.is_enabled().unwrap_or(false) {
                            data[i] |= 1 << (evt.bitshift % 8);
                        }
                    }
                }
            }
            PM1_CONTROL..=PM1_CONTROL_LAST => {
                if data.len() > std::mem::size_of::<u16>()
                    || info.offset + data.len() as u64 > (PM1_CONTROL_LAST + 1).into()
                {
                    warn!("ACPIPM: bad read size: {}", data.len());
                    return;
                }
                let offset = (info.offset - PM1_CONTROL as u64) as usize;
                data.copy_from_slice(
                    &self.pm1.lock().control.to_ne_bytes()[offset..offset + data.len()],
                );
            }
            // OSPM accesses GPE registers through byte accesses (regardless of their length)
            GPE0_STATUS..=GPE0_STATUS_LAST => {
                if data.len() > std::mem::size_of::<u8>()
                    || info.offset + data.len() as u64 > (GPE0_STATUS_LAST + 1).into()
                {
                    warn!("ACPIPM: bad read size: {}", data.len());
                    return;
                }
                let offset = (info.offset - GPE0_STATUS as u64) as usize;
                data[0] = self.gpe0.lock().status[offset];

                #[cfg(feature = "direct")]
                for gpe in self
                    .direct_gpe
                    .iter()
                    .filter(|gpe| gpe.num / 8 == offset as u32)
                {
                    data[0] &= !(1 << (gpe.num % 8));
                    if gpe.is_status_set().unwrap_or(false) {
                        data[0] |= 1 << (gpe.num % 8);
                    }
                }
            }
            GPE0_ENABLE..=GPE0_ENABLE_LAST => {
                if data.len() > std::mem::size_of::<u8>()
                    || info.offset + data.len() as u64 > (GPE0_ENABLE_LAST + 1).into()
                {
                    warn!("ACPIPM: bad read size: {}", data.len());
                    return;
                }
                let offset = (info.offset - GPE0_ENABLE as u64) as usize;
                data[0] = self.gpe0.lock().enable[offset];

                #[cfg(feature = "direct")]
                for gpe in self
                    .direct_gpe
                    .iter()
                    .filter(|gpe| gpe.num / 8 == offset as u32)
                {
                    data[0] &= !(1 << (gpe.num % 8));
                    if gpe.is_enabled().unwrap_or(false) {
                        data[0] |= 1 << (gpe.num % 8);
                    }
                }
            }
            _ => {
                warn!("ACPIPM: Bad read from {}", info);
            }
        }
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        match info.offset as u16 {
            // Accesses to the PM1 registers are done through byte or word accesses
            PM1_STATUS..=PM1_STATUS_LAST => {
                if data.len() > std::mem::size_of::<u16>()
                    || info.offset + data.len() as u64 > (PM1_STATUS_LAST + 1).into()
                {
                    warn!("ACPIPM: bad write size: {}", data.len());
                    return;
                }
                let offset = (info.offset - PM1_STATUS as u64) as usize;

                let mut pm1 = self.pm1.lock();
                let mut v = pm1.status.to_ne_bytes();
                for (i, j) in (offset..offset + data.len()).enumerate() {
                    #[cfg(feature = "direct")]
                    for evt in self
                        .direct_fixed_evts
                        .iter()
                        .filter(|evt| evt.bitshift / 8 == j as u16)
                    {
                        if data[i] & (1 << (evt.bitshift % 8)) != 0 {
                            evt.clear();
                        }
                    }

                    v[j] &= !data[i];
                }
                pm1.status = u16::from_ne_bytes(v);
            }
            PM1_ENABLE..=PM1_ENABLE_LAST => {
                if data.len() > std::mem::size_of::<u16>()
                    || info.offset + data.len() as u64 > (PM1_ENABLE_LAST + 1).into()
                {
                    warn!("ACPIPM: bad write size: {}", data.len());
                    return;
                }
                let offset = (info.offset - PM1_ENABLE as u64) as usize;

                let mut pm1 = self.pm1.lock();
                let mut v = pm1.enable.to_ne_bytes();
                for (i, j) in (offset..offset + data.len()).enumerate() {
                    #[cfg(feature = "direct")]
                    for evt in self
                        .direct_fixed_evts
                        .iter_mut()
                        .filter(|evt| evt.bitshift / 8 == j as u16)
                    {
                        if data[i] & (1 << (evt.bitshift % 8)) != 0 {
                            evt.enable();
                        } else {
                            evt.disable();
                        }
                    }

                    v[j] = data[i];
                }
                pm1.enable = u16::from_ne_bytes(v);
                pm1.trigger_sci(&self.sci_evt);
            }
            PM1_CONTROL..=PM1_CONTROL_LAST => {
                if data.len() > std::mem::size_of::<u16>()
                    || info.offset + data.len() as u64 > (PM1_CONTROL_LAST + 1).into()
                {
                    warn!("ACPIPM: bad write size: {}", data.len());
                    return;
                }
                let offset = (info.offset - PM1_CONTROL as u64) as usize;

                let mut pm1 = self.pm1.lock();

                let mut v = pm1.control.to_ne_bytes();
                for (i, j) in (offset..offset + data.len()).enumerate() {
                    v[j] = data[i];
                }
                let val = u16::from_ne_bytes(v);

                // SLP_EN is a write-only bit and reads to it always return a zero
                if (val & BITMASK_PM1CNT_SLEEP_ENABLE) != 0 {
                    // only support S5 in direct mode
                    #[cfg(feature = "direct")]
                    if let Err(e) = self.exit_evt_wrtube.send::<VmEventType>(&VmEventType::Exit) {
                        error!("ACPIPM: failed to trigger exit event: {}", e);
                    }
                    #[cfg(not(feature = "direct"))]
                    match val & BITMASK_PM1CNT_SLEEP_TYPE {
                        SLEEP_TYPE_S1 => {
                            if let Err(e) = self.suspend_evt.signal() {
                                error!("ACPIPM: failed to trigger suspend event: {}", e);
                            }
                        }
                        SLEEP_TYPE_S5 => {
                            if let Err(e) =
                                self.exit_evt_wrtube.send::<VmEventType>(&VmEventType::Exit)
                            {
                                error!("ACPIPM: failed to trigger exit event: {}", e);
                            }
                        }
                        _ => error!(
                            "ACPIPM: unknown SLP_TYP written: {}",
                            (val & BITMASK_PM1CNT_SLEEP_TYPE) >> 10
                        ),
                    }
                }
                pm1.control = val & !BITMASK_PM1CNT_SLEEP_ENABLE;
            }
            // OSPM accesses GPE registers through byte accesses (regardless of their length)
            GPE0_STATUS..=GPE0_STATUS_LAST => {
                if data.len() > std::mem::size_of::<u8>()
                    || info.offset + data.len() as u64 > (GPE0_STATUS_LAST + 1).into()
                {
                    warn!("ACPIPM: bad write size: {}", data.len());
                    return;
                }
                let offset = (info.offset - GPE0_STATUS as u64) as usize;

                #[cfg(feature = "direct")]
                for gpe in self
                    .direct_gpe
                    .iter()
                    .filter(|gpe| gpe.num / 8 == offset as u32)
                {
                    if data[0] & (1 << (gpe.num % 8)) != 0 {
                        gpe.clear();
                    }
                }

                self.gpe0.lock().status[offset] &= !data[0];
            }
            GPE0_ENABLE..=GPE0_ENABLE_LAST => {
                if data.len() > std::mem::size_of::<u8>()
                    || info.offset + data.len() as u64 > (GPE0_ENABLE_LAST + 1).into()
                {
                    warn!("ACPIPM: bad write size: {}", data.len());
                    return;
                }
                let offset = (info.offset - GPE0_ENABLE as u64) as usize;

                #[cfg(feature = "direct")]
                for gpe in self
                    .direct_gpe
                    .iter_mut()
                    .filter(|gpe| gpe.num / 8 == offset as u32)
                {
                    if data[0] & (1 << (gpe.num % 8)) != 0 {
                        gpe.enable();
                    } else {
                        gpe.disable();
                    }
                }

                let mut gpe = self.gpe0.lock();
                gpe.enable[offset] = data[0];
                gpe.trigger_sci(&self.sci_evt);
            }
            _ => {
                warn!("ACPIPM: Bad write to {}", info);
            }
        };
    }
}

impl BusResumeDevice for ACPIPMResource {
    fn resume_imminent(&mut self) {
        self.pm1.lock().status |= BITMASK_PM1CNT_WAKE_STATUS;
    }
}

impl Aml for ACPIPMResource {
    fn to_aml_bytes(&self, bytes: &mut Vec<u8>) {
        // S1
        aml::Name::new(
            "_S1_".into(),
            &aml::Package::new(vec![&aml::ONE, &aml::ONE, &aml::ZERO, &aml::ZERO]),
        )
        .to_aml_bytes(bytes);

        // S5
        aml::Name::new(
            "_S5_".into(),
            &aml::Package::new(vec![&aml::ZERO, &aml::ZERO, &aml::ZERO, &aml::ZERO]),
        )
        .to_aml_bytes(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suspendable_tests;
    use base::SendTube;
    use base::Tube;

    fn get_evt_tube() -> SendTube {
        let (vm_evt_wrtube, _) = Tube::directional_pair().unwrap();
        vm_evt_wrtube
    }

    fn get_irq_evt() -> IrqLevelEvent {
        match crate::IrqLevelEvent::new() {
            Ok(evt) => evt,
            Err(e) => panic!(
                "failed to create irqlevelevt: {} - panic. Can't test ACPI",
                e
            ),
        }
    }

    fn modify_device(acpi: &mut ACPIPMResource) {
        {
            let mut pm1 = acpi.pm1.lock();
            pm1.enable += 1;
        }
    }

    suspendable_tests!(
        acpi,
        ACPIPMResource::new(
            get_irq_evt(),
            #[cfg(feature = "direct")]
            None,
            Event::new().unwrap(),
            get_evt_tube(),
        ),
        modify_device
    );
}
