// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{BusAccessInfo, BusDevice, BusResumeDevice, IrqLevelEvent};
use acpi_tables::{aml, aml::Aml};
use base::{error, info, warn, Error as SysError, Event, PollToken, WaitContext};
use base::{AcpiNotifyEvent, NetlinkGenericSocket};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;
use sync::Mutex;
use thiserror::Error;
use vm_control::{GpeNotify, PmResource};

#[cfg(feature = "direct")]
use {std::fs, std::io::Error as IoError, std::path::PathBuf};

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

struct Pm1Resource {
    status: u16,
    enable: u16,
    control: u16,
}

struct GpeResource {
    status: [u8; ACPIPM_RESOURCE_GPE0_BLK_LEN as usize / 2],
    enable: [u8; ACPIPM_RESOURCE_GPE0_BLK_LEN as usize / 2],
    gpe_notify: BTreeMap<u32, Vec<Arc<Mutex<dyn GpeNotify>>>>,
}

#[cfg(feature = "direct")]
struct DirectGpe {
    num: u32,
    path: PathBuf,
    ready: bool,
    enabled: bool,
}

/// ACPI PM resource for handling OS suspend/resume request
#[allow(dead_code)]
pub struct ACPIPMResource {
    // This is SCI interrupt that will be raised in the VM.
    sci_evt: IrqLevelEvent,
    // This is the host SCI that is being handled by crosvm.
    #[cfg(feature = "direct")]
    sci_direct_evt: Option<IrqLevelEvent>,
    #[cfg(feature = "direct")]
    direct_gpe: Vec<DirectGpe>,
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<()>>,
    suspend_evt: Event,
    exit_evt: Event,
    pm1: Arc<Mutex<Pm1Resource>>,
    gpe0: Arc<Mutex<GpeResource>>,
}

impl ACPIPMResource {
    /// Constructs ACPI Power Management Resouce.
    ///
    /// `direct_gpe_info` - tuple of host SCI trigger and resample events, and list of direct GPEs
    #[allow(dead_code)]
    pub fn new(
        sci_evt: IrqLevelEvent,
        #[cfg(feature = "direct")] direct_gpe_info: Option<(IrqLevelEvent, &[u32])>,
        suspend_evt: Event,
        exit_evt: Event,
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
        let (sci_direct_evt, direct_gpe) = if let Some(info) = direct_gpe_info {
            let (evt, gpes) = info;
            let gpe_vec = gpes.iter().map(|gpe| DirectGpe::new(*gpe)).collect();
            (Some(evt), gpe_vec)
        } else {
            (None, Vec::new())
        };

        ACPIPMResource {
            sci_evt,
            #[cfg(feature = "direct")]
            sci_direct_evt,
            #[cfg(feature = "direct")]
            direct_gpe,
            kill_evt: None,
            worker_thread: None,
            suspend_evt,
            exit_evt,
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
        // Direct GPEs are forwarded via direct SCI forwarding,
        // not via ACPI netlink events.
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

fn run_worker(
    sci_evt: IrqLevelEvent,
    kill_evt: Event,
    pm1: Arc<Mutex<Pm1Resource>>,
    gpe0: Arc<Mutex<GpeResource>>,
    acpi_event_ignored_gpe: Vec<u32>,
    #[cfg(feature = "direct")] sci_direct_evt: Option<IrqLevelEvent>,
) -> Result<(), ACPIPMError> {
    // Get group id corresponding to acpi_mc_group of acpi_event family
    let nl_groups: u32;
    match get_acpi_event_group() {
        Some(group) if group > 0 => {
            nl_groups = 1 << (group - 1);
            info!("Listening on acpi_mc_group of acpi_event family");
        }
        _ => {
            return Err(ACPIPMError::AcpiMcGroupError);
        }
    }

    let acpi_event_sock = match NetlinkGenericSocket::new(nl_groups) {
        Ok(acpi_sock) => acpi_sock,
        Err(e) => {
            return Err(ACPIPMError::AcpiEventSockError(e));
        }
    };

    #[derive(PollToken)]
    enum Token {
        AcpiEvent,
        InterruptResample,
        #[cfg(feature = "direct")]
        InterruptTriggerDirect,
        Kill,
    }

    let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
        (&acpi_event_sock, Token::AcpiEvent),
        (sci_evt.get_resample(), Token::InterruptResample),
        (&kill_evt, Token::Kill),
    ])
    .map_err(ACPIPMError::CreateWaitContext)?;

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
                    acpi_event_run(
                        &acpi_event_sock,
                        &gpe0,
                        &pm1,
                        &sci_evt,
                        &acpi_event_ignored_gpe,
                    );
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

fn acpi_event_handle_gpe(
    gpe_number: u32,
    _type: u32,
    gpe0: &Arc<Mutex<GpeResource>>,
    sci_evt: &IrqLevelEvent,
    ignored_gpe: &[u32],
) {
    // If gpe event, emulate GPE and trigger SCI
    if _type == 0 && gpe_number < 256 && !ignored_gpe.contains(&gpe_number) {
        let mut gpe0 = gpe0.lock();
        let byte = gpe_number as usize / 8;

        if byte >= gpe0.status.len() {
            error!("gpe_evt: GPE register {} does not exist", byte);
            return;
        }
        gpe0.status[byte] |= 1 << (gpe_number % 8);
        gpe0.trigger_sci(sci_evt);
    }
}

const ACPI_BUTTON_NOTIFY_STATUS: u32 = 0x80;

fn acpi_event_handle_power_button(
    acpi_event: AcpiNotifyEvent,
    pm1: &Arc<Mutex<Pm1Resource>>,
    sci_evt: &IrqLevelEvent,
) {
    // If received power button event, emulate PM/PWRBTN_STS and trigger SCI
    if acpi_event._type == ACPI_BUTTON_NOTIFY_STATUS && acpi_event.bus_id.contains("LNXPWRBN") {
        let mut pm1 = pm1.lock();

        pm1.status |= BITMASK_PM1STS_PWRBTN_STS;
        pm1.trigger_sci(sci_evt);
    }
}

fn get_acpi_event_group() -> Option<u32> {
    // Create netlink generic socket which will be used to query about given family name
    let netlink_ctrl_sock = match NetlinkGenericSocket::new(0) {
        Ok(sock) => sock,
        Err(e) => {
            error!("netlink generic socket creation error: {}", e);
            return None;
        }
    };

    let nlmsg_family_response = netlink_ctrl_sock
        .family_name_query("acpi_event".to_string())
        .unwrap();
    return nlmsg_family_response.get_multicast_group_id("acpi_mc_group".to_string());
}

fn acpi_event_run(
    acpi_event_sock: &NetlinkGenericSocket,
    gpe0: &Arc<Mutex<GpeResource>>,
    pm1: &Arc<Mutex<Pm1Resource>>,
    sci_evt: &IrqLevelEvent,
    ignored_gpe: &[u32],
) {
    let nl_msg = match acpi_event_sock.recv() {
        Ok(msg) => msg,
        Err(e) => {
            error!("recv returned with error {}", e);
            return;
        }
    };

    for netlink_message in nl_msg.iter() {
        let acpi_event = match AcpiNotifyEvent::new(netlink_message) {
            Ok(evt) => evt,
            Err(e) => {
                error!("Received netlink message is not an acpi_event, error {}", e);
                continue;
            }
        };
        match acpi_event.device_class.as_str() {
            "gpe" => {
                acpi_event_handle_gpe(
                    acpi_event.data,
                    acpi_event._type,
                    gpe0,
                    sci_evt,
                    ignored_gpe,
                );
            }
            "button/power" => acpi_event_handle_power_button(acpi_event, pm1, sci_evt),
            c => warn!("unknown acpi event {}", c),
        };
    }
}

impl Drop for ACPIPMResource {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            let _ = kill_evt.write(1);
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

impl Pm1Resource {
    fn trigger_sci(&self, sci_evt: &IrqLevelEvent) {
        if self.status
            & self.enable
            & (BITMASK_PM1EN_GBL_EN
                | BITMASK_PM1EN_PWRBTN_EN
                | BITMASK_PM1EN_SLPBTN_EN
                | BITMASK_PM1EN_RTC_EN)
            != 0
        {
            if let Err(e) = sci_evt.trigger() {
                error!("ACPIPM: failed to trigger sci event for pm1: {}", e);
            }
        }
    }
}

impl GpeResource {
    fn trigger_sci(&self, sci_evt: &IrqLevelEvent) {
        let mut trigger = false;
        for i in 0..self.status.len() {
            let gpes = self.status[i] & self.enable[i];
            if gpes == 0 {
                continue;
            }

            for j in 0..8 {
                if gpes & (1 << j) == 0 {
                    continue;
                }

                let gpe_num: u32 = i as u32 * 8 + j;
                if let Some(notify_devs) = self.gpe_notify.get(&gpe_num) {
                    for notify_dev in notify_devs.iter() {
                        notify_dev.lock().notify();
                    }
                }
            }
            trigger = true;
        }

        if trigger {
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

const BITMASK_PM1STS_PWRBTN_STS: u16 = 1 << 8;
const BITMASK_PM1EN_GBL_EN: u16 = 1 << 5;
const BITMASK_PM1EN_PWRBTN_EN: u16 = 1 << 8;
const BITMASK_PM1EN_SLPBTN_EN: u16 = 1 << 9;
const BITMASK_PM1EN_RTC_EN: u16 = 1 << 10;
const BITMASK_PM1CNT_SLEEP_ENABLE: u16 = 0x2000;
const BITMASK_PM1CNT_WAKE_STATUS: u16 = 0x8000;

#[cfg(not(feature = "direct"))]
const BITMASK_PM1CNT_SLEEP_TYPE: u16 = 0x1C00;
#[cfg(not(feature = "direct"))]
const SLEEP_TYPE_S1: u16 = 1 << 10;
#[cfg(not(feature = "direct"))]
const SLEEP_TYPE_S5: u16 = 0 << 10;

impl PmResource for ACPIPMResource {
    fn pwrbtn_evt(&mut self) {
        let mut pm1 = self.pm1.lock();

        pm1.status |= BITMASK_PM1STS_PWRBTN_STS;
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
                data.copy_from_slice(
                    &self.pm1.lock().status.to_ne_bytes()[offset..offset + data.len()],
                );
            }
            PM1_ENABLE..=PM1_ENABLE_LAST => {
                if data.len() > std::mem::size_of::<u16>()
                    || info.offset + data.len() as u64 > (PM1_ENABLE_LAST + 1).into()
                {
                    warn!("ACPIPM: bad read size: {}", data.len());
                    return;
                }
                let offset = (info.offset - PM1_ENABLE as u64) as usize;
                data.copy_from_slice(
                    &self.pm1.lock().enable.to_ne_bytes()[offset..offset + data.len()],
                );
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
                    if let Err(e) = self.exit_evt.write(1) {
                        error!("ACPIPM: failed to trigger exit event: {}", e);
                    }
                    #[cfg(not(feature = "direct"))]
                    match val & BITMASK_PM1CNT_SLEEP_TYPE {
                        SLEEP_TYPE_S1 => {
                            if let Err(e) = self.suspend_evt.write(1) {
                                error!("ACPIPM: failed to trigger suspend event: {}", e);
                            }
                        }
                        SLEEP_TYPE_S5 => {
                            if let Err(e) = self.exit_evt.write(1) {
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
