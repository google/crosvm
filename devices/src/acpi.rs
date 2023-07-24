// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use acpi_tables::aml;
use acpi_tables::aml::Aml;
use anyhow::Context;
use base::custom_serde::serialize_arc_mutex;
use base::error;
use base::warn;
use base::Error as SysError;
use base::Event;
use base::EventToken;
use base::SendTube;
use base::VmEventType;
use base::WaitContext;
use base::WorkerThread;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use thiserror::Error;
use vm_control::GpeNotify;
use vm_control::PmResource;
use vm_control::PmeNotify;

use crate::ac_adapter::AcAdapter;
use crate::pci::CrosvmDeviceId;
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
    #[error("GPE {0} is out of bound")]
    GpeOutOfBound(u32),
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

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct PciResource {
    #[serde(skip_serializing, skip_deserializing)]
    pub(crate) pme_notify: BTreeMap<u8, Vec<Arc<Mutex<dyn PmeNotify>>>>,
}

/// ACPI PM resource for handling OS suspend/resume request
#[allow(dead_code)]
#[derive(Serialize)]
pub struct ACPIPMResource {
    // This is SCI interrupt that will be raised in the VM.
    #[serde(skip_serializing)]
    sci_evt: IrqLevelEvent,
    #[serde(skip_serializing)]
    worker_thread: Option<WorkerThread<()>>,
    #[serde(skip_serializing)]
    suspend_evt: Event,
    #[serde(skip_serializing)]
    exit_evt_wrtube: SendTube,
    #[serde(serialize_with = "serialize_arc_mutex")]
    pm1: Arc<Mutex<Pm1Resource>>,
    #[serde(serialize_with = "serialize_arc_mutex")]
    gpe0: Arc<Mutex<GpeResource>>,
    #[serde(serialize_with = "serialize_arc_mutex")]
    pci: Arc<Mutex<PciResource>>,
    #[serde(skip_serializing)]
    acdc: Option<Arc<Mutex<AcAdapter>>>,
}

#[derive(Deserialize)]
struct ACPIPMResrourceSerializable {
    pm1: Pm1Resource,
    gpe0: GpeResource,
}

impl ACPIPMResource {
    /// Constructs ACPI Power Management Resouce.
    #[allow(dead_code)]
    pub fn new(
        sci_evt: IrqLevelEvent,
        suspend_evt: Event,
        exit_evt_wrtube: SendTube,
        acdc: Option<Arc<Mutex<AcAdapter>>>,
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
        let pci = PciResource {
            pme_notify: BTreeMap::new(),
        };

        ACPIPMResource {
            sci_evt,
            worker_thread: None,
            suspend_evt,
            exit_evt_wrtube,
            pm1: Arc::new(Mutex::new(pm1)),
            gpe0: Arc::new(Mutex::new(gpe0)),
            pci: Arc::new(Mutex::new(pci)),
            acdc,
        }
    }

    pub fn start(&mut self) {
        let sci_evt = self.sci_evt.try_clone().expect("failed to clone event");
        let pm1 = self.pm1.clone();
        let gpe0 = self.gpe0.clone();
        let acdc = self.acdc.clone();

        let acpi_event_ignored_gpe = Vec::new();

        self.worker_thread = Some(WorkerThread::start("ACPI PM worker", move |kill_evt| {
            if let Err(e) = run_worker(sci_evt, kill_evt, pm1, gpe0, acpi_event_ignored_gpe, acdc) {
                error!("{}", e);
            }
        }));
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
        if let Some(worker_thread) = self.worker_thread.take() {
            worker_thread.stop();
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
    arced_ac_adapter: Option<Arc<Mutex<AcAdapter>>>,
) -> Result<(), ACPIPMError> {
    let acpi_event_sock = crate::sys::get_acpi_event_sock()?;
    #[derive(EventToken)]
    enum Token {
        AcpiEvent,
        InterruptResample,
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

    loop {
        let events = wait_ctx.wait().map_err(ACPIPMError::WaitError)?;
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::AcpiEvent => {
                    crate::sys::acpi_event_run(
                        &sci_evt,
                        &acpi_event_sock,
                        &gpe0,
                        &acpi_event_ignored_gpe,
                        &arced_ac_adapter,
                    );
                }
                Token::InterruptResample => {
                    sci_evt.clear_resample();

                    // Re-trigger SCI if PM1 or GPE status is still not cleared.
                    pm1.lock().trigger_sci(&sci_evt);
                    gpe0.lock().trigger_sci(&sci_evt);
                }
                Token::Kill => return Ok(()),
            }
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
    pub fn trigger_sci(&self, sci_evt: &IrqLevelEvent) {
        if (0..self.status.len()).any(|i| self.status[i] & self.enable[i] != 0) {
            if let Err(e) = sci_evt.trigger() {
                error!("ACPIPM: failed to trigger sci event for gpe: {}", e);
            }
        }
    }

    pub fn set_active(&mut self, gpe: u32) -> Result<(), ACPIPMError> {
        if let Some(status_byte) = self.status.get_mut(gpe as usize / 8) {
            *status_byte |= 1 << (gpe % 8);
        } else {
            return Err(ACPIPMError::GpeOutOfBound(gpe));
        }
        Ok(())
    }
}

/// the ACPI PM register length.
pub const ACPIPM_RESOURCE_EVENTBLK_LEN: u8 = 4;
pub const ACPIPM_RESOURCE_CONTROLBLK_LEN: u8 = 2;
pub const ACPIPM_RESOURCE_GPE0_BLK_LEN: u8 = 64;
pub const ACPIPM_RESOURCE_LEN: u8 = ACPIPM_RESOURCE_EVENTBLK_LEN + 4 + ACPIPM_RESOURCE_GPE0_BLK_LEN;

// Should be in sync with gpe_allocator range
pub const ACPIPM_GPE_MAX: u16 = ACPIPM_RESOURCE_GPE0_BLK_LEN as u16 / 2 * 8 - 1;

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

const BITMASK_PM1CNT_SLEEP_TYPE: u16 = 0x1C00;
const SLEEP_TYPE_S1: u16 = 1 << 10;
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

    fn rtc_evt(&mut self) {
        let mut pm1 = self.pm1.lock();

        pm1.status |= ACPIPMFixedEvent::RTC.bitmask();
        pm1.trigger_sci(&self.sci_evt);
    }

    fn gpe_evt(&mut self, gpe: u32) {
        let mut gpe0 = self.gpe0.lock();

        match gpe0.set_active(gpe) {
            Ok(_) => gpe0.trigger_sci(&self.sci_evt),
            Err(e) => error!("{}", e),
        }
    }

    fn pme_evt(&mut self, requester_id: u16) {
        let bus = ((requester_id >> 8) & 0xFF) as u8;
        let mut pci = self.pci.lock();
        if let Some(root_ports) = pci.pme_notify.get_mut(&bus) {
            for root_port in root_ports {
                root_port.lock().notify(requester_id);
            }
        }
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

    fn register_pme_notify_dev(&mut self, bus: u8, notify_dev: Arc<Mutex<dyn PmeNotify>>) {
        let mut pci = self.pci.lock();
        match pci.pme_notify.get_mut(&bus) {
            Some(v) => v.push(notify_dev),
            None => {
                pci.pme_notify.insert(bus, vec![notify_dev]);
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
    use base::SendTube;
    use base::Tube;

    use super::*;
    use crate::suspendable_tests;

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
        ACPIPMResource::new(get_irq_evt(), Event::new().unwrap(), get_evt_tube(), None,),
        modify_device
    );
}
