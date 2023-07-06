// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implementation of an Intel ICH10 Input/Output Advanced Programmable Interrupt Controller
// See https://www.intel.com/content/dam/doc/datasheet/io-controller-hub-10-family-datasheet.pdf
// for a specification.

use anyhow::Context;
use base::error;
use base::warn;
use base::Error;
use base::Event;
use base::Result;
use base::Tube;
use base::TubeError;
use hypervisor::IoapicRedirectionTableEntry;
use hypervisor::IoapicState;
use hypervisor::MsiAddressMessage;
use hypervisor::MsiDataMessage;
use hypervisor::TriggerMode;
use hypervisor::NUM_IOAPIC_PINS;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use vm_control::VmIrqRequest;
use vm_control::VmIrqResponse;

use super::IrqEvent;
use crate::bus::BusAccessInfo;
use crate::pci::CrosvmDeviceId;
use crate::BusDevice;
use crate::DeviceId;
use crate::IrqEventSource;
use crate::Suspendable;

// ICH10 I/O APIC version: 0x20
const IOAPIC_VERSION_ID: u32 = 0x00000020;
pub const IOAPIC_BASE_ADDRESS: u64 = 0xfec00000;
// The Intel manual does not specify this size, but KVM uses it.
pub const IOAPIC_MEM_LENGTH_BYTES: u64 = 0x100;

// Constants for IOAPIC direct register offset.
const IOAPIC_REG_ID: u8 = 0x00;
const IOAPIC_REG_VERSION: u8 = 0x01;
const IOAPIC_REG_ARBITRATION_ID: u8 = 0x02;

// Register offsets
const IOREGSEL_OFF: u8 = 0x0;
const IOREGSEL_DUMMY_UPPER_32_BITS_OFF: u8 = 0x4;
const IOWIN_OFF: u8 = 0x10;
const IOEOIR_OFF: u8 = 0x40;

const IOWIN_SCALE: u8 = 0x2;

/// Given an IRQ and whether or not the selector should refer to the high bits, return a selector
/// suitable to use as an offset to read to/write from.
#[allow(dead_code)]
fn encode_selector_from_irq(irq: usize, is_high_bits: bool) -> u8 {
    (irq as u8) * IOWIN_SCALE + IOWIN_OFF + (is_high_bits as u8)
}

/// Given an offset that was read from/written to, return a tuple of the relevant IRQ and whether
/// the offset refers to the high bits of that register.
fn decode_irq_from_selector(selector: u8) -> (usize, bool) {
    (
        ((selector - IOWIN_OFF) / IOWIN_SCALE) as usize,
        selector & 1 != 0,
    )
}

// The RTC needs special treatment to work properly for Windows (or other OSs that use tick
// stuffing). In order to avoid time drift, we need to guarantee that the correct number of RTC
// interrupts are injected into the guest. This hack essentialy treats RTC interrupts as level
// triggered, which allows the IOAPIC to be responsible for interrupt coalescing and allows the
// IOAPIC to pass back whether or not the interrupt was coalesced to the CMOS (which allows the
// CMOS to perform tick stuffing). This deviates from the IOAPIC spec in ways very similar to (but
// not exactly the same as) KVM's IOAPIC.
const RTC_IRQ: usize = 0x8;

/// This struct is essentially the complete serialized form of [IrqEvent] as used in
/// [Ioapic::out_events].
///
/// [Ioapic] stores MSIs used to back GSIs, but not enough information to re-create these MSIs
/// (it is missing the address & data). It also includes data that is unused by the userspace
/// ioapic (the per gsi resample event, [IrqEvent::resample_event], is always None). This
/// struct incorporates the necessary information for snapshotting, and excludes that which
/// is not required.
#[derive(Clone, Serialize, Deserialize)]
struct OutEventSnapshot {
    gsi: u32,
    msi_address: u64,
    msi_data: u32,
    source: IrqEventSource,
}

/// Snapshot of [Ioapic] state. Some fields were intentionally excluded:
/// * [Ioapic::resample_events]: these will get re-registered when the VM is
///   created (e.g. prior to restoring a snapshot).
/// * [Ioapic::out_events]: this isn't serializable as it contains Events.
///   Replaced by [IoapicSnapshot::out_event_snapshots].
/// * [Ioapic::irq_tube]: will be set up as part of creating the VM.
///
/// See [Ioapic] for descriptions of fields by the same names.
#[derive(Serialize, Deserialize)]
struct IoapicSnapshot {
    num_pins: usize,
    ioregsel: u8,
    ioapicid: u32,
    rtc_remote_irr: bool,
    out_event_snapshots: Vec<Option<OutEventSnapshot>>,
    redirect_table: Vec<IoapicRedirectionTableEntry>,
    interrupt_level: Vec<bool>,
}

/// Stores the outbound IRQ line in runtime & serializable forms.
struct OutEvent {
    /// The actual IrqEvent used to dispatch IRQs when the VM is running.
    irq_event: IrqEvent,
    /// Serializable form of this IRQ line so that it can be re-created when
    /// the VM is snapshotted & resumed. Will be None until the line is
    /// completely set up.
    snapshot: Option<OutEventSnapshot>,
}

pub struct Ioapic {
    /// Number of supported IO-APIC inputs / redirection entries.
    num_pins: usize,
    /// ioregsel register. Used for selecting which entry of the redirect table to read/write.
    ioregsel: u8,
    /// ioapicid register. Bits 24 - 27 contain the APIC ID for this device.
    ioapicid: u32,
    /// Remote IRR for Edge Triggered Real Time Clock interrupts, which allows the CMOS to know when
    /// one of its interrupts is being coalesced.
    rtc_remote_irr: bool,
    /// Outgoing irq events that are used to inject MSI interrupts.
    /// Also contains the serializable form used for snapshotting.
    out_events: Vec<Option<OutEvent>>,
    /// Events that should be triggered on an EOI. The outer Vec is indexed by GSI, and the inner
    /// Vec is an unordered list of registered resample events for the GSI.
    resample_events: Vec<Vec<Event>>,
    /// Redirection settings for each irq line.
    redirect_table: Vec<IoapicRedirectionTableEntry>,
    /// Interrupt activation state.
    interrupt_level: Vec<bool>,
    /// Tube used to route MSI irqs.
    irq_tube: Tube,
}

impl BusDevice for Ioapic {
    fn debug_label(&self) -> String {
        "userspace IOAPIC".to_string()
    }

    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::Ioapic.into()
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        if data.len() > 8 || data.is_empty() {
            warn!("IOAPIC: Bad read size: {}", data.len());
            return;
        }
        if info.offset >= IOAPIC_MEM_LENGTH_BYTES {
            warn!("IOAPIC: Bad read from {}", info);
        }
        let out = match info.offset as u8 {
            IOREGSEL_OFF => self.ioregsel.into(),
            IOREGSEL_DUMMY_UPPER_32_BITS_OFF => 0,
            IOWIN_OFF => self.ioapic_read(),
            IOEOIR_OFF => 0,
            _ => {
                warn!("IOAPIC: Bad read from {}", info);
                return;
            }
        };
        let out_arr = out.to_ne_bytes();
        for i in 0..4 {
            if i < data.len() {
                data[i] = out_arr[i];
            }
        }
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        if data.len() > 8 || data.is_empty() {
            warn!("IOAPIC: Bad write size: {}", data.len());
            return;
        }
        if info.offset >= IOAPIC_MEM_LENGTH_BYTES {
            warn!("IOAPIC: Bad write to {}", info);
        }
        match info.offset as u8 {
            IOREGSEL_OFF => self.ioregsel = data[0],
            IOREGSEL_DUMMY_UPPER_32_BITS_OFF => {} // Ignored.
            IOWIN_OFF => {
                if data.len() != 4 {
                    warn!("IOAPIC: Bad write size for iowin: {}", data.len());
                    return;
                }
                let data_arr = [data[0], data[1], data[2], data[3]];
                let val = u32::from_ne_bytes(data_arr);
                self.ioapic_write(val);
            }
            IOEOIR_OFF => self.end_of_interrupt(data[0]),
            _ => {
                warn!("IOAPIC: Bad write to {}", info);
            }
        }
    }
}

impl Ioapic {
    pub fn new(irq_tube: Tube, num_pins: usize) -> Result<Ioapic> {
        // TODO(dverkamp): clean this up once we are sure all callers use 24 pins.
        assert_eq!(num_pins, NUM_IOAPIC_PINS);
        let mut entry = IoapicRedirectionTableEntry::new();
        entry.set_interrupt_mask(true);
        Ok(Ioapic {
            num_pins,
            ioregsel: 0,
            ioapicid: 0,
            rtc_remote_irr: false,
            out_events: (0..num_pins).map(|_| None).collect(),
            resample_events: Vec::new(),
            redirect_table: (0..num_pins).map(|_| entry).collect(),
            interrupt_level: (0..num_pins).map(|_| false).collect(),
            irq_tube,
        })
    }

    pub fn get_ioapic_state(&self) -> IoapicState {
        // Convert vector of first NUM_IOAPIC_PINS active interrupts into an u32 value.
        let level_bitmap = self
            .interrupt_level
            .iter()
            .take(NUM_IOAPIC_PINS)
            .rev()
            .fold(0, |acc, &l| acc * 2 + l as u32);
        let mut state = IoapicState {
            base_address: IOAPIC_BASE_ADDRESS,
            ioregsel: self.ioregsel,
            ioapicid: self.ioapicid,
            current_interrupt_level_bitmap: level_bitmap,
            ..Default::default()
        };
        for (dst, src) in state
            .redirect_table
            .iter_mut()
            .zip(self.redirect_table.iter())
        {
            *dst = *src;
        }
        state
    }

    pub fn set_ioapic_state(&mut self, state: &IoapicState) {
        self.ioregsel = state.ioregsel;
        self.ioapicid = state.ioapicid & 0x0f00_0000;
        for (src, dst) in state
            .redirect_table
            .iter()
            .zip(self.redirect_table.iter_mut())
        {
            *dst = *src;
        }
        for (i, level) in self
            .interrupt_level
            .iter_mut()
            .take(NUM_IOAPIC_PINS)
            .enumerate()
        {
            *level = state.current_interrupt_level_bitmap & (1 << i) != 0;
        }
    }

    pub fn register_resample_events(&mut self, resample_events: Vec<Vec<Event>>) {
        self.resample_events = resample_events;
    }

    // The ioapic must be informed about EOIs in order to avoid sending multiple interrupts of the
    // same type at the same time.
    pub fn end_of_interrupt(&mut self, vector: u8) {
        if self.redirect_table[RTC_IRQ].get_vector() == vector && self.rtc_remote_irr {
            // Specifically clear RTC IRQ field
            self.rtc_remote_irr = false;
        }

        for i in 0..self.num_pins {
            if self.redirect_table[i].get_vector() == vector
                && self.redirect_table[i].get_trigger_mode() == TriggerMode::Level
            {
                if self
                    .resample_events
                    .get(i)
                    .map_or(false, |events| !events.is_empty())
                {
                    self.service_irq(i, false);
                }

                if let Some(resample_events) = self.resample_events.get(i) {
                    for resample_evt in resample_events {
                        resample_evt.signal().unwrap();
                    }
                }
                self.redirect_table[i].set_remote_irr(false);
            }
            // There is an inherent race condition in hardware if the OS is finished processing an
            // interrupt and a new interrupt is delivered between issuing an EOI and the EOI being
            // completed.  When that happens the ioapic is supposed to re-inject the interrupt.
            if self.interrupt_level[i] {
                self.service_irq(i, true);
            }
        }
    }

    pub fn service_irq(&mut self, irq: usize, level: bool) -> bool {
        let entry = &mut self.redirect_table[irq];

        // De-assert the interrupt.
        if !level {
            self.interrupt_level[irq] = false;
            return true;
        }

        // If it's an edge-triggered interrupt that's already high we ignore it.
        if entry.get_trigger_mode() == TriggerMode::Edge && self.interrupt_level[irq] {
            return false;
        }

        self.interrupt_level[irq] = true;

        // Interrupts are masked, so don't inject.
        if entry.get_interrupt_mask() {
            return false;
        }

        // Level-triggered and remote irr is already active, so we don't inject a new interrupt.
        // (Coalesce with the prior one(s)).
        if entry.get_trigger_mode() == TriggerMode::Level && entry.get_remote_irr() {
            return false;
        }

        // Coalesce RTC interrupt to make tick stuffing work.
        if irq == RTC_IRQ && self.rtc_remote_irr {
            return false;
        }

        let injected = match self.out_events.get(irq) {
            Some(Some(out_event)) => out_event.irq_event.event.signal().is_ok(),
            _ => false,
        };

        if entry.get_trigger_mode() == TriggerMode::Level && level && injected {
            entry.set_remote_irr(true);
        } else if irq == RTC_IRQ && injected {
            self.rtc_remote_irr = true;
        }

        injected
    }

    fn ioapic_write(&mut self, val: u32) {
        match self.ioregsel {
            IOAPIC_REG_VERSION => { /* read-only register */ }
            IOAPIC_REG_ID => self.ioapicid = val & 0x0f00_0000,
            IOAPIC_REG_ARBITRATION_ID => { /* read-only register */ }
            _ => {
                if self.ioregsel < IOWIN_OFF {
                    // Invalid write; ignore.
                    return;
                }
                let (index, is_high_bits) = decode_irq_from_selector(self.ioregsel);
                if index >= self.num_pins {
                    // Invalid write; ignore.
                    return;
                }

                let entry = &mut self.redirect_table[index];
                if is_high_bits {
                    entry.set(32, 32, val.into());
                } else {
                    let before = *entry;
                    entry.set(0, 32, val.into());

                    // respect R/O bits.
                    entry.set_delivery_status(before.get_delivery_status());
                    entry.set_remote_irr(before.get_remote_irr());

                    // Clear remote_irr when switching to edge_triggered.
                    if entry.get_trigger_mode() == TriggerMode::Edge {
                        entry.set_remote_irr(false);
                    }

                    // NOTE: on pre-4.0 kernels, there's a race we would need to work around.
                    // "KVM: x86: ioapic: Fix level-triggered EOI and IOAPIC reconfigure race"
                    // is the fix for this.
                }

                if self.redirect_table[index].get_trigger_mode() == TriggerMode::Level
                    && self.interrupt_level[index]
                    && !self.redirect_table[index].get_interrupt_mask()
                {
                    self.service_irq(index, true);
                }

                let mut address = MsiAddressMessage::new();
                let mut data = MsiDataMessage::new();
                let entry = &self.redirect_table[index];
                address.set_destination_mode(entry.get_dest_mode());
                address.set_destination_id(entry.get_dest_id());
                address.set_always_0xfee(0xfee);
                data.set_vector(entry.get_vector());
                data.set_delivery_mode(entry.get_delivery_mode());
                data.set_trigger(entry.get_trigger_mode());

                let msi_address = address.get(0, 32);
                let msi_data = data.get(0, 32);
                if let Err(e) = self.setup_msi(index, msi_address, msi_data as u32) {
                    error!("IOAPIC failed to set up MSI for index {}: {}", index, e);
                }
            }
        }
    }

    fn setup_msi(
        &mut self,
        index: usize,
        msi_address: u64,
        msi_data: u32,
    ) -> std::result::Result<(), IoapicError> {
        if msi_data == 0 {
            // During boot, Linux first configures all ioapic pins with msi_data == 0; the routes
            // aren't yet assigned to devices and aren't usable.  We skip MSI setup if msi_data is
            // 0.
            return Ok(());
        }

        // Allocate a GSI and event for the outgoing route, if we haven't already done it.
        // The event will be used on the "outgoing" end of the ioapic to send an interrupt to the
        // apics: when an incoming ioapic irq line gets signalled, the ioapic writes to the
        // corresponding outgoing event. The GSI number is used to update the routing info (MSI
        // data and addr) for the event. The GSI and event are allocated only once for each ioapic
        // irq line, when the guest first sets up the ioapic with a valid route. If the guest
        // later reconfigures an ioapic irq line, the same GSI and event are reused, and we change
        // the GSI's route to the new MSI data+addr destination.
        let name = self.debug_label();
        let gsi = if let Some(evt) = &self.out_events[index] {
            evt.irq_event.gsi
        } else {
            let event = Event::new().map_err(IoapicError::CreateEvent)?;
            let request = VmIrqRequest::AllocateOneMsi {
                irqfd: event,
                device_id: self.device_id().into(),
                queue_id: index, // Use out_events index as queue_id for outgoing ioapic MSIs
                device_name: name.clone(),
            };
            self.irq_tube
                .send(&request)
                .map_err(IoapicError::AllocateOneMsiSend)?;
            match self
                .irq_tube
                .recv()
                .map_err(IoapicError::AllocateOneMsiRecv)?
            {
                VmIrqResponse::AllocateOneMsi { gsi, .. } => {
                    self.out_events[index] = Some(OutEvent {
                        irq_event: IrqEvent {
                            gsi,
                            event: match request {
                                VmIrqRequest::AllocateOneMsi { irqfd, .. } => irqfd,
                                _ => unreachable!(),
                            },
                            resample_event: None,
                            // This source isn't currently used for anything, we already sent the
                            // relevant source information to the main thread via the AllocateOneMsi
                            // request, but we populate it anyways for debugging.
                            source: IrqEventSource {
                                device_id: self.device_id(),
                                queue_id: index,
                                device_name: name,
                            },
                        },
                        snapshot: None,
                    });
                    gsi
                }
                VmIrqResponse::Err(e) => return Err(IoapicError::AllocateOneMsi(e)),
                _ => unreachable!(),
            }
        };

        // Set the MSI route for the GSI.  This controls which apic(s) get the interrupt when the
        // ioapic's outgoing event is written, and various attributes of how the interrupt is
        // delivered.
        let request = VmIrqRequest::AddMsiRoute {
            gsi,
            msi_address,
            msi_data,
        };
        self.irq_tube
            .send(&request)
            .map_err(IoapicError::AddMsiRouteSend)?;
        if let VmIrqResponse::Err(e) = self.irq_tube.recv().map_err(IoapicError::AddMsiRouteRecv)? {
            return Err(IoapicError::AddMsiRoute(e));
        }

        // Track this MSI route for snapshotting so it can be restored.
        self.out_events[index]
            .as_mut()
            .expect("IRQ is guaranteed initialized")
            .snapshot = Some(OutEventSnapshot {
            gsi,
            msi_address,
            msi_data,
            source: IrqEventSource {
                device_id: self.device_id(),
                queue_id: index,
                device_name: self.debug_label(),
            },
        });
        Ok(())
    }

    /// Similar to [Ioapic::setup_msi], but used only to re-create an MSI as
    /// part of the snapshot restore process, which allows us to assume certain
    /// invariants (like msi_data != 0) already hold.
    fn restore_msi(
        &mut self,
        index: usize,
        gsi: u32,
        msi_address: u64,
        msi_data: u32,
    ) -> std::result::Result<(), IoapicError> {
        let event = Event::new().map_err(IoapicError::CreateEvent)?;
        let name = self.debug_label();
        let request = VmIrqRequest::AllocateOneMsiAtGsi {
            irqfd: event,
            gsi,
            device_id: self.device_id().into(),
            queue_id: index, // Use out_events index as queue_id for outgoing ioapic MSIs
            device_name: name.clone(),
        };
        self.irq_tube
            .send(&request)
            .map_err(IoapicError::AllocateOneMsiSend)?;
        if let VmIrqResponse::Err(e) = self
            .irq_tube
            .recv()
            .map_err(IoapicError::AllocateOneMsiRecv)?
        {
            return Err(IoapicError::AllocateOneMsi(e));
        }

        self.out_events[index] = Some(OutEvent {
            irq_event: IrqEvent {
                gsi,
                event: match request {
                    VmIrqRequest::AllocateOneMsiAtGsi { irqfd, .. } => irqfd,
                    _ => unreachable!(),
                },
                resample_event: None,
                // This source isn't currently used for anything, we already sent the
                // relevant source information to the main thread via the AllocateOneMsi
                // request, but we populate it anyways for debugging.
                source: IrqEventSource {
                    device_id: self.device_id(),
                    queue_id: index,
                    device_name: name,
                },
            },
            snapshot: None,
        });

        // Set the MSI route for the GSI.  This controls which apic(s) get the interrupt when the
        // ioapic's outgoing event is written, and various attributes of how the interrupt is
        // delivered.
        let request = VmIrqRequest::AddMsiRoute {
            gsi,
            msi_address,
            msi_data,
        };
        self.irq_tube
            .send(&request)
            .map_err(IoapicError::AddMsiRouteSend)?;
        if let VmIrqResponse::Err(e) = self.irq_tube.recv().map_err(IoapicError::AddMsiRouteRecv)? {
            return Err(IoapicError::AddMsiRoute(e));
        }

        // Track this MSI route for snapshotting so it can be restored.
        self.out_events[index]
            .as_mut()
            .expect("IRQ is guaranteed initialized")
            .snapshot = Some(OutEventSnapshot {
            gsi,
            msi_address,
            msi_data,
            source: IrqEventSource {
                device_id: self.device_id(),
                queue_id: index,
                device_name: self.debug_label(),
            },
        });
        Ok(())
    }

    /// On warm restore, there could already be MSIs registered. We need to
    /// release them in case the routing has changed (e.g. different
    /// data <-> GSI).
    fn release_all_msis(&mut self) -> std::result::Result<(), IoapicError> {
        for out_event in self.out_events.drain(..).flatten() {
            let request = VmIrqRequest::ReleaseOneIrq {
                gsi: out_event.irq_event.gsi,
                irqfd: out_event.irq_event.event,
            };

            self.irq_tube
                .send(&request)
                .map_err(IoapicError::ReleaseOneIrqSend)?;
            if let VmIrqResponse::Err(e) = self
                .irq_tube
                .recv()
                .map_err(IoapicError::ReleaseOneIrqRecv)?
            {
                return Err(IoapicError::ReleaseOneIrq(e));
            }
        }
        Ok(())
    }

    fn ioapic_read(&mut self) -> u32 {
        match self.ioregsel {
            IOAPIC_REG_VERSION => ((self.num_pins - 1) as u32) << 16 | IOAPIC_VERSION_ID,
            IOAPIC_REG_ID | IOAPIC_REG_ARBITRATION_ID => self.ioapicid,
            _ => {
                if self.ioregsel < IOWIN_OFF {
                    // Invalid read; ignore and return 0.
                    0
                } else {
                    let (index, is_high_bits) = decode_irq_from_selector(self.ioregsel);
                    if index < self.num_pins {
                        let offset = if is_high_bits { 32 } else { 0 };
                        self.redirect_table[index].get(offset, 32) as u32
                    } else {
                        !0 // Invalid index - return all 1s
                    }
                }
            }
        }
    }
}

impl Suspendable for Ioapic {
    fn snapshot(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(IoapicSnapshot {
            num_pins: self.num_pins,
            ioregsel: self.ioregsel,
            ioapicid: self.ioapicid,
            rtc_remote_irr: self.rtc_remote_irr,
            out_event_snapshots: self
                .out_events
                .iter()
                .map(|out_event_opt| {
                    if let Some(out_event) = out_event_opt {
                        out_event.snapshot.clone()
                    } else {
                        None
                    }
                })
                .collect(),
            redirect_table: self.redirect_table.clone(),
            interrupt_level: self.interrupt_level.clone(),
        })
        .context("failed serializing Ioapic")
    }

    fn restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let snap: IoapicSnapshot =
            serde_json::from_value(data).context("failed to deserialize Ioapic snapshot")?;

        self.num_pins = snap.num_pins;
        self.ioregsel = snap.ioregsel;
        self.ioapicid = snap.ioapicid;
        self.rtc_remote_irr = snap.rtc_remote_irr;
        self.redirect_table = snap.redirect_table;
        self.interrupt_level = snap.interrupt_level;
        self.release_all_msis()
            .context("failed to clear MSIs prior to restore")?;
        self.out_events = (0..snap.num_pins).map(|_| None).collect();

        for (index, maybe_out_event) in snap.out_event_snapshots.iter().enumerate() {
            if let Some(out_event) = maybe_out_event {
                self.restore_msi(
                    index,
                    out_event.gsi,
                    out_event.msi_address,
                    out_event.msi_data,
                )?;
            }
        }
        Ok(())
    }

    fn sleep(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[sorted]
#[derive(Error, Debug)]
enum IoapicError {
    #[error("AddMsiRoute failed: {0}")]
    AddMsiRoute(Error),
    #[error("failed to receive AddMsiRoute response: {0}")]
    AddMsiRouteRecv(TubeError),
    #[error("failed to send AddMsiRoute request: {0}")]
    AddMsiRouteSend(TubeError),
    #[error("AllocateOneMsi failed: {0}")]
    AllocateOneMsi(Error),
    #[error("failed to receive AllocateOneMsi response: {0}")]
    AllocateOneMsiRecv(TubeError),
    #[error("failed to send AllocateOneMsi request: {0}")]
    AllocateOneMsiSend(TubeError),
    #[error("failed to create event object: {0}")]
    CreateEvent(Error),
    #[error("ReleaseOneIrq failed: {0}")]
    ReleaseOneIrq(Error),
    #[error("failed to receive ReleaseOneIrq response: {0}")]
    ReleaseOneIrqRecv(TubeError),
    #[error("failed to send ReleaseOneIrq request: {0}")]
    ReleaseOneIrqSend(TubeError),
}

#[cfg(test)]
mod tests {
    use hypervisor::DeliveryMode;
    use hypervisor::DeliveryStatus;
    use hypervisor::DestinationMode;
    use std::thread;

    use super::*;

    const DEFAULT_VECTOR: u8 = 0x3a;
    const DEFAULT_DESTINATION_ID: u8 = 0x5f;

    fn new() -> Ioapic {
        let (_, irq_tube) = Tube::pair().unwrap();
        Ioapic::new(irq_tube, NUM_IOAPIC_PINS).unwrap()
    }

    fn ioapic_bus_address(offset: u8) -> BusAccessInfo {
        let offset = offset as u64;
        BusAccessInfo {
            offset,
            address: IOAPIC_BASE_ADDRESS + offset,
            id: 0,
        }
    }

    fn set_up(trigger: TriggerMode) -> (Ioapic, usize) {
        let irq = NUM_IOAPIC_PINS - 1;
        let ioapic = set_up_with_irq(irq, trigger);
        (ioapic, irq)
    }

    fn set_up_with_irq(irq: usize, trigger: TriggerMode) -> Ioapic {
        let mut ioapic = self::new();
        set_up_redirection_table_entry(&mut ioapic, irq, trigger);
        ioapic.out_events[irq] = Some(OutEvent {
            irq_event: IrqEvent {
                gsi: NUM_IOAPIC_PINS as u32,
                event: Event::new().unwrap(),
                resample_event: None,
                source: IrqEventSource {
                    device_id: ioapic.device_id(),
                    queue_id: irq,
                    device_name: ioapic.debug_label(),
                },
            },

            snapshot: Some(OutEventSnapshot {
                gsi: NUM_IOAPIC_PINS as u32,
                msi_address: 0xa,
                msi_data: 0xd,
                source: IrqEventSource {
                    device_id: ioapic.device_id(),
                    queue_id: irq,
                    device_name: ioapic.debug_label(),
                },
            }),
        });
        ioapic
    }

    fn read_reg(ioapic: &mut Ioapic, selector: u8) -> u32 {
        let mut data = [0; 4];
        ioapic.write(ioapic_bus_address(IOREGSEL_OFF), &[selector]);
        ioapic.read(ioapic_bus_address(IOWIN_OFF), &mut data);
        u32::from_ne_bytes(data)
    }

    fn write_reg(ioapic: &mut Ioapic, selector: u8, value: u32) {
        ioapic.write(ioapic_bus_address(IOREGSEL_OFF), &[selector]);
        ioapic.write(ioapic_bus_address(IOWIN_OFF), &value.to_ne_bytes());
    }

    fn read_entry(ioapic: &mut Ioapic, irq: usize) -> IoapicRedirectionTableEntry {
        let mut entry = IoapicRedirectionTableEntry::new();
        entry.set(
            0,
            32,
            read_reg(ioapic, encode_selector_from_irq(irq, false)).into(),
        );
        entry.set(
            32,
            32,
            read_reg(ioapic, encode_selector_from_irq(irq, true)).into(),
        );
        entry
    }

    fn write_entry(ioapic: &mut Ioapic, irq: usize, entry: IoapicRedirectionTableEntry) {
        write_reg(
            ioapic,
            encode_selector_from_irq(irq, false),
            entry.get(0, 32) as u32,
        );
        write_reg(
            ioapic,
            encode_selector_from_irq(irq, true),
            entry.get(32, 32) as u32,
        );
    }

    fn set_up_redirection_table_entry(ioapic: &mut Ioapic, irq: usize, trigger_mode: TriggerMode) {
        let mut entry = IoapicRedirectionTableEntry::new();
        entry.set_vector(DEFAULT_DESTINATION_ID);
        entry.set_delivery_mode(DeliveryMode::Startup);
        entry.set_delivery_status(DeliveryStatus::Pending);
        entry.set_dest_id(DEFAULT_VECTOR);
        entry.set_trigger_mode(trigger_mode);
        write_entry(ioapic, irq, entry);
    }

    fn set_mask(ioapic: &mut Ioapic, irq: usize, mask: bool) {
        let mut entry = read_entry(ioapic, irq);
        entry.set_interrupt_mask(mask);
        write_entry(ioapic, irq, entry);
    }

    #[test]
    fn write_read_ioregsel() {
        let mut ioapic = self::new();
        let data_write = [0x0f, 0xf0, 0x01, 0xff];
        let mut data_read = [0; 4];

        for i in 0..data_write.len() {
            ioapic.write(ioapic_bus_address(IOREGSEL_OFF), &data_write[i..i + 1]);
            ioapic.read(ioapic_bus_address(IOREGSEL_OFF), &mut data_read[i..i + 1]);
            assert_eq!(data_write[i], data_read[i]);
        }
    }

    // Verify that version register is actually read-only.
    #[test]
    fn write_read_ioaic_reg_version() {
        let mut ioapic = self::new();
        let before = read_reg(&mut ioapic, IOAPIC_REG_VERSION);
        let data_write = !before;

        write_reg(&mut ioapic, IOAPIC_REG_VERSION, data_write);
        assert_eq!(read_reg(&mut ioapic, IOAPIC_REG_VERSION), before);
    }

    // Verify that only bits 27:24 of the IOAPICID are readable/writable.
    #[test]
    fn write_read_ioapic_reg_id() {
        let mut ioapic = self::new();

        write_reg(&mut ioapic, IOAPIC_REG_ID, 0x1f3e5d7c);
        assert_eq!(read_reg(&mut ioapic, IOAPIC_REG_ID), 0x0f000000);
    }

    // Write to read-only register IOAPICARB.
    #[test]
    fn write_read_ioapic_arbitration_id() {
        let mut ioapic = self::new();

        let data_write_id = 0x1f3e5d7c;
        let expected_result = 0x0f000000;

        // Write to IOAPICID.  This should also change IOAPICARB.
        write_reg(&mut ioapic, IOAPIC_REG_ID, data_write_id);

        // Read IOAPICARB
        assert_eq!(
            read_reg(&mut ioapic, IOAPIC_REG_ARBITRATION_ID),
            expected_result
        );

        // Try to write to IOAPICARB and verify unchanged result.
        write_reg(&mut ioapic, IOAPIC_REG_ARBITRATION_ID, !data_write_id);
        assert_eq!(
            read_reg(&mut ioapic, IOAPIC_REG_ARBITRATION_ID),
            expected_result
        );
    }

    #[test]
    #[should_panic(expected = "index out of bounds: the len is 24 but the index is 24")]
    fn service_invalid_irq() {
        let mut ioapic = self::new();
        ioapic.service_irq(NUM_IOAPIC_PINS, false);
    }

    // Test a level triggered IRQ interrupt.
    #[test]
    fn service_level_irq() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);

        // TODO(mutexlox): Check that interrupt is fired once.
        ioapic.service_irq(irq, true);
        ioapic.service_irq(irq, false);
    }

    #[test]
    fn service_multiple_level_irqs() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);
        // TODO(mutexlox): Check that interrupt is fired twice.
        ioapic.service_irq(irq, true);
        ioapic.service_irq(irq, false);
        ioapic.end_of_interrupt(DEFAULT_DESTINATION_ID);
        ioapic.service_irq(irq, true);
    }

    // Test multiple level interrupts without an EOI and verify that only one interrupt is
    // delivered.
    #[test]
    fn coalesce_multiple_level_irqs() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);

        // TODO(mutexlox): Test that only one interrupt is delivered.
        ioapic.service_irq(irq, true);
        ioapic.service_irq(irq, false);
        ioapic.service_irq(irq, true);
    }

    // Test multiple RTC interrupts without an EOI and verify that only one interrupt is delivered.
    #[test]
    fn coalesce_multiple_rtc_irqs() {
        let irq = RTC_IRQ;
        let mut ioapic = set_up_with_irq(irq, TriggerMode::Edge);

        // TODO(mutexlox): Verify that only one IRQ is delivered.
        ioapic.service_irq(irq, true);
        ioapic.service_irq(irq, false);
        ioapic.service_irq(irq, true);
    }

    // Test that a level interrupt that has been coalesced is re-raised if a guest issues an
    // EndOfInterrupt after the interrupt was coalesced while the line  is still asserted.
    #[test]
    fn reinject_level_interrupt() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);

        // TODO(mutexlox): Verify that only one IRQ is delivered.
        ioapic.service_irq(irq, true);
        ioapic.service_irq(irq, false);
        ioapic.service_irq(irq, true);

        // TODO(mutexlox): Verify that this last interrupt occurs as a result of the EOI, rather
        // than in response to the last service_irq.
        ioapic.end_of_interrupt(DEFAULT_DESTINATION_ID);
    }

    #[test]
    fn service_edge_triggered_irq() {
        let (mut ioapic, irq) = set_up(TriggerMode::Edge);

        // TODO(mutexlox): Verify that one interrupt is delivered.
        ioapic.service_irq(irq, true);
        ioapic.service_irq(irq, true); // Repeated asserts before a deassert should be ignored.
        ioapic.service_irq(irq, false);
    }

    // Verify that the state of an edge-triggered interrupt is properly tracked even when the
    // interrupt is disabled.
    #[test]
    fn edge_trigger_unmask_test() {
        let (mut ioapic, irq) = set_up(TriggerMode::Edge);

        // TODO(mutexlox): Expect an IRQ.

        ioapic.service_irq(irq, true);

        set_mask(&mut ioapic, irq, true);
        ioapic.service_irq(irq, false);

        // No interrupt triggered while masked.
        ioapic.service_irq(irq, true);
        ioapic.service_irq(irq, false);

        set_mask(&mut ioapic, irq, false);

        // TODO(mutexlox): Expect another interrupt.
        // Interrupt triggered while unmasked, even though when it was masked the level was high.
        ioapic.service_irq(irq, true);
        ioapic.service_irq(irq, false);
    }

    // Verify that a level-triggered interrupt that is triggered while masked will fire once the
    // interrupt is unmasked.
    #[test]
    fn level_trigger_unmask_test() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);

        set_mask(&mut ioapic, irq, true);
        ioapic.service_irq(irq, true);

        // TODO(mutexlox): expect an interrupt after this.
        set_mask(&mut ioapic, irq, false);
    }

    // Verify that multiple asserts before a deassert are ignored even if there's an EOI between
    // them.
    #[test]
    fn end_of_interrupt_edge_triggered_irq() {
        let (mut ioapic, irq) = set_up(TriggerMode::Edge);

        // TODO(mutexlox): Expect 1 interrupt.
        ioapic.service_irq(irq, true);
        ioapic.end_of_interrupt(DEFAULT_DESTINATION_ID);
        // Repeated asserts before a de-assert should be ignored.
        ioapic.service_irq(irq, true);
        ioapic.service_irq(irq, false);
    }

    // Send multiple edge-triggered interrupts in a row.
    #[test]
    fn service_multiple_edge_irqs() {
        let (mut ioapic, irq) = set_up(TriggerMode::Edge);

        ioapic.service_irq(irq, true);
        // TODO(mutexlox): Verify that an interrupt occurs here.
        ioapic.service_irq(irq, false);

        ioapic.service_irq(irq, true);
        // TODO(mutexlox): Verify that an interrupt occurs here.
        ioapic.service_irq(irq, false);
    }

    // Test an interrupt line with negative polarity.
    #[test]
    fn service_negative_polarity_irq() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);

        let mut entry = read_entry(&mut ioapic, irq);
        entry.set_polarity(1);
        write_entry(&mut ioapic, irq, entry);

        // TODO(mutexlox): Expect an interrupt to fire.
        ioapic.service_irq(irq, false);
    }

    // Ensure that remote IRR can't be edited via mmio.
    #[test]
    fn remote_irr_read_only() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);

        ioapic.redirect_table[irq].set_remote_irr(true);

        let mut entry = read_entry(&mut ioapic, irq);
        entry.set_remote_irr(false);
        write_entry(&mut ioapic, irq, entry);

        assert_eq!(read_entry(&mut ioapic, irq).get_remote_irr(), true);
    }

    #[test]
    fn delivery_status_read_only() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);

        ioapic.redirect_table[irq].set_delivery_status(DeliveryStatus::Pending);

        let mut entry = read_entry(&mut ioapic, irq);
        entry.set_delivery_status(DeliveryStatus::Idle);
        write_entry(&mut ioapic, irq, entry);

        assert_eq!(
            read_entry(&mut ioapic, irq).get_delivery_status(),
            DeliveryStatus::Pending
        );
    }

    #[test]
    fn level_to_edge_transition_clears_remote_irr() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);

        ioapic.redirect_table[irq].set_remote_irr(true);

        let mut entry = read_entry(&mut ioapic, irq);
        entry.set_trigger_mode(TriggerMode::Edge);
        write_entry(&mut ioapic, irq, entry);

        assert_eq!(read_entry(&mut ioapic, irq).get_remote_irr(), false);
    }

    #[test]
    fn masking_preserves_remote_irr() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);

        ioapic.redirect_table[irq].set_remote_irr(true);

        set_mask(&mut ioapic, irq, true);
        set_mask(&mut ioapic, irq, false);

        assert_eq!(read_entry(&mut ioapic, irq).get_remote_irr(), true);
    }

    // Test reconfiguration racing with EOIs.
    #[test]
    fn reconfiguration_race() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);

        // Fire one level-triggered interrupt.
        // TODO(mutexlox): Check that it fires.
        ioapic.service_irq(irq, true);

        // Read the redirection table entry before the EOI...
        let mut entry = read_entry(&mut ioapic, irq);
        entry.set_trigger_mode(TriggerMode::Edge);

        ioapic.service_irq(irq, false);
        ioapic.end_of_interrupt(DEFAULT_DESTINATION_ID);

        // ... and write back that (modified) value.
        write_entry(&mut ioapic, irq, entry);

        // Fire one *edge* triggered interrupt
        // TODO(mutexlox): Assert that the interrupt fires once.
        ioapic.service_irq(irq, true);
        ioapic.service_irq(irq, false);
    }

    // Ensure that swapping to edge triggered and back clears the remote irr bit.
    #[test]
    fn implicit_eoi() {
        let (mut ioapic, irq) = set_up(TriggerMode::Level);

        // Fire one level-triggered interrupt.
        ioapic.service_irq(irq, true);
        // TODO(mutexlox): Verify that one interrupt was fired.
        ioapic.service_irq(irq, false);

        // Do an implicit EOI by cycling between edge and level triggered.
        let mut entry = read_entry(&mut ioapic, irq);
        entry.set_trigger_mode(TriggerMode::Edge);
        write_entry(&mut ioapic, irq, entry);
        entry.set_trigger_mode(TriggerMode::Level);
        write_entry(&mut ioapic, irq, entry);

        // Fire one level-triggered interrupt.
        ioapic.service_irq(irq, true);
        // TODO(mutexlox): Verify that one interrupt fires.
        ioapic.service_irq(irq, false);
    }

    #[test]
    fn set_redirection_entry_by_bits() {
        let mut entry = IoapicRedirectionTableEntry::new();
        //                                                          destination_mode
        //                                                         polarity |
        //                                                  trigger_mode |  |
        //                                                             | |  |
        // 0011 1010 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 1001 0110 0101 1111
        // |_______| |______________________________________________||  | |  |_| |_______|
        //  dest_id                      reserved                    |  | |   |    vector
        //                                               interrupt_mask | |   |
        //                                                     remote_irr |   |
        //                                                    delivery_status |
        //                                                              delivery_mode
        entry.set(0, 64, 0x3a0000000000965f);
        assert_eq!(entry.get_vector(), 0x5f);
        assert_eq!(entry.get_delivery_mode(), DeliveryMode::Startup);
        assert_eq!(entry.get_dest_mode(), DestinationMode::Physical);
        assert_eq!(entry.get_delivery_status(), DeliveryStatus::Pending);
        assert_eq!(entry.get_polarity(), 0);
        assert_eq!(entry.get_remote_irr(), false);
        assert_eq!(entry.get_trigger_mode(), TriggerMode::Level);
        assert_eq!(entry.get_interrupt_mask(), false);
        assert_eq!(entry.get_reserved(), 0);
        assert_eq!(entry.get_dest_id(), 0x3a);

        let (mut ioapic, irq) = set_up(TriggerMode::Edge);
        write_entry(&mut ioapic, irq, entry);
        assert_eq!(
            read_entry(&mut ioapic, irq).get_trigger_mode(),
            TriggerMode::Level
        );

        // TODO(mutexlox): Verify that this actually fires an interrupt.
        ioapic.service_irq(irq, true);
    }

    #[track_caller]
    fn recv_allocate_msi(t: &Tube) -> u32 {
        match t.recv::<VmIrqRequest>().unwrap() {
            VmIrqRequest::AllocateOneMsiAtGsi { gsi, .. } => gsi,
            msg => panic!("unexpected irqchip message: {:?}", msg),
        }
    }

    struct MsiRouteDetails {
        gsi: u32,
        msi_address: u64,
        msi_data: u32,
    }

    #[track_caller]
    fn recv_add_msi_route(t: &Tube) -> MsiRouteDetails {
        match t.recv::<VmIrqRequest>().unwrap() {
            VmIrqRequest::AddMsiRoute {
                gsi,
                msi_address,
                msi_data,
            } => MsiRouteDetails {
                gsi,
                msi_address,
                msi_data,
            },
            msg => panic!("unexpected irqchip message: {:?}", msg),
        }
    }

    #[track_caller]
    fn recv_release_one_irq(t: &Tube) -> u32 {
        match t.recv::<VmIrqRequest>().unwrap() {
            VmIrqRequest::ReleaseOneIrq { gsi, irqfd: _ } => gsi,
            msg => panic!("unexpected irqchip message: {:?}", msg),
        }
    }

    #[track_caller]
    fn send_ok(t: &Tube) {
        t.send(&VmIrqResponse::Ok).unwrap();
    }

    /// Simulates restoring the ioapic as if the VM had never booted a guest.
    /// This is called the "cold" restore case since all the devices are
    /// expected to be essentially blank / unconfigured.
    #[test]
    fn verify_ioapic_restore_cold_smoke() {
        let (irqchip_tube, ioapic_irq_tube) = Tube::pair().unwrap();
        let gsi_num = NUM_IOAPIC_PINS as u32;

        // Creates an ioapic w/ an MSI for GSI = NUM_IOAPIC_PINS, MSI
        // address 0xa, and data 0xd. The irq index (pin number) is 10, but
        // this is not meaningful.
        let saved_ioapic = set_up_with_irq(10, TriggerMode::Level);

        // Take a snapshot of the ioapic.
        let snapshot = saved_ioapic.snapshot().unwrap();

        // Create a fake irqchip to respond to our requests.
        let irqchip_fake = thread::spawn(move || {
            assert_eq!(recv_allocate_msi(&irqchip_tube), gsi_num);
            send_ok(&irqchip_tube);
            let route = recv_add_msi_route(&irqchip_tube);
            assert_eq!(route.gsi, gsi_num);
            assert_eq!(route.msi_address, 0xa);
            assert_eq!(route.msi_data, 0xd);
            send_ok(&irqchip_tube);
            irqchip_tube
        });

        let mut restored_ioapic = Ioapic::new(ioapic_irq_tube, NUM_IOAPIC_PINS).unwrap();
        restored_ioapic.restore(snapshot).unwrap();

        irqchip_fake.join().unwrap();
    }

    /// In the warm case, we are restoring to an Ioapic that already exists and
    /// may have MSIs already allocated. Here, we're verifying the restore
    /// process releases any existing MSIs before registering the restored MSIs.
    #[test]
    fn verify_ioapic_restore_warm_smoke() {
        let (irqchip_tube, ioapic_irq_tube) = Tube::pair().unwrap();
        let gsi_num = NUM_IOAPIC_PINS as u32;

        // Creates an ioapic w/ an MSI for GSI = NUM_IOAPIC_PINS, MSI
        // address 0xa, and data 0xd. The irq index (pin number) is 10, but
        // this is not meaningful.
        let mut ioapic = set_up_with_irq(10, TriggerMode::Level);

        // We don't connect this Tube until after the IRQ is initially set up
        // as it triggers messages we don't want to assert on (they're about
        // ioapic functionality, not snapshotting).
        ioapic.irq_tube = ioapic_irq_tube;

        // Take a snapshot of the ioapic.
        let snapshot = ioapic.snapshot().unwrap();

        // Create a fake irqchip to respond to our requests.
        let irqchip_fake = thread::spawn(move || {
            // We should clear the existing MSI as the first restore step.
            assert_eq!(recv_release_one_irq(&irqchip_tube), gsi_num);
            send_ok(&irqchip_tube);

            // Then re-allocate it as part of restoring.
            assert_eq!(recv_allocate_msi(&irqchip_tube), gsi_num);
            send_ok(&irqchip_tube);
            let route = recv_add_msi_route(&irqchip_tube);
            assert_eq!(route.gsi, gsi_num);
            assert_eq!(route.msi_address, 0xa);
            assert_eq!(route.msi_data, 0xd);
            send_ok(&irqchip_tube);
            irqchip_tube
        });

        ioapic.restore(snapshot).unwrap();

        irqchip_fake.join().unwrap();
    }
}
