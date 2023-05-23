// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::Index;
use std::vec::Vec;

use anyhow::anyhow;
use anyhow::Context;
use base::Error;
use base::Event;
use base::Result;
use hypervisor::IoapicState;
use hypervisor::IrqRoute;
use hypervisor::IrqSource;
use hypervisor::IrqSourceChip;
use hypervisor::LapicState;
use hypervisor::MPState;
use hypervisor::PicSelect;
use hypervisor::PicState;
use hypervisor::PitState;
use serde::Deserialize;
use serde::Serialize;

use crate::IrqChip;

pub trait IrqChipX86_64: IrqChip {
    // Clones this trait as a `Box` version of itself.
    fn try_box_clone(&self) -> Result<Box<dyn IrqChipX86_64>>;

    // Get this as the super-trait IrqChip.
    fn as_irq_chip(&self) -> &dyn IrqChip;

    // Get this as the mutable super-trait IrqChip.
    fn as_irq_chip_mut(&mut self) -> &mut dyn IrqChip;

    /// Get the current state of the PIC
    fn get_pic_state(&self, select: PicSelect) -> Result<PicState>;

    /// Set the current state of the PIC
    fn set_pic_state(&mut self, select: PicSelect, state: &PicState) -> Result<()>;

    /// Get the current state of the IOAPIC
    fn get_ioapic_state(&self) -> Result<IoapicState>;

    /// Set the current state of the IOAPIC
    fn set_ioapic_state(&mut self, state: &IoapicState) -> Result<()>;

    /// Get the current state of the specified VCPU's local APIC
    fn get_lapic_state(&self, vcpu_id: usize) -> Result<LapicState>;

    /// Set the current state of the specified VCPU's local APIC
    fn set_lapic_state(&mut self, vcpu_id: usize, state: &LapicState) -> Result<()>;

    /// Get the lapic frequency in Hz
    fn lapic_frequency(&self) -> u32;

    /// Retrieves the state of the PIT.
    fn get_pit(&self) -> Result<PitState>;

    /// Sets the state of the PIT.
    fn set_pit(&mut self, state: &PitState) -> Result<()>;

    /// Returns true if the PIT uses port 0x61 for the PC speaker, false if 0x61 is unused.
    fn pit_uses_speaker_port(&self) -> bool;

    /// Snapshot state specific to different IrqChips.
    fn snapshot_chip_specific(&self) -> anyhow::Result<serde_json::Value>;

    /// Restore state specific to different IrqChips.
    fn restore_chip_specific(&mut self, data: serde_json::Value) -> anyhow::Result<()>;

    /// Snapshot state common to IrqChips.
    fn snapshot(&self, cpus_num: usize) -> anyhow::Result<serde_json::Value> {
        let mut lapics: Vec<LapicState> = Vec::new();
        let mut mp_states: Vec<MPState> = Vec::new();
        for i in 0..cpus_num {
            lapics.push(self.get_lapic_state(i)?);
            mp_states.push(self.get_mp_state(i)?);
        }
        serde_json::to_value(&IrqChipSnapshot {
            ioapic_state: self.get_ioapic_state()?,
            lapic_state: lapics,
            pic_state_1: self.get_pic_state(PicSelect::Primary)?,
            pic_state_2: self.get_pic_state(PicSelect::Secondary)?,
            pit_state: self.get_pit()?,
            chip_specific_state: self.snapshot_chip_specific()?,
            mp_state: mp_states,
        })
        .context("failed to serialize KvmKernelIrqChip")
    }

    /// Restore state common to IrqChips.
    fn restore(&mut self, data: serde_json::Value, vcpus_num: usize) -> anyhow::Result<()> {
        let deser: IrqChipSnapshot =
            serde_json::from_value(data).context("failed to deserialize data")?;
        if deser.mp_state.len() != vcpus_num || deser.lapic_state.len() != vcpus_num {
            return Err(anyhow!("IrqChip data has been modified"));
        }
        self.set_pit(&deser.pit_state)?;
        self.set_pic_state(PicSelect::Primary, &deser.pic_state_1)?;
        self.set_pic_state(PicSelect::Secondary, &deser.pic_state_2)?;
        self.set_ioapic_state(&deser.ioapic_state)?;
        self.restore_chip_specific(deser.chip_specific_state)?;
        for (i, lapic) in deser.lapic_state.iter().enumerate() {
            self.set_lapic_state(i, lapic)?;
        }
        for (i, mp_state) in deser.mp_state.iter().enumerate() {
            self.set_mp_state(i, mp_state)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct IrqChipSnapshot {
    ioapic_state: IoapicState,
    lapic_state: Vec<LapicState>,
    pic_state_1: PicState,
    pic_state_2: PicState,
    pit_state: PitState,
    chip_specific_state: serde_json::Value,
    mp_state: Vec<MPState>,
}

/// A container for x86 IrqRoutes, grouped by GSI.
pub struct Routes {
    /// A list of routes, indexed by GSI.  Each GSI can map to zero or more routes, so this is a
    /// Vec of Vecs.  Specifically, a GSI can map to:
    ///   * no routes; or
    ///   * one IrqSource::Msi route; or
    ///   * one or more IrqSource::Irqchip routes (PicPrimary, PicSecondary, or Ioapic)
    routes: Vec<Vec<IrqSource>>,
}

impl Routes {
    /// Constructs a new `Routes` with an empty routing table.
    pub fn new() -> Self {
        Routes { routes: vec![] }
    }

    /// Inserts a route, replacing any existing route that conflicts.  Two routes conflict if they
    /// have the same GSI, and they're both `IrqSource::Irqchip` routes with the same chip or
    /// they're both `IrqSource::Msi`.  Returns Err if an `IrqSource::Irqchip` and `IrqSource::Msi`
    /// route have the same GSI.
    pub fn add(&mut self, route: IrqRoute) -> Result<()> {
        let routes = self.get_mut(route.gsi as usize);
        if routes.iter().any(|r| !Self::same_source(&route.source, r)) {
            // We keep an invariant that legacy and MSI routes can't be mixed on the same GSI.
            // Irqchip routes are only on GSIs [0..24) and Msi routes are only on GSIs >= 24.  This
            // guarantees that in UserspaceIrqChip, the ioapic's incoming Irqchip routes and
            // outgoing Msi routes can't trigger each other in a cycle.
            return Err(Error::new(libc::EINVAL));
        }
        routes.retain(|r| !Self::conflict(&route.source, r));
        routes.push(route.source);
        Ok(())
    }

    /// Deletes all existing routes and replaces them with `routes`.  If two routes in `routes`
    /// conflict with each other, the one earlier in the slice is dropped.
    pub fn replace_all(&mut self, routes: &[IrqRoute]) -> Result<()> {
        self.routes.clear();
        for r in routes {
            self.add(*r)?;
        }
        Ok(())
    }

    /// Default x86 routing table.  Pins 0-7 go to primary pic and ioapic, pins 8-15 go to secondary
    /// pic and ioapic, and pins 16-23 go only to the ioapic.
    pub fn default_pic_ioapic_routes(ioapic_pins: usize) -> Vec<IrqRoute> {
        let mut routes: Vec<IrqRoute> = Vec::new();

        for i in 0..8 {
            routes.push(IrqRoute::pic_irq_route(IrqSourceChip::PicPrimary, i));
            routes.push(IrqRoute::ioapic_irq_route(i));
        }
        for i in 8..16 {
            routes.push(IrqRoute::pic_irq_route(IrqSourceChip::PicSecondary, i));
            routes.push(IrqRoute::ioapic_irq_route(i));
        }
        for i in 16..ioapic_pins as u32 {
            routes.push(IrqRoute::ioapic_irq_route(i));
        }

        routes
    }

    /// Gets the routes as a flat Vec of `IrqRoute`s.
    pub fn get_routes(&self) -> Vec<IrqRoute> {
        let mut routes = Vec::with_capacity(self.routes.len());
        for (gsi, sources) in self.routes.iter().enumerate() {
            for source in sources.iter() {
                routes.push(IrqRoute {
                    gsi: gsi.try_into().expect("GSIs must be < u32::MAX"),
                    source: *source,
                });
            }
        }
        routes
    }

    /// Determines whether or not two irq routes on the same GSI conflict.
    /// Returns true if they conflict.
    fn conflict(source: &IrqSource, other: &IrqSource) -> bool {
        use IrqSource::*;

        // If they're both MSI then they conflict.
        if let (Msi { .. }, Msi { .. }) = (source, other) {
            return true;
        }

        // If the route chips match then they conflict.
        if let (
            Irqchip { chip, .. },
            Irqchip {
                chip: other_chip, ..
            },
        ) = (source, other)
        {
            return chip == other_chip;
        }

        // Otherwise they do not conflict.
        false
    }

    /// Determines whether two routes have the same IrqSource variant (IrqSource::Irqchip or
    /// IrqSource::Msi).
    fn same_source(source: &IrqSource, other: &IrqSource) -> bool {
        use IrqSource::*;
        matches!(
            (source, other),
            (Irqchip { .. }, Irqchip { .. }) | (Msi { .. }, Msi { .. })
        )
    }

    /// Returns the routes vec for `irq`.  If `irq` is past the end of self.routes, then self.routes
    /// is first resized with empty vecs.
    fn get_mut(&mut self, irq: usize) -> &mut Vec<IrqSource> {
        if irq >= self.routes.len() {
            self.routes.resize_with(irq + 1, Vec::new);
        }
        self.routes.get_mut(irq).unwrap()
    }
}

impl Default for Routes {
    fn default() -> Self {
        Self::new()
    }
}

const EMPTY_ROUTE: [IrqSource; 0] = [];

impl Index<usize> for Routes {
    type Output = [IrqSource];

    /// Returns all routes for `irq`, or an empty slice if no routes registered for `irq`.
    fn index(&self, irq: usize) -> &Self::Output {
        if irq < self.routes.len() {
            self.routes[irq].as_slice()
        } else {
            &EMPTY_ROUTE
        }
    }
}

pub(super) struct DelayedIoApicIrqEvents {
    /// Vec of ioapic irq events that have been delayed because the ioapic was locked when
    /// service_irq was called on the irqchip.
    pub events: Vec<usize>,
    /// Event which is meant to trigger process of any irqs events that were delayed.
    pub trigger: Event,
}

impl DelayedIoApicIrqEvents {
    pub fn new() -> Result<Self> {
        Ok(DelayedIoApicIrqEvents {
            events: Vec::new(),
            trigger: Event::new()?,
        })
    }
}
