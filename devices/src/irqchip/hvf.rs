// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! HVF (Hypervisor.framework) IRQ chip implementation for macOS aarch64.
//!
//! This provides a GICv3 interrupt controller backed by Apple's HVF GIC
//! (available on macOS 15+). IRQ routing and event registration are managed
//! in userspace, while interrupt injection uses `hv_gic_set_spi()` for SPI
//! signaling into the guest.

use std::sync::Arc;

use base::error;
use base::info;
use base::Event;
use base::Result;
use hypervisor::DeviceKind;
use hypervisor::IrqRoute;
use hypervisor::MPState;
use hypervisor::Vcpu;
use resources::SystemAllocator;
use sync::Mutex;

use crate::Bus;
use crate::IrqChip;
use crate::IrqChipAArch64;
use crate::IrqChipCap;
use crate::IrqEdgeEvent;
use crate::IrqEventIndex;
use crate::IrqEventSource;
use crate::IrqLevelEvent;
use crate::VcpuRunState;

use super::AARCH64_GIC_NR_SPIS;

// GIC address space constants (must match aarch64/src/lib.rs and fdt.rs)
const AARCH64_GIC_DIST_SIZE: u64 = 0x10000;
const AARCH64_GIC_DIST_BASE: u64 = 0x40000000 - AARCH64_GIC_DIST_SIZE;
const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;

// SPI offset: ARM GIC SPI INTIDs start at 32
const SPI_INTID_BASE: u32 = 32;

// FFI bindings for HVF GIC functions (Hypervisor.framework)
#[allow(non_camel_case_types, dead_code)]
mod hvf_gic_ffi {
    pub type hv_return_t = i32;
    pub type hv_ipa_t = u64;

    #[repr(C)]
    pub struct hv_gic_config_s {
        _opaque: [u8; 0],
    }
    pub type hv_gic_config_t = *mut hv_gic_config_s;

    pub const HV_SUCCESS: hv_return_t = 0;

    #[link(name = "Hypervisor", kind = "framework")]
    extern "C" {
        pub fn hv_gic_config_create() -> hv_gic_config_t;
        pub fn hv_gic_config_set_distributor_base(
            gic_config: hv_gic_config_t,
            distributor_base_address: hv_ipa_t,
        ) -> hv_return_t;
        pub fn hv_gic_config_set_redistributor_base(
            gic_config: hv_gic_config_t,
            redistributor_base_address: hv_ipa_t,
        ) -> hv_return_t;
        pub fn hv_gic_create(gic_config: hv_gic_config_t) -> hv_return_t;
        pub fn hv_gic_reset() -> hv_return_t;
        pub fn hv_gic_set_spi(intid: u32, level: bool) -> hv_return_t;
        /// Query the system-required distributor region size.
        pub fn hv_gic_get_distributor_size(size: *mut u64) -> hv_return_t;
        /// Query the per-CPU redistributor region size.
        pub fn hv_gic_get_redistributor_size(size: *mut u64) -> hv_return_t;
    }
}

/// A registered IRQ event, tracking the mapping between a GSI and its trigger event.
struct HvfIrqEvent {
    gsi: u32,
    trigger_event: Event,
    resample_event: Option<Event>,
    source: IrqEventSource,
}

/// Default ARM routing table. AARCH64_GIC_NR_SPIS pins go to the GIC.
fn hvf_default_irq_routing_table() -> Vec<IrqRoute> {
    let mut routes: Vec<IrqRoute> = Vec::new();
    for i in 0..AARCH64_GIC_NR_SPIS {
        routes.push(IrqRoute::gic_irq_route(i));
    }
    routes
}

/// Initialize the HVF GIC with dynamically queried sizes.
///
/// The GIC distributor and redistributor addresses are placed just below
/// the PCI MMIO region (0x40000000), matching crosvm's aarch64 memory layout.
fn initialize_hvf_gic(num_vcpus: usize) -> std::result::Result<(), String> {
    // Query the system for actual GIC region sizes
    let mut dist_size: u64 = 0;
    let mut redist_size: u64 = 0;

    // SAFETY: passing valid pointers to receive sizes
    let ret = unsafe { hvf_gic_ffi::hv_gic_get_distributor_size(&mut dist_size) };
    if ret != hvf_gic_ffi::HV_SUCCESS {
        // Fall back to default sizes if query not available
        dist_size = AARCH64_GIC_DIST_SIZE;
        info!("hv_gic_get_distributor_size unavailable, using default {:#x}", dist_size);
    }

    // SAFETY: passing valid pointer to receive size
    let ret = unsafe { hvf_gic_ffi::hv_gic_get_redistributor_size(&mut redist_size) };
    if ret != hvf_gic_ffi::HV_SUCCESS {
        // Fall back to default sizes if query not available
        redist_size = AARCH64_GIC_REDIST_SIZE;
        info!("hv_gic_get_redistributor_size unavailable, using default {:#x}", redist_size);
    }

    let total_redist_size = redist_size * num_vcpus as u64;
    // Place GIC just below 0x40000000 (PCI MMIO base)
    let redist_base = 0x40000000 - total_redist_size;
    let dist_base = redist_base - dist_size;

    info!(
        "HVF GIC layout: dist_size={:#x}, redist_size={:#x}/cpu, dist_base={:#x}, redist_base={:#x}, vcpus={}",
        dist_size, redist_size, dist_base, redist_base, num_vcpus
    );

    // SAFETY: hv_gic_config_create returns a new config object
    let config = unsafe { hvf_gic_ffi::hv_gic_config_create() };
    if config.is_null() {
        return Err("hv_gic_config_create returned null".to_string());
    }

    // SAFETY: config is valid and dist_base is a valid IPA
    let ret = unsafe { hvf_gic_ffi::hv_gic_config_set_distributor_base(config, dist_base) };
    if ret != hvf_gic_ffi::HV_SUCCESS {
        return Err(format!(
            "hv_gic_config_set_distributor_base({:#x}) failed: 0x{:08x}",
            dist_base, ret
        ));
    }

    // SAFETY: config is valid and redist_base is a valid IPA
    let ret =
        unsafe { hvf_gic_ffi::hv_gic_config_set_redistributor_base(config, redist_base) };
    if ret != hvf_gic_ffi::HV_SUCCESS {
        return Err(format!(
            "hv_gic_config_set_redistributor_base({:#x}) failed: 0x{:08x}",
            redist_base, ret
        ));
    }

    // SAFETY: config is fully populated
    let ret = unsafe { hvf_gic_ffi::hv_gic_create(config) };
    if ret != hvf_gic_ffi::HV_SUCCESS {
        return Err(format!("hv_gic_create failed: 0x{:08x}", ret));
    }

    info!(
        "HVF GIC initialized: distributor @ {:#x}, redistributor @ {:#x} ({} VCPUs)",
        dist_base, redist_base, num_vcpus,
    );
    Ok(())
}

/// Inject an SPI into the HVF GIC.
///
/// `gsi` is the crosvm GSI number (0-based SPI index).
/// The HVF GIC API takes the full ARM INTID (SPI INTID = 32 + gsi).
fn hvf_gic_set_spi(gsi: u32, level: bool) {
    let intid = gsi + SPI_INTID_BASE;
    // SAFETY: intid is a valid SPI INTID, the GIC has been initialized
    let ret = unsafe { hvf_gic_ffi::hv_gic_set_spi(intid, level) };
    if ret != hvf_gic_ffi::HV_SUCCESS {
        error!(
            "hv_gic_set_spi(intid={}, level={}) failed: 0x{:08x}",
            intid, level, ret
        );
    }
}

/// HVF-based IRQ chip for macOS aarch64.
///
/// Uses Apple's HVF GIC (macOS 15+) for interrupt distribution and injection.
/// IRQ routing and event registration are managed in userspace, while the HVF
/// GIC handles actual interrupt delivery to guest VCPUs.
pub struct HvfIrqChip {
    vcpu_count: usize,
    routes: Arc<Mutex<Vec<IrqRoute>>>,
    irq_events: Arc<Mutex<Vec<HvfIrqEvent>>>,
    /// Whether the HVF GIC was successfully initialized.
    gic_initialized: bool,
}

impl HvfIrqChip {
    /// Construct a new HvfIrqChip and initialize the HVF GIC.
    ///
    /// The HVF GIC must be created after `hv_vm_create()` and before any
    /// `hv_vcpu_create()` calls. The `num_vcpus` parameter determines the
    /// redistributor region size.
    pub fn new(num_vcpus: usize) -> Result<HvfIrqChip> {
        let gic_initialized = match initialize_hvf_gic(num_vcpus) {
            Ok(()) => true,
            Err(e) => {
                error!(
                    "Failed to initialize HVF GIC: {}. Interrupt injection will not work.",
                    e
                );
                false
            }
        };

        Ok(HvfIrqChip {
            vcpu_count: 0,
            routes: Arc::new(Mutex::new(hvf_default_irq_routing_table())),
            irq_events: Arc::new(Mutex::new(Vec::new())),
            gic_initialized,
        })
    }
}

impl IrqChip for HvfIrqChip {
    fn add_vcpu(&mut self, _vcpu_id: usize, _vcpu: &dyn Vcpu) -> Result<()> {
        self.vcpu_count += 1;
        Ok(())
    }

    fn register_edge_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqEdgeEvent,
        source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>> {
        let mut events = self.irq_events.lock();
        let index = events.len();
        events.push(HvfIrqEvent {
            gsi: irq,
            trigger_event: irq_event.get_trigger().try_clone()?,
            resample_event: None,
            source,
        });
        Ok(Some(index))
    }

    fn unregister_edge_irq_event(&mut self, irq: u32, _irq_event: &IrqEdgeEvent) -> Result<()> {
        let mut events = self.irq_events.lock();
        events.retain(|e| e.gsi != irq || e.resample_event.is_some());
        Ok(())
    }

    fn register_level_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqLevelEvent,
        source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>> {
        let mut events = self.irq_events.lock();
        let index = events.len();
        events.push(HvfIrqEvent {
            gsi: irq,
            trigger_event: irq_event.get_trigger().try_clone()?,
            resample_event: Some(irq_event.get_resample().try_clone()?),
            source,
        });
        Ok(Some(index))
    }

    fn unregister_level_irq_event(
        &mut self,
        irq: u32,
        _irq_event: &IrqLevelEvent,
    ) -> Result<()> {
        let mut events = self.irq_events.lock();
        events.retain(|e| e.gsi != irq || e.resample_event.is_none());
        Ok(())
    }

    fn route_irq(&mut self, route: IrqRoute) -> Result<()> {
        let mut routes = self.routes.lock();
        routes.retain(|r| r.gsi != route.gsi);
        routes.push(route);
        Ok(())
    }

    fn set_irq_routes(&mut self, routes: &[IrqRoute]) -> Result<()> {
        let mut current_routes = self.routes.lock();
        *current_routes = routes.to_vec();
        Ok(())
    }

    fn irq_event_tokens(&self) -> Result<Vec<(IrqEventIndex, IrqEventSource, Event)>> {
        let events = self.irq_events.lock();
        let mut tokens = Vec::new();
        for (index, evt) in events.iter().enumerate() {
            tokens.push((
                index,
                evt.source.clone(),
                evt.trigger_event.try_clone()?,
            ));
        }
        Ok(tokens)
    }

    fn service_irq(&mut self, irq: u32, level: bool) -> Result<()> {
        // Inject the SPI via the HVF GIC
        if self.gic_initialized {
            hvf_gic_set_spi(irq, level);
        }

        // Also signal the event for userspace device notification
        if level {
            let events = self.irq_events.lock();
            for evt in events.iter() {
                if evt.gsi == irq {
                    evt.trigger_event.signal()?;
                }
            }
        }
        Ok(())
    }

    fn service_irq_event(&mut self, event_index: IrqEventIndex) -> Result<()> {
        let events = self.irq_events.lock();
        if let Some(evt) = events.get(event_index) {
            // Read (consume) the trigger event
            evt.trigger_event.wait()?;

            // Inject the SPI via the HVF GIC (edge-triggered: pulse high then low)
            if self.gic_initialized {
                hvf_gic_set_spi(evt.gsi, true);
                hvf_gic_set_spi(evt.gsi, false);
            }

            // For level-triggered with a resample event, signal the resample to
            // let the device know it can re-raise if still active.
            if let Some(ref resample) = evt.resample_event {
                resample.signal()?;
            }
        }
        Ok(())
    }

    fn broadcast_eoi(&self, _vector: u8) -> Result<()> {
        // The HVF GIC handles EOI internally. Signal resample events for
        // level-triggered interrupts so devices can re-assert if needed.
        let events = self.irq_events.lock();
        for evt in events.iter() {
            if let Some(ref resample) = evt.resample_event {
                resample.signal()?;
            }
        }
        Ok(())
    }

    fn inject_interrupts(&self, _vcpu: &dyn Vcpu) -> Result<()> {
        // The HVF GIC handles interrupt injection into VCPUs automatically.
        // When hv_gic_set_spi() is called, the GIC routes the interrupt to
        // the appropriate VCPU, which will see it on the next hv_vcpu_run().
        Ok(())
    }

    fn halted(&self, _vcpu_id: usize) {
        // No-op: HVF handles VCPU blocking via WFI/WFE trapping.
    }

    fn wait_until_runnable(&self, _vcpu: &dyn Vcpu) -> Result<VcpuRunState> {
        // HVF manages VCPU scheduling; from userspace, the VCPU is always runnable.
        Ok(VcpuRunState::Runnable)
    }

    fn kick_halted_vcpus(&self) {
        // No-op: HVF handles VCPU blocking.
    }

    fn get_mp_state(&self, _vcpu_id: usize) -> Result<MPState> {
        // HVF does not expose MP state directly. Return Runnable as default.
        Ok(MPState::Runnable)
    }

    fn set_mp_state(&mut self, _vcpu_id: usize, _state: &MPState) -> Result<()> {
        // No-op: HVF does not support setting MP state.
        Ok(())
    }

    fn try_clone(&self) -> Result<Self> {
        Ok(HvfIrqChip {
            vcpu_count: self.vcpu_count,
            routes: self.routes.clone(),
            irq_events: self.irq_events.clone(),
            gic_initialized: self.gic_initialized,
        })
    }

    fn finalize_devices(
        &mut self,
        _resources: &mut SystemAllocator,
        _io_bus: &Bus,
        _mmio_bus: &Bus,
    ) -> Result<()> {
        Ok(())
    }

    fn process_delayed_irq_events(&mut self) -> Result<()> {
        Ok(())
    }

    fn irq_delayed_event_token(&self) -> Result<Option<Event>> {
        Ok(None)
    }

    fn check_capability(&self, c: IrqChipCap) -> bool {
        match c {
            IrqChipCap::MpStateGetSet => false,
        }
    }
}

impl IrqChipAArch64 for HvfIrqChip {
    fn try_box_clone(&self) -> Result<Box<dyn IrqChipAArch64>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn as_irq_chip(&self) -> &dyn IrqChip {
        self
    }

    fn as_irq_chip_mut(&mut self) -> &mut dyn IrqChip {
        self
    }

    fn get_vgic_version(&self) -> DeviceKind {
        DeviceKind::ArmVgicV3
    }

    fn has_vgic_its(&self) -> bool {
        false
    }

    fn finalize(&self) -> Result<()> {
        Ok(())
    }
}
