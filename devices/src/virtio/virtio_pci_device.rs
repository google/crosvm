// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::sync::Arc;

#[cfg(target_arch = "x86_64")]
use acpi_tables::sdt::SDT;
use anyhow::anyhow;
use anyhow::Context;
use base::debug;
use base::error;
use base::trace;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::Event;
use base::Protection;
use base::RawDescriptor;
use base::Result;
use base::SharedMemory;
use base::Tube;
use base::WorkerThread;
use data_model::Le32;
use hypervisor::Datamatch;
use hypervisor::MemCacheType;
use libc::ERANGE;
#[cfg(target_arch = "x86_64")]
use metrics::MetricEventType;
use resources::AddressRange;
use resources::Alloc;
use resources::AllocOptions;
use resources::SystemAllocator;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
use sync::Mutex;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_ACKNOWLEDGE;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_DRIVER;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_DRIVER_OK;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_FAILED;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_FEATURES_OK;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_NEEDS_RESET;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_SUSPEND;
use vm_control::api::VmMemoryClient;
use vm_control::VmMemoryDestination;
use vm_control::VmMemoryRegionId;
use vm_control::VmMemorySource;
use vm_memory::GuestMemory;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use self::virtio_pci_common_config::VirtioPciCommonConfig;
use super::*;
#[cfg(target_arch = "x86_64")]
use crate::acpi::PmWakeupEvent;
#[cfg(target_arch = "x86_64")]
use crate::pci::pm::PciDevicePower;
use crate::pci::pm::PciPmCap;
use crate::pci::pm::PmConfig;
use crate::pci::pm::PmStatusChange;
use crate::pci::BarRange;
use crate::pci::MsixCap;
use crate::pci::MsixConfig;
use crate::pci::MsixStatus;
use crate::pci::PciAddress;
use crate::pci::PciBarConfiguration;
use crate::pci::PciBarIndex;
use crate::pci::PciBarPrefetchable;
use crate::pci::PciBarRegionType;
use crate::pci::PciBaseSystemPeripheralSubclass;
use crate::pci::PciCapability;
use crate::pci::PciCapabilityID;
use crate::pci::PciClassCode;
use crate::pci::PciConfiguration;
use crate::pci::PciDevice;
use crate::pci::PciDeviceError;
use crate::pci::PciDisplaySubclass;
use crate::pci::PciHeaderType;
use crate::pci::PciId;
use crate::pci::PciInputDeviceSubclass;
use crate::pci::PciInterruptPin;
use crate::pci::PciMassStorageSubclass;
use crate::pci::PciMultimediaSubclass;
use crate::pci::PciNetworkControllerSubclass;
use crate::pci::PciSimpleCommunicationControllerSubclass;
use crate::pci::PciSubclass;
use crate::pci::PciWirelessControllerSubclass;
use crate::virtio::ipc_memory_mapper::IpcMemoryMapper;
#[cfg(feature = "pci-hotplug")]
use crate::HotPluggable;
use crate::IrqLevelEvent;
use crate::Suspendable;

#[repr(u8)]
#[derive(Debug, Copy, Clone, enumn::N)]
pub enum PciCapabilityType {
    CommonConfig = 1,
    NotifyConfig = 2,
    IsrConfig = 3,
    DeviceConfig = 4,
    PciConfig = 5,
    // Doorbell, Notification and SharedMemory are Virtio Vhost User related PCI
    // capabilities. Specified in 5.7.7.4 here
    // https://stefanha.github.io/virtio/vhost-user-slave.html#x1-2830007.
    DoorbellConfig = 6,
    NotificationConfig = 7,
    SharedMemoryConfig = 8,
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VirtioPciCap {
    // cap_vndr and cap_next are autofilled based on id() in pci configuration
    pub cap_vndr: u8, // Generic PCI field: PCI_CAP_ID_VNDR
    pub cap_next: u8, // Generic PCI field: next ptr
    pub cap_len: u8,  // Generic PCI field: capability length
    pub cfg_type: u8, // Identifies the structure.
    pub bar: u8,      // Where to find it.
    id: u8,           // Multiple capabilities of the same type
    padding: [u8; 2], // Pad to full dword.
    pub offset: Le32, // Offset within bar.
    pub length: Le32, // Length of the structure, in bytes.
}

impl PciCapability for VirtioPciCap {
    fn bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::VendorSpecific
    }

    fn writable_bits(&self) -> Vec<u32> {
        vec![0u32; 4]
    }
}

impl VirtioPciCap {
    pub fn new(cfg_type: PciCapabilityType, bar: u8, offset: u32, length: u32) -> Self {
        VirtioPciCap {
            cap_vndr: 0,
            cap_next: 0,
            cap_len: std::mem::size_of::<VirtioPciCap>() as u8,
            cfg_type: cfg_type as u8,
            bar,
            id: 0,
            padding: [0; 2],
            offset: Le32::from(offset),
            length: Le32::from(length),
        }
    }

    pub fn set_cap_len(&mut self, cap_len: u8) {
        self.cap_len = cap_len;
    }
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VirtioPciNotifyCap {
    cap: VirtioPciCap,
    notify_off_multiplier: Le32,
}

impl PciCapability for VirtioPciNotifyCap {
    fn bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::VendorSpecific
    }

    fn writable_bits(&self) -> Vec<u32> {
        vec![0u32; 5]
    }
}

impl VirtioPciNotifyCap {
    pub fn new(
        cfg_type: PciCapabilityType,
        bar: u8,
        offset: u32,
        length: u32,
        multiplier: Le32,
    ) -> Self {
        VirtioPciNotifyCap {
            cap: VirtioPciCap {
                cap_vndr: 0,
                cap_next: 0,
                cap_len: std::mem::size_of::<VirtioPciNotifyCap>() as u8,
                cfg_type: cfg_type as u8,
                bar,
                id: 0,
                padding: [0; 2],
                offset: Le32::from(offset),
                length: Le32::from(length),
            },
            notify_off_multiplier: multiplier,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VirtioPciShmCap {
    cap: VirtioPciCap,
    offset_hi: Le32, // Most sig 32 bits of offset
    length_hi: Le32, // Most sig 32 bits of length
}

impl PciCapability for VirtioPciShmCap {
    fn bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::VendorSpecific
    }

    fn writable_bits(&self) -> Vec<u32> {
        vec![0u32; 6]
    }
}

impl VirtioPciShmCap {
    pub fn new(cfg_type: PciCapabilityType, bar: u8, offset: u64, length: u64, shmid: u8) -> Self {
        VirtioPciShmCap {
            cap: VirtioPciCap {
                cap_vndr: 0,
                cap_next: 0,
                cap_len: std::mem::size_of::<VirtioPciShmCap>() as u8,
                cfg_type: cfg_type as u8,
                bar,
                id: shmid,
                padding: [0; 2],
                offset: Le32::from(offset as u32),
                length: Le32::from(length as u32),
            },
            offset_hi: Le32::from((offset >> 32) as u32),
            length_hi: Le32::from((length >> 32) as u32),
        }
    }
}

// Allocate one bar for the structs pointed to by the capability structures.
const COMMON_CONFIG_BAR_OFFSET: u64 = 0x0000;
const COMMON_CONFIG_SIZE: u64 = 56;
const COMMON_CONFIG_LAST: u64 = COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE - 1;
const ISR_CONFIG_BAR_OFFSET: u64 = 0x1000;
const ISR_CONFIG_SIZE: u64 = 1;
const ISR_CONFIG_LAST: u64 = ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE - 1;
const DEVICE_CONFIG_BAR_OFFSET: u64 = 0x2000;
const DEVICE_CONFIG_SIZE: u64 = 0x1000;
const DEVICE_CONFIG_LAST: u64 = DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE - 1;
const NOTIFICATION_BAR_OFFSET: u64 = 0x3000;
const NOTIFICATION_SIZE: u64 = 0x1000;
const NOTIFICATION_LAST: u64 = NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE - 1;
const MSIX_TABLE_BAR_OFFSET: u64 = 0x6000;
const MSIX_TABLE_SIZE: u64 = 0x1000;
const MSIX_TABLE_LAST: u64 = MSIX_TABLE_BAR_OFFSET + MSIX_TABLE_SIZE - 1;
const MSIX_PBA_BAR_OFFSET: u64 = 0x7000;
const MSIX_PBA_SIZE: u64 = 0x1000;
const MSIX_PBA_LAST: u64 = MSIX_PBA_BAR_OFFSET + MSIX_PBA_SIZE - 1;
const CAPABILITY_BAR_SIZE: u64 = 0x8000;

const NOTIFY_OFF_MULTIPLIER: u32 = 4; // A dword per notification address.

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040; // Add to device type to get device ID.
const VIRTIO_PCI_REVISION_ID: u8 = 1;

const CAPABILITIES_BAR_NUM: usize = 0;
const SHMEM_BAR_NUM: usize = 2;

struct QueueEvent {
    event: Event,
    ioevent_registered: bool,
}

/// Implements the
/// [PCI](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-650001)
/// transport for virtio devices.
pub struct VirtioPciDevice {
    config_regs: PciConfiguration,
    preferred_address: Option<PciAddress>,
    pci_address: Option<PciAddress>,

    device: Box<dyn VirtioDevice>,
    device_activated: bool,
    disable_intx: bool,

    interrupt: Option<Interrupt>,
    interrupt_evt: Option<IrqLevelEvent>,
    interrupt_resample_worker: Option<WorkerThread<()>>,

    queues: Vec<QueueConfig>,
    queue_evts: Vec<QueueEvent>,
    mem: GuestMemory,
    settings_bar: PciBarIndex,
    msix_config: Arc<Mutex<MsixConfig>>,
    pm_config: Arc<Mutex<PmConfig>>,
    common_config: VirtioPciCommonConfig,

    iommu: Option<Arc<Mutex<IpcMemoryMapper>>>,

    // API client that is present if the device has shared memory regions, and
    // is used to map/unmap files into the shared memory region.
    shared_memory_vm_memory_client: Option<VmMemoryClient>,

    // API client for registration of ioevents when PCI BAR reprogramming is detected.
    ioevent_vm_memory_client: VmMemoryClient,

    // State only present while asleep.
    sleep_state: Option<SleepState>,

    vm_control_tube: Arc<Mutex<Tube>>,
}

enum SleepState {
    // Asleep and device hasn't been activated yet by the guest.
    Inactive,
    // Asleep and device has been activated by the guest.
    Active {
        /// The queues returned from `VirtioDevice::virtio_sleep`.
        /// Map is from queue index -> Queue.
        activated_queues: BTreeMap<usize, Queue>,
    },
}

#[derive(Serialize, Deserialize)]
struct VirtioPciDeviceSnapshot {
    config_regs: AnySnapshot,

    inner_device: AnySnapshot,
    device_activated: bool,

    interrupt: Option<InterruptSnapshot>,
    msix_config: AnySnapshot,
    common_config: VirtioPciCommonConfig,

    queues: Vec<AnySnapshot>,
    activated_queues: Option<Vec<(usize, AnySnapshot)>>,
}

impl VirtioPciDevice {
    /// Constructs a new PCI transport for the given virtio device.
    pub fn new(
        mem: GuestMemory,
        device: Box<dyn VirtioDevice>,
        msi_device_tube: Tube,
        disable_intx: bool,
        shared_memory_vm_memory_client: Option<VmMemoryClient>,
        ioevent_vm_memory_client: VmMemoryClient,
        vm_control_tube: Tube,
    ) -> Result<Self> {
        // shared_memory_vm_memory_client is required if there are shared memory regions.
        assert_eq!(
            device.get_shared_memory_region().is_none(),
            shared_memory_vm_memory_client.is_none()
        );

        let mut queue_evts = Vec::new();
        for _ in device.queue_max_sizes() {
            queue_evts.push(QueueEvent {
                event: Event::new()?,
                ioevent_registered: false,
            });
        }
        let queues = device
            .queue_max_sizes()
            .iter()
            .map(|&s| QueueConfig::new(s, device.features()))
            .collect();

        let pci_device_id = VIRTIO_PCI_DEVICE_ID_BASE + device.device_type() as u16;

        let (pci_device_class, pci_device_subclass) = match device.device_type() {
            DeviceType::Net => (
                PciClassCode::NetworkController,
                &PciNetworkControllerSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Block => (
                PciClassCode::MassStorage,
                &PciMassStorageSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Console => (
                PciClassCode::SimpleCommunicationController,
                &PciSimpleCommunicationControllerSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Rng => (
                PciClassCode::BaseSystemPeripheral,
                &PciBaseSystemPeripheralSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Balloon => (
                PciClassCode::BaseSystemPeripheral,
                &PciBaseSystemPeripheralSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Scsi => (
                PciClassCode::MassStorage,
                &PciMassStorageSubclass::Scsi as &dyn PciSubclass,
            ),
            DeviceType::P9 => (
                PciClassCode::NetworkController,
                &PciNetworkControllerSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Gpu => (
                PciClassCode::DisplayController,
                &PciDisplaySubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Input => (
                PciClassCode::InputDevice,
                &PciInputDeviceSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Vsock => (
                PciClassCode::NetworkController,
                &PciNetworkControllerSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Iommu => (
                PciClassCode::BaseSystemPeripheral,
                &PciBaseSystemPeripheralSubclass::Iommu as &dyn PciSubclass,
            ),
            DeviceType::Sound => (
                PciClassCode::MultimediaController,
                &PciMultimediaSubclass::AudioController as &dyn PciSubclass,
            ),
            DeviceType::Fs => (
                PciClassCode::MassStorage,
                &PciMassStorageSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Pmem => (
                PciClassCode::MassStorage,
                &PciMassStorageSubclass::NonVolatileMemory as &dyn PciSubclass,
            ),
            DeviceType::Mac80211HwSim => (
                PciClassCode::WirelessController,
                &PciWirelessControllerSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::VideoEncoder => (
                PciClassCode::MultimediaController,
                &PciMultimediaSubclass::VideoController as &dyn PciSubclass,
            ),
            DeviceType::VideoDecoder => (
                PciClassCode::MultimediaController,
                &PciMultimediaSubclass::VideoController as &dyn PciSubclass,
            ),
            DeviceType::Media => (
                PciClassCode::MultimediaController,
                &PciMultimediaSubclass::VideoController as &dyn PciSubclass,
            ),
            DeviceType::Scmi => (
                PciClassCode::BaseSystemPeripheral,
                &PciBaseSystemPeripheralSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Wl => (
                PciClassCode::DisplayController,
                &PciDisplaySubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Tpm => (
                PciClassCode::BaseSystemPeripheral,
                &PciBaseSystemPeripheralSubclass::Other as &dyn PciSubclass,
            ),
            DeviceType::Pvclock => (
                PciClassCode::BaseSystemPeripheral,
                &PciBaseSystemPeripheralSubclass::Other as &dyn PciSubclass,
            ),
        };

        let num_interrupts = device.num_interrupts();

        // One MSI-X vector per queue plus one for configuration changes.
        let msix_num = u16::try_from(num_interrupts + 1).map_err(|_| base::Error::new(ERANGE))?;
        let msix_config = Arc::new(Mutex::new(MsixConfig::new(
            msix_num,
            msi_device_tube,
            PciId::new(VIRTIO_PCI_VENDOR_ID, pci_device_id).into(),
            device.debug_label(),
        )));

        let config_regs = PciConfiguration::new(
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            pci_device_class,
            pci_device_subclass,
            None,
            PciHeaderType::Device,
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            VIRTIO_PCI_REVISION_ID,
        );

        Ok(VirtioPciDevice {
            config_regs,
            preferred_address: device.pci_address(),
            pci_address: None,
            device,
            device_activated: false,
            disable_intx,
            interrupt: None,
            interrupt_evt: None,
            interrupt_resample_worker: None,
            queues,
            queue_evts,
            mem,
            settings_bar: 0,
            msix_config,
            pm_config: Arc::new(Mutex::new(PmConfig::new(true))),
            common_config: VirtioPciCommonConfig {
                driver_status: 0,
                config_generation: 0,
                device_feature_select: 0,
                driver_feature_select: 0,
                queue_select: 0,
                msix_config: VIRTIO_MSI_NO_VECTOR,
            },
            iommu: None,
            shared_memory_vm_memory_client,
            ioevent_vm_memory_client,
            sleep_state: None,
            vm_control_tube: Arc::new(Mutex::new(vm_control_tube)),
        })
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits = (VIRTIO_CONFIG_S_ACKNOWLEDGE
            | VIRTIO_CONFIG_S_DRIVER
            | VIRTIO_CONFIG_S_DRIVER_OK
            | VIRTIO_CONFIG_S_FEATURES_OK) as u8;
        (self.common_config.driver_status & ready_bits) == ready_bits
            && self.common_config.driver_status & VIRTIO_CONFIG_S_FAILED as u8 == 0
    }

    fn is_device_suspended(&self) -> bool {
        (self.common_config.driver_status & VIRTIO_CONFIG_S_SUSPEND as u8) != 0
    }

    /// Determines if the driver has requested the device reset itself
    fn is_reset_requested(&self) -> bool {
        self.common_config.driver_status == DEVICE_RESET as u8
    }

    fn add_settings_pci_capabilities(
        &mut self,
        settings_bar: u8,
    ) -> std::result::Result<(), PciDeviceError> {
        // Add pointers to the different configuration structures from the PCI capabilities.
        let common_cap = VirtioPciCap::new(
            PciCapabilityType::CommonConfig,
            settings_bar,
            COMMON_CONFIG_BAR_OFFSET as u32,
            COMMON_CONFIG_SIZE as u32,
        );
        self.config_regs
            .add_capability(&common_cap, None)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        let isr_cap = VirtioPciCap::new(
            PciCapabilityType::IsrConfig,
            settings_bar,
            ISR_CONFIG_BAR_OFFSET as u32,
            ISR_CONFIG_SIZE as u32,
        );
        self.config_regs
            .add_capability(&isr_cap, None)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        // TODO(dgreid) - set based on device's configuration size?
        let device_cap = VirtioPciCap::new(
            PciCapabilityType::DeviceConfig,
            settings_bar,
            DEVICE_CONFIG_BAR_OFFSET as u32,
            DEVICE_CONFIG_SIZE as u32,
        );
        self.config_regs
            .add_capability(&device_cap, None)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        let notify_cap = VirtioPciNotifyCap::new(
            PciCapabilityType::NotifyConfig,
            settings_bar,
            NOTIFICATION_BAR_OFFSET as u32,
            NOTIFICATION_SIZE as u32,
            Le32::from(NOTIFY_OFF_MULTIPLIER),
        );
        self.config_regs
            .add_capability(&notify_cap, None)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        //TODO(dgreid) - How will the configuration_cap work?
        let configuration_cap = VirtioPciCap::new(PciCapabilityType::PciConfig, 0, 0, 0);
        self.config_regs
            .add_capability(&configuration_cap, None)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        let msix_cap = MsixCap::new(
            settings_bar,
            self.msix_config.lock().num_vectors(),
            MSIX_TABLE_BAR_OFFSET as u32,
            settings_bar,
            MSIX_PBA_BAR_OFFSET as u32,
        );
        self.config_regs
            .add_capability(&msix_cap, Some(Box::new(self.msix_config.clone())))
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        self.config_regs
            .add_capability(&PciPmCap::new(), Some(Box::new(self.pm_config.clone())))
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        self.settings_bar = settings_bar as PciBarIndex;
        Ok(())
    }

    /// Activates the underlying `VirtioDevice`. `assign_irq` has to be called first.
    fn activate(&mut self) -> anyhow::Result<()> {
        let interrupt = Interrupt::new(
            self.interrupt_evt
                .as_ref()
                .ok_or_else(|| anyhow!("{} interrupt_evt is none", self.debug_label()))?
                .try_clone()
                .with_context(|| format!("{} failed to clone interrupt_evt", self.debug_label()))?,
            Some(self.msix_config.clone()),
            self.common_config.msix_config,
            #[cfg(target_arch = "x86_64")]
            Some((
                PmWakeupEvent::new(self.vm_control_tube.clone(), self.pm_config.clone()),
                MetricEventType::VirtioWakeup {
                    virtio_id: self.device.device_type() as u32,
                },
            )),
        );
        self.interrupt = Some(interrupt.clone());
        self.interrupt_resample_worker = interrupt.spawn_resample_thread();

        let bar0 = self.config_regs.get_bar_addr(self.settings_bar);
        let notify_base = bar0 + NOTIFICATION_BAR_OFFSET;

        // Use ready queues and their events.
        let queues = self
            .queues
            .iter_mut()
            .enumerate()
            .zip(self.queue_evts.iter_mut())
            .filter(|((_, q), _)| q.ready())
            .map(|((queue_index, queue), evt)| {
                if !evt.ioevent_registered {
                    self.ioevent_vm_memory_client
                        .register_io_event(
                            evt.event.try_clone().context("failed to clone Event")?,
                            notify_base + queue_index as u64 * u64::from(NOTIFY_OFF_MULTIPLIER),
                            Datamatch::AnyLength,
                        )
                        .context("failed to register ioevent")?;
                    evt.ioevent_registered = true;
                }
                let queue_evt = evt.event.try_clone().context("failed to clone queue_evt")?;
                Ok((
                    queue_index,
                    queue
                        .activate(&self.mem, queue_evt, interrupt.clone())
                        .context("failed to activate queue")?,
                ))
            })
            .collect::<anyhow::Result<BTreeMap<usize, Queue>>>()?;

        if let Err(e) = self.device.activate(self.mem.clone(), interrupt, queues) {
            error!("{} activate failed: {:#}", self.debug_label(), e);
            self.common_config.driver_status |= VIRTIO_CONFIG_S_NEEDS_RESET as u8;
        } else {
            self.device_activated = true;
        }

        Ok(())
    }

    fn unregister_ioevents(&mut self) -> anyhow::Result<()> {
        let bar0 = self.config_regs.get_bar_addr(self.settings_bar);
        let notify_base = bar0 + NOTIFICATION_BAR_OFFSET;

        for (queue_index, evt) in self.queue_evts.iter_mut().enumerate() {
            if evt.ioevent_registered {
                self.ioevent_vm_memory_client
                    .unregister_io_event(
                        evt.event.try_clone().context("failed to clone Event")?,
                        notify_base + queue_index as u64 * u64::from(NOTIFY_OFF_MULTIPLIER),
                        Datamatch::AnyLength,
                    )
                    .context("failed to unregister ioevent")?;
                evt.ioevent_registered = false;
            }
        }
        Ok(())
    }

    pub fn virtio_device(&self) -> &dyn VirtioDevice {
        self.device.as_ref()
    }

    pub fn pci_address(&self) -> Option<PciAddress> {
        self.pci_address
    }

    #[cfg(target_arch = "x86_64")]
    fn handle_pm_status_change(&mut self, status: &PmStatusChange) {
        if let Some(interrupt) = self.interrupt.as_mut() {
            interrupt.set_wakeup_event_active(status.to == PciDevicePower::D3)
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn handle_pm_status_change(&mut self, _status: &PmStatusChange) {}
}

impl PciDevice for VirtioPciDevice {
    fn debug_label(&self) -> String {
        format!("pci{}", self.device.debug_label())
    }

    fn preferred_address(&self) -> Option<PciAddress> {
        self.preferred_address
    }

    fn allocate_address(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<PciAddress, PciDeviceError> {
        if self.pci_address.is_none() {
            if let Some(address) = self.preferred_address {
                if !resources.reserve_pci(address, self.debug_label()) {
                    return Err(PciDeviceError::PciAllocationFailed);
                }
                self.pci_address = Some(address);
            } else {
                self.pci_address = resources.allocate_pci(0, self.debug_label());
            }
            self.msix_config
                .lock()
                .set_pci_address(self.pci_address.unwrap());
        }
        self.pci_address.ok_or(PciDeviceError::PciAllocationFailed)
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = self.device.keep_rds();
        rds.extend(
            self.queue_evts
                .iter()
                .map(|qe| qe.event.as_raw_descriptor()),
        );
        if let Some(interrupt_evt) = &self.interrupt_evt {
            rds.extend(interrupt_evt.as_raw_descriptors());
        }
        let descriptor = self.msix_config.lock().get_msi_socket();
        rds.push(descriptor);
        if let Some(iommu) = &self.iommu {
            rds.append(&mut iommu.lock().as_raw_descriptors());
        }
        rds.push(self.ioevent_vm_memory_client.as_raw_descriptor());
        rds.push(self.vm_control_tube.lock().as_raw_descriptor());
        rds
    }

    fn assign_irq(&mut self, irq_evt: IrqLevelEvent, pin: PciInterruptPin, irq_num: u32) {
        self.interrupt_evt = Some(irq_evt);
        if !self.disable_intx {
            self.config_regs.set_irq(irq_num as u8, pin);
        }
    }

    fn allocate_io_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<Vec<BarRange>, PciDeviceError> {
        let device_type = self.device.device_type();
        allocate_io_bars(
            self,
            |size: u64, alloc: Alloc, alloc_option: &AllocOptions| {
                resources
                    .allocate_mmio(
                        size,
                        alloc,
                        format!("virtio-{}-cap_bar", device_type),
                        alloc_option,
                    )
                    .map_err(|e| PciDeviceError::IoAllocationFailed(size, e))
            },
        )
    }

    fn allocate_device_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<Vec<BarRange>, PciDeviceError> {
        let device_type = self.device.device_type();
        allocate_device_bars(
            self,
            |size: u64, alloc: Alloc, alloc_option: &AllocOptions| {
                resources
                    .allocate_mmio(
                        size,
                        alloc,
                        format!("virtio-{}-custom_bar", device_type),
                        alloc_option,
                    )
                    .map_err(|e| PciDeviceError::IoAllocationFailed(size, e))
            },
        )
    }

    fn destroy_device(&mut self) {
        if let Err(e) = self.unregister_ioevents() {
            error!("error destroying {}: {:?}", &self.debug_label(), &e);
        }
    }

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        self.config_regs.get_bar_configuration(bar_num)
    }

    fn register_device_capabilities(&mut self) -> std::result::Result<(), PciDeviceError> {
        let mut caps = self.device.get_device_caps();
        if let Some(region) = self.device.get_shared_memory_region() {
            caps.push(Box::new(VirtioPciShmCap::new(
                PciCapabilityType::SharedMemoryConfig,
                SHMEM_BAR_NUM as u8,
                0,
                region.length,
                region.id,
            )));
        }

        for cap in caps {
            self.config_regs
                .add_capability(&*cap, None)
                .map_err(PciDeviceError::CapabilitiesSetup)?;
        }

        Ok(())
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        self.config_regs.read_reg(reg_idx)
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if let Some(res) = self.config_regs.write_reg(reg_idx, offset, data) {
            if let Some(msix_behavior) = res.downcast_ref::<MsixStatus>() {
                self.device.control_notify(*msix_behavior);
            } else if let Some(status) = res.downcast_ref::<PmStatusChange>() {
                self.handle_pm_status_change(status);
            }
        }
    }

    fn setup_pci_config_mapping(
        &mut self,
        shmem: &SharedMemory,
        base: usize,
        len: usize,
    ) -> std::result::Result<bool, PciDeviceError> {
        self.config_regs
            .setup_mapping(shmem, base, len)
            .map(|_| true)
            .map_err(PciDeviceError::MmioSetup)
    }

    fn read_bar(&mut self, bar_index: usize, offset: u64, data: &mut [u8]) {
        if bar_index == self.settings_bar {
            match offset {
                COMMON_CONFIG_BAR_OFFSET..=COMMON_CONFIG_LAST => self.common_config.read(
                    offset - COMMON_CONFIG_BAR_OFFSET,
                    data,
                    &mut self.queues,
                    self.device.as_mut(),
                ),
                ISR_CONFIG_BAR_OFFSET..=ISR_CONFIG_LAST => {
                    if let Some(v) = data.get_mut(0) {
                        // Reading this register resets it to 0.
                        *v = if let Some(interrupt) = &self.interrupt {
                            interrupt.read_and_reset_interrupt_status()
                        } else {
                            0
                        };
                    }
                }
                DEVICE_CONFIG_BAR_OFFSET..=DEVICE_CONFIG_LAST => {
                    self.device
                        .read_config(offset - DEVICE_CONFIG_BAR_OFFSET, data);
                }
                NOTIFICATION_BAR_OFFSET..=NOTIFICATION_LAST => {
                    // Handled with ioevents.
                }
                MSIX_TABLE_BAR_OFFSET..=MSIX_TABLE_LAST => {
                    self.msix_config
                        .lock()
                        .read_msix_table(offset - MSIX_TABLE_BAR_OFFSET, data);
                }
                MSIX_PBA_BAR_OFFSET..=MSIX_PBA_LAST => {
                    self.msix_config
                        .lock()
                        .read_pba_entries(offset - MSIX_PBA_BAR_OFFSET, data);
                }
                _ => (),
            }
        }
    }

    fn write_bar(&mut self, bar_index: usize, offset: u64, data: &[u8]) {
        let was_suspended = self.is_device_suspended();

        if bar_index == self.settings_bar {
            match offset {
                COMMON_CONFIG_BAR_OFFSET..=COMMON_CONFIG_LAST => self.common_config.write(
                    offset - COMMON_CONFIG_BAR_OFFSET,
                    data,
                    &mut self.queues,
                    self.device.as_mut(),
                ),
                ISR_CONFIG_BAR_OFFSET..=ISR_CONFIG_LAST => {
                    if let Some(v) = data.first() {
                        if let Some(interrupt) = &self.interrupt {
                            interrupt.clear_interrupt_status_bits(*v);
                        }
                    }
                }
                DEVICE_CONFIG_BAR_OFFSET..=DEVICE_CONFIG_LAST => {
                    self.device
                        .write_config(offset - DEVICE_CONFIG_BAR_OFFSET, data);
                }
                NOTIFICATION_BAR_OFFSET..=NOTIFICATION_LAST => {
                    // Notifications are normally handled with ioevents inside the hypervisor and
                    // do not reach write_bar(). However, if the ioevent registration hasn't
                    // finished yet, it is possible for a write to the notification region to make
                    // it through as a normal MMIO exit and end up here. To handle that case,
                    // provide a fallback that looks up the corresponding queue for the offset and
                    // triggers its event, which is equivalent to what the ioevent would do.
                    let queue_index = (offset - NOTIFICATION_BAR_OFFSET) as usize
                        / NOTIFY_OFF_MULTIPLIER as usize;
                    trace!("write_bar notification fallback for queue {}", queue_index);
                    if let Some(evt) = self.queue_evts.get(queue_index) {
                        let _ = evt.event.signal();
                    }
                }
                MSIX_TABLE_BAR_OFFSET..=MSIX_TABLE_LAST => {
                    let behavior = self
                        .msix_config
                        .lock()
                        .write_msix_table(offset - MSIX_TABLE_BAR_OFFSET, data);
                    self.device.control_notify(behavior);
                }
                MSIX_PBA_BAR_OFFSET..=MSIX_PBA_LAST => {
                    self.msix_config
                        .lock()
                        .write_pba_entries(offset - MSIX_PBA_BAR_OFFSET, data);
                }
                _ => (),
            }
        }

        if !self.device_activated && self.is_driver_ready() {
            if let Err(e) = self.activate() {
                error!("failed to activate device: {:#}", e);
            }
        }

        let is_suspended = self.is_device_suspended();
        if is_suspended != was_suspended {
            if let Some(interrupt) = self.interrupt.as_mut() {
                interrupt.set_suspended(is_suspended);
            }
        }

        // Device has been reset by the driver
        if self.device_activated && self.is_reset_requested() {
            if let Err(e) = self.device.reset() {
                error!("failed to reset {} device: {:#}", self.debug_label(), e);
            } else {
                self.device_activated = false;
                // reset queues
                self.queues.iter_mut().for_each(QueueConfig::reset);
                // select queue 0 by default
                self.common_config.queue_select = 0;
                if let Err(e) = self.unregister_ioevents() {
                    error!("failed to unregister ioevents: {:#}", e);
                }
                if let Some(interrupt_resample_worker) = self.interrupt_resample_worker.take() {
                    interrupt_resample_worker.stop();
                }
            }
        }
    }

    fn on_device_sandboxed(&mut self) {
        self.device.on_device_sandboxed();
    }

    #[cfg(target_arch = "x86_64")]
    fn generate_acpi(&mut self, sdts: &mut Vec<SDT>) -> anyhow::Result<()> {
        self.device.generate_acpi(
            self.pci_address.expect("pci_address must be assigned"),
            sdts,
        )
    }

    fn as_virtio_pci_device(&self) -> Option<&VirtioPciDevice> {
        Some(self)
    }
}

fn allocate_io_bars<F>(
    virtio_pci_device: &mut VirtioPciDevice,
    mut alloc_fn: F,
) -> std::result::Result<Vec<BarRange>, PciDeviceError>
where
    F: FnMut(u64, Alloc, &AllocOptions) -> std::result::Result<u64, PciDeviceError>,
{
    let address = virtio_pci_device
        .pci_address
        .expect("allocate_address must be called prior to allocate_io_bars");
    // Allocate one bar for the structures pointed to by the capability structures.
    let settings_config_addr = alloc_fn(
        CAPABILITY_BAR_SIZE,
        Alloc::PciBar {
            bus: address.bus,
            dev: address.dev,
            func: address.func,
            bar: 0,
        },
        AllocOptions::new()
            .max_address(u32::MAX.into())
            .align(CAPABILITY_BAR_SIZE),
    )?;
    let config = PciBarConfiguration::new(
        CAPABILITIES_BAR_NUM,
        CAPABILITY_BAR_SIZE,
        PciBarRegionType::Memory32BitRegion,
        PciBarPrefetchable::NotPrefetchable,
    )
    .set_address(settings_config_addr);
    let settings_bar = virtio_pci_device
        .config_regs
        .add_pci_bar(config)
        .map_err(|e| PciDeviceError::IoRegistrationFailed(settings_config_addr, e))?
        as u8;
    // Once the BARs are allocated, the capabilities can be added to the PCI configuration.
    virtio_pci_device.add_settings_pci_capabilities(settings_bar)?;

    Ok(vec![BarRange {
        addr: settings_config_addr,
        size: CAPABILITY_BAR_SIZE,
        prefetchable: false,
    }])
}

fn allocate_device_bars<F>(
    virtio_pci_device: &mut VirtioPciDevice,
    mut alloc_fn: F,
) -> std::result::Result<Vec<BarRange>, PciDeviceError>
where
    F: FnMut(u64, Alloc, &AllocOptions) -> std::result::Result<u64, PciDeviceError>,
{
    let address = virtio_pci_device
        .pci_address
        .expect("allocate_address must be called prior to allocate_device_bars");

    let configs = virtio_pci_device.device.get_device_bars(address);
    let configs = if !configs.is_empty() {
        configs
    } else {
        let region = match virtio_pci_device.device.get_shared_memory_region() {
            None => return Ok(Vec::new()),
            Some(r) => r,
        };
        let config = PciBarConfiguration::new(
            SHMEM_BAR_NUM,
            region
                .length
                .checked_next_power_of_two()
                .expect("bar too large"),
            PciBarRegionType::Memory64BitRegion,
            PciBarPrefetchable::Prefetchable,
        );

        let alloc = Alloc::PciBar {
            bus: address.bus,
            dev: address.dev,
            func: address.func,
            bar: config.bar_index() as u8,
        };

        let vm_memory_client = virtio_pci_device
            .shared_memory_vm_memory_client
            .take()
            .expect("missing shared_memory_tube");

        // See comment VmMemoryRequest::execute
        let can_prepare = !virtio_pci_device
            .device
            .expose_shmem_descriptors_with_viommu();
        let prepare_type = if can_prepare {
            virtio_pci_device.device.get_shared_memory_prepare_type()
        } else {
            SharedMemoryPrepareType::DynamicPerMapping
        };

        let vm_requester = Box::new(VmRequester::new(vm_memory_client, alloc, prepare_type));
        virtio_pci_device
            .device
            .set_shared_memory_mapper(vm_requester);

        vec![config]
    };
    let mut ranges = vec![];
    for config in configs {
        let device_addr = alloc_fn(
            config.size(),
            Alloc::PciBar {
                bus: address.bus,
                dev: address.dev,
                func: address.func,
                bar: config.bar_index() as u8,
            },
            AllocOptions::new()
                .prefetchable(config.is_prefetchable())
                .align(config.size()),
        )?;
        let config = config.set_address(device_addr);
        let _device_bar = virtio_pci_device
            .config_regs
            .add_pci_bar(config)
            .map_err(|e| PciDeviceError::IoRegistrationFailed(device_addr, e))?;
        ranges.push(BarRange {
            addr: device_addr,
            size: config.size(),
            prefetchable: false,
        });
    }

    if virtio_pci_device
        .device
        .get_shared_memory_region()
        .is_some()
    {
        let shmem_region = AddressRange::from_start_and_size(ranges[0].addr, ranges[0].size)
            .expect("invalid shmem region");
        virtio_pci_device
            .device
            .set_shared_memory_region(shmem_region);
    }

    Ok(ranges)
}

#[cfg(feature = "pci-hotplug")]
impl HotPluggable for VirtioPciDevice {
    /// Sets PciAddress to pci_addr
    fn set_pci_address(&mut self, pci_addr: PciAddress) -> std::result::Result<(), PciDeviceError> {
        self.pci_address = Some(pci_addr);
        self.msix_config
            .lock()
            .set_pci_address(self.pci_address.unwrap());
        Ok(())
    }

    /// Configures IO BAR layout without memory alloc.
    fn configure_io_bars(&mut self) -> std::result::Result<(), PciDeviceError> {
        let mut simple_allocator = SimpleAllocator::new(0);
        allocate_io_bars(self, |size, _, _| simple_allocator.alloc(size, size)).map(|_| ())
    }

    /// Configure device BAR layout without memory alloc.
    fn configure_device_bars(&mut self) -> std::result::Result<(), PciDeviceError> {
        // For device BAR, the space for CAPABILITY_BAR_SIZE should be skipped.
        let mut simple_allocator = SimpleAllocator::new(CAPABILITY_BAR_SIZE);
        allocate_device_bars(self, |size, _, _| simple_allocator.alloc(size, size)).map(|_| ())
    }
}

#[cfg(feature = "pci-hotplug")]
/// A simple allocator that can allocate non-overlapping aligned intervals.
///
/// The addresses allocated are not exclusively reserved for the device, and cannot be used for a
/// static device. The allocated placeholder address describes the layout of PCI BAR for hotplugged
/// devices. Actual memory allocation is handled by PCI BAR reprogramming initiated by guest OS.
struct SimpleAllocator {
    current_address: u64,
}

#[cfg(feature = "pci-hotplug")]
impl SimpleAllocator {
    /// Constructs SimpleAllocator. Address will start at or after base_address.
    fn new(base_address: u64) -> Self {
        Self {
            current_address: base_address,
        }
    }

    /// Allocate memory with size and align. Returns the start of address.
    fn alloc(&mut self, size: u64, align: u64) -> std::result::Result<u64, PciDeviceError> {
        if align > 0 {
            // aligns current_address upward to align.
            self.current_address = self.current_address.next_multiple_of(align);
        }
        let start_address = self.current_address;
        self.current_address += size;
        Ok(start_address)
    }
}

impl Suspendable for VirtioPciDevice {
    fn sleep(&mut self) -> anyhow::Result<()> {
        // If the device is already asleep, we should not request it to sleep again.
        if self.sleep_state.is_some() {
            return Ok(());
        }

        if let Some(queues) = self.device.virtio_sleep()? {
            anyhow::ensure!(
                self.device_activated,
                format!(
                    "unactivated device {} returned queues on sleep",
                    self.debug_label()
                ),
            );
            self.sleep_state = Some(SleepState::Active {
                activated_queues: queues,
            });
        } else {
            anyhow::ensure!(
                !self.device_activated,
                format!(
                    "activated device {} didn't return queues on sleep",
                    self.debug_label()
                ),
            );
            self.sleep_state = Some(SleepState::Inactive);
        }
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        match self.sleep_state.take() {
            None => {
                // If the device is already awake, we should not request it to wake again.
            }
            Some(SleepState::Inactive) => {
                self.device.virtio_wake(None).with_context(|| {
                    format!(
                        "virtio_wake failed for {}, can't recover",
                        self.debug_label(),
                    )
                })?;
            }
            Some(SleepState::Active { activated_queues }) => {
                self.device
                    .virtio_wake(Some((
                        self.mem.clone(),
                        self.interrupt
                            .clone()
                            .expect("interrupt missing for already active queues"),
                        activated_queues,
                    )))
                    .with_context(|| {
                        format!(
                            "virtio_wake failed for {}, can't recover",
                            self.debug_label(),
                        )
                    })?;
            }
        };
        Ok(())
    }

    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        if self.iommu.is_some() {
            return Err(anyhow!("Cannot snapshot if iommu is present."));
        }

        AnySnapshot::to_any(VirtioPciDeviceSnapshot {
            config_regs: self.config_regs.snapshot()?,
            inner_device: self.device.virtio_snapshot()?,
            device_activated: self.device_activated,
            interrupt: self.interrupt.as_ref().map(|i| i.snapshot()),
            msix_config: self.msix_config.lock().snapshot()?,
            common_config: self.common_config,
            queues: self
                .queues
                .iter()
                .map(|q| q.snapshot())
                .collect::<anyhow::Result<Vec<_>>>()?,
            activated_queues: match &self.sleep_state {
                None => {
                    anyhow::bail!("tried snapshotting while awake")
                }
                Some(SleepState::Inactive) => None,
                Some(SleepState::Active { activated_queues }) => {
                    let mut serialized_queues = Vec::new();
                    for (index, queue) in activated_queues.iter() {
                        serialized_queues.push((*index, queue.snapshot()?));
                    }
                    Some(serialized_queues)
                }
            },
        })
        .context("failed to serialize VirtioPciDeviceSnapshot")
    }

    fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        // Restoring from an activated state is more complex and low priority, so just fail for
        // now. We'll need to reset the device before restoring, e.g. must call
        // self.unregister_ioevents().
        anyhow::ensure!(
            !self.device_activated,
            "tried to restore after virtio device activated. not supported yet"
        );

        let deser: VirtioPciDeviceSnapshot = AnySnapshot::from_any(data)?;

        self.config_regs.restore(deser.config_regs)?;
        self.device_activated = deser.device_activated;

        self.msix_config.lock().restore(deser.msix_config)?;
        self.common_config = deser.common_config;

        // Restore the interrupt. This must be done after restoring the MSI-X configuration, but
        // before restoring the queues.
        if let Some(deser_interrupt) = deser.interrupt {
            let interrupt = Interrupt::new_from_snapshot(
                self.interrupt_evt
                    .as_ref()
                    .ok_or_else(|| anyhow!("{} interrupt_evt is none", self.debug_label()))?
                    .try_clone()
                    .with_context(|| {
                        format!("{} failed to clone interrupt_evt", self.debug_label())
                    })?,
                Some(self.msix_config.clone()),
                self.common_config.msix_config,
                deser_interrupt,
                #[cfg(target_arch = "x86_64")]
                Some((
                    PmWakeupEvent::new(self.vm_control_tube.clone(), self.pm_config.clone()),
                    MetricEventType::VirtioWakeup {
                        virtio_id: self.device.device_type() as u32,
                    },
                )),
            );
            self.interrupt_resample_worker = interrupt.spawn_resample_thread();
            self.interrupt = Some(interrupt);
        }

        assert_eq!(
            self.queues.len(),
            deser.queues.len(),
            "device must have the same number of queues"
        );
        for (q, s) in self.queues.iter_mut().zip(deser.queues.into_iter()) {
            q.restore(s)?;
        }

        // Verify we are asleep and inactive.
        match &self.sleep_state {
            None => {
                anyhow::bail!("tried restoring while awake")
            }
            Some(SleepState::Inactive) => {}
            Some(SleepState::Active { .. }) => {
                anyhow::bail!("tried to restore after virtio device activated. not supported yet")
            }
        };
        // Restore `sleep_state`.
        if let Some(activated_queues_snapshot) = deser.activated_queues {
            let interrupt = self
                .interrupt
                .as_ref()
                .context("tried to restore active queues without an interrupt")?;
            let mut activated_queues = BTreeMap::new();
            for (index, queue_snapshot) in activated_queues_snapshot {
                let queue_config = self
                    .queues
                    .get(index)
                    .with_context(|| format!("missing queue config for activated queue {index}"))?;
                let queue_evt = self
                    .queue_evts
                    .get(index)
                    .with_context(|| format!("missing queue event for activated queue {index}"))?
                    .event
                    .try_clone()
                    .context("failed to clone queue event")?;
                activated_queues.insert(
                    index,
                    Queue::restore(
                        queue_config,
                        queue_snapshot,
                        &self.mem,
                        queue_evt,
                        interrupt.clone(),
                    )?,
                );
            }

            // Restore the activated queues.
            self.sleep_state = Some(SleepState::Active { activated_queues });
        } else {
            self.sleep_state = Some(SleepState::Inactive);
        }

        // Call register_io_events for the activated queue events.
        let bar0 = self.config_regs.get_bar_addr(self.settings_bar);
        let notify_base = bar0 + NOTIFICATION_BAR_OFFSET;
        self.queues
            .iter()
            .enumerate()
            .zip(self.queue_evts.iter_mut())
            .filter(|((_, q), _)| q.ready())
            .try_for_each(|((queue_index, _queue), evt)| {
                if !evt.ioevent_registered {
                    self.ioevent_vm_memory_client
                        .register_io_event(
                            evt.event.try_clone().context("failed to clone Event")?,
                            notify_base + queue_index as u64 * u64::from(NOTIFY_OFF_MULTIPLIER),
                            Datamatch::AnyLength,
                        )
                        .context("failed to register ioevent")?;
                    evt.ioevent_registered = true;
                }
                Ok::<(), anyhow::Error>(())
            })?;

        // There might be data in the queue that wasn't drained by the device
        // at the time it was snapshotted. In this case, the doorbell should
        // still be signaled. If it is not, the driver may never re-trigger the
        // doorbell, and the device will stall. So here, we explicitly signal
        // every doorbell. Spurious doorbells are safe (devices will check their
        // queue, realize nothing is there, and go back to sleep.)
        self.queue_evts.iter_mut().try_for_each(|queue_event| {
            queue_event
                .event
                .signal()
                .context("failed to wake doorbell")
        })?;

        self.device.virtio_restore(deser.inner_device)?;

        Ok(())
    }
}

struct VmRequester {
    vm_memory_client: VmMemoryClient,
    alloc: Alloc,
    mappings: BTreeMap<u64, VmMemoryRegionId>,
    prepare_type: SharedMemoryPrepareType,
    prepared: bool,
}

impl VmRequester {
    fn new(
        vm_memory_client: VmMemoryClient,
        alloc: Alloc,
        prepare_type: SharedMemoryPrepareType,
    ) -> Self {
        Self {
            vm_memory_client,
            alloc,
            mappings: BTreeMap::new(),
            prepare_type,
            prepared: false,
        }
    }
}

impl SharedMemoryMapper for VmRequester {
    fn add_mapping(
        &mut self,
        source: VmMemorySource,
        offset: u64,
        prot: Protection,
        cache: MemCacheType,
    ) -> anyhow::Result<()> {
        if !self.prepared {
            if let SharedMemoryPrepareType::SingleMappingOnFirst(prepare_cache_type) =
                self.prepare_type
            {
                debug!(
                    "lazy prepare_shared_memory_region with {:?}",
                    prepare_cache_type
                );
                self.vm_memory_client
                    .prepare_shared_memory_region(self.alloc, prepare_cache_type)
                    .context("lazy prepare_shared_memory_region failed")?;
            }
            self.prepared = true;
        }

        // devices must implement VirtioDevice::get_shared_memory_prepare_type(), returning
        // SharedMemoryPrepareType::SingleMappingOnFirst(MemCacheType::CacheNonCoherent) in order to
        // add any mapping that requests MemCacheType::CacheNonCoherent.
        if cache == MemCacheType::CacheNonCoherent {
            if let SharedMemoryPrepareType::SingleMappingOnFirst(MemCacheType::CacheCoherent) =
                self.prepare_type
            {
                error!("invalid request to map with CacheNonCoherent for device with prepared CacheCoherent memory");
                return Err(anyhow!("invalid MemCacheType"));
            }
        }

        let id = self
            .vm_memory_client
            .register_memory(
                source,
                VmMemoryDestination::ExistingAllocation {
                    allocation: self.alloc,
                    offset,
                },
                prot,
                cache,
            )
            .context("register_memory failed")?;

        self.mappings.insert(offset, id);
        Ok(())
    }

    fn remove_mapping(&mut self, offset: u64) -> anyhow::Result<()> {
        let id = self.mappings.remove(&offset).context("invalid offset")?;
        self.vm_memory_client
            .unregister_memory(id)
            .context("unregister_memory failed")
    }

    fn as_raw_descriptor(&self) -> Option<RawDescriptor> {
        Some(self.vm_memory_client.as_raw_descriptor())
    }
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "pci-hotplug")]
    #[test]
    fn allocate_aligned_address() {
        let mut simple_allocator = super::SimpleAllocator::new(0);
        // start at 0, aligned to 0x80. Interval end at 0x20.
        assert_eq!(simple_allocator.alloc(0x20, 0x80).unwrap(), 0);
        // 0x20 => start at 0x40. Interval end at 0x80.
        assert_eq!(simple_allocator.alloc(0x40, 0x40).unwrap(), 0x40);
        // 0x80 => start at 0x80, Interval end at 0x108.
        assert_eq!(simple_allocator.alloc(0x88, 0x80).unwrap(), 0x80);
        // 0x108 => start at 0x180. Interval end at 0x1b0.
        assert_eq!(simple_allocator.alloc(0x30, 0x80).unwrap(), 0x180);
    }
}
