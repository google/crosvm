// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement a userspace PCI device driver for the virtio vhost-user device.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::info;
use base::Event;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use memoffset::offset_of;
use resources::Alloc;
use vfio_sys::*;
use virtio_sys::virtio_config;
use virtio_sys::virtio_config::VIRTIO_F_VERSION_1;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::pci::MsixCap;
use crate::pci::PciAddress;
use crate::pci::PciCapabilityID;
use crate::pci::CAPABILITY_LIST_HEAD_OFFSET;
use crate::vfio::VfioDevice;
use crate::vfio::VfioPciConfig;
use crate::vfio::VfioRegionAddr;
use crate::virtio::vhost::user::device::vvu::bus::open_vfio_device;
use crate::virtio::vhost::user::device::vvu::queue::DescTableAddrs;
use crate::virtio::vhost::user::device::vvu::queue::IovaAllocator;
use crate::virtio::vhost::user::device::vvu::queue::UserQueue;
use crate::virtio::PciCapabilityType;
use crate::virtio::VirtioPciCap;

const VIRTIO_CONFIG_STATUS_RESET: u8 = 0;

fn get_pci_cap_addr(cap: &VirtioPciCap) -> Result<VfioRegionAddr> {
    const PCI_MAX_RESOURCE: u8 = 6;

    if cap.bar >= PCI_MAX_RESOURCE {
        bail!("invalid bar: {:?} >= {}", cap.bar, PCI_MAX_RESOURCE);
    }

    if u32::from(cap.offset)
        .checked_add(u32::from(cap.length))
        .is_none()
    {
        bail!("overflow: {:?} + {:?}", cap.offset, cap.length);
    }

    Ok(VfioRegionAddr {
        index: cap.bar.into(),
        addr: u32::from(cap.offset) as u64,
    })
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, AsBytes, FromBytes)]
/// VirtIO spec: 4.1.4.3 Common configuration structure layout
struct virtio_pci_common_cfg {
    // For the whole device.
    device_feature_select: u32,
    device_feature: u32,
    guest_feature_select: u32,
    guest_feature: u32,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,

    // For a specific virtqueue.
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_desc_lo: u32,
    queue_desc_hi: u32,
    queue_avail_lo: u32,
    queue_avail_hi: u32,
    queue_used_lo: u32,
    queue_used_hi: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, AsBytes, FromBytes)]
struct virtio_pci_notification_cfg {
    notification_select: u16,
    notification_msix_vector: u16,
}

#[derive(Clone)]
pub struct VvuPciCaps {
    msix_table_size: u16,
    common_cfg_addr: VfioRegionAddr,
    notify_off_multiplier: u32,
    notify_base_addr: VfioRegionAddr,
    dev_cfg_addr: VfioRegionAddr,
    isr_addr: VfioRegionAddr,
    doorbell_off_multiplier: u32,
    doorbell_base_addr: VfioRegionAddr,
    notify_cfg_addr: VfioRegionAddr,
    shared_mem_cfg_addr: VfioRegionAddr,
}

impl VvuPciCaps {
    pub fn new(config: &VfioPciConfig) -> Result<Self> {
        // Safe because zero is valid for every field in `VvuPciCaps`.
        let mut caps: Self = unsafe { std::mem::zeroed() };

        // Read PCI capability config one by one and set up each of them.
        let mut pos: u8 = config.read_config(CAPABILITY_LIST_HEAD_OFFSET as u32);
        while pos != 0 {
            let cfg: [u8; 2] = config.read_config(pos.into());
            let (cap_id, cap_next) = (cfg[0], cfg[1]);

            if cap_id == PciCapabilityID::Msix as u8 {
                let cap = config.read_config::<MsixCap>(pos.into());
                // According to PCI 3.0 specification section 6.8.2.3 ("Message Control for MSI-X"),
                // MSI-X Table Size N, which is encoded as N-1.
                caps.msix_table_size = cap.msg_ctl().get_table_size() + 1;
            }

            if cap_id != PciCapabilityID::VendorSpecific as u8 {
                pos = cap_next;
                continue;
            }

            let cap: VirtioPciCap = config.read_config(pos.into());

            let cfg = PciCapabilityType::n(cap.cfg_type)
                .ok_or_else(|| anyhow!("invalid cfg_type: {}", cap.cfg_type))?;
            match cfg {
                PciCapabilityType::CommonConfig => {
                    caps.common_cfg_addr = get_pci_cap_addr(&cap)?;
                }
                PciCapabilityType::NotifyConfig => {
                    caps.notify_off_multiplier =
                        config.read_config(pos as u32 + std::mem::size_of::<VirtioPciCap>() as u32);
                    caps.notify_base_addr = get_pci_cap_addr(&cap)?;
                }
                PciCapabilityType::IsrConfig => {
                    caps.isr_addr = get_pci_cap_addr(&cap)?;
                }
                PciCapabilityType::DeviceConfig => {
                    caps.dev_cfg_addr = get_pci_cap_addr(&cap)?;
                }
                PciCapabilityType::PciConfig => {
                    // do nothing
                }
                PciCapabilityType::DoorbellConfig => {
                    caps.doorbell_off_multiplier =
                        config.read_config(pos as u32 + std::mem::size_of::<VirtioPciCap>() as u32);
                    caps.doorbell_base_addr = get_pci_cap_addr(&cap)?;
                }
                PciCapabilityType::NotificationConfig => {
                    caps.notify_cfg_addr = get_pci_cap_addr(&cap)?;
                }
                PciCapabilityType::SharedMemoryConfig => {
                    caps.shared_mem_cfg_addr = get_pci_cap_addr(&cap)?;
                }
            }

            pos = cap.cap_next;
        }

        Ok(caps)
    }

    pub fn doorbell_off_multiplier(&self) -> u32 {
        self.doorbell_off_multiplier
    }

    pub fn doorbell_base_addr(&self) -> &VfioRegionAddr {
        &self.doorbell_base_addr
    }

    pub fn shared_mem_cfg_addr(&self) -> &VfioRegionAddr {
        &self.shared_mem_cfg_addr
    }
}

macro_rules! write_common_cfg_field {
    ($device:expr, $field:ident, $val:expr) => {
        $device.vfio_dev.region_write_to_addr(
            &$val,
            &$device.caps.common_cfg_addr,
            offset_of!(virtio_pci_common_cfg, $field) as u64,
        )
    };
}

macro_rules! read_common_cfg_field {
    ($device:expr,  $field:ident) => {
        $device.vfio_dev.region_read_from_addr(
            &$device.caps.common_cfg_addr,
            offset_of!(virtio_pci_common_cfg, $field) as u64,
        )
    };
}

macro_rules! write_notify_cfg_field {
    ($device:expr, $mmap:expr, $field:ident, $val:expr) => {
        $mmap.write_obj_volatile(
            $val,
            $device.caps.notify_cfg_addr.addr as usize
                + offset_of!(virtio_pci_notification_cfg, $field),
        )
    };
}

macro_rules! read_notify_cfg_field {
    ($device:expr, $mmap:expr, $field:ident) => {
        $mmap.read_obj_volatile(
            $device.caps.notify_cfg_addr.addr as usize
                + offset_of!(virtio_pci_notification_cfg, $field),
        )
    };
}

/// A VVU notification resource which works as an interrupt for a virtqueue.
pub struct QueueNotifier {
    addr: u64,
    mmap: MemoryMapping,
}

impl QueueNotifier {
    /// Initialize a new QueueNotifier structure given the queue index, the vfio
    /// device, and the VvuPciCaps.
    pub fn new(
        queue_type: QueueType,
        device: &Arc<VfioDevice>,
        caps: &VvuPciCaps,
    ) -> Result<QueueNotifier> {
        let addr =
            caps.notify_base_addr.addr + (queue_type as u64 * caps.notify_off_multiplier as u64);
        let mmap_region = device.get_region_mmap(caps.notify_base_addr.index);
        let region_offset = device.get_region_offset(caps.notify_base_addr.index);
        let offset = region_offset + mmap_region[0].offset;

        let mmap = MemoryMappingBuilder::new(mmap_region[0].size as usize)
            .from_file(device.device_file())
            .offset(offset)
            .build()?;

        Ok(QueueNotifier { addr, mmap })
    }

    pub fn notify(&self) {
        // It's okay to not handle a failure here because if this fails we cannot recover
        // anyway. The mmap address should be correct as initialized in the 'new()' function
        // according to the given vfio device.
        self.mmap
            .write_obj_volatile(0_u8, self.addr as usize)
            .expect("unable to write to mmap area");
    }
}

pub struct VvuPciDevice {
    pub vfio_dev: Arc<VfioDevice>,
    pub caps: VvuPciCaps,
    pub queues: Vec<UserQueue>,
    pub queue_notifiers: Vec<QueueNotifier>,
    pub irqs: Vec<Event>,
    pub notification_evts: Vec<Event>,
}

#[derive(Debug, Clone, Copy)]
pub enum QueueType {
    Rx = 0, // the integer represents the queue index.
    Tx = 1,
}

impl VvuPciDevice {
    /// Creates a driver for virtio-vhost-user PCI device from a PCI address.
    ///
    /// # Arguments
    ///
    /// * `pci_id` - PCI device ID such as `"0000:00:05.0"`. An error will be returned if this is
    /// not a valid PCI device ID string.
    /// * `device_vq_num` - number of virtqueues that the device backend (e.g. block) may use.
    pub fn new(pci_id: &str, device_vq_num: usize) -> Result<Self> {
        Self::new_from_address(
            PciAddress::from_str(pci_id).context("failed to parse PCI address")?,
            device_vq_num,
        )
    }

    /// Creates a driver for virtio-vhost-user PCI device from a string containing a PCI address.
    ///
    /// # Arguments
    ///
    /// * `pci_address` - PCI device address.
    /// * `device_vq_num` - number of virtqueues that the device backend (e.g. block) may use.
    pub fn new_from_address(pci_address: PciAddress, device_vq_num: usize) -> Result<Self> {
        let vfio_path = format!("/sys/bus/pci/devices/{}", pci_address);
        let vfio_dev = Arc::new(open_vfio_device(&vfio_path)?);
        let config = VfioPciConfig::new(vfio_dev.clone());
        let caps = VvuPciCaps::new(&config)?;

        let page_mask = vfio_dev
            .vfio_get_iommu_page_size_mask()
            .context("failed to get iommu page size mask")?;
        if page_mask & (base::pagesize() as u64) == 0 {
            bail!("Unsupported iommu page mask {:x}", page_mask);
        }

        let mut pci_dev = Self {
            vfio_dev,
            caps,
            queues: vec![],
            queue_notifiers: vec![],
            irqs: vec![],
            notification_evts: vec![],
        };

        config.set_bus_master();
        pci_dev.init(device_vq_num)?;

        Ok(pci_dev)
    }

    fn set_status(&self, status: u8) {
        let new_status = if status == VIRTIO_CONFIG_STATUS_RESET {
            VIRTIO_CONFIG_STATUS_RESET
        } else {
            let cur_status: u8 = read_common_cfg_field!(self, device_status);
            status | cur_status
        };

        write_common_cfg_field!(self, device_status, new_status);
    }

    fn get_device_feature(&self) -> u64 {
        write_common_cfg_field!(self, device_feature_select, 0);
        let lower: u32 = read_common_cfg_field!(self, device_feature);
        write_common_cfg_field!(self, device_feature_select, 1);
        let upper: u32 = read_common_cfg_field!(self, device_feature);

        lower as u64 | ((upper as u64) << 32)
    }

    fn set_guest_feature(&self, features: u64) {
        let lower: u32 = (features & (u32::MAX as u64)) as u32;
        let upper: u32 = (features >> 32) as u32;
        write_common_cfg_field!(self, guest_feature_select, 0);
        write_common_cfg_field!(self, guest_feature, lower);
        write_common_cfg_field!(self, guest_feature_select, 1);
        write_common_cfg_field!(self, guest_feature, upper);
    }

    /// Creates the VVU's virtqueue (i.e. rxq or txq).
    fn create_queue(&self, typ: QueueType) -> Result<(UserQueue, QueueNotifier)> {
        write_common_cfg_field!(self, queue_select, typ as u16);

        let queue_size: u16 = read_common_cfg_field!(self, queue_size);
        if queue_size == 0 {
            bail!("queue_size for {:?} queue is 0", typ);
        }

        let device_writable = match typ {
            QueueType::Rx => true,
            QueueType::Tx => false,
        };
        let queue = UserQueue::new(queue_size, device_writable, typ as u8, self)?;
        let DescTableAddrs { desc, avail, used } = queue.desc_table_addrs()?;

        let desc_lo = (desc & 0xffffffff) as u32;
        let desc_hi = (desc >> 32) as u32;
        write_common_cfg_field!(self, queue_desc_lo, desc_lo);
        write_common_cfg_field!(self, queue_desc_hi, desc_hi);

        let avail_lo = (avail & 0xffffffff) as u32;
        let avail_hi = (avail >> 32) as u32;
        write_common_cfg_field!(self, queue_avail_lo, avail_lo);
        write_common_cfg_field!(self, queue_avail_hi, avail_hi);

        let used_lo = (used & 0xffffffff) as u32;
        let used_hi = (used >> 32) as u32;
        write_common_cfg_field!(self, queue_used_lo, used_lo);
        write_common_cfg_field!(self, queue_used_hi, used_hi);

        let notify_off: u16 = read_common_cfg_field!(self, queue_notify_off);
        let mut notify_addr = self.caps.notify_base_addr.clone();
        notify_addr.addr += notify_off as u64 * self.caps.notify_off_multiplier as u64;
        let notifier = QueueNotifier::new(typ, &self.vfio_dev, &self.caps)?;

        Ok((queue, notifier))
    }

    /// Creates the VVU's rxq and txq.
    fn create_queues(&self) -> Result<(Vec<UserQueue>, Vec<QueueNotifier>)> {
        let (rxq, rxq_notifier) = self.create_queue(QueueType::Rx)?;
        rxq_notifier.notify();

        let (txq, txq_notifier) = self.create_queue(QueueType::Tx)?;
        txq_notifier.notify();

        Ok((vec![rxq, txq], vec![rxq_notifier, txq_notifier]))
    }

    /// Creates two sets of interrupts events; ones for the VVU virtqueues (i.e. rxq and txq) and
    /// ones for the device virtqueues.
    ///
    /// # Arguments
    /// * `device_vq_num` - the number of queues for the device.
    fn create_irqs(&self, device_vq_num: usize) -> Result<(Vec<Event>, Vec<Event>)> {
        const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

        // Sets msix_config
        write_common_cfg_field!(self, msix_config, 0u16);
        let v: u16 = read_common_cfg_field!(self, msix_config);
        if v == VIRTIO_MSI_NO_VECTOR {
            bail!("failed to set config vector: {}", v);
        }

        // Creates events for the interrupts of vvu's rxq and txq.
        let vvu_irqs = vec![
            Event::new().context("failed to create event")?,
            Event::new().context("failed to create event")?,
        ];

        // Create events for the device virtqueue interrupts.
        let mut notification_evts = Vec::with_capacity(device_vq_num);
        for _ in 0..device_vq_num {
            notification_evts.push(Event::new().context("failed to create event")?);
        }

        let msix_num = 2 + device_vq_num;
        if msix_num > usize::from(self.caps.msix_table_size) {
            bail!(
                "{} MSI-X vector is required but only {} are available.",
                msix_num,
                self.caps.msix_table_size
            );
        }

        let mut msix_vec = Vec::with_capacity(msix_num);
        msix_vec.push(Some(&vvu_irqs[0]));
        msix_vec.push(Some(&vvu_irqs[1]));
        msix_vec.extend(notification_evts.iter().take(device_vq_num).map(Some));

        self.vfio_dev
            .irq_enable(&msix_vec, VFIO_PCI_MSIX_IRQ_INDEX, 0)
            .map_err(|e| anyhow!("failed to enable irq: {}", e))?;

        // Registers VVU virtqueue's irqs by writing `queue_msix_vector`.
        for index in 0..self.queues.len() {
            write_common_cfg_field!(self, queue_select, index as u16);
            write_common_cfg_field!(self, queue_msix_vector, index as u16);
            let v: u16 = read_common_cfg_field!(self, queue_msix_vector);
            if v == VIRTIO_MSI_NO_VECTOR {
                bail!("failed to set vector {} to {}-th vvu virtqueue", v, index);
            }
        }

        let mmap_region = self
            .vfio_dev
            .get_region_mmap(self.caps.notify_cfg_addr.index);
        let region_offset = self
            .vfio_dev
            .get_region_offset(self.caps.notify_cfg_addr.index);
        let offset = region_offset + mmap_region[0].offset;

        let mmap = MemoryMappingBuilder::new(mmap_region[0].size as usize)
            .from_file(self.vfio_dev.device_file())
            .offset(offset)
            .build()?;

        // Registers the device virtqueus's irqs by writing `notification_msix_vector`.
        for i in 0..device_vq_num as u16 {
            let msix_vector = self.queues.len() as u16 + i;

            write_notify_cfg_field!(self, mmap, notification_select, i)
                .expect("failed to write select");
            let select: u16 = read_notify_cfg_field!(self, mmap, notification_select)
                .expect("failed to verify select");
            if select != i {
                bail!("failed to select {}-th notification", i);
            }

            write_notify_cfg_field!(self, mmap, notification_msix_vector, msix_vector)
                .expect("failed to write vector");
            let vector: u16 = read_notify_cfg_field!(self, mmap, notification_msix_vector)
                .expect("failed to verify vector");
            if msix_vector != vector {
                bail!(
                    "failed to set vector {} to {}-th notification",
                    msix_vector,
                    i
                );
            }
        }

        Ok((vvu_irqs, notification_evts))
    }

    fn init(&mut self, device_vq_num: usize) -> Result<()> {
        self.set_status(VIRTIO_CONFIG_STATUS_RESET);
        // Wait until reset is done with timeout.
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let cur_status: u8 = read_common_cfg_field!(self, device_status);
            if cur_status == 0 {
                break;
            }
            if Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            } else {
                bail!("device initialization didn't finish within the time limit");
            }
        }

        self.set_status(
            (virtio_config::VIRTIO_CONFIG_S_ACKNOWLEDGE | virtio_config::VIRTIO_CONFIG_S_DRIVER)
                as u8,
        );

        // TODO(b/207364742): Support VIRTIO_RING_F_EVENT_IDX.
        let required_features = 1u64 << VIRTIO_F_VERSION_1;
        let enabled_features = self.get_device_feature();
        if (required_features & enabled_features) != required_features {
            bail!(
                "required feature set is 0x{:x} but 0x{:x} is enabled",
                required_features,
                enabled_features
            );
        };
        self.set_guest_feature(required_features);
        self.set_status(virtio_config::VIRTIO_CONFIG_S_FEATURES_OK as u8);

        // Initialize Virtqueues
        let (queues, queue_notifiers) = self.create_queues()?;
        self.queues = queues;
        self.queue_notifiers = queue_notifiers;

        let (irqs, notification_evts) = self.create_irqs(device_vq_num)?;
        self.irqs = irqs;
        self.notification_evts = notification_evts;

        // Enable Virtqueues
        for index in 0..self.queues.len() {
            write_common_cfg_field!(self, queue_select, index as u16);
            write_common_cfg_field!(self, queue_enable, 1_u16);
        }

        self.set_status(virtio_config::VIRTIO_CONFIG_S_DRIVER_OK as u8);

        Ok(())
    }

    pub fn start(&self) -> Result<()> {
        const STATUS_OFFSET: u64 = 0;
        const VIRTIO_VHOST_USER_STATUS_SLAVE_UP: usize = 0;
        let mut status: u32 = self
            .vfio_dev
            .region_read_from_addr(&self.caps.dev_cfg_addr, STATUS_OFFSET);

        status |= 1u32 << VIRTIO_VHOST_USER_STATUS_SLAVE_UP;

        self.vfio_dev
            .region_write_to_addr(&status, &self.caps.dev_cfg_addr, STATUS_OFFSET);

        info!("vvu device started");
        Ok(())
    }
}

impl IovaAllocator for VvuPciDevice {
    fn alloc_iova(&self, size: u64, tag: u8) -> Result<u64> {
        self.vfio_dev
            .alloc_iova(size, base::pagesize() as u64, Alloc::VvuQueue(tag))
            .context("failed to find an iova region to map the gpa region to")
    }

    unsafe fn map_iova(&self, iova: u64, size: u64, addr: *const u8) -> Result<()> {
        self.vfio_dev
            .vfio_dma_map(iova, size, addr as u64, true)
            .context("failed to map iova")
    }
}
