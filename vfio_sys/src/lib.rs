// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux VFIO (Virtual Function I/O) bindings.
//!
//! <https://www.kernel.org/doc/html/latest/driver-api/vfio.html>

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use base::ioctl_io_nr;

pub mod plat;
pub mod vfio;

use crate::plat::ACPI_EVT_FORWARD_BASE;
use crate::plat::PLAT_IRQ_FORWARD_BASE;
use crate::plat::PLAT_IRQ_FORWARD_TYPE;
pub use crate::vfio::vfio_device_feature;
pub use crate::vfio::vfio_device_info;
pub use crate::vfio::vfio_device_low_power_entry_with_wakeup;
pub use crate::vfio::vfio_group_status;
pub use crate::vfio::vfio_info_cap_header;
pub use crate::vfio::vfio_iommu_type1_dma_map;
pub use crate::vfio::vfio_iommu_type1_dma_unmap;
pub use crate::vfio::vfio_iommu_type1_info;
pub use crate::vfio::vfio_iommu_type1_info_cap_iova_range;
pub use crate::vfio::vfio_iommu_type1_info_cap_iova_range_header;
pub use crate::vfio::vfio_iova_range;
pub use crate::vfio::vfio_irq_info;
pub use crate::vfio::vfio_irq_set;
pub use crate::vfio::vfio_region_info;
pub use crate::vfio::vfio_region_info_cap_sparse_mmap;
pub use crate::vfio::vfio_region_info_cap_type;
pub use crate::vfio::vfio_region_info_with_cap;
pub use crate::vfio::vfio_region_sparse_mmap_area;
pub use crate::vfio::VFIO_TYPE1v2_IOMMU;
use crate::vfio::VFIO_BASE;
pub use crate::vfio::VFIO_DEVICE_FEATURE_LOW_POWER_ENTRY;
pub use crate::vfio::VFIO_DEVICE_FEATURE_LOW_POWER_ENTRY_WITH_WAKEUP;
pub use crate::vfio::VFIO_DEVICE_FEATURE_LOW_POWER_EXIT;
pub use crate::vfio::VFIO_DEVICE_FEATURE_SET;
pub use crate::vfio::VFIO_DEVICE_FLAGS_PCI;
pub use crate::vfio::VFIO_DEVICE_FLAGS_PLATFORM;
pub use crate::vfio::VFIO_DMA_MAP_FLAG_READ;
pub use crate::vfio::VFIO_DMA_MAP_FLAG_WRITE;
pub use crate::vfio::VFIO_GROUP_FLAGS_VIABLE;
pub use crate::vfio::VFIO_IOMMU_INFO_CAPS;
pub use crate::vfio::VFIO_IOMMU_INFO_PGSIZES;
pub use crate::vfio::VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE;
pub use crate::vfio::VFIO_IRQ_INFO_AUTOMASKED;
pub use crate::vfio::VFIO_IRQ_SET_ACTION_MASK;
pub use crate::vfio::VFIO_IRQ_SET_ACTION_TRIGGER;
pub use crate::vfio::VFIO_IRQ_SET_ACTION_UNMASK;
pub use crate::vfio::VFIO_IRQ_SET_DATA_EVENTFD;
pub use crate::vfio::VFIO_IRQ_SET_DATA_NONE;
pub use crate::vfio::VFIO_PCI_BAR0_REGION_INDEX;
pub use crate::vfio::VFIO_PCI_CONFIG_REGION_INDEX;
pub use crate::vfio::VFIO_PCI_INTX_IRQ_INDEX;
pub use crate::vfio::VFIO_PCI_MSIX_IRQ_INDEX;
pub use crate::vfio::VFIO_PCI_MSI_IRQ_INDEX;
pub use crate::vfio::VFIO_PCI_REQ_IRQ_INDEX;
pub use crate::vfio::VFIO_PCI_ROM_REGION_INDEX;
pub use crate::vfio::VFIO_REGION_INFO_CAP_MSIX_MAPPABLE;
pub use crate::vfio::VFIO_REGION_INFO_CAP_SPARSE_MMAP;
pub use crate::vfio::VFIO_REGION_INFO_CAP_TYPE;
pub use crate::vfio::VFIO_REGION_INFO_FLAG_CAPS;
pub use crate::vfio::VFIO_REGION_INFO_FLAG_MMAP;
pub use crate::vfio::VFIO_REGION_INFO_FLAG_WRITE;
pub use crate::vfio::VFIO_REGION_SUBTYPE_INTEL_IGD_OPREGION;
pub use crate::vfio::VFIO_REGION_TYPE_PCI_VENDOR_TYPE;
use crate::vfio::VFIO_TYPE;

ioctl_io_nr!(VFIO_GET_API_VERSION, VFIO_TYPE, VFIO_BASE);
ioctl_io_nr!(VFIO_CHECK_EXTENSION, VFIO_TYPE, VFIO_BASE + 1);
ioctl_io_nr!(VFIO_SET_IOMMU, VFIO_TYPE, VFIO_BASE + 2);
ioctl_io_nr!(VFIO_GROUP_GET_STATUS, VFIO_TYPE, VFIO_BASE + 3);
ioctl_io_nr!(VFIO_GROUP_SET_CONTAINER, VFIO_TYPE, VFIO_BASE + 4);
ioctl_io_nr!(VFIO_GROUP_UNSET_CONTAINER, VFIO_TYPE, VFIO_BASE + 5);
ioctl_io_nr!(VFIO_GROUP_GET_DEVICE_FD, VFIO_TYPE, VFIO_BASE + 6);
ioctl_io_nr!(VFIO_DEVICE_GET_INFO, VFIO_TYPE, VFIO_BASE + 7);
ioctl_io_nr!(VFIO_DEVICE_GET_REGION_INFO, VFIO_TYPE, VFIO_BASE + 8);
ioctl_io_nr!(VFIO_DEVICE_GET_IRQ_INFO, VFIO_TYPE, VFIO_BASE + 9);
ioctl_io_nr!(VFIO_DEVICE_SET_IRQS, VFIO_TYPE, VFIO_BASE + 10);
ioctl_io_nr!(VFIO_DEVICE_RESET, VFIO_TYPE, VFIO_BASE + 11);
ioctl_io_nr!(
    VFIO_DEVICE_GET_PCI_HOT_RESET_INFO,
    VFIO_TYPE,
    VFIO_BASE + 12
);
ioctl_io_nr!(VFIO_DEVICE_PCI_HOT_RESET, VFIO_TYPE, VFIO_BASE + 13);
ioctl_io_nr!(VFIO_DEVICE_QUERY_GFX_PLANE, VFIO_TYPE, VFIO_BASE + 14);
ioctl_io_nr!(VFIO_DEVICE_GET_GFX_DMABUF, VFIO_TYPE, VFIO_BASE + 15);
ioctl_io_nr!(VFIO_DEVICE_IOEVENTFD, VFIO_TYPE, VFIO_BASE + 16);
ioctl_io_nr!(VFIO_IOMMU_GET_INFO, VFIO_TYPE, VFIO_BASE + 12);
ioctl_io_nr!(VFIO_IOMMU_MAP_DMA, VFIO_TYPE, VFIO_BASE + 13);
ioctl_io_nr!(VFIO_IOMMU_UNMAP_DMA, VFIO_TYPE, VFIO_BASE + 14);
ioctl_io_nr!(VFIO_IOMMU_ENABLE, VFIO_TYPE, VFIO_BASE + 15);
ioctl_io_nr!(VFIO_IOMMU_DISABLE, VFIO_TYPE, VFIO_BASE + 16);
ioctl_io_nr!(VFIO_DEVICE_FEATURE, VFIO_TYPE, VFIO_BASE + 17);
ioctl_io_nr!(VFIO_DEVICE_ACPI_DSM, VFIO_TYPE, VFIO_BASE + 18);

ioctl_io_nr!(
    PLAT_IRQ_FORWARD_SET,
    PLAT_IRQ_FORWARD_TYPE,
    PLAT_IRQ_FORWARD_BASE
);

ioctl_io_nr!(
    ACPI_EVT_FORWARD_SET,
    PLAT_IRQ_FORWARD_TYPE,
    ACPI_EVT_FORWARD_BASE
);
