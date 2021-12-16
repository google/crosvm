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
pub use crate::plat::*;
pub use crate::vfio::*;

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
