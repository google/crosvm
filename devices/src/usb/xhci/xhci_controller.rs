// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use base::error;
use base::AsRawDescriptor;
use base::RawDescriptor;
use resources::Alloc;
use resources::AllocOptions;
use resources::SystemAllocator;
use vm_memory::GuestMemory;

use crate::pci::BarRange;
use crate::pci::PciAddress;
use crate::pci::PciBarConfiguration;
use crate::pci::PciBarPrefetchable;
use crate::pci::PciBarRegionType;
use crate::pci::PciClassCode;
use crate::pci::PciConfiguration;
use crate::pci::PciDevice;
use crate::pci::PciDeviceError;
use crate::pci::PciHeaderType;
use crate::pci::PciInterruptPin;
use crate::pci::PciProgrammingInterface;
use crate::pci::PciSerialBusSubClass;
use crate::register_space::Register;
use crate::register_space::RegisterSpace;
use crate::usb::xhci::xhci_backend_device_provider::XhciBackendDeviceProvider;
use crate::usb::xhci::xhci_regs::init_xhci_mmio_space_and_regs;
use crate::usb::xhci::xhci_regs::XhciRegs;
use crate::usb::xhci::Xhci;
use crate::utils::FailHandle;
use crate::IrqLevelEvent;
use crate::Suspendable;

const XHCI_BAR0_SIZE: u64 = 0x10000;

#[derive(Clone, Copy)]
enum UsbControllerProgrammingInterface {
    Usb3HostController = 0x30,
}

impl PciProgrammingInterface for UsbControllerProgrammingInterface {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Use this handle to fail xhci controller.
pub struct XhciFailHandle {
    usbcmd: Register<u32>,
    usbsts: Register<u32>,
    xhci_failed: AtomicBool,
}

impl XhciFailHandle {
    pub fn new(regs: &XhciRegs) -> XhciFailHandle {
        XhciFailHandle {
            usbcmd: regs.usbcmd.clone(),
            usbsts: regs.usbsts.clone(),
            xhci_failed: AtomicBool::new(false),
        }
    }
}

impl FailHandle for XhciFailHandle {
    /// Fail this controller. Will set related registers and flip failed bool.
    fn fail(&self) {
        // set run/stop to stop.
        const USBCMD_STOPPED: u32 = 0;
        // Set host system error bit.
        const USBSTS_HSE: u32 = 1 << 2;
        self.usbcmd.set_value(USBCMD_STOPPED);
        self.usbsts.set_value(USBSTS_HSE);

        self.xhci_failed.store(true, Ordering::SeqCst);
        error!("xhci controller stopped working");
    }

    /// Returns true if xhci is already failed.
    fn failed(&self) -> bool {
        self.xhci_failed.load(Ordering::SeqCst)
    }
}

// Xhci controller should be created with backend device provider. Then irq should be assigned
// before initialized. We are not making `failed` as a state here to optimize performance. Cause we
// need to set failed in other threads.
enum XhciControllerState {
    Unknown,
    Created {
        device_provider: Box<dyn XhciBackendDeviceProvider>,
    },
    IrqAssigned {
        device_provider: Box<dyn XhciBackendDeviceProvider>,
        irq_evt: IrqLevelEvent,
    },
    Initialized {
        mmio: RegisterSpace,
        // Xhci init could fail.
        #[allow(dead_code)]
        xhci: Option<Arc<Xhci>>,
        fail_handle: Arc<dyn FailHandle>,
    },
}

/// xHCI PCI interface implementation.
pub struct XhciController {
    config_regs: PciConfiguration,
    pci_address: Option<PciAddress>,
    mem: GuestMemory,
    state: XhciControllerState,
}

impl XhciController {
    /// Create new xhci controller.
    pub fn new(mem: GuestMemory, usb_provider: Box<dyn XhciBackendDeviceProvider>) -> Self {
        let config_regs = PciConfiguration::new(
            0x01b73, // fresco logic, (google = 0x1ae0)
            0x1400,  // fresco logic fl1400. This chip has broken msi. See kernel xhci-pci.c
            PciClassCode::SerialBusController,
            &PciSerialBusSubClass::Usb,
            Some(&UsbControllerProgrammingInterface::Usb3HostController),
            PciHeaderType::Device,
            0,
            0,
            0,
        );
        XhciController {
            config_regs,
            pci_address: None,
            mem,
            state: XhciControllerState::Created {
                device_provider: usb_provider,
            },
        }
    }

    /// Init xhci controller when it's forked.
    pub fn init_when_forked(&mut self) {
        match mem::replace(&mut self.state, XhciControllerState::Unknown) {
            XhciControllerState::IrqAssigned {
                device_provider,
                irq_evt,
            } => {
                let (mmio, regs) = init_xhci_mmio_space_and_regs();
                let fail_handle: Arc<dyn FailHandle> = Arc::new(XhciFailHandle::new(&regs));
                let xhci = match Xhci::new(
                    fail_handle.clone(),
                    self.mem.clone(),
                    device_provider,
                    irq_evt,
                    regs,
                ) {
                    Ok(xhci) => Some(xhci),
                    Err(_) => {
                        error!("fail to init xhci");
                        fail_handle.fail();
                        return;
                    }
                };

                self.state = XhciControllerState::Initialized {
                    mmio,
                    xhci,
                    fail_handle,
                }
            }
            _ => {
                error!("xhci controller is in a wrong state");
            }
        }
    }
}

impl PciDevice for XhciController {
    fn debug_label(&self) -> String {
        "xhci controller".to_owned()
    }

    fn allocate_address(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> Result<PciAddress, PciDeviceError> {
        if self.pci_address.is_none() {
            self.pci_address = match resources.allocate_pci(0, self.debug_label()) {
                Some(Alloc::PciBar {
                    bus,
                    dev,
                    func,
                    bar: _,
                }) => Some(PciAddress { bus, dev, func }),
                _ => None,
            }
        }
        self.pci_address.ok_or(PciDeviceError::PciAllocationFailed)
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        match &self.state {
            XhciControllerState::Created { device_provider } => device_provider.keep_rds(),
            XhciControllerState::IrqAssigned {
                device_provider,
                irq_evt,
            } => {
                let mut keep_rds = device_provider.keep_rds();
                keep_rds.push(irq_evt.get_trigger().as_raw_descriptor());
                keep_rds.push(irq_evt.get_resample().as_raw_descriptor());
                keep_rds
            }
            _ => {
                error!("xhci controller is in a wrong state");
                vec![]
            }
        }
    }

    fn assign_irq(&mut self, irq_evt: IrqLevelEvent, pin: PciInterruptPin, irq_num: u32) {
        match mem::replace(&mut self.state, XhciControllerState::Unknown) {
            XhciControllerState::Created { device_provider } => {
                self.config_regs.set_irq(irq_num as u8, pin);
                self.state = XhciControllerState::IrqAssigned {
                    device_provider,
                    irq_evt,
                }
            }
            _ => {
                error!("xhci controller is in a wrong state");
            }
        }
    }

    fn allocate_io_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<Vec<BarRange>, PciDeviceError> {
        let address = self
            .pci_address
            .expect("assign_address must be called prior to allocate_io_bars");
        // xHCI spec 5.2.1.
        let bar0_addr = resources
            .allocate_mmio(
                XHCI_BAR0_SIZE,
                Alloc::PciBar {
                    bus: address.bus,
                    dev: address.dev,
                    func: address.func,
                    bar: 0,
                },
                "xhci_bar0".to_string(),
                AllocOptions::new()
                    .max_address(u32::MAX.into())
                    .align(XHCI_BAR0_SIZE),
            )
            .map_err(|e| PciDeviceError::IoAllocationFailed(XHCI_BAR0_SIZE, e))?;
        let bar0_config = PciBarConfiguration::new(
            0,
            XHCI_BAR0_SIZE,
            PciBarRegionType::Memory32BitRegion,
            PciBarPrefetchable::NotPrefetchable,
        )
        .set_address(bar0_addr);
        self.config_regs
            .add_pci_bar(bar0_config)
            .map_err(|e| PciDeviceError::IoRegistrationFailed(bar0_addr, e))?;
        Ok(vec![BarRange {
            addr: bar0_addr,
            size: XHCI_BAR0_SIZE,
            prefetchable: false,
        }])
    }

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        self.config_regs.get_bar_configuration(bar_num)
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        self.config_regs.read_reg(reg_idx)
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        self.config_regs.write_reg(reg_idx, offset, data)
    }

    fn read_bar(&mut self, bar_index: usize, offset: u64, data: &mut [u8]) {
        if bar_index != 0 {
            return;
        }

        match &self.state {
            XhciControllerState::Initialized { mmio, .. } => {
                // Read bar would still work even if it's already failed.
                mmio.read(offset, data);
            }
            _ => {
                error!("xhci controller is in a wrong state");
            }
        }
    }

    fn write_bar(&mut self, bar_index: usize, offset: u64, data: &[u8]) {
        if bar_index != 0 {
            return;
        }

        match &self.state {
            XhciControllerState::Initialized {
                mmio, fail_handle, ..
            } => {
                if !fail_handle.failed() {
                    mmio.write(offset, data);
                }
            }
            _ => {
                error!("xhci controller is in a wrong state");
            }
        }
    }

    fn on_device_sandboxed(&mut self) {
        self.init_when_forked();
    }
}

impl Suspendable for XhciController {}
