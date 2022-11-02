// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use hypervisor::kvm::*;
use hypervisor::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[test]
fn set_gsi_routing() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    vm.create_irq_chip().unwrap();
    vm.set_gsi_routing(&[]).unwrap();
    vm.set_gsi_routing(&[IrqRoute {
        gsi: 1,
        source: IrqSource::Irqchip {
            chip: IrqSourceChip::Gic,
            pin: 3,
        },
    }])
    .unwrap();
    vm.set_gsi_routing(&[IrqRoute {
        gsi: 1,
        source: IrqSource::Msi {
            address: 0xf000000,
            data: 0xa0,
        },
    }])
    .unwrap();
    vm.set_gsi_routing(&[
        IrqRoute {
            gsi: 1,
            source: IrqSource::Irqchip {
                chip: IrqSourceChip::Gic,
                pin: 3,
            },
        },
        IrqRoute {
            gsi: 2,
            source: IrqSource::Msi {
                address: 0xf000000,
                data: 0xa0,
            },
        },
    ])
    .unwrap();
}
