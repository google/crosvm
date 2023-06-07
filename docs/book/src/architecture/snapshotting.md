# Architecture: Snapshotting

Snapshotting is a **highly experimental** `x86_64` only feature currently under development. It is
100% **not supported** and only supports a very limited set of devices. This page roughly summarizes
how the system works, and how device authors should think about it when writing new devices.

## The snapshot & restore sequence

The data required for a snapshot is stored in several places, including guest memory, and the
devices running on the host. To take an accurate snapshot, we need a point in time snapshot. Since
there is no way to fetch this state atomically, we have to freeze the guest (VCPUs) and the device
backends. Similarly, on restore we must freeze in the same way to prevent partially restored state
from being modified.

## Snapshotting a running VM

In code, this is implemented by
[vm_control::do_snapshot](https://crosvm.dev/doc/vm_control/fn.do_snapshot.html). We always freeze
the VCPUs first
([vm_control::VcpuSuspendGuard](https://crosvm.dev/doc/vm_control/struct.VcpuSuspendGuard.html)).
This is done so that we can flush all pending interrupts to the irqchip (LAPIC) without triggering
further activity from the driver (which could in turn trigger more device activity). With the VCPUs
frozen, we freeze devices
([vm_control::DeviceSleepGuard](https://crosvm.dev/doc/vm_control/struct.DeviceSleepGuard.html)).
From here, it's a just a matter of serializing VCPU state, guest memory, and device state.

### A word about interrupts

Interrupts come in two primary flavors from the snapshotting perspective: legacy interrupts (e.g.
IOAPIC interrupt lines), and MSIs.

#### Legacy interrupts

These are a little tricky because they are allocated as part of device creation, and device creation
happens **before** we snapshot or restore. To avoid actually having to snapshot or restore the
`Event` object wiring for these interrupts, we rely on the fact that as long as the VM is created
with the right shape (e.g. devices), the interrupt `Event`s will be wired between the device & the
irqchip correctly. As part of restoring, we will set the routing table, which ensures that those
events map to the right GSIs in the hypervisor.

#### MSIs

These are much simpler, because of how MSIs are implemented in CrosVM. In `MsixConfig`, we save the
MSI routing information for every IRQ. At restore time, we just register these MSIs with the
hypervisor using the exact same mechanism that would be invoked on device activation (albeit
bypassing GSI allocation since we know from the saved state exactly which GSI must be used).

#### Flushing IRQs to the irqchip

IRQs sometimes pass through multiple host `Event`s before reaching the hypervisor (or VCPU loop) for
injection. Rather than trying to snapshot the `Event` state, we freeze all interrupt sources
(devices) and flush all pending interrupts into the irqchip. This way, snapshotting the irqchip
state is sufficient to capture all pending interrupts.

## Restoring a VM in lieu of booting

Restoring on to a running VM is not supported, and may never be. Our preferred approach is to
instead create a new VM from a snapshot. This is why `vm_control::do_restore` can be invoked as part
of the VM creation process.

## Implications for device authors

New devices SHOULD be compatible with the `devices::Suspendable` trait, but MAY defer actual
implementation to the future. This trait's implementation defines how the device will sleep/wake,
and how its state will be saved & restored as part of snapshotting.

New virtio devices SHOULD implement the virtio device snapshot methods on
[VirtioDevice](https://crosvm.dev/doc/devices/virtio/virtio_device/trait.VirtioDevice.html):
`virtio_sleep`, `virtio_wake`, `virtio_snapshot`, and `virtio_restore`.
