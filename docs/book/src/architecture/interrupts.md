# Interrupts (x86_64)

Interrupts are how devices request service from the guest drivers. This page explores the details of
interrupt routing from the perspective of CrosVM.

## Critical acronyms

This subject area uses *a lot* of acronyms:

- IRQ: Interrupt ReQuest
- ISR: Interrupt Service Routine
- EOI: End Of Interrupt
- MSI: message signaled interrupts. In this document, synonymous with MSI-X.
- MSI-X: message signaled interrupts - extended
- LAPIC: local APIC
- APIC: Advanced Programmable Interrupt Controller (successor to the legacy PIC)
- IOAPIC: IO APIC (has physical interrupt lines, which it responds to by triggering an MSI directed
  to the LAPIC).
- PIC: Programmable Interrupt Controller (the "legacy PIC" / Intel 8259 chip).

## Interrupts come in two flavors

Interrupts on `x86_64` in CrosVM come in two primary flavors: legacy and MSI-X. In this document,
MSI is used to refer to the concept of message signaled interrupts, but it always refers to
interrupts sent via MSI-X because that is what CrosVM uses.

### Legacy interrupts (INTx)

These interrupts are traditionally delivered via dedicated signal lines to PICs and/or the IOAPIC.
Older devices, especially those that are used during early boot, often rely on these types of
interrupts. These typically are the first 24 GSIs, and are serviced either by the PIC (during very
early boot), or by the IOAPIC (after it is activated & the PIC is switched off).

#### Background on EOI

The purpose of EOI is rooted in how legacy interrupt lines are shared. If two devices `D1` and `D2`
share a line `L`, `D2` has no guarantee that it will be serviced when `L` is asserted. After
receiving EOI, `D2` has to check whether it was serviced, and if it was not, to re-assert `L`. An
example of how this occurs is if `D2` requests service while `D1` is already being serviced. In that
case, the line has to be reasserted otherwise `D2` won't be serviced.

Because interrupt lines to the IOAPIC can be shared by multiple devices, EOI is critical for devices
to figure out whether they were serviced in response to sending the IRQ, or whether the IRQ needs to
be resent. The operating principles mean that sending extra EOIs to a legacy device is perfectly
safe, because they could be due to another device on the same line receiving service, and so devices
must be tolerant of such "extra" (from their perspective) EOIs.

These "extra" EOIs come from the fact that EOI is often a broadcast message that goes to all legacy
devices. Broadcast is required because interrupt lines can be routed through the two 8259 PICs via
cascade before they reach the CPU, broadcast to both PICs (and attached devices) is the only way to
ensure EOI reaches the device that was serviced.

#### EOI in CrosVM

When the guest's ISR completes and signals EOI, the CrosVM irqchip implementation is responsible for
propagating EOI to the device backends. EOI is delivered to the devices via their
[resample event](https://crosvm.dev/doc/devices/struct.IrqLevelEvent.html). Devices are then
responsible for listening to that resample event, and checking their internal state to see if they
received service. If the device wasn't serviced, it must then reassert the IRQ.

### MSIs

MSIs do not use dedicated signal lines; instead, they are "messages" which are sent on the system
bus. The LAPIC(s) receive these messages, and inject the interrupt into the VCPU (where injection
means: jump to ISR).

#### About EOI

EOI is not meaningful for MSIs because lines are *never* shared. No devices using MSI will listen
for the EOI event, and the irqchip will not signal it.

## The fundamental deception on x86_64: there are no legacy interrupts (usually)

After very early boot, the PIC is switched off and legacy interrupts somewhat cease to be legacy.
Instead of being handled by the PIC, legacy interrupts are handled by the IOAPIC, and all the IOAPIC
does is convert them into MSIs; in other words, from the perspective of CrosVM & the guest VCPUs,
after early boot, every interrupt is a MSI.

## Interrupt handling irqchip specifics

Each `IrqChip` can handle interrupts differently. Often these differences are because the underlying
hypervisors will have different interrupt features such as KVM's irqfds. Generally a hypervisor has
three choices for implementing an irqchip:

- Fully in kernel: all of the irqchip (LAPIC & IOAPIC) are implemented in the kernel portion of the
  hypervisor.
- Split: the performance critical part of the irqchip (LAPIC) is implemented in the kernel, but the
  IOAPIC is implemented by the VMM.
- Userspace: here, the entire irqchip is implemented in the VMM. This is generally slower and not
  commonly used.

Below, we describe the rough flow for interrupts in virtio devices for each of the chip types. We
limit ourselves to virtio devices becauseas these are the performance critical devices in CrosVM.

### Kernel mode IRQ chip (w/ irqfd support)

#### MSIs

1. Device wants service, so it signals an `Event` object.
1. The `Event` object is registered with the hypervisor, so the hypervisor immediately routes the
   IRQ to a LAPIC so a VCPU can be interrupted.
1. The LAPIC interrupts the VCPU, which jumps to the kernel's ISR (interrupt service routine).
1. The ISR runs.

#### Legacy interrupts

These are handled similarly to MSIs, except the kernel mode IOAPIC is what initially picks up the
event, rather than the LAPIC.

### Split IRQ chip (w/ irqfd support)

This is the same as the kernel mode case.

### Split IRQ chip (no irqfd kernel support)

#### MSIs

1. Device wants service, so it signals an `Event` object.
1. The `Event`object is attached to the IrqChip in CrosVM. An interrupt handling thread wakes up
   from the `Event` signal.
1. The IrqChip resets the `Event`.
1. The IrqChip asserts the interrupt to the LAPIC in the kernel via an ioctl (or equivalent).
1. The LAPIC interrupts the VCPU, which jumps to the kernel’s ISR (interrupt service routine).
1. The ISR runs, and on completion sends EOI (end of interrupt). In CrosVM, this is called the
   [resample event](https://crosvm.dev/doc/devices/struct.IrqLevelEvent.html).
1. EOI is sent.

#### Legacy interrupts

This introduces an additional `Event` object in the interrupt path, since the IRQ pin itself is an
`Event`, and the MSI is also an `Event`. These interrupts are processed twice by the IRQ handler:
once as a legacy IOAPIC event, and a second time as an MSI.

### Userspace IRQ chip

This chip is not widely used in production. Contributions to fill in this section are welcome.
