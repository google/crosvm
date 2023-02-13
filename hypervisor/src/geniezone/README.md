# MTK GenieZone Hypervisor

GenieZone is a type-1 hypervisor designed for MTK proprietary ARM-based SoC.

By trapping high-level exceptions and isolated memory acess segment from various OS, the GenieZone
hypervisor increases the security of the system, and prevents possible attacks from compromised
guest OS.

## Current Features

- Implement GenieZone hypervisor
- Implement GenieZone’s irqchip
- Create config and feature for GenieZone
- Probe proper hypervisor backend with naive logic
- Inject virtual interrupts
- Bootup guest VM with linux kernel to shell

## Backlogs

- Integrate with protected VM and pvmfw
- Support multi-core VM
