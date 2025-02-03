# Exynos Halla Hypervisor

Halla is a type-1 hypervisor designed for Exynos proprietary ARM-based SoC.

By trapping high-level exceptions and isolated memory access segment from various OS, the Halla
hypervisor increases the security of the system, and prevents possible attacks from compromised
guest OS.

## Current Features

- Implement Halla hypervisor
- Implement Halla’s irqchip
- Create config and feature for Halla
- Probe proper hypervisor backend with naive logic
- Inject virtual interrupts
- Bootup guest VM with linux kernel to shell
- Support multi-core VM

## Backlogs

- Integrate with protected VM and pvmfw
