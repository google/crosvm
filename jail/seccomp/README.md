# Policy files for crosvm

This folder holds the seccomp policies for crosvm devices, organized by architecture.

Each crosvm device can run within its owned jailed process. A jailed process is only able to perform
the system calls specified in the seccomp policy file the jail has been created with, which improves
security as a rogue process cannot perform any system call it wants.

Each device can run from different contexts, which require a different set of authorized system
calls. This file explains how the policy files are named in order to allow these various scenario.

## Naming conventions

Since Minijail only allows for one level of policy inclusion, we need to be a little bit creative in
order to minimize policy duplication.

- `common_device.policy` contains a set of syscalls that are common to all devices, and is never
  loaded directly - only included from other policy files.
- `foo.policy` contains the set of syscalls that device `foo` is susceptible to use, regardless of
  the underlying virtio transport. This policy is also never loaded directly.
- `foo_device.policy` is the policy that is loaded when device `foo` is used as an in-VMM (i.e.
  regular virtio) device. It will generally simply include `common_device.policy` as well as
  `foo.policy`.

When using vhost-user, the virtio protocol needs to be sent over a different medium, e.g. a Unix
socket. Supporting this transport requires some extra system calls after the device is jailed, and
thus dedicated policies:

- `vhost_user.policy` contains the set of syscalls required by the regular (i.e. socket-based)
  vhost-user listener. It is never loaded directly.
- `vvu.policy` contains the set of syscalls required by the VFIO-based vhost-user (aka
  Virtio-Vhost-User) listener. It is also never loaded directly.
- `foo_device_vhost_user.policy` is the policy that is loaded when device `foo` is used as a regular
  vhost-user device. It will generally include `common_device.policy`, `vhost_user.policy` and
  `foo.policy`.
- `foo_device_vvu.policy` is the policy that is loaded when device `foo` is used as a VVU device. It
  will generally include `common_device.policy`, `vvu.policy` and `foo.policy`.
