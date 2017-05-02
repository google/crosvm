# Chrome OS KVM

This component, known as crosvm, runs untrusted operating systems along with
virtualized devices. No actual hardware is emulated. This only runs VMs
through the Linux's KVM interface. What makes crosvm unique is a focus on
safety within the programming language and a sandbox around the virtual
devices to protect the kernel from attack in case of an exploit in the
devices.

## Overview

The crosvm source code is organized into crates, each with their own
unit tests. These crates are:

* `kernel_loader` Loads elf64 kernel files to a slice of memory.
* `kvm_sys` low-level (mostly) auto-generated structures and constants for using KVM
* `kvm` unsafe, low-level wrapper code for using kvm_sys
* `crosvm` the top-level binary front-end for using crosvm
* `x86_64` Support code specific to 64 bit intel machines.

## Usage

Currently there is no front-end, so the best you can do is run `cargo test` in
each crate.
