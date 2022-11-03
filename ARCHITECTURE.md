# Architecture

The principle characteristics of crosvm are:

- A process per virtual device, made using fork
- Each process is sandboxed using [minijail]
- Takes full advantage of KVM and low-level Linux syscalls, and so only runs on Linux
- Written in Rust for security and safety

A typical session of crosvm starts in `main.rs` where command line parsing is done to build up a
`Config` structure. The `Config` is used by `run_config` in `linux/mod.rs` to setup and execute a
VM. Broken down into rough steps:

1. Load the linux kernel from an ELF file.
1. Create a handful of control sockets used by the virtual devices.
1. Invoke the architecture specific VM builder `Arch::build_vm` (located in `x86_64/src/lib.rs` or
   `aarch64/src/lib.rs`).
1. `Arch::build_vm` will itself invoke the provided `create_devices` function from `linux/mod.rs`
1. `create_devices` creates every PCI device, including the virtio devices, that were configured in
   `Config`, along with matching [minijail] configs for each.
1. `Arch::assign_pci_addresses` assigns an address to each PCI device, prioritizing devices that
   report a preferred slot by implementing the `PciDevice` trait's `preferred_address` function.
1. `Arch::generate_pci_root`, using a list of every PCI device with optional `Minijail`, will
   finally jail the PCI devices and construct a `PciRoot` that communicates with them.
1. Once the VM has been built, it's contained within a `RunnableLinuxVm` object that is used by the
   VCPUs and control loop to service requests until shutdown.

## Forking

During the device creation routine, each device will be created and then wrapped in a `ProxyDevice`
which will internally `fork` (but not `exec`) and [minijail] the device, while dropping it for the
main process. The only interaction that the device is capable of having with the main process is via
the proxied trait methods of `BusDevice`, shared memory mappings such as the guest memory, and file
descriptors that were specifically allowed by that device's security policy. This can lead to some
surprising behavior to be aware of such as why some file descriptors which were once valid are now
invalid.

## Sandboxing Policy

Every sandbox is made with [minijail] and starts with `create_base_minijail` in
`linux/jail_helpers.rs` which set some very restrictive settings. Linux namespaces and seccomp
filters are used extensively. Each seccomp policy can be found under
`seccomp/{arch}/{device}.policy` and should start by `@include`-ing the `common_device.policy`. With
the exception of architecture specific devices (such as `Pl030` on ARM or `I8042` on x86_64), every
device will need a different policy for each supported architecture.

## The VM Control Sockets

For the operations that devices need to perform on the global VM state, such as mapping into guest
memory address space, there are the vm control sockets. There are a few kinds, split by the type of
request and response that the socket will process. This also proves basic security privilege
separation in case a device becomes compromised by a malicious guest. For example, a rogue device
that is able to allocate MSI routes would not be able to use the same socket to (de)register guest
memory. During the device initialization stage, each device that requires some aspect of VM control
will have a constructor that requires the corresponding control socket. The control socket will get
preserved when the device is sandboxed and the other side of the socket will be waited on in the
main process's control loop.

The socket exposed by crosvm with the `--socket` command line argument is another form of the VM
control socket. Because the protocol of the control socket is internal and unstable, the only
supported way of using that resulting named unix domain socket is via crosvm command line
subcommands such as `crosvm stop`.

## GuestMemory

`GuestMemory` and its friends `VolatileMemory`, `VolatileSlice`, `MemoryMapping`, and
`SharedMemory`, are common types used throughout crosvm to interact with guest memory. Know which
one to use in what place using some guidelines

- `GuestMemory` is for sending around references to all of the guest memory. It can be cloned
  freely, but the underlying guest memory is always the same. Internally, it's implemented using
  `MemoryMapping` and `SharedMemory`. Note that `GuestMemory` is mapped into the host address space
  (for non-protected VMs), but it is non-contiguous. Device memory, such as mapped DMA-Bufs, are not
  present in `GuestMemory`.
- `SharedMemory` wraps a `memfd` and can be mapped using `MemoryMapping` to access its data.
  `SharedMemory` can't be cloned.
- `VolatileMemory` is a trait that exposes generic access to non-contiguous memory. `GuestMemory`
  implements this trait. Use this trait for functions that operate on a memory space but don't
  necessarily need it to be guest memory.
- `VolatileSlice` is analogous to a Rust slice, but unlike those, a `VolatileSlice` has data that
  changes asynchronously by all those that reference it. Exclusive mutability and data
  synchronization are not available when it comes to a `VolatileSlice`. This type is useful for
  functions that operate on contiguous shared memory, such as a single entry from a scatter gather
  table, or for safe wrappers around functions which operate on pointers, such as a `read` or
  `write` syscall.
- `MemoryMapping` is a safe wrapper around anonymous and file mappings. Provides RAII and does
  munmap after use. Access via Rust references is forbidden, but indirect reading and writing is
  available via `VolatileSlice` and several convenience functions. This type is most useful for
  mapping memory unrelated to `GuestMemory`.

See [memory layout](https://crosvm.dev/book/appendix/memory_layout.html) for details how crosvm
arranges the guest address space.

### Device Model

### `Bus`/`BusDevice`

The root of the crosvm device model is the `Bus` structure and its friend the `BusDevice` trait. The
`Bus` structure is a virtual computer bus used to emulate the memory-mapped I/O bus and also I/O
ports for x86 VMs. On a read or write to an address on a VM's bus, the corresponding `Bus` object is
queried for a `BusDevice` that occupies that address. `Bus` will then forward the read/write to the
`BusDevice`. Because of this behavior, only one `BusDevice` may exist at any given address. However,
a `BusDevice` may be placed at more than one address range. Depending on how a `BusDevice` was
inserted into the `Bus`, the forwarded read/write will be relative to 0 or to the start of the
address range that the `BusDevice` occupies (which would be ambiguous if the `BusDevice` occupied
more than one range).

Only the base address of a multi-byte read/write is used to search for a device, so a device
implementation should be aware that the last address of a single read/write may be outside its
address range. For example, if a `BusDevice` was inserted at base address 0x1000 with a length of
0x40, a 4-byte read by a VCPU at 0x39 would be forwarded to that `BusDevice`.

Each `BusDevice` is reference counted and wrapped in a mutex, so implementations of `BusDevice` need
not worry about synchronizing their access across multiple VCPUs and threads. Each VCPU will get a
complete copy of the `Bus`, so there is no contention for querying the `Bus` about an address. Once
the `BusDevice` is found, the `Bus` will acquire an exclusive lock to the device and forward the
VCPU's read/write. The implementation of the `BusDevice` will block execution of the VCPU that
invoked it, as well as any other VCPU attempting access, until it returns from its method.

Most devices in crosvm do not implement `BusDevice` directly, but some are examples are `i8042` and
`Serial`. With the exception of PCI devices, all devices are inserted by architecture specific code
(which may call into the architecture-neutral `arch` crate). A `BusDevice` can be proxied to a
sandboxed process using `ProxyDevice`, which will create the second process using a fork, with no
exec.

### `PciConfigIo`/`PciConfigMmio`

In order to use the more complex PCI bus, there are a couple adapters that implement `BusDevice` and
call into a `PciRoot` with higher level calls to `config_space_read`/`config_space_write`. The
`PciConfigMmio` is a `BusDevice` for insertion into the MMIO `Bus` for ARM devices. For x86_64,
`PciConfigIo` is inserted into the I/O port `Bus`. There is only one implementation of `PciRoot`
that is used by either of the `PciConfig*` structures. Because these devices are very simple, they
have very little code or state. They aren't sandboxed and are run as part of the main process.

### `PciRoot`/`PciDevice`/`VirtioPciDevice`

The `PciRoot`, analogous to `BusDevice` for `Bus`s, contains all the `PciDevice` trait objects.
Because of a shortcut (or hack), the `ProxyDevice` only supports jailing `BusDevice` traits.
Therefore, `PciRoot` only contains `BusDevice`s, even though they also implement `PciDevice`. In
fact, every `PciDevice` also implements `BusDevice` because of a blanket implementation
(`impl<T: PciDevice> BusDevice for T { … }`). There are a few PCI related methods in `BusDevice` to
allow the `PciRoot` to still communicate with the underlying `PciDevice` (yes, this abstraction is
very leaky). Most devices will not implement `PciDevice` directly, instead using the
`VirtioPciDevice` implementation for virtio devices, but the xHCI (USB) controller is an example
that implements `PciDevice` directly. The `VirtioPciDevice` is an implementation of `PciDevice` that
wraps a `VirtioDevice`, which is how the virtio specified PCI transport is adapted to a transport
agnostic `VirtioDevice` implementation.

### `VirtioDevice`

The `VirtioDevice` is the most widely implemented trait among the device traits. Each of the
different virtio devices (block, rng, net, etc.) implement this trait directly and they follow a
similar pattern. Most of the trait methods are easily filled in with basic information about the
specific device, but `activate` will be the heart of the implementation. It's called by the virtio
transport after the guest's driver has indicated the device has been configured and is ready to run.
The virtio device implementation will receive the run time related resources (`GuestMemory`,
`Interrupt`, etc.) for processing virtio queues and associated interrupts via the arguments to
`activate`, but `activate` can't spend its time actually processing the queues. A VCPU will be
blocked as long as `activate` is running. Every device uses `activate` to launch a worker thread
that takes ownership of run time resources to do the actual processing. There is some subtlety in
dealing with virtio queues, so the smart thing to do is copy a simpler device and adapt it, such as
the rng device (`rng.rs`).

## Communication Framework

Because of the multi-process nature of crosvm, communication is done over several IPC primitives.
The common ones are shared memory pages, unix sockets, anonymous pipes, and various other file
descriptor variants (DMA-buf, eventfd, etc.). Standard methods (`read`/`write`) of using these
primitives may be used, but crosvm has developed some helpers which should be used where applicable.

### `WaitContext`

Most threads in crosvm will have a wait loop using a [`WaitContext`], which is a wrapper around a
`epoll` on Linux and `WaitForMultipleObjects` on Windows. In either case, waitable objects can be
added to the context along with an associated token, whose type is the type parameter of
`WaitContext`. A call to the `wait` function will block until at least one of the waitable objects
has become signaled and will return a collection of the tokens associated with those objects. The
tokens used with `WaitContext` must be convertible to and from a `u64`. There is a custom derive
`#[derive(EventToken)]` which can be applied to an `enum` declaration that makes it easy to use your
own enum in a `WaitContext`.

#### Linux Platform Limitations

The limitations of `WaitContext` on Linux are the same as the limitations of `epoll`. The same FD
can not be inserted more than once, and the FD will be automatically removed if the process runs out
of references to that FD. A `dup`/`fork` call will increment that reference count, so closing the
original FD will not actually remove it from the `WaitContext`. It is possible to receive tokens
from `WaitContext` for an FD that was closed because of a race condition in which an event was
registered in the background before the `close` happened. Best practice is to keep an FD open and
remove it from the `WaitContext` before closing it so that events associated with it can be reliably
eliminated.

### `serde` with Descriptors

Using raw sockets and pipes to communicate is very inconvenient for rich data types. To help make
this easier and less error prone, crosvm uses the `serde` crate. To allow transmitting types with
embedded descriptors (FDs on Linux or HANDLEs on Windows), a module is provided for sending and
receiving descriptors alongside the plain old bytes that serde consumes.

## Code Map

Source code is organized into crates, each with their own unit tests.

- `./src/` - The top-level binary front-end for using crosvm.
- `aarch64` - Support code specific to 64 bit ARM architectures.
- `base` - Safe wrappers for system facilities which provides cross-platform-compatible interfaces.
- `bin` - Scripts for code health such as wrappers of `rustfmt` and `clippy`.
- `ci` - Scripts for continuous integration.
- `cros_async` - Runtime for async/await programming. This crate provides a `Future` executor based
  on `io_uring` and one based on `epoll`.
- `devices` - Virtual devices exposed to the guest OS.
- `disk` - Library to create and manipulate several types of disks such as raw disk, [qcow], etc.
- `hypervisor` - Abstract layer to interact with hypervisors. For Linux, this crate is a wrapper of
  `kvm`.
- `e2e_tests` - End-to-end tests that run a crosvm VM.
- `kernel_loader` - Loads elf64 kernel files to a slice of memory.
- `kvm_sys` - Low-level (mostly) auto-generated structures and constants for using KVM.
- `kvm` - Unsafe, low-level wrapper code for using `kvm_sys`.
- `media/libvda` - Safe wrapper of [libvda], a Chrome OS HW-accelerated video decoding/encoding
  library.
- `net_sys` - Low-level (mostly) auto-generated structures and constants for creating TUN/TAP
  devices.
- `net_util` - Wrapper for creating TUN/TAP devices.
- `qcow_util` - A library and a binary to manipulate [qcow] disks.
- `seccomp` - Contains minijail seccomp policy files for each sandboxed device. Because some
  syscalls vary by architecture, the seccomp policies are split by architecture.
- `sync` - Our version of `std::sync::Mutex` and `std::sync::Condvar`.
- `third_party` - Third-party libraries which we are maintaining on the Chrome OS tree or the AOSP
  tree.
- `vfio_sys` - Low-level (mostly) auto-generated structures, constants and ioctls for [VFIO].
- `vhost` - Wrappers for creating vhost based devices.
- `virtio_sys` - Low-level (mostly) auto-generated structures and constants for interfacing with
  kernel vhost support.
- `vm_control` - IPC for the VM.
- `vm_memory` - Vm-specific memory objects.
- `x86_64` - Support code specific to 64 bit intel machines.

[libvda]: https://chromium.googlesource.com/chromiumos/platform2/+/refs/heads/main/arc/vm/libvda/
[minijail]: https://android.googlesource.com/platform/external/minijail
[qcow]: https://en.wikipedia.org/wiki/Qcow
[vfio]: https://www.kernel.org/doc/html/latest/driver-api/vfio.html
[`waitcontext`]: https://crosvm.dev/doc/base/struct.WaitContext.html
