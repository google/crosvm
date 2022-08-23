# Onboarding Resources

Various links to useful resources for learning about virtual machines and the technology behind
crosvm.

## Talks

### [Chrome University](https://www.youtube.com/watch?v=2Pc71zYWFDM) by zachr (2018, 30m)

- Life of a Crostini VM (user click -> terminal opens)
- All those French daemons (Concierge, Maitred, Garcon, Sommelier)

### [NYULG: Crostini](https://www.youtube.com/watch?v=WwrXqDERFm8) by zachr / reveman (2018, 50m)

- Overlaps Chrome University talk
- More details on wayland / sommelier from reveman
- More details on crostini integration of app icons, files, clipboard
- Lots of demos

## Introductory Resources

### OS Basics

- [OSDev Wiki](https://wiki.osdev.org/Main_Page) (A lot of articles on OS development)
- [PCI Enumeration](https://www.khoury.northeastern.edu/~pjd/cs7680/homework/pci-enumeration.html)
  (Most of our devices are on PCI, this is how they are found)
- [ACPI Source Language Tutorial](https://acpica.org/sites/acpica/files/asl_tutorial_v20190625.pdf)

### Rust

- [Rust Cheat Sheet](https://cheats.rs/) Beautiful website with idiomatic rust examples, overview of
  pointer- and container types
- [Rust Programming Tipz](https://github.com/ferrous-systems/elements-of-rust) (with a z, that’s how
  you know it’s cool!)
- Rust [design patterns](https://github.com/rust-unofficial/patterns) repo
- Organized [collection](https://github.com/brson/rust-anthology/blob/master/master-list.md) of blog
  posts on various Rust topics

### KVM Virtualization

- [Low-level tutorial](https://lwn.net/Articles/658511/) on how to run code via KVM
- [KVM Hello World](https://github.com/dpw/kvm-hello-world) sample program (host + guest)
- [KVM API docs](https://www.kernel.org/doc/html/latest/virt/kvm/api.html)
- [Awesome Virtualization](https://github.com/Wenzel/awesome-virtualization) (Definitely check out
  the Hypervisor Development section)

### Virtio (device emulation)

- [Good overview](https://developer.ibm.com/articles/l-virtio/) of virtio architecture from IBM
- [Virtio drivers](https://www.redhat.com/en/blog/virtio-devices-and-drivers-overview-headjack-and-phone)
  overview by RedHat
- [Virtio specs](https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html)
  (so exciting, I can’t stop reading)
- [Basics of devices in QEMU ](https://www.qemu.org/2018/02/09/understanding-qemu-devices/)

### VFIO (Device passthrough)

- [Introduction to PCI Device Assignment with VFIO](https://www.youtube.com/watch?v=WFkdTFTOTpA)

### Virtualization History and Basics

- By the end of this section you should be able to answer the following questions
  - What problems do VMs solve?
  - What is trap-and-emulate?
  - Why was the x86 instruction set not “virtualizable” with just trap-and-emulate?
  - What is binary translation? Why is it required?
  - What is a hypervisor? What is a VMM? What is the difference? (If any)
  - What problem does paravirtualization solve?
  - What is the virtualization model we use with Crostini?
  - What is our hypervisor?
  - What is our VMM?
- [CMU slides](http://www.cs.cmu.edu/~410-f06/lectures/L31_Virtualization.pdf) go over motivation,
  why x86 instruction set wasn’t “virtualizable” and the good old trap-and-emulate
- Why Intel VMX was needed; what does it do
  ([Link](https://lettieri.iet.unipi.it/virtualization/2018/hardware-assisted-intel-vmx.pdf))
- What is a VMM and what does it do ([Link](http://pages.cs.wisc.edu/~remzi/OSTEP/vmm-intro.pdf))
- Building a super simple VMM blog article
  ([Link](https://unixism.net/2019/10/sparkler-kvm-based-virtual-machine-manager/))

## Relevant Specs

- [ACPI Specs](https://uefi.org/acpi/specs)
- [DeviceTree Specs](https://www.devicetree.org/specifications/)
- [Vhost-user protocol](https://qemu-project.gitlab.io/qemu/interop/vhost-user.html)
