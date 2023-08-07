# Introduction

The crosvm project is a hosted (a.k.a.
[type-2](https://en.wikipedia.org/wiki/Hypervisor#Classification)) virtual machine monitor similar
to QEMU-KVM or VirtualBox.

It is a VMM that can run untrusted operating systems in a sandboxed environment. crosvm focuses on
safety first and foremost, both in its language of choice (Rust) and through its
[runtime sandbox](appendix/sandboxing.md) system. Each virtual device (disk, network, etc) is by
default executed inside a [minijail](appendix/minijail.md) sandbox, isolated from the rest. In case
of an exploit or vulnerability, this sandbox prevents an attacker from escaping and doing harmful
things to the host operating system. On top of that, crosvm also relies on a
[syscall security policy](appendix/seccomp.md) that prevents unwanted system calls from being
executed by a compromised device.

Initially it was intended to be used with KVM and Linux, but it now also supports
[other types of platforms](https://github.com/google/crosvm/tree/main/hypervisor/src).

To run crosvm all that is needed is an operating system image (a root file system plus a kernel) and
crosvm will run it through the platform's hypervisor. See the
[example usage](running_crosvm/example_usage.md) page to get started or visit the
[building crosvm](building_crosvm/index.md) section to compile your own from source.

- [Announcements](https://groups.google.com/a/chromium.org/g/crosvm-announce)
- [Developer Mailing List](https://groups.google.com/a/chromium.org/g/crosvm-dev)
- [#crosvm on matrix.org](https://matrix.to/#/#crosvm:matrix.org)
- [Source code](https://chromium.googlesource.com/crosvm/crosvm/)
  - [GitHub mirror](https://github.com/google/crosvm)
  - [API documentation](https://crosvm.dev/doc/crosvm/), useful for searching API.
  - Files for this book are under
    [/docs/](https://chromium.googlesource.com/crosvm/crosvm/+/HEAD/docs/).
- [Public issue tracker](https://issuetracker.google.com/issues?q=status:open%20componentid:1161302)
  - For Googlers: See [go/crosvm#filing-bugs](https://goto.google.com/crosvm#filing-bugs).

![logo](./logo.svg)
