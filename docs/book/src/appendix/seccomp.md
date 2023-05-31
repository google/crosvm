# Seccomp

The seccomp system is used to filter the syscalls that sandboxed processes can use. The form of
seccomp used by crosvm (`SECCOMP_SET_MODE_FILTER`) allows for a BPF program to be used. To generate
the BPF programs, crosvm uses minijail's policy file format. A policy file is written for each
device per architecture. Each device requires a unique set of syscalls to accomplish their function
and each architecture has slightly different naming for similar syscalls. The ChromeOS docs have a
useful
[listing of syscalls](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md).

The seccomp policies are compiled from `.policy` source files into BPF bytecode by
[`jail/build.rs`](https://chromium.googlesource.com/crosvm/crosvm/+/refs/heads/main/jail/build.rs)
and embedded in the crosvm executable, so it is not necessary to install the seccomp policy files,
only the crosvm binary itself. Be sure to remember to rebuild crosvm after changing a policy file to
observe the updated behavior.

## Writing a Policy for crosvm

The detailed rules for naming policy files can be found in
[jail/seccomp/README.md](https://chromium.googlesource.com/crosvm/crosvm/+/refs/heads/main/jail/seccomp/README.md)

Most policy files will include the `common_device.policy` from a given architecture using this
directive near the top:

```
@include /usr/share/policy/crosvm/common_device.policy
```

The common device policy for `x86_64` is:

```
{{#include ../../../../jail/seccomp/x86_64/common_device.policy:5:}}
```

The syntax is simple: one syscall per line, followed by a colon `:`, followed by a boolean
expression used to constrain the arguments of the syscall. The simplest expression is `1` which
unconditionally allows the syscall. Only simple expressions work, often to allow or deny specific
flags. A major limitation is that checking the contents of pointers isn't possible using minijail's
policy format. If a syscall is not listed in a policy file, it is not allowed.
