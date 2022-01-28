# Minijail

On Linux hosts, crosvm uses [minijail](https://google.github.io/minijail/) to sandbox the child
devices. The minijail C library is utilized via a
[Rust wrapper](https://android.googlesource.com/platform/external/minijail/+/refs/heads/master/rust/minijail/src/lib.rs)
so as not to repeat the intricate sequence of syscalls used to make a secure isolated child process.
The fact that minijail was written, maintained, and continuously tested by a professional security
team more than makes up for its being written in an memory unsafe language.

The exact configuration of the sandbox varies by device, but they are mostly alike. See
`create_base_minijail` from `linux/jail_helpers.rs`. The set of security constraints explicitly used
in crosvm are:

- PID Namespace
  - Runs as init
- [Deny setgroups](https://lwn.net/Articles/626665/)
- Optional limit the capabilities mask to `0`
- User namespace
  - Optional uid/gid mapping
- Mount namespace
  - Optional pivot into a new root
- Network namespace
- [PR_SET_NO_NEW_PRIVS](https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt)
- [seccomp](seccomp.html) with optional log failure mode
- Limit to number of file descriptors
