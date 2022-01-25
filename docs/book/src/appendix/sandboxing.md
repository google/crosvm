# Sandboxing

```mermaid
%%{init: {'theme':'base'}}%%
graph BT
    subgraph guest
        subgraph guest_kernel
            virtio_blk_driver
            virtio_net_driver
        end
    end
    subgraph crosvm Process
        vcpu0:::vcpu
        vcpu1:::vcpu
        subgraph device_proc0[Device Process]
            virtio_blk --- virtio_blk_driver
            disk_fd[(Disk FD)]
        end
        subgraph device_proc1[Device Process]
            virtio_net --- virtio_net_driver
            tapfd{{TAP FD}}
        end
    end
    subgraph kernel[Host Kernel]
        KVM --- vcpu1 & vcpu0
    end
    style KVM fill:#4285f4
    classDef vcpu fill:#7890cd
    classDef system fill:#fff,stroke:#777;
    class crosvm,guest,kernel system;
    style guest_kernel fill:#d23369,stroke:#777
```

Generally speaking, sandboxing is achieved in crosvm by isolating each virtualized devices into its
own process. A process is always somewhat isolated from another by virtue of being in a different
address space. Depending on the operating system, crosvm will use additional measures to sandbox the
child processes of crosvm by limiting each process to just what it needs to function.

In the example diagram above, the virtio block device exists as a child process of crosvm. It has
been limited to having just the FD needed to access the backing file on the host and has no ability
to open new files. A similar setup exists for other devices like virtio net.
