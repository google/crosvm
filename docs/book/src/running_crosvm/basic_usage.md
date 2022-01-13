# Basic Usage

This page describes how to prepare VM artifacts and run crosvm with them. If you
haven't built crosvm yet, please read the [Building crosvm] section first.

The example code is available in [tools/examples].

## Run a simple Guest OS (using virt-builder)

To run a VM with crosvm, we need two things: A kernel binary and a rootfs. You
can build those [yourself](#using-a-custom-kernel-and-rootfs) or use prebuilt
cloud/vm images that some linux distributions provide.

### Build the Guest OS image

One of the more convenient ways to customize these VM images is to use
[virt-builder] from the `libguestfs-tools` package.

```bash
{{#include ../../../../tools/examples/example_simple:build}}
```

### Extract the Kernel (And initrd)

Crosvm directly runs the kernel instead of using the bootloader. So we need to
extract the kernel binary from the image. [virt-builder] has a tool for that:

```bash
{{#include ../../../../tools/examples/example_simple:kernel}}
```

The kernel binary is going to be saved in the same directory.

Note: Most distributions use an init ramdisk, which is extracted at the same
time and needs to be passed to crosvm as well.

### Launch the VM

With all the files in place, crosvm can be run:

```bash
{{#include ../../../../tools/examples/example_simple:run}}
```

## Using a custom Kernel and rootfs

Instead of using prebuilt images, you can build a custom kernel and use
debootstrab to build a rootfs. The resulting artifacts can be used just like the
ones above.

### Build a kernel

Because crosvm usually runs the latest stable Chrome OS kernel, that is the most
convenient one to use. If you are using the chroot for Chromium OS development,
you already have the kernel source. Otherwise, you can clone it:

```bash
git clone --depth 1 -b chromeos-5.10 https://chromium.googlesource.com/chromiumos/third_party/kernel
```

Either way that you get the kernel, the next steps are to configure and build
the bzImage:

```bash
make chromiumos-container-vm-x86_64_defconfig
make -j$(nproc) bzImage
```

This kernel does not build any modules, nor does it support loading them, so
there is no need to worry about an initramfs, although they are supported in
crosvm.

### Build a rootfs disk

This stage enjoys the most flexibility. There aren't any special requirements
for a rootfs in crosvm, but you will at a minimum need an init binary. This
could even be `/bin/bash` if that is enough for your purposes. To get you
started, a Debian rootfs can be created with [debootstrap]. Make sure to define
`$CHROOT_PATH`.

```bash
truncate -s 20G debian.ext4
mkfs.ext4 debian.ext4
mkdir -p "${CHROOT_PATH}"
sudo mount debian.ext4 "${CHROOT_PATH}"
sudo debootstrap stable "${CHROOT_PATH}" http://deb.debian.org/debian/
sudo chroot "${CHROOT_PATH}"
passwd
echo "tmpfs /tmp tmpfs defaults 0 0" >> /etc/fstab
echo "tmpfs /var/log tmpfs defaults 0 0" >> /etc/fstab
echo "tmpfs /root tmpfs defaults 0 0" >> /etc/fstab
echo "sysfs /sys sysfs defaults 0 0" >> /etc/fstab
echo "proc /proc proc defaults 0 0" >> /etc/fstab
exit
sudo umount "${CHROOT_PATH}"
```

> Note: If you run crosvm on a testing device (e.g. Chromebook in Developer
> mode), another option is to share the host's rootfs with the guest via
> virtiofs. See the [virtiofs usage](./usage.html#with-virtiofs).

You can simply create a disk image as follows:

```bash
fallocate --length 4G disk.img
mkfs.ext4 ./disk.img
```

[building crosvm]: ../building_crosvm/index.md
[cloud-init]: https://cloudinit.readthedocs.io/
[debian]: https://cloud.debian.org/images/cloud/
[debootstrap]: https://wiki.debian.org/Debootstrap
[ubuntu]: https://cloud-images.ubuntu.com/
[virt-builder]: https://libguestfs.org/virt-builder.1.html
[tools/examples]:
    https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform/crosvm/tools/examples
