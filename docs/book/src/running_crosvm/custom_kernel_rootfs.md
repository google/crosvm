# Custom Kernel / Rootfs

This document explains how to build a custom kernel and use debootstrab to build a rootfs for
running crosvm.

For an easier way to get started with prebuilt images, see [Example Usage](./example_usage.md)

### Build a kernel

The linux kernel in chromiumos comes preconfigured for running in a crosvm guest and is the easiest
to build. You can use any mainline kernel though as long as it's configured for para-virtualized
(virtio) devices

If you are using the chroot for ChromiumOS development, you already have the kernel source.
Otherwise, you can clone it:

```bash
git clone --depth 1 -b chromeos-5.10 https://chromium.googlesource.com/chromiumos/third_party/kernel
```

Either way that you get the kernel, the next steps are to configure and build the bzImage:

```bash
CHROMEOS_KERNEL_FAMILY=termina ./chromeos/scripts/prepareconfig container-vm-x86_64
make olddefconfig
make -j$(nproc) bzImage
```

This kernel does not build any modules, nor does it support loading them, so there is no need to
worry about an initramfs, although they are supported in crosvm.

### Build a rootfs disk

This stage enjoys the most flexibility. There aren't any special requirements for a rootfs in
crosvm, but you will at a minimum need an init binary. This could even be `/bin/bash` if that is
enough for your purposes. To get you started, a Debian rootfs can be created with [debootstrap].
Make sure to define `$CHROOT_PATH`.

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

> Note: If you run crosvm on a testing device (e.g. Chromebook in Developer mode), another option is
> to share the host's rootfs with the guest via virtiofs. See the
> [virtiofs usage](./advanced_usage.md#virtiofs-as-rootfs).

You can simply create a disk image as follows:

```bash
fallocate --length 4G disk.img
mkfs.ext4 ./disk.img
```

[debootstrap]: https://wiki.debian.org/Debootstrap
