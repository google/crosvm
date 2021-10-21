# Basic Usage

This page describes how to prepare VM artifacts and run crosvm with them. If you
haven't built crosvm yet, please read the [Building crosvm] section first.

[Building crosvm]: ../building_crosvm/index.md

## Get a Kernel

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

## Get a rootfs disk

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

[debootstrap]: https://wiki.debian.org/Debootstrap

> Note: If you run crosvm on a testing device (e.g. Chromebook in Developer
> mode),　another option is to share the host's rootfs with the guest via
> virtiofs. See the [virtiofs usage](./usage.html#with-virtiofs).

<!-- TODO: Is it possible to use a prebuilt Debian image downloaded from the official site? -->

## Create a disk image

You can simply create a disk image as follows:

```bash
fallocate --length 4G disk.img
mkfs.ext4 ./disk.img
```

## Launch a VM

Now, you can start a VM with the `crosvm run` command. Note that the user must
be added to a group which can access `/dev/kvm` (usually `kvm`).

```bash
./target/debug/crosvm run \
  --disable-sandbox \
  --rwroot /path/to/debian.ext4 \
  --rwdisk /path/to/disk.img \
  -p 'init=/bin/bash' \
  /path/to/kernel/vmlinux
```

Once the guest started, disk.img will be available as `/dev/vdb` in the guest.
For more advanced usage, see the next section.
