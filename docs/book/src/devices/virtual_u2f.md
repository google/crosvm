# Virtual U2F Passthrough

crosvm supports sharing a single [u2f](https://en.wikipedia.org/wiki/Universal_2nd_Factor) USB
device between the host and the guest. Unlike with normal [USB](usb.md) devices which require to be
exclusively attached to one VM, it is possible to share a single security key between multiple VMs
and the host in a non-exclusive manner using the `attach_key` command.

A generic hardware security key that supports the fido1/u2f protocol should appear as a
`/dev/hidraw` interface on the host, like this:

```shell
$ lsusb
Bus 004 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 003 Device 018: ID 1050:0407 Yubico.com YubiKey OTP+FIDO+CCID
Bus 003 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
$ ls /dev/hidraw*
/dev/hidraw0  /dev/hidraw1
```

In this example, the physical YubiKey presents both a keyboard interface (`/dev/hidraw0`) and a
u2f-hid interface (`/dev/hidraw1`). Crosvm supports passing the `/dev/hidraw1` interface to the
guest via the `crosvm usb attach_key` command.

First, start crosvm making sure to specify a control socket:

```shell
$ crosvm run -s /run/crosvm.sock ${USUAL_CROSVM_ARGS}
```

Since the virtual u2f device is surfaced as a generic HID device, make sure your guest kernel is
built with support for HID devices. Specifically it needs CONFIG_HID, CONFIG_HIDRAW,
CONFIG_HID_GENERIC, and CONFIG_USB_HID enabled.

Once the VM is launched, attach the security key with the following command on the host:

```shell
$ crosvm usb attach_key /dev/hidraw1 /run/crosvm.sock
ok 1
```

The virtual security key will show up inside the guest as a Google USB device with Product and
Vendor IDs as `18d1:f1d0`:

```shell
$ lsusb
Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 001 Device 002: ID 18d1:f1d0 Google Inc.
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
```

You can verify that the correct hidraw device has been created in the `/dev/` tree:

```shell
$ ls /dev/hidraw*
/dev/hidraw0
```

The device should now be usable as u2f-supported security key both inside the guest and on the host.
It can also be attached to other crosvm instances at the same time too.
