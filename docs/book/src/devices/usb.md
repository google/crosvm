# USB

crosvm supports attaching USB devices from the host by emulating an
[xhci backend](https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/extensible-host-controler-interface-usb-xhci.pdf).

Unlike some other VM software like qemu, crosvm does not support attaching USB devices at boot time,
however we can tell the VM to attach the devices once the kernel has booted, as long as we started
crosvm with a control socket (see the control socket section in
[advanced usage](../running_crosvm/advanced_usage.md#control-socket)).

First, start crosvm making sure to specify the control socket:

```shell
$ crosvm run -s /run/crosvm.sock ${USUAL_CROSVM_ARGS}
```

Then, you need to identify which device you want to attach by looking for its USB bus and device
number:

```shell
$ lsusb
Bus 004 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 003 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
Bus 002 Device 022: ID 18d1:4ee7 Google Inc. Pixel 5
Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
```

Assuming in this example the device you want is the `Google Inc. Pixel 5`, its bus and port numbers
are 002 and 022 respectively.

There should be a USB device file on the host at the path `/dev/bus/usb/002/022` which is what you
want to pass to the `crosvm usb attach` command:

```shell
# crosvm usb attach 00:00:00:00 /dev/bus/usb/002/022 /run/crosvm.sock
```

You can run this command as root or make sure your current user has permissions to access the device
file. Also make sure the device is not currently attached to any other drivers on the host and is
not already in use.

NOTE: You need to pass some string formatted like `00:00:00:00` as the first parameter to the
`usb attach` command. This is a deprecated argument and **is not used** by crosvm, but we need to
include it anyway for it to work. It will be removed in the future.

On the host you should see a message like:

```shell
ok 9
```

Which tells you the operation succeeded and which port number the USB device is attached to (in this
case `9`).

Inside the VM you should see dmesg messages that the USB device has been attached successfully and
you should be able to use it as normal.

If you want to detach the device, simply issue a detach command to the same number as the port
returned by the attach command:

```shell
# crosvm usb detach 9 /run/crosvm.sock
```

Which should return another `ok 9` confirmation.

Keep in mind that when a USB device is attached to a VM, it is in exclusive mode and cannot be used
by the host or attached to other VMs.
