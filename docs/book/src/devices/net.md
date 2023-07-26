# Network

## Host TAP configuration

The most convenient way to provide a network device to a guest is to setup a persistent TAP
interface on the host. This section will explain how to do this for basic IPv4 connectivity.

```sh
sudo ip tuntap add mode tap user $USER vnet_hdr crosvm_tap
sudo ip addr add 192.168.10.1/24 dev crosvm_tap
sudo ip link set crosvm_tap up
```

These commands create a TAP interface named `crosvm_tap` that is accessible to the current user,
configure the host to use the IP address `192.168.10.1`, and bring the interface up.

The next step is to make sure that traffic from/to this interface is properly routed:

```sh
sudo sysctl net.ipv4.ip_forward=1
# Network interface used to connect to the internet.
HOST_DEV=$(ip route get 8.8.8.8 | awk -- '{printf $5}')
sudo iptables -t nat -A POSTROUTING -o "${HOST_DEV}" -j MASQUERADE
sudo iptables -A FORWARD -i "${HOST_DEV}" -o crosvm_tap -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i crosvm_tap -o "${HOST_DEV}" -j ACCEPT
```

## Start crosvm with network

The interface is now configured and can be used by crosvm:

```sh
crosvm run \
  ...
  --net tap-name=crosvm_tap \
  ...
```

## Configure network in host

Provided the guest kernel had support for `VIRTIO_NET`, the network device should be visible and
configurable from the guest.

```sh
# Replace with the actual network interface name of the guest
# (use "ip addr" to list the interfaces)
GUEST_DEV=enp0s5
sudo ip addr add 192.168.10.2/24 dev "${GUEST_DEV}"
sudo ip link set "${GUEST_DEV}" up
sudo ip route add default via 192.168.10.1
# "8.8.8.8" is chosen arbitrarily as a default, please replace with your local (or preferred global)
# DNS provider, which should be visible in `/etc/resolv.conf` on the host.
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

These commands assign IP address `192.168.10.2` to the guest, activate the interface, and route all
network traffic to the host. The last line also ensures DNS will work.

Please refer to your distribution's documentation for instructions on how to make these settings
persistent for the host and guest if desired.

## Device hotplug (experimental)

On a [hotplug-enabled VM](index.md#device-hotplug-experimental), a TAP device can be hotplugged
using the `virtio-net` command:

```sh
crosvm virtio-net add crosvm_tap ${VM_SOCKET}
```

Upon success, `crosvm virtio_net` will report the PCI bus number the device is plugged into:

```sh
[[time redacted] INFO  crosvm] Tap device crosvm_tap plugged to PCI bus 3
```

The hotplugged device can then be configured inside the guest OS similar to a statically configured
device. (Replace `${GUEST_DEV}` with the hotplugged device, e.g.: `enp3s0`.)

Due to [sandboxing](../architecture/overview.md#sandboxing-policy), crosvm do not have CAP_NET_ADMIN
even if crosvm is started using sudo. Therefore, hotplug only accepts a persistent TAP device owned
by the user running crosvm, unless
[sandboxing is disabled.](../running_crosvm/advanced_usage.md#multiprocess-mode)

The device can be removed from the guest using the PCI bus number:

```sh
crosvm virtio-net remove 3 ${VM_SOCKET}
```
