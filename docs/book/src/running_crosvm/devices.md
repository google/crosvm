# Devices

| Device           | Description                                                                        |
| ---------------- | ---------------------------------------------------------------------------------- |
| `CMOS/RTC`       | Used to get the current calendar time.                                             |
| `i8042`          | Used by the guest kernel to exit crosvm.                                           |
| `serial`         | x86 I/O port driven serial devices that print to stdout and take input from stdin. |
| `virtio-block`   | Basic read/write block device.                                                     |
| `virtio-net`     | Device to interface the host and guest networks.                                   |
| `virtio-rng`     | Entropy source used to seed guest OS's entropy pool.                               |
| `virtio-vsock`   | Enabled VSOCKs for the guests.                                                     |
| `virtio-wayland` | Allowed guest to use host Wayland socket.                                          |
