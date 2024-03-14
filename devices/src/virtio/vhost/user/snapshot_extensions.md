# vhost-user protocol extensions: sleep/wake/snapshot/restore

WORK IN PROGRESS

Documentation for the vhost-user protocol extensions added to crosvm as part of the snapshot-restore
project. Written in the style of https://qemu-project.gitlab.io/qemu/interop/vhost-user.html so that
we can send it upstream as a proposal.

These extensions might be redundant with the VHOST_USER_PROTOCOL_F_DEVICE_STATE features recently
added to the spec.

## Protocol features

TODO: Include a protocol feature for backends to advertise snapshotting support.

## Front-end message types

### VHOST_USER_SLEEP

id: 1000 (temporary)

equivalent ioctl: N/A

request payload: N/A

reply payload: i8

Backend should stop all active queues. If the backend interacts with resources on the host, e.g. if
it writes to a socket, it is expected that all activity with those resources stops before the
VHOST_USER_SLEEP response is sent. This requirement allows other host side processes to snapshot
their own state without the risk of race conditions. For example, if a virtio-blk flushed pending
writes after VHOST_USER_SLEEP, then a disk image snapshot taken by the VMM could be missing data.

The first byte of the response should be 1 to indicate success or 0 to indicate failure.

### VHOST_USER_WAKE

id: 1001 (temporary)

equivalent ioctl: N/A

request payload: N/A

reply payload: i8

Backend should start all active queues and may restart any interactions with host side resources.

The first byte of the response should be 1 to indicate success or 0 to indicate failure.

### VHOST_USER_SNAPSHOT

id: 1002 (temporary)

equivalent ioctl: N/A

request payload: N/A

reply payload: i8, followed by (payload size - 1) bytes of opaque snapshot data

Backend should create a snapshot of all state needed to perform a restore.

The first byte of the response should be 1 to indicate success or 0 to indicate failure. The rest of
the response is the snapshot bytes, which are opaque from the perspective of the frontend.

### VHOST_USER_RESTORE

id: 1003 (temporary)

equivalent ioctl: N/A

request payload: (payload size) bytes of opaque snapshot data

reply payload: i8

Backend should restore itself to state of the snapshot provided in the request payload. The request
will contain the exact same bytes returned from a previous VHOST_USER_SNAPSHOT request.

The frontend must send the VHOST_USER_SET_MEM_TABLE request before VHOST_USER_RESTORE so that the
backend has enough information to perform the vring restore.

The event file descriptors for adding buffers to the vrings (normally passed via
VHOST_USER_SET_VRING_KICK) are included in the ancillary data. The index of the file descriptor in
the ancillary data is the index of the queue it belongs to.

The one byte response should be 1 to indicate success or 0 to indicate failure.

## Snapshot-Restore

TODO: write an overview for the feature

### Frontend

Snapshot sequence:

1. Frontend connects to vhost-user devices.
1. ... proceed as usual ...
1. For each vhost-user device
   - Frontend sends VHOST_USER_SLEEP request.
1. For each vhost-user device
   - Frontend sends VHOST_USER_SNAPSHOT request and saves the response payload somewhere.
1. For each vhost-user device
   - Frontend sends VHOST_USER_WAKE request.
1. ... proceed as usual ...

Restore sequence:

1. Frontend connects to vhost-user devices.
1. For each vhost-user device
   - Frontend sends VHOST_USER_SLEEP request.
1. For each vhost-user device
   - Frontend sends VHOST_USER_SET_MEM_TABLE request.
   - For every queue that was active at the time of snapshotting, frontend sends a
     VHOST_USER_SET_VRING_CALL request for that queue.
   - Frontend sends VHOST_USER_RESTORE request.
1. For each vhost-user device
   - Frontend sends VHOST_USER_WAKE request.
1. ... proceed as usual ...

### Backend

TODO: anything interesting to write here?
