# vhost-user protocol extensions: sleep/wake/snapshot/restore

WORK IN PROGRESS

Documentation for the vhost-user protocol extensions added to crosvm as part of the snapshot-restore
project. Written in the style of https://qemu-project.gitlab.io/qemu/interop/vhost-user.html so that
we can send it upstream as a proposal.

These extensions might be redundant with the VHOST_USER_PROTOCOL_F_DEVICE_STATE features recently
added to the spec.

## Suspended device state

(proposed additions are **bold**)

While all vrings are stopped, the device is suspended. In addition to not processing any vring
(because they are stopped), the device must:

- not write to any guest memory regions,
- not send any notifications to the guest,
- not send any messages to the front-end,
- **NEW: not interact with host resources. For example, a block device should not read or modify the
  disk image file**
- still process and reply to messages from the front-end.

**NEW: The frontend can assume those requirements are obeyed both (1) before the first queue is
started and (2) as soon as it receives a response for the message that stopped the last queue.**

## Front-end message types

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

The one byte response should be 1 to indicate success or 0 to indicate failure.

## Snapshot-Restore

TODO: write an overview for the feature

### Frontend

Snapshot sequence:

1. Frontend connects to vhost-user devices.
1. ... proceed as usual ...
1. For each vhost-user device
   - Frontend stops all the queues using VHOST_USER_GET_VRING_BASE and saves the vring bases
     somewhere.
   - Backend enters the "suspended device state" when the last queue is stopped.
1. For each vhost-user device
   - Frontend sends VHOST_USER_SNAPSHOT request and saves the response payload somewhere.
1. For each vhost-user device
   - Frontend sends VHOST_USER_SET_MEM_TABLE request.
   - Frontend starts all the queues as if from scratch, using the saved vring base in the
     VHOST_USER_SET_VRING_BASE request.
   - Backend exits the "suspended device state" (as early as) when the first queue is started.
1. ... proceed as usual ...

Restore sequence:

1. Frontend connects to vhost-user devices.
1. For each vhost-user device
   - Frontend stops all the queues using VHOST_USER_GET_VRING_BASE and saves the vring bases
     somewhere.
   - Backend enters the "suspended device state" when the last queue is stopped.
1. For each vhost-user device
   - Frontend sends VHOST_USER_RESTORE request.
1. For each vhost-user device
   - Frontend sends VHOST_USER_SET_MEM_TABLE request.
   - Frontend starts all the queues as if from scratch, using the saved vring base in the
     VHOST_USER_SET_VRING_BASE request.
   - Backend exits the "suspended device state" (as early as) when the first queue is started.
1. ... proceed as usual ...

### Backend

TODO: anything interesting to write here?
