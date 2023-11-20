// Copyright TUNTAP, 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux networking API bindings.

#![cfg(any(target_os = "android", target_os = "linux"))]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use base::ioctl_ior_nr;
use base::ioctl_iow_nr;

pub mod if_tun;
pub mod iff; // Named "iff" to avoid conflicting with "if" keyword.
pub mod sockios;
pub use crate::if_tun::sock_fprog;
pub use crate::if_tun::IFF_MULTI_QUEUE;
pub use crate::if_tun::IFF_NO_PI;
pub use crate::if_tun::IFF_TAP;
pub use crate::if_tun::IFF_VNET_HDR;
pub use crate::if_tun::TUN_F_CSUM;
pub use crate::if_tun::TUN_F_TSO4;
pub use crate::if_tun::TUN_F_TSO6;
pub use crate::if_tun::TUN_F_TSO_ECN;
pub use crate::if_tun::TUN_F_UFO;
pub use crate::iff::ifreq;
pub use crate::iff::net_device_flags;

pub const TUNTAP: ::std::os::raw::c_uint = 84;

ioctl_iow_nr!(TUNSETNOCSUM, TUNTAP, 200, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETDEBUG, TUNTAP, 201, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETIFF, TUNTAP, 202, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETPERSIST, TUNTAP, 203, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETOWNER, TUNTAP, 204, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETLINK, TUNTAP, 205, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETGROUP, TUNTAP, 206, ::std::os::raw::c_int);
ioctl_ior_nr!(TUNGETFEATURES, TUNTAP, 207, ::std::os::raw::c_uint);
ioctl_iow_nr!(TUNSETOFFLOAD, TUNTAP, 208, ::std::os::raw::c_uint);
ioctl_iow_nr!(TUNSETTXFILTER, TUNTAP, 209, ::std::os::raw::c_uint);
ioctl_ior_nr!(TUNGETIFF, TUNTAP, 210, ::std::os::raw::c_uint);
ioctl_ior_nr!(TUNGETSNDBUF, TUNTAP, 211, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETSNDBUF, TUNTAP, 212, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNATTACHFILTER, TUNTAP, 213, sock_fprog);
ioctl_iow_nr!(TUNDETACHFILTER, TUNTAP, 214, sock_fprog);
ioctl_ior_nr!(TUNGETVNETHDRSZ, TUNTAP, 215, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETVNETHDRSZ, TUNTAP, 216, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETQUEUE, TUNTAP, 217, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETIFINDEX, TUNTAP, 218, ::std::os::raw::c_uint);
ioctl_ior_nr!(TUNGETFILTER, TUNTAP, 219, sock_fprog);
ioctl_iow_nr!(TUNSETVNETLE, TUNTAP, 220, ::std::os::raw::c_int);
ioctl_ior_nr!(TUNGETVNETLE, TUNTAP, 221, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETVNETBE, TUNTAP, 222, ::std::os::raw::c_int);
ioctl_ior_nr!(TUNGETVNETBE, TUNTAP, 223, ::std::os::raw::c_int);
