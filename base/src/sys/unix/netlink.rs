// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::alloc::Layout;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::str;

use libc::EINVAL;
use log::error;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::LayoutVerified;

use super::errno_result;
use super::getpid;
use super::Error;
use super::RawDescriptor;
use super::Result;
use crate::alloc::LayoutAllocation;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::SafeDescriptor;

macro_rules! debug_pr {
    // By default debugs are suppressed, to enabled them replace macro body with:
    // $($args:tt)+) => (println!($($args)*))
    ($($args:tt)+) => {};
}

const NLMSGHDR_SIZE: usize = std::mem::size_of::<NlMsgHdr>();
const GENL_HDRLEN: usize = std::mem::size_of::<GenlMsgHdr>();
const NLA_HDRLEN: usize = std::mem::size_of::<NlAttr>();
const NLATTR_ALIGN_TO: usize = 4;

#[repr(C)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

/// Netlink attribute struct, can be used by netlink consumer
#[repr(C)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct NlAttr {
    pub len: u16,
    pub _type: u16,
}

/// Generic netlink header struct, can be used by netlink consumer
#[repr(C)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct GenlMsgHdr {
    pub cmd: u8,
    pub version: u8,
    pub reserved: u16,
}
/// A single netlink message, including its header and data.
pub struct NetlinkMessage<'a> {
    pub _type: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
    pub data: &'a [u8],
}

pub struct NlAttrWithData<'a> {
    pub len: u16,
    pub _type: u16,
    pub data: &'a [u8],
}

fn nlattr_align(offset: usize) -> usize {
    (offset + NLATTR_ALIGN_TO - 1) & !(NLATTR_ALIGN_TO - 1)
}

/// Iterator over `struct NlAttr` as received from a netlink socket.
pub struct NetlinkGenericDataIter<'a> {
    // `data` must be properly aligned for NlAttr.
    data: &'a [u8],
}

impl<'a> Iterator for NetlinkGenericDataIter<'a> {
    type Item = NlAttrWithData<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < NLA_HDRLEN {
            return None;
        }
        let nl_hdr = NlAttr::read_from(&self.data[..NLA_HDRLEN])?;

        // Make sure NlAtrr fits
        let nl_data_len = nl_hdr.len as usize;
        if nl_data_len < NLA_HDRLEN || nl_data_len > self.data.len() {
            return None;
        }

        // Get data related to processed NlAttr
        let data_start = NLA_HDRLEN;
        let data = &self.data[data_start..nl_data_len];

        // Get next NlAttr
        let next_hdr = nlattr_align(nl_data_len);
        if next_hdr >= self.data.len() {
            self.data = &[];
        } else {
            self.data = &self.data[next_hdr..];
        }

        Some(NlAttrWithData {
            _type: nl_hdr._type,
            len: nl_hdr.len,
            data,
        })
    }
}

/// Iterator over `struct nlmsghdr` as received from a netlink socket.
pub struct NetlinkMessageIter<'a> {
    // `data` must be properly aligned for nlmsghdr.
    data: &'a [u8],
}

impl<'a> Iterator for NetlinkMessageIter<'a> {
    type Item = NetlinkMessage<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < NLMSGHDR_SIZE {
            return None;
        }
        let hdr = NlMsgHdr::read_from(&self.data[..NLMSGHDR_SIZE])?;

        // NLMSG_OK
        let msg_len = hdr.nlmsg_len as usize;
        if msg_len < NLMSGHDR_SIZE || msg_len > self.data.len() {
            return None;
        }

        // NLMSG_DATA
        let data_start = NLMSGHDR_SIZE;
        let data = &self.data[data_start..msg_len];

        // NLMSG_NEXT
        let align_to = std::mem::align_of::<NlMsgHdr>();
        let next_hdr = (msg_len + align_to - 1) & !(align_to - 1);
        if next_hdr >= self.data.len() {
            self.data = &[];
        } else {
            self.data = &self.data[next_hdr..];
        }

        Some(NetlinkMessage {
            _type: hdr.nlmsg_type,
            flags: hdr.nlmsg_flags,
            seq: hdr.nlmsg_seq,
            pid: hdr.nlmsg_pid,
            data,
        })
    }
}

/// Safe wrapper for `NETLINK_GENERIC` netlink sockets.
pub struct NetlinkGenericSocket {
    sock: SafeDescriptor,
}

impl AsRawDescriptor for NetlinkGenericSocket {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.sock.as_raw_descriptor()
    }
}

impl NetlinkGenericSocket {
    /// Create and bind a new `NETLINK_GENERIC` socket.
    pub fn new(nl_groups: u32) -> Result<Self> {
        // Safe because we check the return value and convert the raw fd into a SafeDescriptor.
        let sock = unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_GENERIC,
            );
            if fd < 0 {
                return errno_result();
            }

            SafeDescriptor::from_raw_descriptor(fd)
        };

        // This MaybeUninit dance is needed because sockaddr_nl has a private padding field and
        // doesn't implement Default. Safe because all 0s is valid data for sockaddr_nl.
        let mut sa = unsafe { MaybeUninit::<libc::sockaddr_nl>::zeroed().assume_init() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        sa.nl_groups = nl_groups;

        // Safe because we pass a descriptor that we own and valid pointer/size for sockaddr.
        unsafe {
            let res = libc::bind(
                sock.as_raw_fd(),
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of_val(&sa) as libc::socklen_t,
            );
            if res < 0 {
                return errno_result();
            }
        }

        Ok(NetlinkGenericSocket { sock })
    }

    /// Receive messages from the netlink socket.
    pub fn recv(&self) -> Result<NetlinkGenericRead> {
        let buf_size = 8192; // TODO(dverkamp): make this configurable?

        // Create a buffer with sufficient alignment for nlmsghdr.
        let layout = Layout::from_size_align(buf_size, std::mem::align_of::<NlMsgHdr>())
            .map_err(|_| Error::new(EINVAL))?;
        let allocation = LayoutAllocation::uninitialized(layout);

        // Safe because we pass a valid, owned socket fd and a valid pointer/size for the buffer.
        let bytes_read = unsafe {
            let res = libc::recv(
                self.sock.as_raw_fd(),
                allocation.as_ptr() as *mut libc::c_void,
                buf_size,
                0,
            );
            if res < 0 {
                return errno_result();
            }
            res as usize
        };

        Ok(NetlinkGenericRead {
            allocation,
            len: bytes_read,
        })
    }

    pub fn family_name_query(&self, family_name: String) -> Result<NetlinkGenericRead> {
        let buf_size = 1024;
        debug_pr!(
            "preparing query for family name {}, len {}",
            family_name,
            family_name.len()
        );

        // Create a buffer with sufficient alignment for nlmsghdr.
        let layout = Layout::from_size_align(buf_size, std::mem::align_of::<NlMsgHdr>())
            .map_err(|_| Error::new(EINVAL))
            .unwrap();
        let mut allocation = LayoutAllocation::zeroed(layout);

        // Safe because the data in allocation was initialized up to `buf_size` and is
        // sufficiently aligned.
        let data = unsafe { allocation.as_mut_slice(buf_size) };

        // Prepare the netlink message header
        let hdr = LayoutVerified::<_, NlMsgHdr>::new(&mut data[..NLMSGHDR_SIZE])
            .expect("failed to unwrap")
            .into_mut();
        hdr.nlmsg_len = NLMSGHDR_SIZE as u32 + GENL_HDRLEN as u32;
        hdr.nlmsg_len += NLA_HDRLEN as u32 + family_name.len() as u32 + 1;
        hdr.nlmsg_flags = libc::NLM_F_REQUEST as u16;
        hdr.nlmsg_type = libc::GENL_ID_CTRL as u16;
        hdr.nlmsg_pid = getpid() as u32;

        // Prepare generic netlink message header
        let genl_hdr_end = NLMSGHDR_SIZE + GENL_HDRLEN;
        let genl_hdr = LayoutVerified::<_, GenlMsgHdr>::new(&mut data[NLMSGHDR_SIZE..genl_hdr_end])
            .expect("unable to get GenlMsgHdr from slice")
            .into_mut();
        genl_hdr.cmd = libc::CTRL_CMD_GETFAMILY as u8;
        genl_hdr.version = 0x1;

        // Netlink attributes
        let nlattr_start = genl_hdr_end;
        let nlattr_end = nlattr_start + NLA_HDRLEN;
        let nl_attr = LayoutVerified::<_, NlAttr>::new(&mut data[nlattr_start..nlattr_end])
            .expect("unable to get NlAttr from slice")
            .into_mut();
        nl_attr._type = libc::CTRL_ATTR_FAMILY_NAME as u16;
        nl_attr.len = family_name.len() as u16 + 1 + NLA_HDRLEN as u16;

        // Fill the message payload with the family name
        let payload_start = nlattr_end;
        let payload_end = payload_start + family_name.len();
        data[payload_start..payload_end].copy_from_slice(family_name.as_bytes());

        // Safe because we pass a valid, owned socket fd and a valid pointer/size for the buffer.
        unsafe {
            let res = libc::send(
                self.sock.as_raw_fd(),
                allocation.as_ptr() as *mut libc::c_void,
                payload_end + 1,
                0,
            );
            if res < 0 {
                error!("failed to send get_family_cmd");
                return errno_result();
            }
        };

        // Return the answer
        match self.recv() {
            Ok(msg) => Ok(msg),
            Err(e) => {
                error!("recv get_family returned with error {}", e);
                Err(e)
            }
        }
    }
}

fn parse_ctrl_group_name_and_id(
    nested_nl_attr_data: NetlinkGenericDataIter,
    group_name: &str,
) -> Option<u32> {
    let mut mcast_group_id: Option<u32> = None;

    for nested_nl_attr in nested_nl_attr_data {
        debug_pr!(
            "\t\tmcast_grp: nlattr type {}, len {}",
            nested_nl_attr._type,
            nested_nl_attr.len
        );

        if nested_nl_attr._type == libc::CTRL_ATTR_MCAST_GRP_ID as u16 {
            mcast_group_id = Some(u32::from_ne_bytes(nested_nl_attr.data.try_into().unwrap()));
            debug_pr!("\t\t mcast group_id {}", mcast_group_id?);
        }

        if nested_nl_attr._type == libc::CTRL_ATTR_MCAST_GRP_NAME as u16 {
            debug_pr!(
                "\t\t mcast group name {}",
                strip_padding(&nested_nl_attr.data)
            );

            // If the group name match and the group_id was set in previous iteration, return,
            // valid for group_name, group_id
            if group_name.eq(strip_padding(nested_nl_attr.data)) && mcast_group_id.is_some() {
                debug_pr!(
                    "\t\t Got what we were looking for group_id = {} for {}",
                    mcast_group_id?,
                    group_name
                );

                return mcast_group_id;
            }
        }
    }

    None
}

/// Parse CTRL_ATTR_MCAST_GROUPS data in order to get multicast group id
///
/// On success, returns group_id for a given `group_name`
///
/// # Arguments
///
/// * `nl_attr_area`    - Nested attributes area (CTRL_ATTR_MCAST_GROUPS data), where nl_attr's
///                       corresponding to specific groups are embed
/// * `group_name`      - String with group_name for which we are looking group_id
///
/// the CTRL_ATTR_MCAST_GROUPS data has nested attributes. Each of nested attribute is per
/// multicast group attributes, which have another nested attributes: CTRL_ATTR_MCAST_GRP_NAME and
/// CTRL_ATTR_MCAST_GRP_ID. Need to parse all of them to get mcast group id for a given group_name..
///
/// Illustrated layout:
/// CTRL_ATTR_MCAST_GROUPS:
///   GR1 (nl_attr._type = 1):
///       CTRL_ATTR_MCAST_GRP_ID,
///       CTRL_ATTR_MCAST_GRP_NAME,
///   GR2 (nl_attr._type = 2):
///       CTRL_ATTR_MCAST_GRP_ID,
///       CTRL_ATTR_MCAST_GRP_NAME,
///   ..
///
/// Unfortunately kernel implementation uses `nla_nest_start_noflag` for that
/// purpose, which means that it never marked their nest attributes with NLA_F_NESTED flag.
/// Therefore all this nesting stages need to be deduced based on specific nl_attr type.
fn parse_ctrl_mcast_group_id(
    nl_attr_area: NetlinkGenericDataIter,
    group_name: &str,
) -> Option<u32> {
    // There may be multiple nested multicast groups, go through all of them.
    // Each of nested group, has other nested nlattr:
    //  CTRL_ATTR_MCAST_GRP_ID
    //  CTRL_ATTR_MCAST_GRP_NAME
    //
    //  which are further proceed by parse_ctrl_group_name_and_id
    for nested_gr_nl_attr in nl_attr_area {
        debug_pr!(
            "\tmcast_groups: nlattr type(gr_nr) {}, len {}",
            nested_gr_nl_attr._type,
            nested_gr_nl_attr.len
        );

        let netlink_nested_attr = NetlinkGenericDataIter {
            data: nested_gr_nl_attr.data,
        };

        if let Some(mcast_group_id) = parse_ctrl_group_name_and_id(netlink_nested_attr, group_name)
        {
            return Some(mcast_group_id);
        }
    }

    None
}

// Like `CStr::from_bytes_with_nul` but strips any bytes starting from first '\0'-byte and
// returns &str. Panics if `b` doesn't contain any '\0' bytes.
fn strip_padding(b: &[u8]) -> &str {
    // It would be nice if we could use memchr here but that's locked behind an unstable gate.
    let pos = b
        .iter()
        .position(|&c| c == 0)
        .expect("`b` doesn't contain any nul bytes");

    str::from_utf8(&b[..pos]).unwrap()
}

pub struct NetlinkGenericRead {
    allocation: LayoutAllocation,
    len: usize,
}

impl NetlinkGenericRead {
    pub fn iter(&self) -> NetlinkMessageIter {
        // Safe because the data in allocation was initialized up to `self.len` by `recv()` and is
        // sufficiently aligned.
        let data = unsafe { &self.allocation.as_slice(self.len) };
        NetlinkMessageIter { data }
    }

    /// Parse NetlinkGeneric response in order to get multicast group id
    ///
    /// On success, returns group_id for a given `group_name`
    ///
    /// # Arguments
    ///
    /// * `group_name` - String with group_name for which we are looking group_id
    ///
    /// Response from family_name_query (CTRL_CMD_GETFAMILY) is a netlink message with multiple
    /// attributes encapsulated (some of them are nested). An example response layout is
    /// illustrated below:
    ///
    ///  {
    ///    CTRL_ATTR_FAMILY_NAME
    ///    CTRL_ATTR_FAMILY_ID
    ///    CTRL_ATTR_VERSION
    ///    ...
    ///    CTRL_ATTR_MCAST_GROUPS {
    ///      GR1 (nl_attr._type = 1) {
    ///          CTRL_ATTR_MCAST_GRP_ID    *we need parse this attr to obtain group id used for
    ///                                     the group mask
    ///          CTRL_ATTR_MCAST_GRP_NAME  *group_name that we need to match with
    ///      }
    ///      GR2 (nl_attr._type = 2) {
    ///          CTRL_ATTR_MCAST_GRP_ID
    ///          CTRL_ATTR_MCAST_GRP_NAME
    ///      }
    ///      ...
    ///     }
    ///   }
    ///
    pub fn get_multicast_group_id(&self, group_name: String) -> Option<u32> {
        for netlink_msg in self.iter() {
            debug_pr!(
                "received type: {}, flags {}, pid {}, data {:?}",
                netlink_msg._type,
                netlink_msg.flags,
                netlink_msg.pid,
                netlink_msg.data
            );

            if netlink_msg._type != libc::GENL_ID_CTRL as u16 {
                error!("Received not a generic netlink controller msg");
                return None;
            }

            let netlink_data = NetlinkGenericDataIter {
                data: &netlink_msg.data[GENL_HDRLEN..],
            };
            for nl_attr in netlink_data {
                debug_pr!("nl_attr type {}, len {}", nl_attr._type, nl_attr.len);

                if nl_attr._type == libc::CTRL_ATTR_MCAST_GROUPS as u16 {
                    let netlink_nested_attr = NetlinkGenericDataIter { data: nl_attr.data };

                    if let Some(mcast_group_id) =
                        parse_ctrl_mcast_group_id(netlink_nested_attr, &group_name)
                    {
                        return Some(mcast_group_id);
                    }
                }
            }
        }
        None
    }
}
