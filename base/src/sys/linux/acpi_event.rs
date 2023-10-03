// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str;

use thiserror::Error;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use super::netlink::*;

const ACPI_EVENT_SIZE: usize = std::mem::size_of::<AcpiGenlEvent>();
const GENL_HDRLEN: usize = std::mem::size_of::<GenlMsgHdr>();
const NLA_HDRLEN: usize = std::mem::size_of::<NlAttr>();

#[derive(Error, Debug)]
pub enum AcpiEventError {
    #[error("GenmsghdrCmd or NlAttrType inappropriate for acpi event")]
    TypeAttrMissmatch,
    #[error("Something goes wrong: msg_len {0} is not correct")]
    InvalidMsgLen(usize),
}
type Result<T> = std::result::Result<T, AcpiEventError>;

/// attributes of AcpiGenlFamily
#[allow(dead_code)]
enum NlAttrType {
    AcpiGenlAttrUnspec,
    AcpiGenlAttrEvent, // acpi_event (needed by user space)
    AcpiGenlAttrMax,
}

/// commands supported by the AcpiGenlFamily
#[allow(dead_code)]
enum GenmsghdrCmd {
    AcpiGenlCmdUnspec,
    AcpiGenlCmdEvent, // kernel->user notifications for acpi_events
    AcpiGenlCmdMax,
}

#[repr(C)]
#[derive(Copy, Clone, FromZeroes, FromBytes)]
struct AcpiGenlEvent {
    device_class: [::std::os::raw::c_char; 20usize],
    bus_id: [::std::os::raw::c_char; 15usize],
    _type: u32,
    data: u32,
}

pub struct AcpiNotifyEvent {
    pub device_class: String,
    pub bus_id: String,
    pub _type: u32,
    pub data: u32,
}

impl AcpiNotifyEvent {
    /// Create acpi event by decapsulating it from NetlinkMessage.
    pub fn new(netlink_message: NetlinkMessage) -> Result<Self> {
        let msg_len = netlink_message.data.len();
        if msg_len != GENL_HDRLEN + NLA_HDRLEN + ACPI_EVENT_SIZE {
            return Err(AcpiEventError::InvalidMsgLen(msg_len));
        }

        let genl_hdr = GenlMsgHdr::read_from(&netlink_message.data[..GENL_HDRLEN])
            .expect("unable to get GenlMsgHdr from slice");

        let nlattr_end = GENL_HDRLEN + NLA_HDRLEN;
        let nl_attr = NlAttr::read_from(&netlink_message.data[GENL_HDRLEN..nlattr_end])
            .expect("unable to get NlAttr from slice");

        // Sanity check that the headers have correct for acpi event `cmd` and `_type`
        if genl_hdr.cmd != GenmsghdrCmd::AcpiGenlCmdEvent as u8
            || nl_attr._type != NlAttrType::AcpiGenlAttrEvent as u16
        {
            return Err(AcpiEventError::TypeAttrMissmatch);
        }

        let acpi_event = AcpiGenlEvent::read_from(&netlink_message.data[nlattr_end..msg_len])
            .expect("unable to get AcpiGenlEvent from slice");

        // The raw::c_char is either i8 or u8 which is known portability issue:
        // https://github.com/rust-lang/rust/issues/79089,
        // before using device_class further cast it to u8.
        let device_class: &[u8; 20usize] =
            unsafe { ::std::mem::transmute(&acpi_event.device_class) };
        let bus_id: &[u8; 15usize] = unsafe { ::std::mem::transmute(&acpi_event.bus_id) };

        Ok(AcpiNotifyEvent {
            device_class: strip_padding(device_class).to_owned(),
            bus_id: strip_padding(bus_id).to_owned(),
            _type: acpi_event._type,
            data: acpi_event.data,
        })
    }
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
