// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str;

use thiserror::Error;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::KnownLayout;

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
#[derive(Copy, Clone, FromBytes, Immutable, KnownLayout)]
struct AcpiGenlEvent {
    device_class: [u8; 20],
    bus_id: [u8; 15],
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

        let (genl_hdr, nl_attr) = GenlMsgHdr::read_from_prefix(netlink_message.data)
            .expect("unable to get GenlMsgHdr from slice");

        let (nl_attr, body) =
            NlAttr::read_from_prefix(nl_attr).expect("unable to get NlAttr from slice");

        // Sanity check that the headers have correct for acpi event `cmd` and `_type`
        if genl_hdr.cmd != GenmsghdrCmd::AcpiGenlCmdEvent as u8
            || nl_attr._type != NlAttrType::AcpiGenlAttrEvent as u16
        {
            return Err(AcpiEventError::TypeAttrMissmatch);
        }

        let acpi_event =
            AcpiGenlEvent::read_from_bytes(body).expect("unable to get AcpiGenlEvent from slice");

        Ok(AcpiNotifyEvent {
            device_class: strip_padding(&acpi_event.device_class).to_owned(),
            bus_id: strip_padding(&acpi_event.bus_id).to_owned(),
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
