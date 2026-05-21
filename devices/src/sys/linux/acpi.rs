// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::error;
use base::info;
use base::AcpiNotifyEvent;
use base::NetlinkGenericSocket;

use crate::acpi::ACPIPMError;
use crate::IrqLevelEvent;

pub(crate) fn get_acpi_event_sock() -> Result<Option<NetlinkGenericSocket>, ACPIPMError> {
    // Get group id corresponding to acpi_mc_group of acpi_event family
    let nl_groups: u32;
    match get_acpi_event_group() {
        Some(group) if group > 0 => {
            nl_groups = 1 << (group - 1);
            info!("Listening on acpi_mc_group of acpi_event family");
        }
        _ => {
            return Err(ACPIPMError::AcpiMcGroupError);
        }
    }

    match NetlinkGenericSocket::new(nl_groups) {
        Ok(acpi_sock) => Ok(Some(acpi_sock)),
        Err(e) => Err(ACPIPMError::AcpiEventSockError(e)),
    }
}

fn get_acpi_event_group() -> Option<u32> {
    // Create netlink generic socket which will be used to query about given family name
    let netlink_ctrl_sock = match NetlinkGenericSocket::new(0) {
        Ok(sock) => sock,
        Err(e) => {
            error!("netlink generic socket creation error: {}", e);
            return None;
        }
    };

    let nlmsg_family_response = netlink_ctrl_sock
        .family_name_query("acpi_event".to_string())
        .unwrap();
    nlmsg_family_response.get_multicast_group_id("acpi_mc_group".to_string())
}

pub(crate) fn acpi_event_run(
    _sci_evt: &IrqLevelEvent,
    acpi_event_sock: &Option<NetlinkGenericSocket>,
) {
    let acpi_event_sock = acpi_event_sock.as_ref().unwrap();
    let nl_msg = match acpi_event_sock.recv() {
        Ok(msg) => msg,
        Err(e) => {
            error!("recv returned with error {}", e);
            return;
        }
    };

    for netlink_message in nl_msg.iter() {
        let _acpi_event = match AcpiNotifyEvent::new(netlink_message) {
            Ok(evt) => evt,
            Err(e) => {
                error!("Received netlink message is not an acpi_event, error {}", e);
                continue;
            }
        };
    }
}
