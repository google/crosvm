// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::debug;
use base::error;
use base::info;
use base::AcpiNotifyEvent;
use base::NetlinkGenericSocket;
use sync::Mutex;

use crate::acpi::ACPIPMError;
use crate::acpi::GpeResource;
use crate::acpi::ACPIPM_GPE_MAX;
use crate::AcAdapter;
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
    sci_evt: &IrqLevelEvent,
    acpi_event_sock: &Option<NetlinkGenericSocket>,
    gpe0: &Arc<Mutex<GpeResource>>,
    ignored_gpe: &[u32],
    ac_adapter: &Option<Arc<Mutex<AcAdapter>>>,
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
        let acpi_event = match AcpiNotifyEvent::new(netlink_message) {
            Ok(evt) => evt,
            Err(e) => {
                error!("Received netlink message is not an acpi_event, error {}", e);
                continue;
            }
        };
        match acpi_event.device_class.as_str() {
            "gpe" => {
                acpi_event_handle_gpe(acpi_event.data, acpi_event._type, gpe0, ignored_gpe);
            }
            "ac_adapter" => {
                if let Some(ac_adapter) = ac_adapter {
                    // Currently we only support Status change event - other are ignored
                    if acpi_event._type == 0x80 {
                        // Set acex
                        let ac_gpe_nr = {
                            let mut ac_adapter = ac_adapter.lock();
                            ac_adapter.acex = acpi_event.data;
                            ac_adapter.gpe_nr
                        };

                        // Generate GPE
                        debug!(
                            "getting ac_adapter event {} type {} and triggering GPE {}",
                            acpi_event.data, acpi_event._type, ac_gpe_nr
                        );
                        let mut gpe0 = gpe0.lock();
                        match gpe0.set_active(ac_gpe_nr) {
                            Ok(_) => gpe0.trigger_sci(sci_evt),
                            Err(e) => error!("{}", e),
                        }
                    }
                }
            }
            c => debug!("ignored acpi event {}", c),
        };
    }
}

fn acpi_event_handle_gpe(
    gpe_number: u32,
    _type: u32,
    gpe0: &Arc<Mutex<GpeResource>>,
    ignored_gpe: &[u32],
) {
    // If gpe event fired in the host, notify registered GpeNotify listeners
    if _type == 0 && gpe_number <= ACPIPM_GPE_MAX as u32 && !ignored_gpe.contains(&gpe_number) {
        if let Some(notify_devs) = gpe0.lock().gpe_notify.get(&gpe_number) {
            for notify_dev in notify_devs.iter() {
                notify_dev.lock().notify();
            }
        }
    }
}
