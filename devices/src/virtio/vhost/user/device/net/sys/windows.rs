// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::error;
use base::info;
use base::named_pipes::OverlappedWrapper;
use base::named_pipes::PipeConnection;
use base::warn;
use base::Event;
use base::RawDescriptor;
use broker_ipc::common_child_setup;
use broker_ipc::CommonChildStartupArgs;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::IntoAsync;
use cros_async::IoSourceExt;
use futures::future::AbortHandle;
use futures::future::Abortable;
use hypervisor::ProtectionType;
#[cfg(feature = "slirp")]
use net_util::Slirp;
use net_util::TapT;
#[cfg(feature = "slirp")]
use serde::Deserialize;
#[cfg(feature = "slirp")]
use serde::Serialize;
use sync::Mutex;
use tube_transporter::TubeToken;
use virtio_sys::virtio_net;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserVirtioFeatures;

use crate::virtio;
use crate::virtio::base_features;
use crate::virtio::net::process_rx;
use crate::virtio::net::NetError;
#[cfg(feature = "slirp")]
use crate::virtio::net::MAX_BUFFER_SIZE;
use crate::virtio::vhost::user::device::handler::sys::windows::read_from_tube_transporter;
use crate::virtio::vhost::user::device::handler::sys::Doorbell;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::net::run_ctrl_queue;
use crate::virtio::vhost::user::device::net::run_tx_queue;
use crate::virtio::vhost::user::device::net::NetBackend;
use crate::virtio::vhost::user::device::net::NET_EXECUTOR;
use crate::virtio::SignalableInterrupt;

impl<T: 'static> NetBackend<T>
where
    T: TapT + IntoAsync,
{
    #[cfg(feature = "slirp")]
    pub fn new_slirp(
        guest_pipe: PipeConnection,
        slirp_kill_event: Event,
    ) -> anyhow::Result<NetBackend<Slirp>> {
        let avail_features = base_features(ProtectionType::Unprotected)
            | 1 << virtio_net::VIRTIO_NET_F_CTRL_VQ
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let slirp = Slirp::new_for_multi_process(guest_pipe).map_err(NetError::SlirpCreateError)?;

        Ok(NetBackend::<Slirp> {
            tap: slirp,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            workers: Default::default(),
            mtu: 1500,
            slirp_kill_event,
        })
    }
}

async fn run_rx_queue<T: TapT>(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    mut tap: Box<dyn IoSourceExt<T>>,
    call_evt: Doorbell,
    kick_evt: EventAsync,
    read_notifier: EventAsync,
    mut overlapped_wrapper: OverlappedWrapper,
) {
    let mut rx_buf = [0u8; MAX_BUFFER_SIZE];
    let mut rx_count = 0;
    let mut deferred_rx = false;
    tap.as_source_mut()
        .read_overlapped(&mut rx_buf, &mut overlapped_wrapper)
        .expect("read_overlapped failed");
    loop {
        // If we already have a packet from deferred RX, we don't need to wait for the slirp device.
        if !deferred_rx {
            if let Err(e) = read_notifier.next_val().await {
                error!("Failed to wait for tap device to become readable: {}", e);
                break;
            }
        }

        let needs_interrupt = process_rx(
            &call_evt,
            &mut queue,
            &mem,
            tap.as_source_mut(),
            &mut rx_buf,
            &mut deferred_rx,
            &mut rx_count,
            &mut overlapped_wrapper,
        );
        if needs_interrupt {
            call_evt.signal_used_queue(queue.vector());
        }

        // There aren't any RX descriptors available for us to write packets to. Wait for the guest
        // to consume some packets and make more descriptors available to us.
        if deferred_rx {
            if let Err(e) = kick_evt.next_val().await {
                error!("Failed to read kick event for rx queue: {}", e);
                break;
            }
        }
    }
}

/// Platform specific impl of VhostUserBackend::start_queue.
pub(in crate::virtio::vhost::user::device::net) fn start_queue<T: 'static + IntoAsync + TapT>(
    backend: &mut NetBackend<T>,
    idx: usize,
    mut queue: virtio::Queue,
    mem: GuestMemory,
    doorbell: Doorbell,
    kick_evt: Event,
) -> anyhow::Result<()> {
    if let Some(handle) = backend.workers.get_mut(idx).and_then(Option::take) {
        warn!("Starting new queue handler without stopping old handler");
        handle.abort();
    }

    // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
    queue.ack_features(backend.acked_features);

    let overlapped_wrapper =
        OverlappedWrapper::new(true).expect("Failed to create overlapped wrapper");

    super::super::NET_EXECUTOR.with(|ex| {
        // Safe because the executor is initialized in main() below.
        let ex = ex.get().expect("Executor not initialized");

        let kick_evt =
            EventAsync::new(kick_evt, ex).context("failed to create EventAsync for kick_evt")?;
        let tap = backend
            .tap
            .try_clone()
            .context("failed to clone tap device")?;
        let (handle, registration) = AbortHandle::new_pair();
        match idx {
            0 => {
                let tap = ex
                    .async_from(tap)
                    .context("failed to create async tap device")?;
                let read_notifier = overlapped_wrapper
                    .get_h_event_ref()
                    .unwrap()
                    .try_clone()
                    .unwrap();
                let read_notifier = EventAsync::new_without_reset(read_notifier, ex)
                    .context("failed to create async read notifier")?;

                ex.spawn_local(Abortable::new(
                    run_rx_queue(
                        queue,
                        mem,
                        tap,
                        doorbell,
                        kick_evt,
                        read_notifier,
                        overlapped_wrapper,
                    ),
                    registration,
                ))
                .detach();
            }
            1 => {
                ex.spawn_local(Abortable::new(
                    run_tx_queue(queue, mem, tap, doorbell, kick_evt),
                    registration,
                ))
                .detach();
            }
            2 => {
                ex.spawn_local(Abortable::new(
                    run_ctrl_queue(
                        queue,
                        mem,
                        tap,
                        doorbell,
                        kick_evt,
                        backend.acked_features,
                        1, /* vq_pairs */
                    ),
                    registration,
                ))
                .detach();
            }
            _ => bail!("attempted to start unknown queue: {}", idx),
        }

        backend.workers[idx] = Some(handle);
        Ok(())
    })
}

#[cfg(feature = "slirp")]
impl<T> Drop for NetBackend<T>
where
    T: TapT + IntoAsync,
{
    fn drop(&mut self) {
        let _ = self.slirp_kill_event.write(1);
    }
}

/// Config arguments passed through the bootstrap Tube from the broker to the Net backend
/// process.
#[cfg(feature = "slirp")]
#[derive(Serialize, Deserialize, Debug)]
pub struct NetBackendConfig {
    pub guest_pipe: PipeConnection,
    pub slirp_kill_event: Event,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "net", description = "")]
pub struct Options {
    #[argh(
        option,
        description = "pipe handle end for Tube Transporter",
        arg_name = "HANDLE"
    )]
    bootstrap: usize,
}

#[cfg(all(windows, not(feature = "slirp")))]
compile_error!("vhost-user net device requires slirp feature on Windows.");

#[cfg(feature = "slirp")]
pub fn start_device(opts: Options) -> anyhow::Result<()> {
    // Get the Tubes from the TubeTransporter. Then get the "Config" from the bootstrap_tube
    // which will contain slirp settings.
    let raw_transport_tube = opts.bootstrap as RawDescriptor;

    let mut tubes = read_from_tube_transporter(raw_transport_tube).unwrap();

    let vhost_user_tube = tubes.get_tube(TubeToken::VhostUser).unwrap();
    let bootstrap_tube = tubes.get_tube(TubeToken::Bootstrap).unwrap();

    let startup_args: CommonChildStartupArgs =
        bootstrap_tube.recv::<CommonChildStartupArgs>().unwrap();
    let _child_cleanup = common_child_setup(startup_args).unwrap();

    let net_backend_config = bootstrap_tube.recv::<NetBackendConfig>().unwrap();

    let exit_event = bootstrap_tube.recv::<Event>()?;

    // We only have one net device for now.
    let dev = Box::new(
        NetBackend::<net_util::Slirp>::new_slirp(
            net_backend_config.guest_pipe,
            net_backend_config.slirp_kill_event,
        )
        .unwrap(),
    );

    let handler = DeviceRequestHandler::new(dev);

    let ex = Executor::new().context("failed to create executor")?;

    NET_EXECUTOR.with(|net_ex| {
        let _ = net_ex.set(ex.clone());
    });

    // TODO(b/213170185): Uncomment once sandbox is upstreamed.
    // if sandbox::is_sandbox_target() {
    //     sandbox::TargetServices::get()
    //         .expect("failed to get target services")
    //         .unwrap()
    //         .lower_token();
    // }

    info!("vhost-user net device ready, starting run loop...");
    if let Err(e) = ex.run_until(handler.run(vhost_user_tube, exit_event, &ex)) {
        bail!("error occurred: {}", e);
    }

    Ok(())
}
