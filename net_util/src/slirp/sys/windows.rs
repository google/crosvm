// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod handler;

use std::io::Read;
use std::io::Result as IoResult;
use std::io::Write;
use std::net;
use std::os::raw::*;
use std::os::windows::io::AsRawHandle;
use std::thread;

use base::info;
use base::named_pipes;
use base::named_pipes::BlockingMode;
use base::named_pipes::FramingMode;
use base::named_pipes::OverlappedWrapper;
use base::named_pipes::PipeConnection;
use base::named_pipes::ReadOverlapped;
use base::named_pipes::WriteOverlapped;
use base::warn;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::Event;
use base::RawDescriptor;
use base::ReadNotifier;
use cros_async::IntoAsync;
use serde::Deserialize;
use serde::Serialize;

use crate::slirp::SlirpError;
use crate::slirp::ETHERNET_FRAME_SIZE;
use crate::Error;
use crate::MacAddress;
use crate::Result;
use crate::TapT;
use crate::TapTCommon;

// Size of the buffer for packets in transit between the the virtio-net backend & Slirp.
pub const SLIRP_BUFFER_SIZE: usize = 1000 * ETHERNET_FRAME_SIZE;

/// Handle for a pseudo-tap interface backed by libslirp.
pub struct Slirp {
    guest_pipe: PipeConnection,
    overlapped_wrapper: OverlappedWrapper,
    slirp_thread: Option<thread::JoinHandle<()>>,
}

impl Slirp {
    // TODO(nkgold): delete this code path as single process mode is no longer supported.
    pub fn new(
        shutdown_event: Event,
        #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
        slirp_capture_file: &Option<String>,
    ) -> Result<Slirp> {
        let (host_pipe, guest_pipe) = named_pipes::pair_with_buffer_size(
            &FramingMode::Message,
            &BlockingMode::Wait,
            /* timeout= */ 0,
            SLIRP_BUFFER_SIZE,
            /* overlapped= */ true,
        )
        .map_err(SysError::from)
        .map_err(Error::CreateSocket)?;
        // TODO: (b/188947559): put this in a separate process
        let slirp_thread;
        {
            let slirp_pipe = host_pipe;
            #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
            let slirp_capture_file_clone = slirp_capture_file.clone();
            slirp_thread = thread::spawn(move || {
                let disable_access_to_host = !cfg!(feature = "guest-to-host-net-loopback");

                handler::start_slirp(
                    slirp_pipe,
                    shutdown_event,
                    disable_access_to_host,
                    #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
                    slirp_capture_file_clone,
                )
                .expect("Failed to start slirp");
            });
        }

        Ok(Slirp {
            guest_pipe,
            overlapped_wrapper: OverlappedWrapper::new(true).unwrap(),
            slirp_thread: Some(slirp_thread),
        })
    }

    /// Instantiate Slirp when running crosvm in multi process mode.
    pub fn new_for_multi_process(guest_pipe: PipeConnection) -> Result<Slirp> {
        Ok(Slirp {
            guest_pipe,
            overlapped_wrapper: OverlappedWrapper::new(true).unwrap(),
            slirp_thread: None,
        })
    }

    fn try_clone(&self) -> Result<Self> {
        Ok(Slirp {
            guest_pipe: self
                .guest_pipe
                .try_clone()
                .map_err(|e| Error::Slirp(SlirpError::CloneFailed(e)))?,
            overlapped_wrapper: OverlappedWrapper::new(true).unwrap(),
            slirp_thread: None,
        })
    }

    /// Start the Slirp listening loop. This is meant to be called when running crosvm in multi
    /// process mode.
    pub fn run_slirp_process(
        slirp_pipe: PipeConnection,
        shutdown_event: Event,
        #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
        mut slirp_capture_file: Option<String>,
    ) {
        // SLIRP_DEBUG is basically a CSV of debug options as defined in libslirp/src/slirp.c. See
        // g_parse_debug_string for more info on the format.
        std::env::set_var("SLIRP_DEBUG", "dhcp,error");

        // libslirp uses glib's g_debug facility. Yes, that means it has glib's log level system,
        // and its own internal system. Anyway, we have to tell glib to actually print things out,
        // because libslirp logs *everything* as a debug entry.
        std::env::set_var("G_MESSAGES_DEBUG", "all");

        let disable_access_to_host = !cfg!(feature = "guest-to-host-net-loopback");

        info!("starting slirp loop...");
        match handler::start_slirp(
            slirp_pipe,
            shutdown_event,
            disable_access_to_host,
            #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
            slirp_capture_file.take(),
        ) {
            Err(Error::Slirp(SlirpError::BrokenPipe(e))) => {
                warn!("exited slirp listening loop: {}", e)
            }
            Err(e) => panic!("error while running slirp listening loop: {}", e),
            _ => {}
        }
    }
}

impl Drop for Slirp {
    fn drop(&mut self) {
        if let Some(slirp_thread) = self.slirp_thread.take() {
            slirp_thread.join().expect("Failed to join slirp thread");
        }
    }
}

impl TapT for Slirp {}

impl TapTCommon for Slirp {
    fn new_with_name(_name: &[u8], _vnet_hdr: bool, _multi_vq: bool) -> Result<Self> {
        unimplemented!("not implemented for Slirp");
    }

    fn new(_vnet_hdr: bool, _multi_vq: bool) -> Result<Slirp> {
        unimplemented!("not implemented for Slirp");
    }

    fn into_mq_taps(self, vq_pairs: u16) -> Result<Vec<Self>> {
        if vq_pairs != 1 {
            unimplemented!("libslirp is single threaded; only one vq pair is supported.");
        }

        Ok(vec![self])
    }

    fn ip_addr(&self) -> Result<net::Ipv4Addr> {
        // Only used by the plugin system.
        unimplemented!("need to fetch the client's IP address from Slirp");
    }

    fn set_ip_addr(&self, _ip_addr: net::Ipv4Addr) -> Result<()> {
        // Only used by the plugin system.
        unimplemented!("need to fetch the client's IP address from Slirp");
    }

    fn netmask(&self) -> Result<net::Ipv4Addr> {
        // Only used by the plugin system.
        unimplemented!("need to fetch the client's IP address from Slirp");
    }

    fn set_netmask(&self, _netmask: net::Ipv4Addr) -> Result<()> {
        // Only used by the plugin system.
        unimplemented!("need to fetch the client's IP address from Slirp");
    }

    fn mtu(&self) -> Result<u16> {
        unimplemented!("Get MTU unsupported by Slirp");
    }

    fn set_mtu(&self, _mtu: u16) -> Result<()> {
        unimplemented!("Set MTU unsupported by Slirp");
    }

    fn mac_address(&self) -> Result<MacAddress> {
        // Only used by the plugin system.
        unimplemented!("need to fetch the client's IP address from Slirp");
    }

    fn set_mac_address(&self, _mac_addr: MacAddress) -> Result<()> {
        // Only used by the plugin system.
        unimplemented!("need to fetch the client's IP address from Slirp");
    }

    fn set_offload(&self, flags: c_uint) -> Result<()> {
        // Slirp does not support offload.
        if flags != 0 {
            unimplemented!("offloading is unsupported by Slirp.");
        }
        Ok(())
    }

    fn enable(&self) -> Result<()> {
        Ok(())
    }

    fn set_vnet_hdr_size(&self, _size: c_int) -> Result<()> {
        // Unused by Slirp specific code that uses this struct.
        unimplemented!("offloading is unsupported by Slirp.");
    }

    fn get_ifreq(&self) -> net_sys::ifreq {
        // Used only by accessors on this struct, which are unimplemented for Slirp.
        unimplemented!("not used by Slirp");
    }

    fn if_flags(&self) -> u32 {
        // This function is unused by the Slirp code paths.
        unimplemented!("not used by Slirp");
    }

    /// WARNING: This is used so that we can pass Slirp into a listening loop. StreamChannels can't
    /// have >1 reader on one end of a channel, but in Slirp, there is only one guest packet stream
    /// so we have one reader and one writer.
    fn try_clone(&self) -> Result<Self> {
        self.try_clone()
    }

    unsafe fn from_raw_descriptor(_descriptor: RawDescriptor) -> Result<Self> {
        unimplemented!("not used by Slirp");
    }
}

impl Read for Slirp {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        // Safe because we are reading simple bytes.
        unsafe {
            self.guest_pipe
                .read_overlapped(buf, &mut self.overlapped_wrapper)?;
        };
        self.guest_pipe
            .get_overlapped_result(&mut self.overlapped_wrapper)
            .map(|x| x as usize)
    }
}

impl ReadOverlapped for Slirp {
    /// # Safety
    /// See requirements on [ReadOverlapped].
    unsafe fn read_overlapped(
        &mut self,
        buf: &mut [u8],
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> IoResult<()> {
        self.guest_pipe.read_overlapped(buf, overlapped_wrapper)
    }

    fn read_result(&mut self, overlapped_wrapper: &mut OverlappedWrapper) -> IoResult<usize> {
        self.guest_pipe
            .get_overlapped_result(overlapped_wrapper)
            .map(|x| x as usize)
    }

    fn try_read_result(&mut self, overlapped_wrapper: &mut OverlappedWrapper) -> IoResult<usize> {
        self.guest_pipe
            .try_get_overlapped_result(overlapped_wrapper)
            .map(|x| x as usize)
    }
}

impl Write for Slirp {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        // SAFETY: safe because the operation ends with buf & overlapped_wrapper
        // still in scope.
        unsafe {
            self.guest_pipe
                .write_overlapped(buf, &mut self.overlapped_wrapper)?
        };
        self.guest_pipe
            .get_overlapped_result(&mut self.overlapped_wrapper)
            .map(|x| x as usize)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl WriteOverlapped for Slirp {
    /// # Safety
    /// See requirements on [WriteOverlapped].
    unsafe fn write_overlapped(
        &mut self,
        buf: &mut [u8],
        overlapped_wrapper: &mut OverlappedWrapper,
    ) -> IoResult<()> {
        self.guest_pipe.write_overlapped(buf, overlapped_wrapper)
    }

    fn write_result(&mut self, overlapped_wrapper: &mut OverlappedWrapper) -> IoResult<usize> {
        self.guest_pipe
            .get_overlapped_result(overlapped_wrapper)
            .map(|x| x as usize)
    }

    fn try_write_result(&mut self, overlapped_wrapper: &mut OverlappedWrapper) -> IoResult<usize> {
        self.guest_pipe
            .try_get_overlapped_result(overlapped_wrapper)
            .map(|x| x as usize)
    }
}

impl AsRawDescriptor for Slirp {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.guest_pipe.as_raw_descriptor()
    }
}

impl ReadNotifier for Slirp {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self.overlapped_wrapper.get_h_event_ref().unwrap()
    }
}

impl AsRawHandle for Slirp {
    fn as_raw_handle(&self) -> RawDescriptor {
        self.guest_pipe.as_raw_descriptor()
    }
}

impl IntoAsync for Slirp {}

/// Config arguments passed through the bootstrap Tube from the broker to the Slirp listening
/// process.
#[derive(Serialize, Deserialize, Debug)]
pub struct SlirpStartupConfig {
    pub slirp_pipe: PipeConnection,
    pub shutdown_event: Event,
    #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
    pub slirp_capture_file: Option<String>,
}
