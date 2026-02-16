// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod vmnet_ffi;

use std::ffi::CStr;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net;
use std::os::raw::c_uint;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::Arc;
use std::sync::Mutex;

use base::volatile_impl;
use base::AsRawDescriptor;
use base::FileReadWriteVolatile;
use base::RawDescriptor;
use base::ReadNotifier;
use cros_async::IntoAsync;

use crate::Error;
use crate::MacAddress;
use crate::Result;
use crate::TapTCommon;

use vmnet_ffi::*;

/// macOS TAP trait - matches Linux interface for cross-platform compatibility
pub trait TapT: FileReadWriteVolatile + TapTCommon {}

/// Shared vmnet interface state, wrapped in Arc<Mutex<>> so VmnetTap can be cloned.
struct VmnetInner {
    iface: interface_ref,
    queue: dispatch_queue_t,
}

// SAFETY: The vmnet interface_ref and dispatch_queue_t are thread-safe handles
// managed by Apple's vmnet.framework and GCD respectively.
unsafe impl Send for VmnetInner {}
unsafe impl Sync for VmnetInner {}

impl Drop for VmnetInner {
    fn drop(&mut self) {
        if !self.iface.is_null() {
            let sem = unsafe { dispatch_semaphore_create(0) };
            extern "C" fn stop_handler(block_ptr: *mut BlockWithCapture<dispatch_semaphore_t>, _status: u32) {
                unsafe { dispatch_semaphore_signal((*block_ptr).capture) };
            }
            let mut block = BlockWithCapture::new(
                stop_handler as *const std::ffi::c_void,
                sem,
            );
            unsafe {
                vmnet_stop_interface(self.iface, self.queue, block.as_ptr());
                dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
                dispatch_release(sem);
                dispatch_release(self.queue);
            }
        }
    }
}

/// A vmnet.framework-backed network interface for macOS, implementing the same
/// TAP-like interface that crosvm uses on Linux.
pub struct VmnetTap {
    inner: Arc<Mutex<VmnetInner>>,
    mac: MacAddress,
    mtu: u16,
    max_packet_size: usize,
    /// Read end of the notification pipe. A byte is written here when vmnet has
    /// packets available, making this fd pollable with kqueue/WaitContext.
    notify_read: RawFd,
    /// Write end of the notification pipe (used by the event callback).
    notify_write: RawFd,
}

impl VmnetTap {
    /// Start a vmnet interface in shared mode and return the interface along
    /// with its properties (MAC, MTU, max packet size).
    fn start_vmnet_interface() -> Result<(interface_ref, dispatch_queue_t, MacAddress, u16, usize)> {
        let queue = unsafe {
            dispatch_queue_create(
                c"org.chromium.crosvm.vmnet".as_ptr(),
                ptr::null(),
            )
        };
        if queue.is_null() {
            return Err(Error::Vmnet("failed to create dispatch queue".into()));
        }

        let desc = unsafe {
            let d = xpc_dictionary_create(ptr::null(), ptr::null(), 0);
            xpc_dictionary_set_uint64(d, vmnet_operation_mode_key, VMNET_SHARED_MODE);
            xpc_dictionary_set_bool(d, vmnet_allocate_mac_address_key, true);
            d
        };

        struct StartResult {
            sem: dispatch_semaphore_t,
            status: u32,
            props: xpc_object_t,
        }

        let sem = unsafe { dispatch_semaphore_create(0) };
        let mut result = StartResult {
            sem,
            status: VMNET_FAILURE,
            props: ptr::null_mut(),
        };

        extern "C" fn start_handler(
            block_ptr: *mut BlockWithCapture<*mut StartResult>,
            status: u32,
            props: xpc_object_t,
        ) {
            unsafe {
                let result = &mut *(*block_ptr).capture;
                result.status = status;
                result.props = props;
                dispatch_semaphore_signal(result.sem);
            }
        }

        let result_ptr: *mut StartResult = &mut result;
        let mut block = BlockWithCapture::new(
            start_handler as *const std::ffi::c_void,
            result_ptr,
        );

        let iface = unsafe {
            let i = vmnet_start_interface(desc, queue, block.as_ptr());
            dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
            dispatch_release(sem);
            xpc_release(desc);
            i
        };

        if result.status != VMNET_SUCCESS || iface.is_null() {
            unsafe { dispatch_release(queue) };
            return Err(Error::Vmnet(format!(
                "vmnet_start_interface failed with status {}",
                result.status
            )));
        }

        // Extract MAC address
        let mac = unsafe {
            let mac_str = xpc_dictionary_get_string(result.props, vmnet_mac_address_key);
            if mac_str.is_null() {
                dispatch_release(queue);
                return Err(Error::Vmnet("no MAC address in vmnet properties".into()));
            }
            let mac_cstr = CStr::from_ptr(mac_str);
            mac_cstr
                .to_str()
                .map_err(|_| Error::Vmnet("invalid MAC address string".into()))?
                .replace('-', ":")
                .parse::<MacAddress>()
                .map_err(|e| Error::Vmnet(format!("failed to parse MAC: {}", e)))?
        };

        // Extract MTU
        let mtu = unsafe {
            xpc_dictionary_get_uint64(result.props, vmnet_mtu_key) as u16
        };
        let mtu = if mtu == 0 { 1500 } else { mtu };

        // Extract max packet size
        let max_packet_size = unsafe {
            xpc_dictionary_get_uint64(result.props, vmnet_max_packet_size_key) as usize
        };
        let max_packet_size = if max_packet_size == 0 { 1514 } else { max_packet_size };

        Ok((iface, queue, mac, mtu, max_packet_size))
    }

    /// Set up the event callback so that a byte is written to `notify_write`
    /// whenever packets are available for reading.
    fn setup_event_callback(
        iface: interface_ref,
        queue: dispatch_queue_t,
        notify_write: RawFd,
    ) -> Result<()> {
        extern "C" fn event_handler(
            block_ptr: *mut BlockWithCapture<RawFd>,
            _event: u32,
            _props: xpc_object_t,
        ) {
            let fd = unsafe { (*block_ptr).capture };
            // Best-effort write; if the pipe is full the reader will still drain it.
            let buf: [u8; 1] = [1];
            unsafe { libc::write(fd, buf.as_ptr() as *const _, 1) };
        }

        let mut block = BlockWithCapture::new(
            event_handler as *const std::ffi::c_void,
            notify_write,
        );

        let ret = unsafe {
            vmnet_interface_set_event_callback(
                iface,
                VMNET_INTERFACE_PACKETS_AVAILABLE,
                queue,
                block.as_ptr(),
            )
        };

        if ret != VMNET_SUCCESS {
            return Err(Error::Vmnet(format!(
                "vmnet_interface_set_event_callback failed: {}",
                ret
            )));
        }

        // Leak the block so the callback closure stays alive for the lifetime
        // of the interface. It will be cleaned up when the interface is stopped.
        std::mem::forget(block);

        Ok(())
    }
}

impl TapTCommon for VmnetTap {
    fn new_with_name(_name: &[u8], _vnet_hdr: bool, _multi_vq: bool) -> Result<Self> {
        Self::new(_vnet_hdr, _multi_vq)
    }

    fn new(_vnet_hdr: bool, _multi_vq: bool) -> Result<Self> {
        let (iface, queue, mac, mtu, max_packet_size) = Self::start_vmnet_interface()?;

        // Create notification pipe (non-blocking read end)
        let mut pipe_fds = [0i32; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(Error::Vmnet("failed to create notification pipe".into()));
        }
        let notify_read = pipe_fds[0];
        let notify_write = pipe_fds[1];

        // Make read end non-blocking
        unsafe {
            let flags = libc::fcntl(notify_read, libc::F_GETFL);
            libc::fcntl(notify_read, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        // Set up the event callback
        Self::setup_event_callback(iface, queue, notify_write)?;

        Ok(VmnetTap {
            inner: Arc::new(Mutex::new(VmnetInner { iface, queue })),
            mac,
            mtu,
            max_packet_size,
            notify_read,
            notify_write,
        })
    }

    fn into_mq_taps(self, vq_pairs: u16) -> Result<Vec<Self>> {
        // vmnet doesn't support multi-queue; return self as a single tap
        let mut taps = Vec::new();
        if vq_pairs <= 1 {
            taps.push(self);
        } else {
            // For multi-queue, clone the interface
            for _ in 0..vq_pairs - 1 {
                taps.push(self.try_clone()?);
            }
            taps.insert(0, self);
        }
        Ok(taps)
    }

    fn ip_addr(&self) -> Result<net::Ipv4Addr> {
        // vmnet manages IP addressing internally; return a placeholder
        Ok(net::Ipv4Addr::new(192, 168, 64, 1))
    }

    fn set_ip_addr(&self, _ip_addr: net::Ipv4Addr) -> Result<()> {
        // vmnet manages IP addressing internally
        Ok(())
    }

    fn netmask(&self) -> Result<net::Ipv4Addr> {
        Ok(net::Ipv4Addr::new(255, 255, 255, 0))
    }

    fn set_netmask(&self, _netmask: net::Ipv4Addr) -> Result<()> {
        Ok(())
    }

    fn mtu(&self) -> Result<u16> {
        Ok(self.mtu)
    }

    fn set_mtu(&self, _mtu: u16) -> Result<()> {
        // vmnet doesn't support changing MTU after creation
        Ok(())
    }

    fn mac_address(&self) -> Result<MacAddress> {
        Ok(self.mac)
    }

    fn set_mac_address(&self, _mac_addr: MacAddress) -> Result<()> {
        // vmnet assigns MAC addresses; changing is not supported
        Ok(())
    }

    fn set_offload(&self, _flags: c_uint) -> Result<()> {
        // vmnet doesn't support offload configuration
        Ok(())
    }

    fn enable(&self) -> Result<()> {
        // vmnet interfaces are active immediately after creation
        Ok(())
    }

    fn try_clone(&self) -> Result<Self> {
        // Create new notification pipe for the clone
        let mut pipe_fds = [0i32; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(Error::Vmnet("failed to create notification pipe for clone".into()));
        }
        let notify_read = pipe_fds[0];
        let notify_write = pipe_fds[1];

        unsafe {
            let flags = libc::fcntl(notify_read, libc::F_GETFL);
            libc::fcntl(notify_read, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        // Set up event callback for the cloned pipe
        let inner = self.inner.lock().unwrap();
        Self::setup_event_callback(inner.iface, inner.queue, notify_write)?;
        drop(inner);

        Ok(VmnetTap {
            inner: Arc::clone(&self.inner),
            mac: self.mac,
            mtu: self.mtu,
            max_packet_size: self.max_packet_size,
            notify_read,
            notify_write,
        })
    }

    unsafe fn from_raw_descriptor(_descriptor: RawDescriptor) -> Result<Self> {
        // vmnet interfaces cannot be created from raw descriptors
        Err(Error::Vmnet(
            "VmnetTap cannot be created from raw descriptor".into(),
        ))
    }
}

impl Read for VmnetTap {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Drain the notification pipe (consume the "data available" signal)
        let mut drain = [0u8; 64];
        unsafe { libc::read(self.notify_read, drain.as_mut_ptr() as *mut _, drain.len()) };

        let inner = self.inner.lock().unwrap();

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut pkt = vmpktdesc {
            vm_pkt_size: buf.len(),
            vm_pkt_iov: &mut iov,
            vm_pkt_iovcnt: 1,
            vm_flags: 0,
        };
        let mut pktcnt: std::ffi::c_int = 1;

        let ret = unsafe { vmnet_read(inner.iface, &mut pkt, &mut pktcnt) };

        if ret != VMNET_SUCCESS {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("vmnet_read failed: {}", ret),
            ));
        }

        if pktcnt == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no packets available",
            ));
        }

        Ok(pkt.vm_pkt_size)
    }
}

impl Write for VmnetTap {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let inner = self.inner.lock().unwrap();

        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut pkt = vmpktdesc {
            vm_pkt_size: buf.len(),
            vm_pkt_iov: &mut iov,
            vm_pkt_iovcnt: 1,
            vm_flags: 0,
        };
        let mut pktcnt: std::ffi::c_int = 1;

        let ret = unsafe { vmnet_write(inner.iface, &mut pkt, &mut pktcnt) };

        if ret != VMNET_SUCCESS {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("vmnet_write failed: {}", ret),
            ));
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsRawFd for VmnetTap {
    fn as_raw_fd(&self) -> RawFd {
        self.notify_read
    }
}

impl AsRawDescriptor for VmnetTap {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.notify_read
    }
}

impl ReadNotifier for VmnetTap {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self
    }
}

impl Drop for VmnetTap {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.notify_read);
            libc::close(self.notify_write);
        }
    }
}

// Export VmnetTap as the platform Tap type
pub type Tap = VmnetTap;

impl TapT for VmnetTap {}
impl IntoAsync for VmnetTap {}
volatile_impl!(VmnetTap);
