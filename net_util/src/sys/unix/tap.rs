// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Read;
use std::io::Result as IoResult;
use std::io::Write;
use std::mem;
use std::net;
use std::os::raw::*;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;

use base::error;
use base::ioctl_with_mut_ref;
use base::ioctl_with_ref;
use base::ioctl_with_val;
use base::volatile_impl;
use base::warn;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::FileReadWriteVolatile;
use base::FromRawDescriptor;
use base::IoctlNr;
use base::RawDescriptor;
use base::ReadNotifier;
use cros_async::IntoAsync;
use libc::EPERM;

use crate::Error;
use crate::MacAddress;
use crate::Result;
use crate::TapT;
use crate::TapTCommon;

/// Handle for a network tap interface.
///
/// For now, this simply wraps the file descriptor for the tap device so methods
/// can run ioctls on the interface. The tap interface descriptor will be closed when
/// Tap goes out of scope, and the kernel will clean up the interface
/// automatically.
#[derive(Debug)]
pub struct Tap {
    tap_file: File,
    if_name: [c_char; 16usize],
    if_flags: ::std::os::raw::c_short,
}

impl Tap {
    /// # Safety
    /// 1. descriptor's ownership must be released by the caller. It is now owned by
    ///    the returned value (`Tap`), or is closed (if an error is returned).
    pub unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Result<Tap> {
        let tap_file = File::from_raw_descriptor(descriptor);

        // Get the interface name since we will need it for some ioctls.
        let mut ifreq: net_sys::ifreq = Default::default();
        let ret = ioctl_with_mut_ref(&tap_file, net_sys::TUNGETIFF(), &mut ifreq);

        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(Tap {
            tap_file,
            if_name: ifreq.ifr_ifrn.ifrn_name,
            if_flags: ifreq.ifr_ifru.ifru_flags,
        })
    }

    pub fn create_tap_with_ifreq(ifreq: &mut net_sys::ifreq) -> Result<Tap> {
        // Open calls are safe because we give a constant nul-terminated
        // string and verify the result.
        let rd = unsafe {
            libc::open64(
                b"/dev/net/tun\0".as_ptr() as *const c_char,
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if rd < 0 {
            return Err(Error::OpenTun(SysError::last()));
        }

        // We just checked that the fd is valid.
        let tuntap = unsafe { File::from_raw_descriptor(rd) };
        // ioctl is safe since we call it with a valid tap fd and check the return
        // value.
        let ret = unsafe { ioctl_with_mut_ref(&tuntap, net_sys::TUNSETIFF(), ifreq) };

        if ret < 0 {
            let error = SysError::last();

            // In a non-root, test environment, we won't have permission to call this; allow
            if !(cfg!(test) && error.errno() == EPERM) {
                return Err(Error::CreateTap(error));
            }
        }

        // Safe since only the name is accessed, and it's copied out.
        Ok(Tap {
            tap_file: tuntap,
            if_name: unsafe { ifreq.ifr_ifrn.ifrn_name },
            if_flags: unsafe { ifreq.ifr_ifru.ifru_flags },
        })
    }
    pub fn try_clone(&self) -> Result<Tap> {
        self.tap_file
            .try_clone()
            .map(|tap_file| Tap {
                tap_file,
                if_name: self.if_name,
                if_flags: self.if_flags,
            })
            .map_err(SysError::from)
            .map_err(Error::CloneTap)
    }
}

impl TapTCommon for Tap {
    /// Create a new tap interface.
    ///
    /// Set the `vnet_hdr` flag to true to allow offloading on this tap,
    /// which will add an extra 12 byte virtio net header to incoming frames. Offloading cannot
    /// be used if `vnet_hdr` is false.
    /// Set 'multi_vq' to true, if tap have multi virt queue pairs
    fn new(vnet_hdr: bool, multi_vq: bool) -> Result<Self> {
        const TUNTAP_DEV_FORMAT: &[u8] = b"vmtap%d";
        Self::new_with_name(TUNTAP_DEV_FORMAT, vnet_hdr, multi_vq)
    }

    fn new_with_name(name: &[u8], vnet_hdr: bool, multi_vq: bool) -> Result<Tap> {
        // This is pretty messy because of the unions used by ifreq. Since we
        // don't call as_mut on the same union field more than once, this block
        // is safe.
        let mut ifreq: net_sys::ifreq = Default::default();
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            for (dst, src) in ifrn_name
                .iter_mut()
                // Add a zero terminator to the source string.
                .zip(name.iter().chain(std::iter::once(&0)))
            {
                *dst = *src as c_char;
            }
            ifreq.ifr_ifru.ifru_flags =
                (libc::IFF_TAP | libc::IFF_NO_PI | if vnet_hdr { libc::IFF_VNET_HDR } else { 0 })
                    as c_short;
            if multi_vq {
                ifreq.ifr_ifru.ifru_flags |= libc::IFF_MULTI_QUEUE as c_short;
            }
        }

        Tap::create_tap_with_ifreq(&mut ifreq)
    }

    fn into_mq_taps(self, vq_pairs: u16) -> Result<Vec<Tap>> {
        let mut taps: Vec<Tap> = Vec::new();

        if vq_pairs <= 1 {
            taps.push(self);
            return Ok(taps);
        }

        // Add other socket into the origin tap interface
        for _ in 0..vq_pairs - 1 {
            let mut ifreq = self.get_ifreq();
            let tap = Tap::create_tap_with_ifreq(&mut ifreq)?;

            tap.enable()?;

            taps.push(tap);
        }

        taps.insert(0, self);
        Ok(taps)
    }

    fn ip_addr(&self) -> Result<net::Ipv4Addr> {
        let sock = create_socket()?;
        let mut ifreq = self.get_ifreq();

        // ioctl is safe. Called with a valid sock descriptor, and we check the return.
        let ret = unsafe {
            ioctl_with_mut_ref(&sock, net_sys::sockios::SIOCGIFADDR as IoctlNr, &mut ifreq)
        };

        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        // We only access one field of the ifru union, hence this is safe.
        let addr = unsafe { ifreq.ifr_ifru.ifru_addr };

        Ok(read_ipv4_addr(&addr))
    }

    fn set_ip_addr(&self, ip_addr: net::Ipv4Addr) -> Result<()> {
        let sock = create_socket()?;
        let addr = create_sockaddr(ip_addr);

        let mut ifreq = self.get_ifreq();
        ifreq.ifr_ifru.ifru_addr = addr;

        // ioctl is safe. Called with a valid sock descriptor, and we check the return.
        let ret =
            unsafe { ioctl_with_ref(&sock, net_sys::sockios::SIOCSIFADDR as IoctlNr, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn netmask(&self) -> Result<net::Ipv4Addr> {
        let sock = create_socket()?;
        let mut ifreq = self.get_ifreq();

        // ioctl is safe. Called with a valid sock descriptor, and we check the return.
        let ret = unsafe {
            ioctl_with_mut_ref(
                &sock,
                net_sys::sockios::SIOCGIFNETMASK as IoctlNr,
                &mut ifreq,
            )
        };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        // We only access one field of the ifru union, hence this is safe.
        let addr = unsafe { ifreq.ifr_ifru.ifru_netmask };

        Ok(read_ipv4_addr(&addr))
    }

    fn set_netmask(&self, netmask: net::Ipv4Addr) -> Result<()> {
        let sock = create_socket()?;
        let addr = create_sockaddr(netmask);

        let mut ifreq = self.get_ifreq();
        ifreq.ifr_ifru.ifru_netmask = addr;

        // ioctl is safe. Called with a valid sock descriptor, and we check the return.
        let ret =
            unsafe { ioctl_with_ref(&sock, net_sys::sockios::SIOCSIFNETMASK as IoctlNr, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn mtu(&self) -> Result<u16> {
        let sock = create_socket()?;
        let mut ifreq = self.get_ifreq();

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret = unsafe {
            ioctl_with_mut_ref(&sock, net_sys::sockios::SIOCGIFMTU as IoctlNr, &mut ifreq)
        };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        // We only access one field of the ifru union, hence this is safe.
        let mtu = unsafe { ifreq.ifr_ifru.ifru_mtu } as u16;
        Ok(mtu)
    }

    fn set_mtu(&self, mtu: u16) -> Result<()> {
        let sock = create_socket()?;

        let mut ifreq = self.get_ifreq();
        ifreq.ifr_ifru.ifru_mtu = i32::from(mtu);

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret = unsafe { ioctl_with_ref(&sock, net_sys::sockios::SIOCSIFMTU as IoctlNr, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn mac_address(&self) -> Result<MacAddress> {
        let sock = create_socket()?;
        let mut ifreq = self.get_ifreq();

        // ioctl is safe. Called with a valid sock descriptor, and we check the return.
        let ret = unsafe {
            ioctl_with_mut_ref(
                &sock,
                net_sys::sockios::SIOCGIFHWADDR as IoctlNr,
                &mut ifreq,
            )
        };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        // We only access one field of the ifru union, hence this is safe.
        // This is safe since the MacAddress struct is already sized to match the C sockaddr
        // struct. The address family has also been checked.
        Ok(unsafe { mem::transmute(ifreq.ifr_ifru.ifru_hwaddr) })
    }

    fn set_mac_address(&self, mac_addr: MacAddress) -> Result<()> {
        let sock = create_socket()?;

        let mut ifreq = self.get_ifreq();

        // We only access one field of the ifru union, hence this is safe.
        unsafe {
            // This is safe since the MacAddress struct is already sized to match the C sockaddr
            // struct.
            ifreq.ifr_ifru.ifru_hwaddr = std::mem::transmute(mac_addr);
        }

        // ioctl is safe. Called with a valid sock descriptor, and we check the return.
        let ret =
            unsafe { ioctl_with_ref(&sock, net_sys::sockios::SIOCSIFHWADDR as IoctlNr, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn set_offload(&self, flags: c_uint) -> Result<()> {
        // ioctl is safe. Called with a valid tap descriptor, and we check the return.
        let ret =
            unsafe { ioctl_with_val(&self.tap_file, net_sys::TUNSETOFFLOAD(), flags as c_ulong) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn enable(&self) -> Result<()> {
        let sock = create_socket()?;

        let mut ifreq = self.get_ifreq();
        ifreq.ifr_ifru.ifru_flags =
            (net_sys::net_device_flags::IFF_UP | net_sys::net_device_flags::IFF_RUNNING).0 as i16;

        // ioctl is safe. Called with a valid sock descriptor, and we check the return.
        let ret =
            unsafe { ioctl_with_ref(&sock, net_sys::sockios::SIOCSIFFLAGS as IoctlNr, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn set_vnet_hdr_size(&self, size: c_int) -> Result<()> {
        // ioctl is safe. Called with a valid tap descriptor, and we check the return.
        let ret = unsafe { ioctl_with_ref(&self.tap_file, net_sys::TUNSETVNETHDRSZ(), &size) };
        if ret < 0 {
            return Err(Error::IoctlError(SysError::last()));
        }

        Ok(())
    }

    fn get_ifreq(&self) -> net_sys::ifreq {
        let mut ifreq: net_sys::ifreq = Default::default();

        // This sets the name of the interface, which is the only entry
        // in a single-field union.
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            ifrn_name.clone_from_slice(&self.if_name);
        }

        // This sets the flags with which the interface was created, which is the only entry we set
        // on the second union.
        ifreq.ifr_ifru.ifru_flags = self.if_flags;

        ifreq
    }

    fn if_flags(&self) -> u32 {
        self.if_flags as u32
    }

    fn try_clone(&self) -> Result<Self> {
        self.try_clone()
    }

    // Safe if caller provides a valid descriptor.
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Result<Self> {
        Tap::from_raw_descriptor(descriptor)
    }
}

impl Read for Tap {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.tap_file.read(buf)
    }
}

impl Write for Tap {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.tap_file.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.tap_file.as_raw_descriptor()
    }
}

impl AsRawDescriptor for Tap {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.tap_file.as_raw_descriptor()
    }
}

impl ReadNotifier for Tap {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self
    }
}

fn create_socket() -> Result<net::UdpSocket> {
    // This is safe since we check the return value.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock >= 0 {
        // This is safe; nothing else will use or hold onto the raw sock descriptor.
        return Ok(unsafe { net::UdpSocket::from_raw_fd(sock) });
    }

    warn!("INET not supported on this machine. Trying to open an INET6 socket.");

    // Open an AF_INET6 socket
    let sock6 = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sock6 >= 0 {
        // This is safe; nothing else will use or hold onto the raw sock descriptor.
        return Ok(unsafe { net::UdpSocket::from_raw_fd(sock6) });
    }

    error!("Neither INET nor INET6 supported on this machine");

    return Err(Error::CreateSocket(SysError::last()));
}

/// Create a sockaddr_in from an IPv4 address, and expose it as
/// an opaque sockaddr suitable for usage by socket ioctls.
fn create_sockaddr(ip_addr: net::Ipv4Addr) -> libc::sockaddr {
    // IPv4 addresses big-endian (network order), but Ipv4Addr will give us
    // a view of those bytes directly so we can avoid any endian trickiness.
    let addr_in = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: unsafe { mem::transmute(ip_addr.octets()) },
        sin_zero: [0; 8usize],
    };

    unsafe { mem::transmute(addr_in) }
}

/// Extract the IPv4 address from a sockaddr. Assumes the sockaddr is a sockaddr_in.
fn read_ipv4_addr(addr: &libc::sockaddr) -> net::Ipv4Addr {
    debug_assert_eq!(addr.sa_family as i32, libc::AF_INET);
    // This is safe because sockaddr and sockaddr_in are the same size, and we've checked that
    // this address is AF_INET.
    let in_addr: libc::sockaddr_in = unsafe { mem::transmute(*addr) };
    net::Ipv4Addr::from(in_addr.sin_addr.s_addr)
}

impl TapT for Tap {}
impl IntoAsync for Tap {}
volatile_impl!(Tap);

pub mod fakes {
    use std::fs::remove_file;
    use std::fs::OpenOptions;

    use super::*;

    const TMP_FILE: &str = "/tmp/crosvm_tap_test_file";

    pub struct FakeTap {
        tap_file: File,
    }

    impl TapTCommon for FakeTap {
        fn new(_vnet_hdr: bool, _multi_vq: bool) -> Result<Self> {
            // Params don't matter
            Self::new_with_name(b"", false, false)
        }

        fn new_with_name(_: &[u8], _: bool, _: bool) -> Result<FakeTap> {
            Ok(FakeTap {
                tap_file: OpenOptions::new()
                    .read(true)
                    .append(true)
                    .create(true)
                    .open(TMP_FILE)
                    .unwrap(),
            })
        }

        fn into_mq_taps(self, _vq_pairs: u16) -> Result<Vec<FakeTap>> {
            Ok(Vec::new())
        }

        fn ip_addr(&self) -> Result<net::Ipv4Addr> {
            Ok(net::Ipv4Addr::new(1, 2, 3, 4))
        }

        fn set_ip_addr(&self, _: net::Ipv4Addr) -> Result<()> {
            Ok(())
        }

        fn netmask(&self) -> Result<net::Ipv4Addr> {
            Ok(net::Ipv4Addr::new(255, 255, 255, 252))
        }

        fn set_netmask(&self, _: net::Ipv4Addr) -> Result<()> {
            Ok(())
        }

        fn mtu(&self) -> Result<u16> {
            Ok(1500)
        }

        fn set_mtu(&self, _: u16) -> Result<()> {
            Ok(())
        }

        fn mac_address(&self) -> Result<MacAddress> {
            Ok("01:02:03:04:05:06".parse().unwrap())
        }

        fn set_mac_address(&self, _: MacAddress) -> Result<()> {
            Ok(())
        }

        fn set_offload(&self, _: c_uint) -> Result<()> {
            Ok(())
        }

        fn enable(&self) -> Result<()> {
            Ok(())
        }

        fn set_vnet_hdr_size(&self, _: c_int) -> Result<()> {
            Ok(())
        }

        fn get_ifreq(&self) -> net_sys::ifreq {
            let ifreq: net_sys::ifreq = Default::default();
            ifreq
        }

        fn if_flags(&self) -> u32 {
            net_sys::IFF_TAP
        }

        // Return self so it can compile
        fn try_clone(&self) -> Result<Self> {
            Ok(FakeTap {
                tap_file: self.tap_file.try_clone().unwrap(),
            })
        }

        unsafe fn from_raw_descriptor(_descriptor: RawDescriptor) -> Result<Self> {
            unimplemented!()
        }
    }

    impl Drop for FakeTap {
        fn drop(&mut self) {
            let _ = remove_file(TMP_FILE);
        }
    }

    impl Read for FakeTap {
        fn read(&mut self, _: &mut [u8]) -> IoResult<usize> {
            Ok(0)
        }
    }

    impl Write for FakeTap {
        fn write(&mut self, _: &[u8]) -> IoResult<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    impl AsRawFd for FakeTap {
        fn as_raw_fd(&self) -> RawFd {
            self.tap_file.as_raw_descriptor()
        }
    }

    impl AsRawDescriptor for FakeTap {
        fn as_raw_descriptor(&self) -> RawDescriptor {
            self.tap_file.as_raw_descriptor()
        }
    }
    impl TapT for FakeTap {}
    volatile_impl!(FakeTap);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tap_create() {
        Tap::new(true, false).unwrap();
    }

    #[test]
    fn tap_configure() {
        let tap = Tap::new(true, false).unwrap();
        let ip_addr: net::Ipv4Addr = "100.115.92.5".parse().unwrap();
        let netmask: net::Ipv4Addr = "255.255.255.252".parse().unwrap();
        let mac_addr: MacAddress = "a2:06:b9:3d:68:4d".parse().unwrap();

        let ret = tap.set_ip_addr(ip_addr);
        assert_ok_or_perm_denied(ret);
        let ret = tap.set_netmask(netmask);
        assert_ok_or_perm_denied(ret);
        let ret = tap.set_mac_address(mac_addr);
        assert_ok_or_perm_denied(ret);
    }

    /// This test will only work if the test is run with root permissions and, unlike other tests
    /// in this file, do not return PermissionDenied. They fail because the TAP descriptor is not
    /// initialized (as opposed to permission denial). Run this with "cargo test -- --ignored".
    #[test]
    #[ignore]
    fn root_only_tests() {
        // This line will fail to provide an initialized descriptor if the test is not run as root.
        let tap = Tap::new(true, false).unwrap();
        tap.set_vnet_hdr_size(16).unwrap();
        tap.set_offload(0).unwrap();
    }

    #[test]
    fn tap_enable() {
        let tap = Tap::new(true, false).unwrap();

        let ret = tap.enable();
        assert_ok_or_perm_denied(ret);
    }

    fn assert_ok_or_perm_denied<T>(res: Result<T>) {
        match res {
            // We won't have permission in test environments; allow that
            Ok(_t) => {}
            Err(Error::IoctlError(e)) if e.errno() == EPERM => {}
            Err(e) => panic!("Unexpected Error:\n{}", e),
        }
    }
}
