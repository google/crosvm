use nix::fcntl::OFlag;
use nix::ioctl_write_ptr;
use nix::sys::stat::Mode;
use std::error::Error;
use std::os::raw::c_short;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixDatagram;

//pub const IFF_TUN: c_short = 0x0001;
pub const IFF_TAP: c_short = 0x0002;
pub const IFF_NO_PI: c_short = 0x1000;

const INTERFACE_NAME_SIZE: usize = 16;
const INTERFACE_REQUEST_UNION_SIZE: usize = 24;

const TUN_MAGIC: u8 = b'T';
const TUN_SETIFF: u8 = 202;

#[repr(C)]
#[derive(Default)]
pub struct InterfaceRequest {
    pub interface_name: [u8; INTERFACE_NAME_SIZE],
    pub union: InterfaceRequestUnion,
}

impl InterfaceRequest {
    pub fn with_interface_name(name: &str) -> Result<Self, Box<dyn Error>> {
        let mut interface_request: Self = Default::default();
        interface_request.set_interface_name(name)?;
        Ok(interface_request)
    }

    pub fn set_interface_name(&mut self, name: &str) -> Result<(), Box<dyn Error>> {
        let name_len = name.len();

        let mut name = Vec::from(name);
        if name_len < INTERFACE_NAME_SIZE {
            name.resize(INTERFACE_NAME_SIZE, 0);
        } else {
            return Err("interface name too long".into());
        }

        assert_eq!(name.len(), INTERFACE_NAME_SIZE);
        self.interface_name.clone_from_slice(&name);
        Ok(())
    }
}

#[repr(C)]
pub union InterfaceRequestUnion {
    pub data: [u8; INTERFACE_REQUEST_UNION_SIZE],
    pub flags: c_short,
}

impl Default for InterfaceRequestUnion {
    fn default() -> Self {
        InterfaceRequestUnion {
            data: Default::default(),
        }
    }
}

ioctl_write_ptr!(tun_set_iff, TUN_MAGIC, TUN_SETIFF, libc::c_int);

pub fn open(name: &str) -> Result<UnixDatagram, Box<dyn Error>> {
    let flags = IFF_TAP | IFF_NO_PI;
    let fd = nix::fcntl::open("/dev/net/tun", OFlag::O_RDWR, Mode::empty())?;

    let mut ifr = InterfaceRequest::with_interface_name(name)?;
    ifr.union.flags = flags;

    unsafe { tun_set_iff(fd, &mut ifr as *mut InterfaceRequest as *mut i32) }?;

    Ok(unsafe { UnixDatagram::from_raw_fd(fd) })
}
