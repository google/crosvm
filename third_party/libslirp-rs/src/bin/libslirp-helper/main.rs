use std::convert::TryInto;
use std::error::Error;
use std::fs::File;
use std::io::{self, Cursor, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process;
use std::rc::Rc;

use enumflags2::BitFlags;
#[cfg(feature = "libsystemd")]
use libsystemd::daemon::{self, NotifyState};
use mio::unix::EventedFd;
use mio::*;
use nix::sched::{setns, CloneFlags};
use structopt::{clap::ArgGroup, StructOpt};
use zbus::dbus_interface;

#[macro_use]
extern crate lazy_static;

mod tun;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "libslirp-helper",
    about = "slirp helper process",
    rename_all = "kebab-case",
    group = ArgGroup::with_name("verb").required(true)
)]
struct Opt {
    /// Activate debug mode
    #[structopt(long)]
    debug: bool,
    /// Print capabilities
    #[structopt(long, group = "verb")]
    print_capabilities: bool,
    /// Exit with parent process
    #[structopt(long)]
    exit_with_parent: bool,
    /// DBus bus address
    #[structopt(long)]
    dbus_address: Option<String>,
    /// Helper instance ID
    #[structopt(long, name = "id")]
    dbus_id: Option<String>,
    /// Incoming migration data from DBus
    #[structopt(long)]
    dbus_incoming: bool,
    /// Unix datagram socket path
    #[structopt(long, parse(from_os_str), group = "verb")]
    socket_path: Option<PathBuf>,
    /// Unix datagram socket file descriptor
    #[structopt(long, group = "verb")]
    fd: Option<i32>,
    /// Incoming migration data
    #[structopt(long)]
    incoming_fd: Option<i32>,
    /// Set DHCP NBP URL (ex: tftp://10.0.0.1/my-nbp)
    #[structopt(long, name = "url")]
    dhcp_nbp: Option<String>,

    /// Path to network namespace to join.
    #[structopt(long)]
    netns: Option<PathBuf>,
    /// Interface name, such as "tun0".
    #[structopt(long, group = "verb")]
    interface: Option<String>,

    #[structopt(flatten)]
    slirp: libslirp::Opt,
}

fn set_exit_with_parent() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
    }
}

const DBUS_TOKEN: Token = Token(10_000_000);

fn slirp_state_read<'a, R: Read>(
    slirp: &libslirp::MioHandler<'a>,
    reader: &mut R,
) -> Result<(), Box<dyn Error>> {
    let mut buf = [0; 4];
    reader.read(&mut buf)?;
    let in_version = i32::from_be_bytes(buf);
    if in_version > libslirp::state_version() {
        return Err(format!(
            "Incompatible migration data version: {} > {}",
            in_version,
            libslirp::state_version()
        )
        .into());
    }

    slirp.ctxt.state_read(in_version, reader)?;
    slirp.register();
    Ok(())
}

fn print_capabilities() -> Result<(), Box<dyn Error>> {
    io::stdout().write_all(
        r#"{
  "type": "slirp-helper",
  "features": [
    "dbus-address",
    "dhcp",
    "exit-with-parent",
    "migrate",
    "tftp",
    "ipv4",
    "ipv6",
    "netns",
    "notify-socket",
    "restrict"
  ]
}
"#
        .as_bytes(),
    )?;

    Ok(())
}

fn set_netns(fd: RawFd) -> Result<(), nix::Error> {
    setns(fd, CloneFlags::CLONE_NEWNET)
}

lazy_static! {
    // XXX: when do we get async yet?
    static ref POLL: Poll = Poll::new().unwrap();
}

struct Slirp1 {
    slirp: Rc<libslirp::MioHandler<'static>>,
}

#[dbus_interface(name = "org.freedesktop.Slirp1.Helper")]
impl Slirp1 {
    fn get_info(&self) -> String {
        self.slirp.ctxt.connection_info().to_string()
    }
}

struct VMState1 {
    id: String,
    slirp: Rc<libslirp::MioHandler<'static>>,
}

#[dbus_interface(name = "org.qemu.VMState1")]
impl VMState1 {
    fn save(&self) -> zbus::fdo::Result<Vec<u8>> {
        let mut data = libslirp::state_version().to_be_bytes().to_vec();
        let mut state = self
            .slirp
            .ctxt
            .state_get()
            .map_err(|e| zbus::fdo::Error::Failed(format!("Failed to save: {}", e)))?;
        data.append(&mut state);
        Ok(data)
    }

    fn load(&self, data: &[u8]) -> zbus::fdo::Result<()> {
        let mut data = Cursor::new(data);
        Ok(slirp_state_read(&self.slirp, &mut data)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Failed to load: {}", e)))?)
    }

    #[dbus_interface(property)]
    fn id(&self) -> &str {
        &self.id
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let m = Opt::clap().get_matches();
    let mut opt = Opt::from_clap(&m);
    if opt.debug {
        dbg!(&opt);
    }
    if opt.print_capabilities {
        return print_capabilities();
    }

    if m.occurrences_of("dhcp-start") == 0 {
        let dhcp_start = opt.slirp.ipv4.net.nth(15).expect("Invalid --net");
        opt.slirp.ipv4.dhcp_start = dhcp_start;
    }

    if let Some(url) = &opt.dhcp_nbp {
        let url = url::Url::parse(url)?;
        if url.scheme() != "tftp" {
            return Err("Invalid NBP URL".into());
        }
        opt.slirp.tftp.name = Some(url.host_str().unwrap().to_string());
        opt.slirp.tftp.bootfile = Some(url.path().to_string());
    }

    let mut main_netns = None;
    if let Some(netns) = &opt.netns {
        main_netns = Some(File::open("/proc/self/ns/net")?);
        let netns = File::open(netns)?;
        set_netns(netns.as_raw_fd())?;
        opt.interface.get_or_insert("tun0".to_string());
    }

    let stream = match &opt {
        Opt { fd: Some(fd), .. } => unsafe { UnixDatagram::from_raw_fd(*fd) },
        Opt {
            socket_path: Some(path),
            ..
        } => UnixDatagram::bind(path)?,
        Opt {
            interface: Some(tun),
            ..
        } => tun::open(tun)?,
        _ => return Err("Missing a socket argument".into()),
    };

    if let Some(netns) = main_netns {
        set_netns(netns.as_raw_fd())?;
    }

    if opt.exit_with_parent {
        set_exit_with_parent();
    }

    let slirp = Rc::new(libslirp::MioHandler::new(&opt.slirp, &POLL, stream));

    let dbus = if let Some(dbus_addr) = opt.dbus_address {
        if opt.dbus_id.is_none() {
            return Err("You must specify an id with DBus".into());
        }

        let c = zbus::Connection::new_for_address(&dbus_addr, true)?;
        zbus::fdo::DBusProxy::new(&c)?.request_name(
            &format!("org.freedesktop.Slirp1_{}", process::id()),
            BitFlags::empty(),
        )?;
        zbus::fdo::DBusProxy::new(&c)?.request_name("org.qemu.VMState1", BitFlags::empty())?;

        let dbus_fd = c.as_raw_fd();
        POLL.register(
            &EventedFd(&dbus_fd),
            DBUS_TOKEN,
            Ready::readable(),
            PollOpt::level(),
        )?;

        Some(c)
    } else {
        None
    };

    let mut s = if let Some(c) = &dbus {
        let mut s = zbus::ObjectServer::new(c);
        s.at(
            &"/org/freedesktop/Slirp1/Helper".try_into()?,
            Slirp1 {
                slirp: slirp.clone(),
            },
        )?;
        s.at(
            &"/org/qemu/VMState1".try_into()?,
            VMState1 {
                id: opt.dbus_id.unwrap(),
                slirp: slirp.clone(),
            },
        )?;
        Some(s)
    } else {
        None
    };

    if opt.dbus_incoming && opt.incoming_fd.is_some() {
        return Err("Invalid multiple incoming paths.".into());
    }

    let mut events = Events::with_capacity(1024);
    let mut duration = None;

    if let Some(fd) = opt.incoming_fd {
        let mut f = unsafe { File::from_raw_fd(fd) };
        slirp_state_read(&slirp, &mut f)?;
    } else if !opt.dbus_incoming {
        slirp.register();
    }

    #[cfg(feature = "libsystemd")]
    daemon::notify(true, &[NotifyState::Ready])?;

    loop {
        if opt.debug {
            dbg!(duration);
        }

        POLL.poll(&mut events, duration)?;
        duration = slirp.dispatch(&events)?;
        if let Some(dbus) = &dbus {
            for event in &events {
                match event.token() {
                    DBUS_TOKEN => {
                        let m = dbus.receive_message()?;
                        if let Err(e) = s.as_mut().unwrap().dispatch_message(&m) {
                            eprintln!("{}", e);
                        }
                    }
                    _ => {
                        continue;
                    }
                }
            }
        }
    }
}
