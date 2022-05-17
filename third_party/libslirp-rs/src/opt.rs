use ipnetwork::{Ipv4Network, Ipv6Network};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct OptIpv4 {
    /// Whether to disable IPv4
    #[structopt(name = "disable-ipv4", long = "disable-ipv4")]
    pub disable: bool,
    /// IPv4 network CIDR
    #[structopt(name = "net", long = "net", default_value = "10.0.2.0/24")]
    pub net: Ipv4Network,
    /// Guest-visible address of the host
    #[structopt(long, default_value = "10.0.2.2")]
    pub host: Ipv4Addr,
    /// The first of the 16 IPs the built-in DHCP server can assign
    #[structopt(
        name = "dhcp-start",
        long = "dhcp-start",
        short,
        default_value = "10.0.2.15"
    )]
    pub dhcp_start: Ipv4Addr,
    /// Guest-visible address of the virtual nameserver
    #[structopt(long = "dhcp-dns", default_value = "10.0.2.3")]
    pub dns: Ipv4Addr,
}

#[derive(Debug, StructOpt)]
pub struct OptIpv6 {
    /// Whether to disable IPv6
    #[structopt(name = "disable-ipv6", long = "disable-ipv6")]
    pub disable: bool,
    /// IPv6 network CIDR
    #[structopt(name = "net6", long = "net6", default_value = "fec0::/64")]
    pub net6: Ipv6Network,
    /// Guest-visible IPv6 address of the host
    #[structopt(name = "host-ipv6", long = "host-ipv6", default_value = "fec0::2")]
    pub host: Ipv6Addr,
    /// Guest-visible address of the virtual nameserver
    #[structopt(name = "dns-ipv6", long, default_value = "fec0::3")]
    pub dns: Ipv6Addr,
}

#[derive(Debug, StructOpt)]
pub struct OptTftp {
    /// RFC2132 "TFTP server name" string
    #[structopt(name = "name", long = "tftp-name")]
    pub name: Option<String>,
    /// root directory of the built-in TFTP server
    #[structopt(name = "root-path", parse(from_os_str), long = "tftp")]
    pub root: Option<PathBuf>,
    /// BOOTP filename, for use with tftp
    #[structopt(long = "dhcp-bootfile")]
    pub bootfile: Option<String>,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "slirp-opt")]
pub struct Opt {
    /// Isolate guest from host
    #[structopt(long, short)]
    pub restrict: bool,
    /// Set interface MTU
    #[structopt(long, default_value = "1500")]
    pub mtu: usize,
    /// Prohibit connection to 127.0.0.1
    #[structopt(long)]
    pub disable_host_loopback: bool,

    /// Client hostname reported by the builtin DHCP server
    #[structopt(long)]
    pub hostname: Option<String>,
    /// List of DNS suffixes to search, passed as DHCP option to the guest
    #[structopt(long = "dns-suffixes")]
    pub dns_suffixes: Vec<String>,
    /// Guest-visible domain name of the virtual nameserver from DHCP server
    #[structopt(long)]
    pub domainname: Option<String>,

    #[structopt(flatten)]
    pub ipv4: OptIpv4,
    #[structopt(flatten)]
    pub ipv6: OptIpv6,
    #[structopt(flatten)]
    pub tftp: OptTftp,
}
