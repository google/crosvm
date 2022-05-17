import json
import unittest

from . import base
from scapy.all import *
from ipaddress import IPv4Address
from pydbus import SessionBus


class CLITest(base.TestCase):
    def test_help(self):
        """ Test if -h prints stuff looking like help screen. """
        p = self.run_helper("-h", netns=False, wait_ready=False)
        e = p.stderr_all()
        self.assertFalse(e)
        o = p.stdout_all().lower()
        self.assertIn("usage:", o)

    def test_print_capabilities(self):
        """ Test if --print-capabilities output valid json. """
        p = self.run_helper("--print-capabilities", netns=False, wait_ready=False)
        e = p.stderr_all()
        self.assertFalse(e)
        o = p.stdout_all()
        j = json.loads(o)
        self.assertEqual(j["type"], "slirp-helper")
        if "features" in j:
            self.assertIsInstance(j["features"], list)
            f = set(j["features"])
            unknown = f.difference(
                {
                    "dbus-address",
                    "dhcp",
                    "exit-with-parent",
                    "ipv4",
                    "ipv6",
                    "migrate",
                    "netns",
                    "notify-socket",
                    "restrict",
                    "tftp",
                }
            )
            for cap in unknown:
                if not cap.startswith("x-"):
                    self.fail("Unknown capability: %s" % cap)

    def test_restrict(self):
        """ Basic test if 'restrict' options exists. """
        self.skipIfNotCapable("restrict")
        self.run_helper("--restrict")

    def test_ipv4(self):
        """ Basic test if 'ipv4' options exists. """
        self.skipIfNotCapable("ipv4")
        self.run_helper("--disable-ipv4 --net 12.12.0.1/8")

    def test_ipv4(self):
        """ Basic test if 'ipv6' options exists. """
        self.skipIfNotCapable("ipv6")
        self.run_helper("--disable-ipv6 --net6 fec0::/64")

    def test_exit_with_parent(self):
        """ Basic test if 'exit-with-parent' option exists. """
        self.skipIfNotCapable("exit-with-parent")
        self.run_helper("--exit-with-parent")

    def test_tftp(self):
        """ Basic test if 'tftp' options exists. """
        self.skipIfNotCapable("tftp")
        self.run_helper("--tftp .")

    def test_net(self):
        """ Basic test if --net parses successfully. """
        p = self.run_helper("--net 12.12.0.1/23")
        p.graceful_stop()
        p = self.run_helper("--net wefo/23", wait_ready=False)
        e = p.stderr_all()
        self.assertTrue(e)
        p.graceful_stop()

    def test_dbus(self):
        """ Test if --dbus-address works. """
        self.skipIfNotCapable("dbus-address")
        if not base.DBUS_SESSION_BUS_ADDRESS:
            self.skipTest("DBUS_SESSION_BUS_ADDRESS unset")
        p = self.run_helper(
            "--dbus-id TestId --dbus-address %s" % base.DBUS_SESSION_BUS_ADDRESS
        )
        bus = SessionBus()
        iface = bus.get(".Slirp1_%u" % p.p.pid, "/org/freedesktop/Slirp1/Helper")
        info = iface.GetInfo()
        self.assertIn("Protocol[State]", info)


class ConnTest(base.TestCase):
    @base.withScapy()
    def test_ping(self, s):
        """ Test Scapy ping """
        pkt = s.sr1(IP(dst="10.0.2.2") / ICMP())
        self.assertEqual(pkt.sprintf("%ICMP.type%"), "echo-reply")

    @base.isolateHostNetwork()
    def test_restrict(self):
        """ Test --restrict behaviour """
        port = self.start_echo()
        self.run_helper("--restrict")
        with self.guest_netns():
            with self.assertRaises((ConnectionError, ConnectionRefusedError)):
                self.assertTcpEcho("192.168.1.100", port)

    @base.isolateHostNetwork()
    def test_tcp_echo(self):
        """ Test TCP echo """
        port = self.start_echo()
        self.run_helper()
        with self.guest_netns():
            self.assertTcpEcho("192.168.1.100", port)

    @base.isolateHostNetwork()
    def test_udp_echo(self):
        """ Test UDP echo """
        port = self.start_echo(udp=True)
        self.run_helper()
        with self.guest_netns():
            self.assertUdpEcho("192.168.1.100", port)


@unittest.skipUnless(base.has_cap("dhcp"), "Missing 'dhcp' feature")
class DHCPTest(base.TestCase):
    @base.withScapy()
    def test_dhcp_v4(self, s):
        """ Test DHCPv4 discover """
        bootp = BOOTP(xid=RandInt())
        dhcp = DHCP(options=[("message-type", "discover"), "end"])
        p = (
            IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / bootp
            / dhcp
        )
        pkt = s.sr1(p, checkIPaddr=False)
        self.assertEqual(pkt.sprintf("%BOOTP.op%"), "BOOTREPLY")
        addr = IPv4Address(pkt[BOOTP].yiaddr)
        self.assertGreaterEqual(addr, IPv4Address("10.0.2.15"))
        self.assertLess(addr, IPv4Address("10.0.2.100"))
        for o in pkt[DHCP].options:
            if o[0] in ("router", "server_id"):
                self.assertEqual(o[1], "10.0.2.2")
        opts = [o[0] for o in pkt[DHCP].options if isinstance(o, tuple)]
        self.assertIn("router", opts)
        self.assertIn("name_server", opts)
        self.assertIn("lease_time", opts)
        self.assertIn("server_id", opts)

    @base.withScapy()
    def dhcp_and_net(self, s):
        bootp = BOOTP(xid=RandInt())
        dhcp = DHCP(options=[("message-type", "discover"), "end"])
        p = (
            IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / bootp
            / dhcp
        )
        pkt = s.sr1(p, checkIPaddr=False)
        self.assertEqual(pkt.sprintf("%BOOTP.op%"), "BOOTREPLY")
        addr = IPv4Address(pkt[BOOTP].yiaddr)
        self.assertGreaterEqual(addr, IPv4Address("12.34.56.15"))
        self.assertLess(addr, IPv4Address("12.34.56.100"))

    def test_dhcp_and_net(self):
        """ Test DHCPv4 and -net """
        self.dhcp_and_net(parg="--net 12.34.56.1/24")

    @base.withScapy()
    def dhcp_dns(self, s):
        bootp = BOOTP(xid=RandInt())
        dhcp = DHCP(options=[("message-type", "discover"), "end"])
        p = (
            IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / bootp
            / dhcp
        )
        pkt = s.sr1(p, checkIPaddr=False)
        # BOOTREPLY
        for o in pkt[DHCP].options:
            if o[0] == "name_server":
                self.assertEqual(o[1], "8.8.8.8")
                return
        self.fail()

    def test_dhcp_dns(self):
        """ Test DHCPv4 DNS option """
        self.dhcp_dns(parg="--dhcp-dns 8.8.8.8")

    @base.withScapy()
    def dhcp_nbp(self, s):
        bootp = BOOTP(xid=RandInt())
        dhcp = DHCP(options=[("message-type", "discover"), "end"])
        p = (
            IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / bootp
            / dhcp
        )
        pkt = s.sr1(p, checkIPaddr=False)
        # BOOTREPLY
        bootFileName = pkt[BOOTP].file.partition(b"\0")[0].decode()
        tftpServerName = None
        for o in pkt[DHCP].options:
            if o[0] == "boot-file-name":
                bootFileName = o[1].decode()  # Higher precedence?
            elif o[0] in (
                66,
                "tftp-server-name",
                "tftp_server_name",
            ):  # FIXME: scapy doesn't know that field?
                tftpServerName = o[1].decode()
        self.assertEqual(tftpServerName, "10.0.0.1")
        self.assertEqual(bootFileName, "/my-nbp")

    def test_dhcp_nbp(self):
        """ Test DHCPv4 NBP option """
        self.dhcp_nbp(parg="--dhcp-nbp tftp://10.0.0.1/my-nbp")

    @base.withScapy()
    def dhcp_bootfile(self, s):
        bootp = BOOTP(xid=RandInt())
        dhcp = DHCP(options=[("message-type", "discover"), "end"])
        p = (
            IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / bootp
            / dhcp
        )
        pkt = s.sr1(p, checkIPaddr=False)
        # BOOTREPLY
        self.assertEqual(
            pkt[BOOTP].file.partition(b"\0")[0].decode(), "http://boot.netboot.xyz/"
        )

    def test_dhcp_bootfile(self):
        """ Test DHCPv4 bootfile option """
        self.dhcp_bootfile(parg="--dhcp-bootfile http://boot.netboot.xyz/")
