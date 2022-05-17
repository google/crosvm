import ctypes
import functools
import io
import json
import os
import pathlib
import shlex
import signal
import socket
import subprocess
import tempfile
import unittest

from scapy.all import StreamSocket, sndrcv, Ether, conf, Route, ARP

SLIRPHELPER = os.environ.get("SLIRPHELPER")
LIBC = ctypes.CDLL("libc.so.6")
CLONE_NEWNET = 0x40000000
ORIGINAL_NET_NS = open("/proc/self/ns/net", "rb")
THISDIR = pathlib.Path(__file__).parent.absolute()
DBUS_SESSION_BUS_ADDRESS = os.environ.get("DBUS_SESSION_BUS_ADDRESS")


@functools.lru_cache()
def helper_capabilities():
    p = subprocess.run(
        [SLIRPHELPER, "--print-capabilities"], stdout=subprocess.PIPE, text=True
    )
    return json.loads(p.stdout)


def has_cap(cap):
    return cap in helper_capabilities()["features"]


class Process:
    def __init__(self, argv, close_fds=True, env=None):
        self.p = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=close_fds,
            env=env,
        )
        self.rc = None

    def stdout_all(self):
        return self.p.stdout.read()

    def stdout_line(self):
        return self.p.stdout.readline()

    def stderr_all(self):
        return self.p.stderr.read()

    def stderr_line(self):
        return self.p.stderr.readline()

    def close(self, kill=True):
        """Returns process return code."""
        if self.p:
            if kill:
                # Ensure the process registers two signals by sending a combo of
                # SIGINT and SIGTERM. Sending the same signal two times is racy
                # because the process can't reliably detect how many times the
                # signal was sent.
                self.p.send_signal(signal.SIGINT)
                self.p.send_signal(signal.SIGTERM)
            self.rc = self.p.wait()
            self.p.stderr.close()
            self.p.stdout.close()

        self.p = None
        return self.rc

    def graceful_stop(self, wait=True):
        self.p.send_signal(signal.SIGINT)
        if wait:
            self.p.wait()


class TestCase(unittest.TestCase):
    has_notify_socket = None
    execno = 0

    def setUp(self):
        if self.has_notify_socket is None:
            self.has_notify_socket = has_cap("notify-socket")

        self.cleanups = None
        prev_net_fd = open("/proc/self/ns/net", "rb")
        r = LIBC.unshare(CLONE_NEWNET)
        if r != 0:
            self.fail('Are you running within "unshare -Ur" ? Need unshare() syscall.')
        self.guest_net_fd = open("/proc/self/ns/net", "rb")
        self._add_teardown(self.guest_net_fd)

        # mode tap, means ethernet headers
        os.system(
            "ip link set lo up;"
            "ip tuntap add mode tap name tun0;"
            "ip link set tun0 mtu 65521;"
            "ip link set tun0 up;"
            "ip addr add 10.0.2.100/24 dev tun0;"
            "ip addr add 2001:2::100/32 dev tun0 nodad;"
            "ip route add 0.0.0.0/0 via 10.0.2.2 dev tun0;"
            "ip route add ::/0 via 2001:2::2 dev tun0;"
        )
        w = subprocess.Popen(["/bin/sleep", "1073741824"])
        self.guest_ns_pid = w.pid
        self._add_teardown(w)
        LIBC.setns(prev_net_fd.fileno(), CLONE_NEWNET)
        prev_net_fd.close()
        self._tmpdir = tempfile.TemporaryDirectory()
        self._add_teardown(self._tmpdir)

    def tearDown(self):
        while self.cleanups:
            item = self.cleanups.pop()
            if isinstance(item, subprocess.Popen):
                item.send_signal(signal.SIGINT)
                item.wait()
            elif isinstance(item, Process):
                item.close()
                if getattr(item, "stdout", None):
                    item.stdout.close()
                if getattr(item, "stderr", None):
                    item.stderr.close()
            elif isinstance(item, io.BufferedReader):
                item.close()
            elif isinstance(item, tempfile.TemporaryDirectory):
                item.cleanup()
            else:
                print("Unknown cleanup type")
                print(type(item))

    def run_helper(self, argv1=[], wait_ready=True, netns=True):
        if isinstance(argv1, str):
            argv1 = shlex.split(argv1)

        a = [SLIRPHELPER] + argv1
        if netns:
            a = a + ["--netns", self.net_ns_path(), "--interface", "tun0"]
        sn = None
        env = None
        if self.has_notify_socket and wait_ready:
            self.execno += 1
            sn = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            path = self.get_tmp_filename("sn-%d" % self.execno)
            sn.bind(path)
            env = dict(os.environ, NOTIFY_SOCKET="%s" % path)
        p = Process(a, close_fds=False, env=env)
        if sn:
            sn.settimeout(1)  # FIXME: remove timeout, end if process exit
            try:
                self.assertIn("READY=1", sn.recv(4096).decode())
            except:
                print(p.stderr_all())
            sn.close()
        self._add_teardown(p)
        return p

    def skipIfNotCapable(self, cap):
        if not has_cap(cap):
            self.skipTest("since '%s' capability is missing" % cap)

    def start_echo(self, udp=False):
        cmd = [THISDIR / "echo.py"]
        if udp:
            cmd += ["-u"]
        p = Process(cmd)
        self._add_teardown(p)
        return int(p.stdout_line())

    def assertTcpEcho(self, ip, port):
        data = os.getrandom(16)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.sendall(data)
            self.assertEqual(s.recv(len(data)), data)

    def assertUdpEcho(self, ip, port):
        data = os.getrandom(16)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(data, (ip, port))
            self.assertEqual(s.recv(len(data)), data)

    def get_tmp_filename(self, name):
        return os.path.join(self._tmpdir.name, name)

    def _add_teardown(self, item):
        if not self.cleanups:
            self.cleanups = []
        self.cleanups.append(item)

    def net_ns_path(self):
        return "/proc/%s/ns/net" % self.guest_ns_pid

    def guest_netns(self):
        xself = self

        class controlled_execution:
            def __enter__(self):
                self.prev_net_fd = open("/proc/self/ns/net", "rb")
                LIBC.setns(xself.guest_net_fd.fileno(), CLONE_NEWNET)

            def __exit__(self, type, value, traceback):
                LIBC.setns(self.prev_net_fd.fileno(), CLONE_NEWNET)
                self.prev_net_fd.close()

        return controlled_execution()


class testScapySocket:
    def __init__(self, fd):
        ss = StreamSocket(fd)
        ss.basecls = Ether
        self.ss = ss
        conf.route = Route()  # reinitializes the route based on the NS
        self.e = Ether(src="52:55:0a:00:02:42")

    def send(self, x):
        self.ss.send(self.e / x)

    def recv(self, x):
        # this is not symmetrical with send, which appends Ether
        # header, but ss.basecls will strip it of: not sure if that's
        # the best way of doing things in fact, but that seem to work..
        return self.ss.recv(x)

    def fileno(self):
        return self.ss.fileno()

    def sr1(self, x, checkIPaddr=True, *args, **kwargs):
        conf.checkIPaddr = checkIPaddr
        kwargs.setdefault("verbose", False)
        ans, _ = sndrcv(self.ss, self.e / x, *args, **kwargs)
        return ans[0][1]

    def sr(self, x, checkIPaddr=True, *args, **kwargs):
        conf.checkIPaddr = checkIPaddr
        kwargs.setdefault("verbose", False)
        return sndrcv(self.ss, self.e / x, *args, **kwargs)


def withScapy():
    def decorate(fn):
        @functools.wraps(fn)
        def maybe(*args, **kw):
            sp = socket.socketpair(type=socket.SOCK_DGRAM)
            os.set_inheritable(sp[0].fileno(), True)
            self = args[0]
            arg = kw.pop("parg", "")
            p = self.run_helper(arg + " --fd %d" % sp[0].fileno(), netns=False)
            s = testScapySocket(sp[1])
            # gratious advertizing ARP
            s.send(ARP(psrc="10.0.2.100", pdst="10.0.2.100", hwsrc=s.e.src))
            kw["s"] = s
            ret = fn(*args, **kw)
            sp[0].close()
            sp[1].close()
            return ret

        return maybe

    return decorate


def isolateHostNetwork():
    def decorate(fn):
        @functools.wraps(fn)
        def maybe(*args, **kw):
            prev_net_fd = open("/proc/self/ns/net", "rb")
            r = LIBC.unshare(CLONE_NEWNET)
            if r != 0:
                self.fail(
                    'Are you running within "unshare -Ur" ? Need unshare() syscall.'
                )
            # mode tun, since we don't actually plan on anyone reading the other side.
            os.system(
                "ip link set lo up;"
                "ip tuntap add mode tun name eth0;"
                "ip link set eth0 mtu 65521;"
                "ip link set eth0 up;"
                "ip addr add 192.168.1.100/24 dev eth0;"
                "ip addr add 3ffe::100/16 dev eth0 nodad;"
                "ip route add 0.0.0.0/0 via 192.168.1.1 dev eth0;"
                "ip route add ::/0 via 3ffe::1 dev eth0;"
            )
            ret = fn(*args, **kw)
            LIBC.setns(prev_net_fd.fileno(), CLONE_NEWNET)
            prev_net_fd.close()
            return ret

        return maybe

    return decorate
