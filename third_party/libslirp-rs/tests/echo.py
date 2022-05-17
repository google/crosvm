#!/usr/bin/env python3

import socket
import sys
import getopt


def main(argv):
    stype = socket.SOCK_STREAM
    opts, args = getopt.getopt(argv, "u")
    for opt, arg in opts:
        if opt == "-u":
            stype = socket.SOCK_DGRAM

    s = socket.socket(socket.AF_INET, stype)
    s.bind(("", 0))
    print(s.getsockname()[1], flush=True)

    if stype == socket.SOCK_STREAM:
        s.listen(1)
        s, _ = s.accept()

    while 1:
        data, addr = s.recvfrom(1024)
        if not data:
            break
        if addr:
            s.sendto(data, addr)
        else:
            s.sendall(data)
    s.close()


if __name__ == "__main__":
    main(sys.argv[1:])
