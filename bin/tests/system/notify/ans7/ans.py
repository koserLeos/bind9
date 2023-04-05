# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import os
import select
import signal
import socket
import sys
import time

import dns.flags
import dns.message


def port():
    env_port = os.getenv("PORT")
    if env_port is None:
        env_port = 5300
    else:
        env_port = int(env_port)

    return env_port


def udp_listen(port):
    udp = socket.socket(type=socket.SOCK_DGRAM)
    udp.bind(("10.53.0.7", port))

    return udp


def tcp_listen(port):
    tcp = socket.socket(type=socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("10.53.0.7", port))
    tcp.listen(100)

    return tcp


def udp_response(udp):
    qrybytes, clientaddr = udp.recvfrom(65535)
    qry = dns.message.from_wire(qrybytes)
    answbytes = b'utter garbage'
    udp.sendto(answbytes, clientaddr)


def tcp_response(tcp):
    csock, _clientaddr = tcp.accept()
    while True:
      qrylen = csock.recv(4096)
      answbytes = b'utter garbage\n'
      csock.send(answbytes)
    csock.close()


def sigterm(signum, frame):
    os.remove("ans.pid")
    sys.exit(0)


def write_pid():
    with open("ans.pid", "w") as f:
        pid = os.getpid()
        f.write("{}".format(pid))


signal.signal(signal.SIGTERM, sigterm)
write_pid()

udp = udp_listen(port())
tcp = tcp_listen(port())

input = [udp, tcp]

while True:
    try:
        inputready, outputready, exceptready = select.select(input, [], [])
    except select.error:
        break
    except socket.error:
        break
    except KeyboardInterrupt:
        break

    for s in inputready:
        if s == udp:
            udp_response(udp)
        if s == tcp:
            tcp_response(tcp)

sigterm(signal.SIGTERM, 0)
