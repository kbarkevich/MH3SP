#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Monster Hunter DNS server.

    Monster Hunter 3 Server Project
    Copyright (C) 2015  Sepalani

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import socket

from optparse import OptionParser
from other.utils import get_default_ip

try:
    # Python 3
    import socketserver as SocketServer
except ImportError:
    # Python 2
    import SocketServer


class MHTriDNSServer(SocketServer.UDPServer):
    """Generic DNS server class for MHTri.

    Empty record will point to the server IP.
    """

    record = {
        # Nintendo WFC
        "gpcm.gs.nintendowifi.net": "",
        "gpsp.gs.nintendowifi.net": "",
        "naswii.nintendowifi.net": "",
        "nas.nintendowifi.net": "",
        "gamestats.gs.nintendowifi.net": "",
        "gamestats2.gs.nintendowifi.net": "",
        "wiinat.available.gs.nintendowifi.net": "",
        "wiinat.natneg1.gs.nintendowifi.net": "",
        "wiinat.natneg2.gs.nintendowifi.net": "",
        "wiinat.natneg3.gs.nintendowifi.net": "",
        # Monster Hunter 3 (JAP)
        "monhunter3wii.gamestats.gs.nintendowifi.net": "",
        "monhunter3wii.gamestats2.gs.nintendowifi.net": "",
        "monhunter3wii.available.gs.nintendowifi.net": "",
        "monhunter3wii.natneg1.gs.nintendowifi.net": "",
        "monhunter3wii.natneg2.gs.nintendowifi.net": "",
        "monhunter3wii.natneg3.gs.nintendowifi.net": "",
        "monhunter3wii.master.gs.nintendowifi.net": "",
        "monhunter3wii.ms16.gs.nintendowifi.net": "",
        # Monster Hunter 3 (EU/US)
        "mh3uswii.available.gs.nintendowifi.net": "",
        "mh3uswii.natneg1.gs.nintendowifi.net": "",
        "mh3uswii.natneg2.gs.nintendowifi.net": "",
        "mh3uswii.natneg3.gs.nintendowifi.net": "",
        "mh3uswii.master.gs.nintendowifi.net": "",
        "mh3uswii.gamestats.gs.nintendowifi.net": "",
        "mh3uswii.gamestats2.gs.nintendowifi.net": "",
        "mh3uswii.ms1.gs.nintendowifi.net": "",
        # Wiimmfi
        "gpcm.gs.wiimmfi.de": "",
        "gpsp.gs.wiimmfi.de": "",
        "naswii.wiimmfi.de": "",
        "nas.wiimmfi.de": "",
        "gamestats.gs.wiimmfi.de": "",
        "gamestats2.gs.wiimmfi.de": "",
        "wiinat.available.gs.wiimmfi.de": "",
        "wiinat.natneg1.gs.wiimmfi.de": "",
        "wiinat.natneg2.gs.wiimmfi.de": "",
        "wiinat.natneg3.gs.wiimmfi.de": "",
        # Monster Hunter 3 (JAP)
        "monhunter3wii.gamestats.gs.wiimmfi.de": "",
        "monhunter3wii.gamestats2.gs.wiimmfi.de": "",
        "monhunter3wii.available.gs.wiimmfi.de": "",
        "monhunter3wii.natneg1.gs.wiimmfi.de": "",
        "monhunter3wii.natneg2.gs.wiimmfi.de": "",
        "monhunter3wii.natneg3.gs.wiimmfi.de": "",
        "monhunter3wii.master.gs.wiimmfi.de": "",
        "monhunter3wii.ms16.gs.wiimmfi.de": "",
        # Monster Hunter 3 (EU/US)
        "mh3uswii.available.gs.wiimmfi.de": "",
        "mh3uswii.natneg1.gs.wiimmfi.de": "",
        "mh3uswii.natneg2.gs.wiimmfi.de": "",
        "mh3uswii.natneg3.gs.wiimmfi.de": "",
        "mh3uswii.master.gs.wiimmfi.de": "",
        "mh3uswii.gamestats.gs.wiimmfi.de": "",
        "mh3uswii.gamestats2.gs.wiimmfi.de": "",
        "mh3uswii.ms1.gs.wiimmfi.de": "",
        # Capcom server
        "mh.capcom.co.jp": "",
        "mmh-t1-opn01.mmh-service.capcom.co.jp": "",
        "mmh-t1-opn02.mmh-service.capcom.co.jp": "",
        "mmh-t1-opn03.mmh-service.capcom.co.jp": "",
        "mmh-t1-opn04.mmh-service.capcom.co.jp": "",
    }

    def __init__(self, server_address, RequestHandlerClass,
                 bind_and_activate=True, record={}):
        SocketServer.UDPServer.__init__(self,
                                        server_address,
                                        RequestHandlerClass,
                                        bind_and_activate)
        if len(record) > 0:
            self.record = record

    def __len__(self):
        return len(self.record)

    def __getitem__(self, key):
        return self.record[key]

    def __setitem__(self, key, item):
        self.record[key] = item

    def __delitem__(self, key):
        del self.record[key]


def dns_pack(data, ip):
    """Pack DNS answer"""
    header = b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    response = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x08\x47\x00\x04"
    answer = data[0:2] + header + data[12:]
    answer += response + socket.inet_aton(ip)
    return answer


class MHTriDNSRequestHandler(SocketServer.BaseRequestHandler):
    """Basic DNS request handler"""

    def handle(self):
        data = bytearray(self.request[0])
        sock = self.request[1]
        name = data.strip()[13:].split(b'\0')[0]
        s = "".join("." if c < 32 else chr(c) for c in name)
        print("<<< %s" % s)

        if s in self.server.record:
            s = self.server.record[s]
            if not s:
                s = get_default_ip()

        try:
            ip = socket.gethostbyname(s)
            print(">>> %s" % ip)
            sock.sendto(dns_pack(data, ip), self.client_address)
        except socket.gaierror:
            pass


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-H", "--hostname", action="store", type=str,
                      default=get_default_ip(), dest="host",
                      help="set server hostname")
    parser.add_option("-P", "--port", action="store", type=int,
                      default=53, dest="port",
                      help="set server port")
    opt, arg = parser.parse_args()

    server = MHTriDNSServer((opt.host, opt.port), MHTriDNSRequestHandler)

    try:
        print("Server: %s | Port: %d" %
              (server.server_address[0], server.server_address[1]))
        server.serve_forever()
    except KeyboardInterrupt:
        print("[Server] Closing...")
        server.server_close()