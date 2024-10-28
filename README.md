# SSL VPN tunnel fuzzer - VPN Gremlin project

Fuzzing SSL VPN Tunneling protocols with Scapy and mitmproxy, based on VPN Gremlin research done by TXOne Research.

## Introduction

VPN Gremlin is a series of user impersonation attack on multiple SSL VPNs, enabling one to spoof source IPs as authenticated user in SSL VPN tunnels. Scripts in the repository implements SSL VPN tunneling protocols by vendors, which is based on knowledge from openconnect project. 


We have implemented a partial of vendor's SSL VPN tunneling protocol in Scapy and enables one to fuzz said protocol with ease. The project also relies on mitmproxy as it does not implement authentication and requires an existing and working client implementation to complete neceressary connection creation steps.

## Setup

This was intended to use along with a legitimate SSL VPN client.

## Usage

1. Export Fortigate SSL VPN certificate as cert.pem
2. Create WireGuard configuration file as wgk.conf. This project relies on mitmproxy's WireGuard mode to route traffic made by SSL VPN clients.
3. Run corresponding script to start mitmproxy in WireGuard mode.
4. Create connection with SSL VPN client. The script will intercept its traffic and let authentication steps to be done.
5. The scripts will be able to insert traffic in the tunnel, once the connection is made.
