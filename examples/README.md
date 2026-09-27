# Examples

A client, a proxy and a server, each in its own Docker container, emulating the Remote Access L2 VPN use case
(Section 8.1 of the draft):

* the **client** connects to the proxy, and bridges the tunnel with a local TAP device, having its own IP addresses
  on the server network;
* the **proxy** bridges its server-facing interface with a Linux bridge (`br0`). For each connected client,
  a new TAP device is created and added to the bridge, so that the bridge forwards to each client only the frames
  destined to it (plus broadcast and multicast frames), and clients can reach each other;
* the **server** is a plain host on the server network.

STP is disabled on the proxy bridge: in this topology each client is a leaf, so no loops can occur.
It should be enabled when bridging Ethernet segments with redundant paths (e.g. Site-to-Site L2 VPN).

## How to run:

Building the sources and Docker images:
```sh
make build
```

Running a test (append `v6` to the target to run it over IPv6, e.g. `make pingv6`):
```sh
make ping         # 50 pings from the client to the server
make iperf        # TCP throughput from the client to the server, in upload and download (iperf3)
make vlan         # ping from the client to the server on IEEE 802.1Q VLAN 100, tagged frames are
                  # transparently forwarded through the tunnel (Section 9.2 of the draft)
make twoclients   # two clients connected to the same proxy, pinging the server and each other
```

Obtaining logs, keys and packet captures:
```sh
make copylogs target=../pcaps/
```
