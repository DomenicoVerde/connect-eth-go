#!/bin/bash

set -e

ethtool -K eth0 tx off

case "$TESTCASE" in
  iperf)
    iperf3 -s -D
    ;;
  vlan)
    # IEEE 802.1Q VLAN interface, reached by the client through the tunnel with tagged frames
    ip link add link eth0 name "eth0.$VLAN_ID" type vlan id "$VLAN_ID"
    ip addr add "$VLAN_IPV4" dev "eth0.$VLAN_ID"
    ip addr add "$VLAN_IPV6" dev "eth0.$VLAN_ID"
    ip link set "eth0.$VLAN_ID" up
    ;;
esac

tcpdump -i eth0 -w server.pcap -U &

sleep infinity