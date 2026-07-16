#!/bin/bash

set -e

ethtool -K eth0 tx off

ip route replace default dev eth0

# delete all routes except default
for route in $(ip route show | grep -v default | awk '{print $1}'); do
    ip route del $route
done

tcpdump -i eth0 -w server.pcap -U &

./server
