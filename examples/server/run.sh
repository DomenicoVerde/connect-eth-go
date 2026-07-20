#!/bin/bash

set -e

ethtool -K eth0 tx off

tcpdump -i eth0 -w server.pcap -U &

sleep infinity