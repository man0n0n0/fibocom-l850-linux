#!/bin/bash
sleep 60
IP=$(journalctl -u xmm7360 --since "2 minutes ago" --no-pager | grep "IP address:" | tail -1 | awk '{print $NF}')
if [ -n "$IP" ]; then
    ip link set wwan0 up
    ip addr flush dev wwan0
    ip addr add $IP/32 dev wwan0
    ip route add default dev wwan0 metric 100 2>/dev/null || true
    resolvectl dns wwan0 8.8.8.8 1.1.1.1 2>/dev/null || true
fi
