#!/bin/bash

# Clean up interface
ip link set wwan0 down 2>/dev/null || true
ip addr flush dev wwan0 2>/dev/null || true
ip route del default dev wwan0 2>/dev/null || true

# Force close any open file descriptors on the device
fuser -k /dev/wwan0xmmrpc0 2>/dev/null || true
sleep 2

# Unload and reload the kernel driver (hardware reset)
modprobe -r iosm 2>/dev/null || true
sleep 3
modprobe iosm
sleep 5

echo "Modem hardware reset complete"
