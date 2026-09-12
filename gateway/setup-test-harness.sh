#!/bin/bash
# SecurePi Gateway - recreate the isolated test-traffic harness.
#
# Idempotent: safe to run at every boot. Builds a bridge (br-test) with two
# network namespaces (ns_attacker, ns_victim) attached via veth pairs,
# entirely separate from the production ap0/hostapd network - this exists so
# port-scan/brute-force detections can be exercised repeatedly (e.g. for the
# day-14 evaluation) without generating traffic against real devices.
#
# Suricata captures on veth-atk (the attacker's bridge-side port) as a SECOND
# af-packet interface, alongside its real ap0 capture. It must exist before
# Suricata starts, which is why this runs as a systemd unit ordered first -
# see securepi-test-harness.service.
set -e

if ip link show br-test >/dev/null 2>&1; then
    echo "test harness already present, nothing to do"
    exit 0
fi

ip link add br-test type bridge
ip link set br-test up

ip netns add ns_attacker 2>/dev/null || true
ip netns add ns_victim 2>/dev/null || true

ip link add veth-atk type veth peer name veth-atk-p
ip link add veth-vic type veth peer name veth-vic-p
ip link set veth-atk master br-test
ip link set veth-vic master br-test
ip link set veth-atk up
ip link set veth-vic up
ip link set veth-atk-p netns ns_attacker
ip link set veth-vic-p netns ns_victim

ip netns exec ns_attacker ip link set lo up
ip netns exec ns_attacker ip link set veth-atk-p name eth0
ip netns exec ns_attacker ip link set eth0 up
ip netns exec ns_attacker ip addr add 10.10.0.220/24 dev eth0

ip netns exec ns_victim ip link set lo up
ip netns exec ns_victim ip link set veth-vic-p name eth0
ip netns exec ns_victim ip link set eth0 up
ip netns exec ns_victim ip addr add 10.10.0.221/24 dev eth0

echo "test harness created: ns_attacker=10.10.0.220, ns_victim=10.10.0.221"
