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

# Segmentation offload off on both namespace interfaces. With it on, the
# kernel hands bulk TCP across the veth as 64 KB packets, and Suricata
# (capturing veth-atk) keeps only the first part of each: step 7.2's
# 150 MB iperf3 transfers were logged as under 1 MB and volume_anomaly
# never fired. Real Wi-Fi clients' packets arrive at normal size, so only
# the harness needs this. A function, so it also runs when the harness
# already exists (the early exit below).
offloads_off() {
    for ns in ns_attacker ns_victim; do
        ip netns exec "$ns" ethtool -K eth0 tso off gso off gro off
    done
}

if ip link show br-test >/dev/null 2>&1; then
    offloads_off
    echo "test harness already present, offloads checked"
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
# Nine extra addresses on the SAME interface (ENHANCEMENT-PLAN.md step 2.1),
# purely so a network-sweep test has real distinct hosts to find. A scan
# against an address with no host behind it never produces a Suricata flow
# event at all - the kernel can't ARP-resolve it, so no IP packet ever
# leaves ns_attacker's interface for that address. These are IP aliases on
# ns_victim's own single interface, not new namespaces: still fully
# isolated from ap0/hostapd and the two real devices, same as the existing
# .221 address.
for i in $(seq 222 230); do
    ip netns exec ns_victim ip addr add "10.10.0.$i/24" dev eth0
done

offloads_off

echo "test harness created: ns_attacker=10.10.0.220, ns_victim=10.10.0.221-230"
