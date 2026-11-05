#!/usr/bin/env bash
# Build or remove the lab network. Needs root. Usage: netns_setup.sh up|down
#
#   pb-src [src0] <-veth-> [dut-in] pb-dut [dut-mon] <-veth-> [mon0] pb-mon
set -euo pipefail

NAMESPACES=(pb-src pb-dut pb-mon)

down() {
    for ns in "${NAMESPACES[@]}"; do
        ip netns delete "$ns" 2>/dev/null || true  # deleting a namespace also removes its veths
    done
}

up() {
    down  # start clean, even if an earlier run was interrupted

    for ns in "${NAMESPACES[@]}"; do
        ip netns add "$ns"
        # IPv6 sends its own frames when a link comes up, which would pollute the captures.
        ip netns exec "$ns" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
    done

    ip link add src0 netns pb-src type veth peer name dut-in netns pb-dut
    # The monitor link needs room for tunnel headers on top of a full-size frame.
    ip link add dut-mon netns pb-dut mtu 1600 type veth peer name mon0 netns pb-mon mtu 1600

    ip -n pb-src link set src0 up
    ip -n pb-dut link set dut-in up
    ip -n pb-dut link set dut-mon up
    ip -n pb-mon link set mon0 up
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
