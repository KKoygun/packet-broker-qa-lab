"""Read and write pcap files, and decode frame fields with scapy."""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Dot1Q, Ether
from scapy.utils import rdpcap, wrpcap


def write_pcap(path, frames):
    packets = [Ether(frame) for frame in frames]
    for index, packet in enumerate(packets):
        packet.time = index  # fixed timestamps keep the golden files reproducible
    wrpcap(str(path), packets)


def read_pcap(path):
    return [bytes(packet) for packet in rdpcap(str(path))]


def decode(frame):
    """Return the header fields a reviewer would look at in a capture tool."""
    packet = Ether(frame)
    l4 = packet[UDP] if UDP in packet else packet[TCP]
    return {
        "eth_src": packet.src,
        "eth_dst": packet.dst,
        "vlan": packet[Dot1Q].vlan if Dot1Q in packet else None,
        "ip_src": packet[IP].src,
        "ip_dst": packet[IP].dst,
        "l4": l4.name,
        "sport": l4.sport,
        "dport": l4.dport,
    }


def checksums_are_valid(frame):
    """Let scapy recompute the IP and L4 checksums. The bytes must not change."""
    packet = Ether(frame)
    for layer in (IP, UDP, TCP):
        if layer in packet:
            del packet[layer].chksum
    return bytes(packet) == frame
