"""Read and write pcap files, and validate checksums with scapy."""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap, wrpcap


def write_pcap(path, frames):
    packets = [Ether(frame) for frame in frames]
    for index, packet in enumerate(packets):
        packet.time = index  # fixed timestamps keep the golden files reproducible
    wrpcap(str(path), packets)


def read_pcap(path):
    return [bytes(packet) for packet in rdpcap(str(path))]


def checksums_are_valid(frame):
    """Let scapy recompute the IP and L4 checksums. The bytes must not change."""
    packet = Ether(frame)
    for layer in (IP, UDP, TCP):
        if layer in packet:
            del packet[layer].chksum
    return bytes(packet) == frame
