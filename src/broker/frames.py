"""Frame builders (scapy) and byte-level header readers (struct).

The readers avoid scapy because scapy is forgiving about bad input, and the
broker has to make strict decisions. The tests then use scapy as a second
opinion, so the broker's parser and the test oracle do not share code.
"""

import struct

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Dot1Q, Ether
from scapy.packet import Raw

ETH_HEADER_LEN = 14
VLAN_TAG_LEN = 4
MIN_FRAME_LEN = 60  # 64 on the wire minus the 4-byte FCS, which is not modelled here
DEFAULT_MTU = 1500
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100
RESERVED_VLAN_ID = 4095  # 802.1Q reserves this value, so it must never appear on the wire

SRC_MAC = "02:00:00:00:00:01"  # 02: locally administered, so never a real vendor address
DST_MAC = "02:00:00:00:00:02"


def build_frame(payload=b"", *, vlan=None, proto="udp", src_ip="10.0.0.1", dst_ip="10.0.0.2"):
    """Build a valid Ethernet/IPv4 frame, padded up to the 60-byte minimum."""
    l2 = Ether(src=SRC_MAC, dst=DST_MAC)
    if vlan is not None:
        l2 = l2 / Dot1Q(vlan=vlan)
    l4 = TCP(sport=1024, dport=80) if proto == "tcp" else UDP(sport=1024, dport=53)
    frame = bytes(l2 / IP(src=src_ip, dst=dst_ip) / l4 / Raw(payload))
    return frame.ljust(MIN_FRAME_LEN, b"\x00")


def build_frame_of_size(size, *, vlan=None):
    """Build a UDP frame of exactly `size` bytes, for boundary tests."""
    tag_len = VLAN_TAG_LEN if vlan is not None else 0
    headers = ETH_HEADER_LEN + tag_len + 20 + 8  # Ethernet + tag + IPv4 + UDP
    return build_frame(b"\xab" * (size - headers), vlan=vlan)


def build_runt(size=40):
    """Cut a valid frame short, as a collision or a bad NIC would."""
    return build_frame()[:size]


def is_tagged(frame):
    """Return True if the frame carries an 802.1Q tag."""
    return struct.unpack_from("!H", frame, 12)[0] == ETHERTYPE_VLAN


def vlan_id(frame):
    """Return the VLAN ID, or None for untagged frames.

    VID 0 is a "priority tag": 802.1Q says it belongs to no VLAN, so it counts as untagged.
    """
    if not is_tagged(frame):
        return None
    tci = struct.unpack_from("!H", frame, ETH_HEADER_LEN)[0]
    return (tci & 0x0FFF) or None  # the low 12 bits of the tag are the VID


def ipv4_header_is_valid(frame):
    """Check the IPv4 header fields a capture tool relies on. Non-IPv4 frames pass."""
    l3_offset = ETH_HEADER_LEN + (VLAN_TAG_LEN if is_tagged(frame) else 0)
    ethertype = struct.unpack_from("!H", frame, l3_offset - 2)[0]
    if ethertype != ETHERTYPE_IPV4:
        return True
    version = frame[l3_offset] >> 4
    header_len = (frame[l3_offset] & 0x0F) * 4
    total_len = struct.unpack_from("!H", frame, l3_offset + 2)[0]
    # total_len may be smaller than the frame (padding) but never larger (truncation).
    return version == 4 and header_len >= 20 and header_len <= total_len <= len(frame) - l3_offset
