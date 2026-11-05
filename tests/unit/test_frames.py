"""Unit tests for the frame builders and the byte-level readers."""

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Dot1Q, Ether

from broker.frames import (
    DST_MAC,
    MIN_FRAME_LEN,
    SRC_MAC,
    build_frame,
    build_frame_of_size,
    build_runt,
    ipv4_header_is_valid,
    is_tagged,
    vlan_id,
)


def test_builder_pads_short_frames_to_minimum():
    """Every other test assumes the builder makes legal frames, so check that first."""
    assert len(build_frame()) == MIN_FRAME_LEN


@pytest.mark.parametrize("size", [60, 64, 512, 1514])
def test_builder_hits_exact_sizes(size):
    """MTU boundary tests are only meaningful if the frame size is exact."""
    assert len(build_frame_of_size(size)) == size


def test_runt_builder_returns_requested_length():
    """The runt tests need frames that really are below the minimum."""
    assert len(build_runt(20)) == 20


@pytest.mark.parametrize("proto, layer", [("udp", UDP), ("tcp", TCP)])
def test_scapy_agrees_with_builder(proto, layer):
    """Scapy re-parses the bytes, which catches a builder that writes bad headers."""
    parsed = Ether(build_frame(b"data", vlan=7, proto=proto))
    assert parsed[Dot1Q].vlan == 7
    assert parsed[IP].src == "10.0.0.1"
    assert layer in parsed


@pytest.mark.parametrize("vlan, expected", [(None, None), (1, 1), (100, 100), (4094, 4094)])
def test_vlan_reader_agrees_with_builder(vlan, expected):
    """The broker's filter depends on this reader, including the VLAN range limits."""
    assert vlan_id(build_frame(vlan=vlan)) == expected


def test_priority_tag_is_tagged_but_has_no_vlan():
    """VID 0 means "no VLAN" in 802.1Q. Treating it as VLAN 0 would misfilter such frames."""
    frame = build_frame(vlan=0)
    assert is_tagged(frame) and vlan_id(frame) is None


def test_vlan_reader_ignores_priority_bits():
    """The 3 PCP bits share a field with the VID, so a bad mask would give a wrong VLAN."""
    frame = bytearray(build_frame(vlan=10))
    frame[14] |= 0xE0  # byte 14 starts the tag; its top 3 bits are the priority
    assert vlan_id(bytes(frame)) == 10


def test_ipv4_check_passes_padded_and_non_ip_frames():
    """Padding is legal and non-IP traffic such as ARP is not the broker's business."""
    assert ipv4_header_is_valid(build_frame())
    arp = bytes(Ether(src=SRC_MAC, dst=DST_MAC, type=0x0806)).ljust(MIN_FRAME_LEN, b"\x00")
    assert ipv4_header_is_valid(arp)
