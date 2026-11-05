"""Unit tests for the frame builders and the byte-level readers."""

import pytest

from broker.frames import build_frame, build_frame_of_size, ipv4_header_is_valid, vlan_id


@pytest.mark.parametrize("size", [60, 64, 512, 1514])
def test_builder_hits_exact_sizes(size):
    """MTU boundary tests are only meaningful if the frame size is exact."""
    assert len(build_frame_of_size(size)) == size


@pytest.mark.parametrize("vlan", [None, 1, 100, 4094])
def test_vlan_reader_agrees_with_builder(vlan):
    """The broker's filter depends on this reader, including the VLAN range limits."""
    assert vlan_id(build_frame(vlan=vlan)) == vlan


def test_vlan_reader_ignores_priority_bits():
    """The 3 PCP bits share a field with the VID, so a bad mask would give a wrong VLAN."""
    frame = bytearray(build_frame(vlan=10))
    frame[14] |= 0xE0  # byte 14 starts the tag; its top 3 bits are the priority
    assert vlan_id(bytes(frame)) == 10


def test_ipv4_check_passes_padded_and_non_ip_frames():
    """Padding is legal and non-IP traffic such as ARP is not the broker's business."""
    frame = bytearray(build_frame())
    assert ipv4_header_is_valid(bytes(frame))
    frame[12:14] = b"\x08\x06"  # ARP EtherType, so the IPv4 fields must be ignored
    frame[14] = 0xFF
    assert ipv4_header_is_valid(bytes(frame))
