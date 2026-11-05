"""Malformed and runt frames: bad input must be counted and dropped, never crash the broker."""

import pytest

from broker.frames import ETH_HEADER_LEN, VLAN_TAG_LEN, build_frame, build_runt


def with_bad_ip_byte(vlan, ip_offset, value):
    """Build a frame and overwrite one byte of its IPv4 header."""
    frame = bytearray(build_frame(vlan=vlan))
    frame[ETH_HEADER_LEN + (VLAN_TAG_LEN if vlan else 0) + ip_offset] = value
    return bytes(frame)


@pytest.mark.parametrize("size", [0, 1, 13, 14, 40, 59])
def test_runts_are_dropped_without_crashing(broker, size):
    """Short frames break naive header parsing, so sizes around the header length are covered."""
    broker.process(build_runt(size))
    assert broker.monitor_port == []
    assert broker.network_port == []
    assert broker.counters.dropped_runt == 1


@pytest.mark.parametrize("vlan", [None, 10], ids=["untagged", "tagged"])
@pytest.mark.parametrize(
    "ip_offset, value",
    [(0, 0x65), (0, 0x44), (2, 0xFF)],
    ids=["version-not-4", "header-under-20-bytes", "total-length-beyond-frame"],
)
def test_bad_ipv4_headers_are_dropped(broker, vlan, ip_offset, value):
    """These headers claim what the bytes cannot back up. A tag also shifts them by 4 bytes."""
    broker.process(with_bad_ip_byte(vlan, ip_offset, value))
    assert broker.monitor_port == []
    assert broker.counters.dropped_malformed == 1


def test_bad_frames_do_not_disturb_good_ones(broker):
    """One bad frame must not stall the stream or change the frames around it."""
    good = [build_frame(b"first"), build_frame(b"second")]
    broker.process_all([good[0], build_runt(), b"", good[1]])
    assert broker.monitor_port == good
