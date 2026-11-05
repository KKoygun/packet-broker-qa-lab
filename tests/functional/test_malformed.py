"""Malformed and runt frames: bad input must be counted and dropped, never crash the broker."""

import pytest

from broker.broker import PacketBroker
from broker.frames import ETH_HEADER_LEN, MIN_FRAME_LEN, build_frame, build_runt


def corrupt(frame, offset, value):
    """Overwrite one byte of a frame."""
    return frame[:offset] + bytes([value]) + frame[offset + 1 :]


@pytest.mark.parametrize("size", [0, 1, 13, 14, 40, MIN_FRAME_LEN - 1])
def test_runts_are_dropped_without_crashing(broker, size):
    """Short frames break naive header parsing, so sizes around the header length are covered."""
    broker.process(build_runt(size))
    assert broker.monitor_port == []
    assert broker.network_port == []
    assert broker.counters.dropped_runt == 1


def test_frame_at_minimum_size_is_accepted(broker):
    """This is the other side of the runt boundary, which catches an off-by-one."""
    broker.process(build_frame())
    assert broker.counters.dropped_runt == 0
    assert len(broker.monitor_port) == 1


@pytest.mark.parametrize(
    "name, byte_offset, value",
    [
        ("IP version is not 4", 0, 0x65),
        ("IP header length below 20 bytes", 0, 0x44),
        ("IP total length larger than frame", 2, 0xFF),
    ],
)
def test_bad_ipv4_headers_are_dropped(broker, name, byte_offset, value):
    """These headers claim things the bytes cannot back up and would mislead a capture tool."""
    broker.process(corrupt(build_frame(), ETH_HEADER_LEN + byte_offset, value))
    assert broker.monitor_port == [], name
    assert broker.counters.dropped_malformed == 1


def test_bad_header_behind_a_vlan_tag_is_dropped(broker):
    """The tag moves the IP header by 4 bytes. A fixed offset would read the wrong byte."""
    broker.process(corrupt(build_frame(vlan=10), ETH_HEADER_LEN + 4, 0x65))
    assert broker.counters.dropped_malformed == 1


def test_reserved_vlan_id_is_dropped(broker):
    """802.1Q reserves VID 4095, so a frame carrying it cannot be legitimate."""
    broker.process(build_frame(vlan=4095))
    assert broker.counters.dropped_malformed == 1


def test_bad_frames_do_not_disturb_good_ones(broker):
    """One bad frame must not stall the stream or change the frames around it."""
    good = [build_frame(b"first"), build_frame(b"second")]
    broker.process_all([good[0], build_runt(), b"", good[1]])
    assert broker.monitor_port == good


def test_malformed_frames_are_counted_before_the_filter():
    """A bad frame should show up as malformed, not as filtered, or the counters mislead."""
    broker = PacketBroker(vlan_allow={10})
    broker.process(corrupt(build_frame(vlan=20), ETH_HEADER_LEN + 4, 0x65))
    assert broker.counters.dropped_malformed == 1
    assert broker.counters.filtered_vlan == 0
