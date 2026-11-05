"""Counters: when a capture looks wrong, they are the first thing people trust."""

from broker.broker import PacketBroker
from broker.frames import build_frame, build_frame_of_size, build_runt


def run_mixed_traffic():
    valid = [build_frame(vlan=10), build_frame(vlan=20), build_frame()]
    invalid = [build_runt(), build_frame_of_size(1600), build_frame(vlan=4095)]
    broker = PacketBroker(vlan_allow={10})
    broker.process_all(valid + invalid)
    return broker.counters


def test_each_counter_counts_its_own_event():
    """A frame counted in the wrong bucket sends an investigation in the wrong direction."""
    c = run_mixed_traffic()
    assert (c.rx_frames, c.forwarded_frames, c.mirrored_frames, c.filtered_vlan) == (6, 3, 1, 2)
    assert (c.dropped_runt, c.dropped_oversize, c.dropped_malformed) == (1, 1, 1)


def test_every_received_frame_is_accounted_for():
    """If received does not equal forwarded plus dropped, a frame vanished without a trace."""
    c = run_mixed_traffic()
    dropped = c.dropped_runt + c.dropped_oversize + c.dropped_malformed
    assert c.rx_frames == c.forwarded_frames + dropped
    assert c.forwarded_frames == c.mirrored_frames + c.filtered_vlan


def test_byte_counters_match_real_lengths():
    """Bandwidth figures come from byte counters, so they must match the actual frames."""
    broker = PacketBroker()
    broker.process_all([build_frame(), build_frame_of_size(1000), build_runt(30)])
    assert broker.counters.rx_bytes == 60 + 1000 + 30
    assert broker.counters.mirrored_bytes == 60 + 1000
