"""Counters: when a capture looks wrong, they are the first thing people trust."""

from broker.broker import PacketBroker
from broker.frames import build_frame, build_frame_of_size, build_runt


def mixed_traffic():
    return [
        build_frame(vlan=10),
        build_frame(vlan=20),
        build_frame(),
        build_runt(),
        build_frame_of_size(1600),
        build_frame(vlan=4095),
    ]


def test_each_counter_counts_its_own_event():
    """A frame counted in the wrong bucket sends an investigation in the wrong direction."""
    broker = PacketBroker(vlan_allow={10})
    broker.process_all(mixed_traffic())
    c = broker.counters
    assert c.rx_frames == 6
    assert c.forwarded_frames == 3
    assert c.mirrored_frames == 1
    assert c.filtered_vlan == 2
    assert (c.dropped_runt, c.dropped_oversize, c.dropped_malformed) == (1, 1, 1)


def test_every_received_frame_is_accounted_for():
    """If received does not equal forwarded plus dropped, a frame vanished without a trace."""
    broker = PacketBroker(vlan_allow={10})
    broker.process_all(mixed_traffic())
    c = broker.counters
    assert c.rx_frames == (
        c.forwarded_frames + c.dropped_runt + c.dropped_oversize + c.dropped_malformed
    )
    assert c.forwarded_frames == c.mirrored_frames + c.filtered_vlan


def test_byte_counters_match_real_lengths():
    """Bandwidth figures come from byte counters, so they must match the actual frames."""
    frames = [build_frame(), build_frame_of_size(1000), build_runt(30)]
    broker = PacketBroker()
    broker.process_all(frames)
    assert broker.counters.rx_bytes == 60 + 1000 + 30
    assert broker.counters.mirrored_bytes == 60 + 1000


def test_counters_start_at_zero_and_stay_per_broker():
    """Shared state between instances would make tests and readings depend on each other."""
    first, second = PacketBroker(), PacketBroker()
    first.process(build_frame())
    assert first.counters.rx_frames == 1
    assert second.counters.rx_frames == 0
