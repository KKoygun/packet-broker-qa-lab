"""Mirror correctness: the monitor port must show exactly what crossed the network."""

from broker.frames import build_frame, build_frame_of_size


def numbered_frames(count):
    return [build_frame(f"frame-{i}".encode()) for i in range(count)]


def test_mirrored_frame_is_byte_identical(broker):
    """A capture is evidence. If the mirror changes any byte, analysis is misleading."""
    frame = build_frame(b"payload", vlan=10, proto="tcp")
    broker.process(frame)
    assert broker.monitor_port == [frame]


def test_network_traffic_is_untouched(broker):
    """Monitoring must stay invisible, so live traffic passes through unchanged."""
    frames = numbered_frames(5)
    broker.process_all(frames)
    assert broker.network_port == frames


def test_no_frames_lost(broker):
    """Losing a frame in a capture can hide the very problem being investigated."""
    frames = numbered_frames(1000)
    broker.process_all(frames)
    assert len(broker.monitor_port) == 1000


def test_order_is_preserved(broker):
    """Reordering looks like a network fault, for example TCP retransmits, in analysis tools."""
    frames = numbered_frames(100)
    broker.process_all(frames)
    assert broker.monitor_port == frames


def test_mixed_sizes_and_tags_keep_their_order(broker):
    """A broker that handles tagged or large frames on a separate path could reorder them."""
    frames = [
        build_frame(),
        build_frame_of_size(1514),
        build_frame(vlan=10),
        build_frame_of_size(1518, vlan=20),
        build_frame(proto="tcp"),
    ]
    broker.process_all(frames)
    assert broker.monitor_port == frames


def test_duplicates_are_not_collapsed(broker):
    """Identical frames are real events, such as retransmits, and must all be mirrored."""
    frame = build_frame(b"same")
    broker.process_all([frame, frame, frame])
    assert broker.monitor_port == [frame, frame, frame]
