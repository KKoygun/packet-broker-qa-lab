"""Mirror correctness: the monitor port must show exactly what crossed the network."""

from broker.frames import build_frame


def numbered_frames(count):
    return [build_frame(f"frame-{i}".encode()) for i in range(count)]


def test_mirrored_frame_is_byte_identical(broker):
    """A capture is evidence. If the mirror changes any byte, analysis is misleading."""
    frame = build_frame(b"payload", vlan=10, proto="tcp")
    broker.process(frame)
    assert broker.monitor_port == [frame]


def test_no_frames_lost(broker):
    """Losing a frame in a capture can hide the very problem being investigated."""
    broker.process_all(numbered_frames(1000))
    assert len(broker.monitor_port) == 1000


def test_order_is_preserved(broker):
    """Reordering looks like a network fault, for example TCP retransmits, in analysis tools."""
    frames = numbered_frames(100)
    broker.process_all(frames)
    assert broker.monitor_port == frames
