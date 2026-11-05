"""A basic sanity check. This is not a performance test."""

import time

from broker.broker import PacketBroker
from broker.frames import build_frame


def test_ten_thousand_frames_finish_quickly_with_no_loss():
    """The generous limit only catches accidental slowness, such as quadratic behaviour."""
    frame = build_frame(vlan=10)
    broker = PacketBroker(vlan_allow={10})
    start = time.perf_counter()
    broker.process_all([frame] * 10_000)
    assert time.perf_counter() - start < 2.0
    assert broker.counters.mirrored_frames == 10_000
