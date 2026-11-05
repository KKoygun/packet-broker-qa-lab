"""MTU edges: the classic off-by-one area, so each limit is tested on both sides."""

import pytest

from broker.broker import PacketBroker
from broker.frames import build_frame_of_size


@pytest.mark.parametrize(
    "size, vlan, accepted",
    [
        (1514, None, True),  # 1500 MTU + 14 Ethernet header
        (1515, None, False),
        (1518, None, False),  # 1518 is legal only with a tag
        (1518, 10, True),  # the 802.1Q tag gets 4 extra bytes
        (1519, 10, False),
    ],
)
def test_default_mtu_boundaries(broker, size, vlan, accepted):
    """A one-byte error here silently loses every full-size frame on a busy link."""
    broker.process(build_frame_of_size(size, vlan=vlan))
    assert (len(broker.monitor_port) == 1) is accepted
    assert broker.counters.dropped_oversize == (0 if accepted else 1)


@pytest.mark.parametrize(
    "mtu, size, accepted",
    [(9000, 9014, True), (9000, 9015, False), (1000, 1014, True), (1000, 1015, False)],
)
def test_mtu_is_configurable(mtu, size, accepted):
    """Checks that the limit comes from the setting, raised or lowered, not a hard-coded 1500."""
    broker = PacketBroker(mtu=mtu)
    broker.process(build_frame_of_size(size))
    assert (len(broker.monitor_port) == 1) is accepted
