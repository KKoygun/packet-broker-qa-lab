"""MTU edges: the classic off-by-one area, so each limit is tested on both sides."""

import pytest

from broker.broker import PacketBroker
from broker.frames import build_frame_of_size


@pytest.mark.parametrize(
    "size, vlan, accepted",
    [
        (1514, None, True),  # 1500 MTU + 14 Ethernet header
        (1515, None, False),
        (1518, 10, True),  # the 802.1Q tag gets 4 extra bytes
        (1519, 10, False),
    ],
)
def test_default_mtu_boundaries(broker, size, vlan, accepted):
    """A one-byte error here silently loses every full-size frame on a busy link."""
    broker.process(build_frame_of_size(size, vlan=vlan))
    assert (len(broker.monitor_port) == 1) is accepted
    assert broker.counters.dropped_oversize == (0 if accepted else 1)


def test_untagged_frame_gets_no_tag_allowance(broker):
    """1518 is legal only with a tag. Applying that limit to all frames hides oversize ones."""
    broker.process(build_frame_of_size(1518))
    assert broker.counters.dropped_oversize == 1


@pytest.mark.parametrize("size, accepted", [(9014, True), (9015, False)])
def test_jumbo_mtu_is_configurable(size, accepted):
    """Checks that the limit comes from the setting, not from a hard-coded 1500."""
    broker = PacketBroker(mtu=9000)
    broker.process(build_frame_of_size(size))
    assert (len(broker.monitor_port) == 1) is accepted


def test_smaller_mtu_is_enforced():
    """A lowered MTU must be enforced too, not just a raised one."""
    broker = PacketBroker(mtu=1000)
    broker.process_all([build_frame_of_size(1014), build_frame_of_size(1015)])
    assert broker.counters.mirrored_frames == 1
    assert broker.counters.dropped_oversize == 1
