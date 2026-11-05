"""VLAN filtering: only the selected VLANs reach the monitor port."""

import pytest

from broker.broker import PacketBroker
from broker.frames import build_frame


def test_only_allowed_vlans_are_mirrored():
    """This is the filter's basic promise, and it must honour every entry in the allow list."""
    frames = [build_frame(vlan=vid) for vid in (10, 20, 30)]
    broker = PacketBroker(vlan_allow={10, 30})
    broker.process_all(frames)
    assert broker.monitor_port == [frames[0], frames[2]]


def test_filter_never_affects_the_network_port():
    """A monitoring rule that drops live traffic would turn a tool into an outage."""
    frames = [build_frame(vlan=10), build_frame(vlan=20), build_frame()]
    broker = PacketBroker(vlan_allow={99})
    broker.process_all(frames)
    assert broker.network_port == frames
    assert broker.monitor_port == []


@pytest.mark.parametrize("vlan", [None, 0], ids=["untagged", "priority-tagged"])
@pytest.mark.parametrize("allow_untagged, expected", [(False, 0), (True, 1)])
def test_frames_without_a_vlan_follow_the_setting(vlan, allow_untagged, expected):
    """These frames belong to no VLAN (VID 0 included), so handling them must be a choice."""
    broker = PacketBroker(vlan_allow={10}, allow_untagged=allow_untagged)
    broker.process(build_frame(vlan=vlan))
    assert len(broker.monitor_port) == expected


def test_empty_allow_list_mirrors_nothing():
    """An empty set means "allow none". Treating it like None would leak all traffic."""
    broker = PacketBroker(vlan_allow=set())
    broker.process_all([build_frame(vlan=10), build_frame(vlan=20)])
    assert broker.monitor_port == []
