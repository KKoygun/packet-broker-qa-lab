"""VLAN filtering: only the selected VLANs reach the monitor port."""

import pytest

from broker.broker import PacketBroker
from broker.frames import build_frame


def test_only_allowed_vlan_is_mirrored():
    """This is the filter's basic promise: analysis tools see only what was selected."""
    allowed = build_frame(vlan=10)
    broker = PacketBroker(vlan_allow={10})
    broker.process_all([allowed, build_frame(vlan=20), build_frame(vlan=30)])
    assert broker.monitor_port == [allowed]


def test_several_vlans_can_be_allowed():
    """Checks that the filter treats the allow list as a set, not only its first entry."""
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


@pytest.mark.parametrize("allow_untagged, expected", [(False, 0), (True, 1)])
def test_untagged_frames_follow_the_setting(allow_untagged, expected):
    """Untagged traffic belongs to no VLAN, so its handling must be an explicit choice."""
    broker = PacketBroker(vlan_allow={10}, allow_untagged=allow_untagged)
    broker.process(build_frame())
    assert len(broker.monitor_port) == expected


@pytest.mark.parametrize("allow_untagged, expected", [(False, 0), (True, 1)])
def test_priority_tagged_frames_count_as_untagged(allow_untagged, expected):
    """VID 0 carries a tag but no VLAN, which is an easy edge case to get wrong."""
    broker = PacketBroker(vlan_allow={10}, allow_untagged=allow_untagged)
    broker.process(build_frame(vlan=0))
    assert len(broker.monitor_port) == expected


def test_no_filter_mirrors_everything():
    """The default must lose nothing, or a new user gets incomplete captures."""
    frames = [build_frame(), build_frame(vlan=10), build_frame(vlan=4094)]
    broker = PacketBroker()
    broker.process_all(frames)
    assert broker.monitor_port == frames


def test_empty_allow_list_mirrors_nothing():
    """An empty set means "allow none". Treating it like None would leak all traffic."""
    broker = PacketBroker(vlan_allow=set())
    broker.process_all([build_frame(vlan=10), build_frame(vlan=20)])
    assert broker.monitor_port == []
