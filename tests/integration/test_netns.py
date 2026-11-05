"""Integration tests over real veth pairs. Unlike the in-memory tests, the kernel is involved."""

import pytest

from broker.broker import PacketBroker
from broker.frames import build_frame, build_frame_of_size
from broker.netns import mirror_through_lab, run_lab_script
from broker.tunnel import GreTunnel, VxlanTunnel

pytestmark = pytest.mark.netns


@pytest.fixture(scope="module", autouse=True)
def lab():
    run_lab_script("up")
    yield
    run_lab_script("down")


def test_frames_cross_the_lab_unchanged_and_in_order():
    """Real sockets can pad, reorder or lose frames, which an in-memory list never does."""
    frames = [build_frame(f"frame-{i}".encode()) for i in range(50)]
    assert mirror_through_lab(PacketBroker(), frames) == frames


def test_vlan_filter_works_on_tags_from_the_kernel():
    """The kernel strips tags on receive, so this fails if they are not restored correctly."""
    allowed = build_frame(vlan=10)
    broker = PacketBroker(vlan_allow={10})
    assert mirror_through_lab(broker, [allowed, build_frame(vlan=20)]) == [allowed]
    assert broker.counters.filtered_vlan == 1


@pytest.mark.parametrize("tunnel", [GreTunnel(), VxlanTunnel()], ids=["gre", "vxlan"])
def test_tunnelled_full_size_frame_reaches_the_monitor(tunnel):
    """A full-size frame plus tunnel headers exceeds 1500 bytes, so link MTU matters here."""
    frame = build_frame_of_size(1514)
    received = mirror_through_lab(PacketBroker(tunnel=tunnel), [frame])
    assert [tunnel.decap(packet) for packet in received] == [frame]
