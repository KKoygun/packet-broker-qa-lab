"""Integration tests over real veth pairs. Unlike the in-memory tests, the kernel is involved."""

import subprocess

import pytest

from broker.broker import PacketBroker
from broker.frames import build_frame, build_frame_of_size
from broker.netns import lab_down, lab_up, mirror_through_lab
from broker.tunnel import GreTunnel, VxlanTunnel

pytestmark = pytest.mark.netns


@pytest.fixture(scope="module", autouse=True)
def lab():
    lab_up()
    yield
    lab_down()


@pytest.mark.parametrize(
    "namespace, interface",
    [("pb-src", "src0"), ("pb-dut", "dut-in"), ("pb-dut", "dut-mon"), ("pb-mon", "mon0")],
)
def test_lab_interfaces_exist(namespace, interface):
    """If the setup script breaks, this says so directly instead of failing as a timeout later."""
    command = ["ip", "-n", namespace, "link", "show", interface]
    assert subprocess.run(command, capture_output=True).returncode == 0


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


def test_runt_frame_from_a_socket_is_dropped():
    """A veth pair carries short frames as they are, so the broker must catch them itself."""
    good = build_frame()
    broker = PacketBroker()
    assert mirror_through_lab(broker, [good[:40], good]) == [good]
    assert broker.counters.dropped_runt == 1


@pytest.mark.parametrize("tunnel", [GreTunnel(), VxlanTunnel()], ids=["gre", "vxlan"])
def test_tunnelled_full_size_frame_reaches_the_monitor(tunnel):
    """A full-size frame plus tunnel headers exceeds 1500 bytes, so link MTU matters here."""
    frame = build_frame_of_size(1514)
    received = mirror_through_lab(PacketBroker(tunnel=tunnel), [frame])
    assert [tunnel.decap(packet) for packet in received] == [frame]
