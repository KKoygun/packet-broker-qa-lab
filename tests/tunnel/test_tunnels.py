"""GRE and VXLAN encapsulation and decapsulation."""

import pytest
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from broker.broker import PacketBroker
from broker.frames import build_frame, build_frame_of_size
from broker.tunnel import GreTunnel, TunnelError, VxlanTunnel

# Offsets into an encapsulated packet: 14 Ethernet + 20 IPv4 = 34 is where the tunnel starts.
IP_PROTO_OFFSET = 23
TUNNEL_OFFSET = 34


@pytest.fixture(params=[GreTunnel(), VxlanTunnel()], ids=["gre", "vxlan"])
def tunnel(request):
    return request.param


@pytest.mark.parametrize(
    "frame",
    [build_frame(), build_frame(vlan=10), build_frame(proto="tcp"), build_frame_of_size(1514)],
    ids=["untagged", "tagged", "tcp", "full-size"],
)
def test_round_trip_is_byte_exact(tunnel, frame):
    """A tunnel must be invisible. The remote tool has to see the original frame, tag included."""
    assert tunnel.decap(tunnel.encap(frame)) == frame


@pytest.mark.parametrize(
    "tunnel, overhead", [(GreTunnel(), 38), (VxlanTunnel(), 50)], ids=["gre", "vxlan"]
)
def test_outer_headers(tunnel, overhead):
    """MTU planning relies on the overhead (38 and 50 bytes), and DF stops silent fragmenting."""
    frame = build_frame()
    packet = tunnel.encap(frame)
    outer = Ether(packet)
    assert len(packet) == len(frame) + overhead
    assert (outer[IP].src, outer[IP].dst) == ("192.0.2.1", "192.0.2.2")
    assert "DF" in outer[IP].flags


def test_gre_header_bytes():
    """Checks raw bytes rather than scapy, because scapy also produced them: RFC 2784 layout."""
    packet = GreTunnel().encap(build_frame())
    assert packet[IP_PROTO_OFFSET] == 47  # 47 = GRE
    assert packet[TUNNEL_OFFSET : TUNNEL_OFFSET + 4] == bytes.fromhex("00006558")


def test_vxlan_header_bytes():
    """Raw layout from RFC 7348: destination port 4789, UDP checksum 0, I flag and 24-bit VNI."""
    packet = VxlanTunnel(vni=0x123456).encap(build_frame())
    assert packet[IP_PROTO_OFFSET] == 17  # 17 = UDP
    assert packet[TUNNEL_OFFSET + 2 : TUNNEL_OFFSET + 4] == (4789).to_bytes(2)
    assert packet[TUNNEL_OFFSET + 6 : TUNNEL_OFFSET + 8] == b"\x00\x00"
    assert packet[TUNNEL_OFFSET + 8 : TUNNEL_OFFSET + 16] == bytes.fromhex("0800000012345600")


def test_plain_and_truncated_packets_are_rejected(tunnel):
    """Decapsulation must fail loudly rather than return garbage or a shortened frame."""
    for bad in (build_frame(), tunnel.encap(build_frame())[:-10]):
        with pytest.raises(TunnelError):
            tunnel.decap(bad)


@pytest.mark.parametrize(
    "tunnel, offset, new_bytes",
    [
        (GreTunnel(), 2, b"\x08\x00"),  # payload type is IPv4, so no Ethernet frame inside
        (VxlanTunnel(), 2, b"\x04\xd2"),  # UDP destination port 1234, so not VXLAN
        (VxlanTunnel(), 8, b"\x00"),  # I flag cleared, so the VNI is not valid
        (VxlanTunnel(), 14, b"\x00"),  # a different VNI, which would mix up tenants' traffic
    ],
    ids=["gre-payload-type", "vxlan-port", "vxlan-flag", "vxlan-vni"],
)
def test_wrong_tunnel_header_is_rejected(tunnel, offset, new_bytes):
    """Each field decides whether the packet is really for this endpoint. See the notes above."""
    packet = tunnel.encap(build_frame())
    start = TUNNEL_OFFSET + offset
    with pytest.raises(TunnelError):
        tunnel.decap(packet[:start] + new_bytes + packet[start + len(new_bytes) :])


def test_broker_encapsulates_only_the_monitor_copy(tunnel):
    """Live traffic must stay unchanged. Only the copy for the remote tool gets a tunnel."""
    frame = build_frame()
    broker = PacketBroker(tunnel=tunnel)
    broker.process(frame)
    assert broker.network_port == [frame]
    assert broker.monitor_port == [tunnel.encap(frame)]
    assert broker.counters.mirrored_bytes == len(tunnel.encap(frame))


def test_filter_applies_before_encapsulation(tunnel):
    """Once tunnelled, the tag is buried in the payload, so the filter has to run first."""
    allowed = build_frame(vlan=10)
    broker = PacketBroker(vlan_allow={10}, tunnel=tunnel)
    broker.process_all([allowed, build_frame(vlan=20)])
    assert [tunnel.decap(packet) for packet in broker.monitor_port] == [allowed]
