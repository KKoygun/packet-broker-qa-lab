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
def test_overhead_is_exact(tunnel, overhead):
    """Link MTU planning relies on these numbers: Eth+IP+GRE = 38, Eth+IP+UDP+VXLAN = 50."""
    frame = build_frame()
    assert len(tunnel.encap(frame)) == len(frame) + overhead


def test_outer_ip_header(tunnel):
    """The outer header routes the tunnel, and DF stops copies being silently fragmented."""
    outer = Ether(tunnel.encap(build_frame()))
    assert (outer[IP].src, outer[IP].dst) == ("192.0.2.1", "192.0.2.2")
    assert "DF" in outer[IP].flags


def test_plain_frame_is_rejected(tunnel):
    """Decapsulating ordinary traffic must fail loudly rather than return garbage."""
    with pytest.raises(TunnelError):
        tunnel.decap(build_frame())


def test_truncated_packet_is_rejected(tunnel):
    """A cut-off tunnel packet would otherwise return a shortened inner frame as if valid."""
    with pytest.raises(TunnelError):
        tunnel.decap(tunnel.encap(build_frame())[:-10])


def test_gre_header_bytes():
    """Checks raw bytes rather than scapy, because scapy also produced them: RFC 2784 layout."""
    packet = GreTunnel().encap(build_frame())
    assert packet[IP_PROTO_OFFSET] == 47  # 47 = GRE
    assert packet[TUNNEL_OFFSET : TUNNEL_OFFSET + 4] == bytes.fromhex("00006558")


def test_gre_rejects_other_payload_types():
    """A GRE packet carrying plain IP has no Ethernet frame inside to hand back."""
    packet = bytearray(GreTunnel().encap(build_frame()))
    packet[TUNNEL_OFFSET + 2 : TUNNEL_OFFSET + 4] = bytes.fromhex("0800")
    with pytest.raises(TunnelError):
        GreTunnel().decap(bytes(packet))


def test_vxlan_header_bytes():
    """Raw layout from RFC 7348: destination port 4789, UDP checksum 0, I flag and 24-bit VNI."""
    packet = VxlanTunnel(vni=0x123456).encap(build_frame())
    assert packet[IP_PROTO_OFFSET] == 17  # 17 = UDP
    assert packet[TUNNEL_OFFSET + 2 : TUNNEL_OFFSET + 4] == (4789).to_bytes(2)
    assert packet[TUNNEL_OFFSET + 6 : TUNNEL_OFFSET + 8] == b"\x00\x00"
    assert packet[TUNNEL_OFFSET + 8 : TUNNEL_OFFSET + 16] == bytes.fromhex("0800000012345600")


def test_vxlan_rejects_a_different_vni():
    """The VNI separates tenants, so accepting the wrong one would leak traffic between them."""
    packet = VxlanTunnel(vni=100).encap(build_frame())
    with pytest.raises(TunnelError):
        VxlanTunnel(vni=200).decap(packet)


def test_vxlan_rejects_a_cleared_vni_flag():
    """RFC 7348 says the VNI is only valid when the I flag is set."""
    packet = bytearray(VxlanTunnel().encap(build_frame()))
    packet[TUNNEL_OFFSET + 8] = 0x00
    with pytest.raises(TunnelError):
        VxlanTunnel().decap(bytes(packet))


def test_vxlan_rejects_the_wrong_udp_port():
    """Other UDP traffic must not be mistaken for VXLAN."""
    packet = bytearray(VxlanTunnel().encap(build_frame()))
    packet[TUNNEL_OFFSET + 2 : TUNNEL_OFFSET + 4] = (1234).to_bytes(2)
    with pytest.raises(TunnelError):
        VxlanTunnel().decap(bytes(packet))


def test_vxlan_source_port_is_stable_for_a_flow():
    """A changing port would send one flow over several paths and reorder its packets."""
    ports = {Ether(VxlanTunnel().encap(build_frame(bytes([i])))).sport for i in range(5)}
    assert len(ports) == 1
    assert 49152 <= ports.pop() <= 65535


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
