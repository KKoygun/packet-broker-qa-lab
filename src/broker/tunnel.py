"""GRE and VXLAN tunnels, for sending mirrored frames across a routed network.

Both wrap the whole Ethernet frame, so the far side gets back exactly the original bytes.
Outer addresses default to 192.0.2.0/24, a range reserved for documentation (RFC 5737).
"""

import zlib
from dataclasses import dataclass

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import GRE, Ether
from scapy.layers.vxlan import VXLAN
from scapy.packet import Raw

from broker.frames import DST_MAC, ETH_HEADER_LEN, SRC_MAC

ETHERTYPE_TEB = 0x6558  # Transparent Ethernet Bridging: "GRE payload is an Ethernet frame"
VXLAN_PORT = 4789  # IANA-assigned VXLAN port
VXLAN_FLAG_VNI_VALID = 0x08  # the "I" flag from RFC 7348


class TunnelError(ValueError):
    """The packet is not a valid tunnel packet for this endpoint."""


def _outer_headers(src_ip, dst_ip):
    # DF is set because fragmenting a mirror copy would only make the capture harder to read.
    return Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src_ip, dst=dst_ip, flags="DF")


def _parse_outer(packet):
    """Parse the outer headers, refusing packets shorter than the outer IP header claims."""
    outer = Ether(packet)
    if IP not in outer or outer[IP].len != len(packet) - ETH_HEADER_LEN:
        raise TunnelError("not IPv4, or truncated")
    return outer


@dataclass(frozen=True)
class GreTunnel:
    src_ip: str = "192.0.2.1"
    dst_ip: str = "192.0.2.2"

    def encap(self, frame):
        return bytes(_outer_headers(self.src_ip, self.dst_ip) / GRE(proto=ETHERTYPE_TEB) / frame)

    def decap(self, packet):
        outer = _parse_outer(packet)
        if GRE not in outer or outer[GRE].proto != ETHERTYPE_TEB:
            raise TunnelError("not GRE carrying Ethernet")
        return bytes(outer[GRE].payload)


@dataclass(frozen=True)
class VxlanTunnel:
    src_ip: str = "192.0.2.1"
    dst_ip: str = "192.0.2.2"
    vni: int = 100

    def encap(self, frame):
        # RFC 7348: the source port is derived from the inner frame so that routers
        # balancing on UDP ports keep one flow on one path. It also says to send UDP checksum 0.
        sport = 49152 + zlib.crc32(frame[:12]) % 16384  # 49152-65535, from the two MACs
        udp = UDP(sport=sport, dport=VXLAN_PORT, chksum=0)
        outer = _outer_headers(self.src_ip, self.dst_ip)
        return bytes(outer / udp / VXLAN(vni=self.vni) / Raw(frame))

    def decap(self, packet):
        outer = _parse_outer(packet)
        if VXLAN not in outer or outer[UDP].dport != VXLAN_PORT:
            raise TunnelError("not VXLAN")
        if not int(outer[VXLAN].flags) & VXLAN_FLAG_VNI_VALID:
            raise TunnelError("VNI flag not set")
        if outer[VXLAN].vni != self.vni:
            raise TunnelError(f"expected VNI {self.vni}, got {outer[VXLAN].vni}")
        return bytes(outer[VXLAN].payload)
