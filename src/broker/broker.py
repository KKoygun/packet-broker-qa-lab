"""The device under test: an in-memory packet broker with no root requirement.

Each valid frame passes through to the network port untouched. A copy goes to the
monitor port if it passes the VLAN filter, wrapped in a tunnel if one is configured.
The filter only limits what the monitor sees, so it can never disturb live traffic.
"""

from dataclasses import dataclass

from broker.frames import (
    DEFAULT_MTU,
    ETH_HEADER_LEN,
    MIN_FRAME_LEN,
    RESERVED_VLAN_ID,
    VLAN_TAG_LEN,
    ipv4_header_is_valid,
    is_tagged,
    vlan_id,
)


@dataclass
class Counters:
    rx_frames: int = 0
    rx_bytes: int = 0
    forwarded_frames: int = 0
    mirrored_frames: int = 0
    mirrored_bytes: int = 0  # bytes leaving the monitor port, tunnel headers included
    filtered_vlan: int = 0  # valid and forwarded, just not mirrored
    dropped_runt: int = 0
    dropped_oversize: int = 0
    dropped_malformed: int = 0


class PacketBroker:
    def __init__(self, vlan_allow=None, allow_untagged=False, mtu=DEFAULT_MTU, tunnel=None):
        """`vlan_allow=None` mirrors everything; a set mirrors only those VLANs."""
        self.vlan_allow = vlan_allow
        self.allow_untagged = allow_untagged
        self.mtu = mtu
        self.tunnel = tunnel
        self.network_port = []
        self.monitor_port = []
        self.counters = Counters()

    def process(self, frame):
        """Handle one frame arriving on the ingress port."""
        self.counters.rx_frames += 1
        self.counters.rx_bytes += len(frame)

        if not self._frame_is_acceptable(frame):
            return

        self.network_port.append(frame)
        self.counters.forwarded_frames += 1

        if not self._vlan_is_allowed(frame):
            self.counters.filtered_vlan += 1
            return

        mirrored = self.tunnel.encap(frame) if self.tunnel else frame
        self.monitor_port.append(mirrored)
        self.counters.mirrored_frames += 1
        self.counters.mirrored_bytes += len(mirrored)

    def process_all(self, frames):
        for frame in frames:
            self.process(frame)

    def _frame_is_acceptable(self, frame):
        # The runt check goes first: the other checks read header offsets it guarantees.
        if len(frame) < MIN_FRAME_LEN:
            self.counters.dropped_runt += 1
            return False
        if len(frame) > self._max_frame_len(frame):
            self.counters.dropped_oversize += 1
            return False
        if vlan_id(frame) == RESERVED_VLAN_ID or not ipv4_header_is_valid(frame):
            self.counters.dropped_malformed += 1
            return False
        return True

    def _max_frame_len(self, frame):
        # MTU covers the IP packet only. A VLAN tag gets 4 extra bytes so that
        # tagging a full-size frame does not make it oversized.
        return ETH_HEADER_LEN + self.mtu + (VLAN_TAG_LEN if is_tagged(frame) else 0)

    def _vlan_is_allowed(self, frame):
        if self.vlan_allow is None:
            return True
        vid = vlan_id(frame)
        return self.allow_untagged if vid is None else vid in self.vlan_allow
