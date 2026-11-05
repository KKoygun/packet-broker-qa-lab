"""Generate the golden pcap files. Usage: python scripts/generate_golden_pcaps.py [out_dir]

The VLAN expectation is picked by hand from known input, not by running the broker,
so a broker bug cannot end up baked into its own expected result.
"""

import sys
from pathlib import Path

from broker.capture import write_pcap
from broker.frames import build_frame, build_frame_of_size, build_runt
from broker.tunnel import GreTunnel, VxlanTunnel

DEFAULT_OUT_DIR = Path(__file__).resolve().parents[1] / "golden"

MIXED = [
    build_frame(b"untagged udp"),
    build_frame(b"vlan 10 udp", vlan=10),
    build_frame(b"vlan 20 tcp", vlan=20, proto="tcp"),
    build_frame(b"vlan 10 tcp", vlan=10, proto="tcp", src_ip="10.0.1.1", dst_ip="10.0.1.2"),
    build_frame(b"untagged tcp", proto="tcp"),
    build_frame_of_size(1514),
]
VLAN_10_ONLY = [MIXED[1], MIXED[3]]
INVALID = [build_runt(40), build_frame_of_size(1515), build_frame(vlan=4095)]


def main():
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    write_pcap(out_dir / "mixed.pcap", MIXED)
    write_pcap(out_dir / "vlan10_expected.pcap", VLAN_10_ONLY)
    write_pcap(out_dir / "gre_expected.pcap", [GreTunnel().encap(f) for f in MIXED])
    write_pcap(out_dir / "vxlan_expected.pcap", [VxlanTunnel().encap(f) for f in MIXED])
    write_pcap(out_dir / "invalid.pcap", INVALID)


if __name__ == "__main__":
    main()
