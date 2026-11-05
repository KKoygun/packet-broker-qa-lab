"""Golden captures: parse them, validate their fields and replay them through the broker."""

import filecmp
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Dot1Q, Ether

from broker.broker import PacketBroker
from broker.capture import checksums_are_valid, read_pcap
from broker.frames import DST_MAC, SRC_MAC
from broker.tunnel import GreTunnel, VxlanTunnel

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "golden"
FILES = ["mixed", "vlan10_expected", "gre_expected", "vxlan_expected"]


def golden(name):
    return read_pcap(GOLDEN / f"{name}.pcap")


@pytest.mark.parametrize("name", FILES)
def test_pcap_file_header_is_valid(name):
    """Other tools refuse a file with a bad header, whatever the frames inside look like."""
    header = (GOLDEN / f"{name}.pcap").read_bytes()[:24]
    magic, major, minor, _, _, _, linktype = struct.unpack("<IHHiIII", header)
    assert (magic, major, minor) == (0xA1B2C3D4, 2, 4)
    assert linktype == 1  # 1 = Ethernet


def test_generator_reproduces_the_checked_in_files(tmp_path):
    """If code changes the expected output, the golden files must be regenerated on purpose."""
    script = ROOT / "scripts" / "generate_golden_pcaps.py"
    subprocess.run([sys.executable, str(script), str(tmp_path)], check=True)
    for name in FILES:
        fresh, checked_in = tmp_path / f"{name}.pcap", GOLDEN / f"{name}.pcap"
        assert filecmp.cmp(fresh, checked_in, shallow=False), name


@pytest.mark.parametrize(
    "index, vlan, ip_src, ip_dst, l4, dport",
    [
        (0, None, "10.0.0.1", "10.0.0.2", UDP, 5000),
        (1, 10, "10.0.0.1", "10.0.0.2", UDP, 5000),
        (2, 20, "10.0.0.1", "10.0.0.2", TCP, 80),
        (3, 10, "10.0.1.1", "10.0.1.2", TCP, 80),
        (4, None, "10.0.0.1", "10.0.0.2", TCP, 80),
        (5, None, "10.0.0.1", "10.0.0.2", UDP, 5000),
    ],
)
def test_mixed_capture_fields(index, vlan, ip_src, ip_dst, l4, dport):
    """A field-by-field check of Ethernet, 802.1Q, IP and L4, like reading a capture by hand."""
    packet = Ether(golden("mixed")[index])
    assert (packet.src, packet.dst) == (SRC_MAC, DST_MAC)
    assert (packet[Dot1Q].vlan if Dot1Q in packet else None) == vlan
    assert (packet[IP].src, packet[IP].dst) == (ip_src, ip_dst)
    assert (packet[l4].sport, packet[l4].dport) == (1024, dport)


def test_checksum_validation_passes_good_frames_and_fails_bad_ones():
    """Bad checksums look like errors in analysis tools. A check must also be able to fail."""
    frames = golden("mixed")
    assert all(checksums_are_valid(frame) for frame in frames)
    corrupted = bytearray(frames[0])
    corrupted[42] ^= 0xFF  # first UDP payload byte
    assert not checksums_are_valid(bytes(corrupted))


@pytest.mark.parametrize(
    "settings, expected",
    [
        ({}, "mixed"),
        ({"vlan_allow": {10}}, "vlan10_expected"),
        ({"tunnel": GreTunnel()}, "gre_expected"),
        ({"tunnel": VxlanTunnel()}, "vxlan_expected"),
    ],
    ids=["no-filter", "vlan-10", "gre", "vxlan"],
)
def test_replay_matches_golden_output(settings, expected):
    """Regression guard: any change to the mirrored bytes makes this comparison fail."""
    broker = PacketBroker(**settings)
    broker.process_all(golden("mixed"))
    assert broker.monitor_port == golden(expected)


@pytest.mark.skipif(shutil.which("tcpdump") is None, reason="tcpdump is not installed")
@pytest.mark.parametrize(
    "name, expected",
    [("vlan10_expected", "vlan 10"), ("gre_expected", "GREv0"), ("vxlan_expected", "vni 100")],
)
def test_tcpdump_agrees_with_our_decoding(name, expected):
    """tcpdump shares no code with this project, which makes it a truly independent check."""
    command = ["tcpdump", "-nn", "-e", "-v", "-r", str(GOLDEN / f"{name}.pcap")]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    assert expected in result.stdout
    assert "bad" not in result.stdout  # tcpdump -v prints "bad cksum" for wrong checksums
