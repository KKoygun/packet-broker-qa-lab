"""Linux namespace helpers for the integration tests and the Robot suite.

A socket stays attached to the namespace it was created in, so one process can
open a port in each namespace and drive them all. That avoids background
processes and start-up races. The topology is drawn in scripts/netns_setup.sh.
"""

import os
import shutil
import socket
import struct
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

from broker.frames import ETHERTYPE_VLAN

SETUP_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "netns_setup.sh"

# From <linux/if_packet.h>; Python's socket module does not export these.
SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4
ETH_P_ALL = 3


def have_privileges():
    return sys.platform == "linux" and os.geteuid() == 0 and shutil.which("ip") is not None


def run_lab_script(action):
    """Run netns_setup.sh with "up" or "down"."""
    subprocess.run(["bash", str(SETUP_SCRIPT), action], check=True)


@contextmanager
def in_namespace(name):
    """Run a block inside a network namespace, then come back."""
    with open("/proc/self/ns/net") as home, open(f"/var/run/netns/{name}") as target:
        os.setns(target, os.CLONE_NEWNET)
        try:
            yield
        finally:
            os.setns(home, os.CLONE_NEWNET)


def open_port(namespace, interface, timeout=1.0):
    """Open a raw socket on an interface inside a namespace."""
    with in_namespace(namespace):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        sock.bind((interface, ETH_P_ALL))
    sock.settimeout(timeout)
    return sock


def receive_frame(sock):
    """Receive one frame, putting back the VLAN tag if the kernel removed it.

    Linux strips the 802.1Q tag on receive and reports it in ancillary data, so a
    plain recv() would make every tagged frame look untagged. libpcap does the same fix.
    """
    frame, ancillary, _, _ = sock.recvmsg(65535, socket.CMSG_SPACE(20))
    for level, kind, data in ancillary:
        if level == SOL_PACKET and kind == PACKET_AUXDATA:
            # struct tpacket_auxdata: status, len, snaplen, mac, net, vlan_tci, vlan_tpid
            status, _, _, _, _, tci, tpid = struct.unpack("=IIIHHHH", data[:20])
            if status & TP_STATUS_VLAN_VALID:
                tag = struct.pack("!HH", tpid or ETHERTYPE_VLAN, tci)
                return frame[:12] + tag + frame[12:]
    return frame


def mirror_through_lab(broker, frames):
    """Send frames from pb-src through the broker; return what pb-mon receives."""
    src = open_port("pb-src", "src0")
    dut_in = open_port("pb-dut", "dut-in")
    dut_mon = open_port("pb-dut", "dut-mon")
    mon = open_port("pb-mon", "mon0", timeout=0.2)
    try:
        for frame in frames:
            src.send(frame)
        for _ in frames:
            already_sent = len(broker.monitor_port)
            broker.process(receive_frame(dut_in))
            for mirrored in broker.monitor_port[already_sent:]:
                dut_mon.send(mirrored)
        received = []
        try:
            while True:  # read until quiet, so extra or duplicate frames get noticed too
                received.append(receive_frame(mon))
        except TimeoutError:
            return received
    finally:
        for sock in (src, dut_in, dut_mon, mon):
            sock.close()
