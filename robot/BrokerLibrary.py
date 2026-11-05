"""Robot Framework keywords, wrapping the same helpers the pytest suite uses."""

from robot.api import SkipExecution

from broker.broker import PacketBroker
from broker.frames import build_frame, build_runt
from broker.netns import have_privileges, lab_down, lab_up, mirror_through_lab


class BrokerLibrary:
    ROBOT_LIBRARY_SCOPE = "TEST"  # a new instance per test, so no state leaks between tests

    def __init__(self):
        self.broker = PacketBroker()
        self.received = []

    def create_broker(self, *allowed_vlans):
        """Create a broker, filtering on the given VLANs if any are listed."""
        vlans = {int(vlan) for vlan in allowed_vlans} or None
        self.broker = PacketBroker(vlan_allow=vlans)

    def send_frames(self, count, vlan=None):
        vlan = int(vlan) if vlan is not None else None
        self.broker.process_all(build_frame(vlan=vlan) for _ in range(int(count)))

    def send_runt_frame(self):
        self.broker.process(build_runt())

    def monitor_port_should_have(self, count):
        actual = len(self.broker.monitor_port)
        if actual != int(count):
            raise AssertionError(f"monitor port has {actual} frames, expected {count}")

    def counter_should_be(self, name, value):
        actual = getattr(self.broker.counters, name)
        if actual != int(value):
            raise AssertionError(f"{name} is {actual}, expected {value}")

    def skip_without_privileges(self):
        if not have_privileges():
            raise SkipExecution("needs Linux, root and iproute2")

    def start_lab(self):
        lab_up()

    def stop_lab(self):
        if have_privileges():  # teardown also runs after a skipped test
            lab_down()

    def send_frames_through_lab(self, count):
        frames = [build_frame(f"frame-{i}".encode()) for i in range(int(count))]
        self.received = mirror_through_lab(self.broker, frames)

    def monitor_namespace_should_have(self, count):
        if len(self.received) != int(count):
            raise AssertionError(f"pb-mon got {len(self.received)} frames, expected {count}")
