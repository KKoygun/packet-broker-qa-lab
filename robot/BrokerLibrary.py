"""Robot Framework keywords, wrapping the same helpers the pytest suite uses."""

from robot.api import SkipExecution

from broker.broker import PacketBroker
from broker.frames import build_frame
from broker.netns import have_privileges, mirror_through_lab, run_lab_script


class BrokerLibrary:
    ROBOT_LIBRARY_SCOPE = "TEST"  # a new instance per test, so no state leaks between tests

    def create_broker(self, *allowed_vlans):
        """Create a broker, filtering on the given VLANs if any are listed."""
        vlans = {int(vlan) for vlan in allowed_vlans} or None
        self.broker = PacketBroker(vlan_allow=vlans)

    def send_frames(self, count, vlan=None):
        vlan = int(vlan) if vlan is not None else None
        self.broker.process_all(build_frame(vlan=vlan) for _ in range(int(count)))

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
        run_lab_script("up")

    def stop_lab(self):
        if have_privileges():  # teardown also runs after a skipped test
            run_lab_script("down")

    def lab_should_deliver_frames(self, count):
        """Send frames across the veth lab and compare what the monitor namespace received."""
        frames = [build_frame(f"frame-{i}".encode()) for i in range(int(count))]
        received = mirror_through_lab(PacketBroker(), frames)
        if received != frames:
            raise AssertionError(f"pb-mon got {len(received)} frames, expected them to match")
