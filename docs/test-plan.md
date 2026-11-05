# Test plan

## Scope

The in-memory broker (mirror, VLAN filter, frame validation, counters), the GRE and VXLAN
tunnels, and the same broker driven over Linux veth pairs.

## Environment

Python 3.12, scapy and pytest on Linux. The integration tests need root and iproute2. The
tcpdump checks skip themselves if tcpdump is not installed.

## Features and test cases

| ID | Feature | What is checked | Tests |
| --- | --- | --- | --- |
| M1 | Mirror | Byte-identical copies | `test_mirror.py` |
| M2 | Mirror | No loss, order kept | `test_mirror.py` |
| V1 | VLAN filter | Allow list, empty list, network port unaffected | `test_vlan_filter.py` |
| V2 | VLAN filter | Untagged and VID 0 follow the setting | `test_vlan_filter.py` |
| B1 | Validation | Runts at 0, 1, 13, 14, 40 and 59 bytes are dropped | `test_malformed.py` |
| B2 | Validation | Bad IPv4 version, header length, total length | `test_malformed.py` |
| S1 | MTU | 1514/1515 untagged, 1518/1519 tagged, jumbo, lowered MTU | `test_mtu.py` |
| C1 | Counters | Right bucket (VID 4095 too), bytes correct, all frames accounted for | `test_counters.py` |
| P1 | Capture | Pcap header, Ethernet, 802.1Q, IP, TCP/UDP fields, checksums | `test_golden_pcaps.py` |
| P2 | Capture | Replay matches golden output, tcpdump agrees | `test_golden_pcaps.py` |
| T1 | Tunnels | Byte-exact round trip, exact overhead, header bytes | `test_tunnels.py` |
| T2 | Tunnels | Rejects wrong VNI, flag, port, payload type, truncated input | `test_tunnels.py` |
| I1 | Integration | Mirror, filter and tunnels over veth pairs | `test_netns.py` |
| R1 | Acceptance | Mirror, filter and veth checks in Robot Framework | `broker.robot` |
| Q1 | Sanity | 10,000 frames with no loss in under 2 seconds | `test_sanity.py` |

## Entry and exit criteria

- **Entry:** ruff passes and the project installs from a clean checkout.
- **Exit:** every test passes. A skip is acceptable only for a missing privilege or tool.

## Reporting

Each CI run on `main` publishes the pytest HTML report and the Robot report to GitHub Pages.
