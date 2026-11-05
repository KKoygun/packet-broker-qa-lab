# Test strategy

## Goal

A packet broker is trusted as a source of evidence. The main risks are therefore a capture
that differs from what crossed the network, and monitoring that disturbs live traffic.

## Risks and how they are covered

| Risk | Effect | Main coverage |
| --- | --- | --- |
| Mirror changes, loses or reorders frames | Misleading analysis | Functional, integration |
| Filter passes the wrong VLAN or affects live traffic | Missing data, outage | Functional |
| Bad frames crash the broker or reach the tools | Stalled monitoring | Functional |
| Off-by-one at MTU limits | Silent loss of full-size frames | Boundary tests |
| Counters disagree with traffic | Wrong diagnosis | Conservation checks |
| Tunnel changes the inner frame or breaks the format | Remote tools cannot decode | Byte-level checks, tcpdump |
| Behaviour drifts between versions | Unnoticed regression | Golden pcaps |

## Test levels

| Level | Location | Needs root | Purpose |
| --- | --- | --- | --- |
| Unit | `tests/unit` | No | Builders, header readers, counters |
| Functional | `tests/functional` | No | Broker behaviour, in memory |
| Capture | `tests/capture` | No | Pcap parsing, field checks, golden replay |
| Tunnel | `tests/tunnel` | No | GRE and VXLAN encap and decap |
| Integration | `tests/integration` | Yes | Real sockets over veth pairs |
| Acceptance | `robot/` | Only for one test | Readable checks using the same helpers |

## Approach

- **Independent oracles.** The broker reads headers with `struct`, and tests check them with
  scapy. Scapy also builds the tunnels, so those are checked with raw bytes and tcpdump.
- **Boundary value analysis** on frame sizes, always testing both sides of a limit.
- **Golden files** for regression. Expected VLAN output is chosen by hand, not by the broker.
- **Skip, do not fail, without privileges.** Tests needing root skip themselves, so the suite
  stays usable anywhere. CI runs as root, so nothing is skipped there.

## Out of scope

Real hardware, line-rate performance, FCS, IPv6 header validation, QinQ, and timing accuracy.
A software model cannot show these, so only a basic sanity check on speed exists.
