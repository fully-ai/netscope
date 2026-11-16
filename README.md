# NetScope

Pure-Rust PCAP network traffic analyzer, protocol dissector, session tracker, and communication graph exporter.

## Features

- **Pure-Rust PCAP Parser**: Parses little-endian and big-endian microsecond/nanosecond `.pcap` captures without external `libpcap` C dependencies.
- **Multi-Layer Dissection**: Ethernet II, 802.1Q VLAN, ARP, IPv4, IPv6, ICMP/ICMPv6, TCP (flags & payload length), UDP, and DNS query/response headers.
- **Session Reconstruction**: Groups 5-tuple TCP/UDP flows with packet counts, byte totals, and TCP handshake/termination state (`SYN_SENT`, `ESTABLISHED`, `CLOSED`, `RESET`).
- **Communication Mapping & Exports**: Outputs summary analytics, Graphviz DOT communication graphs, CSV packet tables, full JSON bundles, and standalone HTML Canvas graph reports.
- **Filtering**: Filter packet views by protocol, IP address, or port.

## Installation

```bash
git clone https://github.com/fully-ai/netscope.git
cd netscope
cargo build --release
```

## Usage

```bash
netscope analyze capture.pcap
netscope packets capture.pcap --proto tcp --port 443
netscope sessions capture.pcap
netscope dns capture.pcap
netscope arp capture.pcap
netscope export capture.pcap --format html --output report.html
netscope export capture.pcap --format dot --output graph.dot
```

## Testing

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --verbose
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
