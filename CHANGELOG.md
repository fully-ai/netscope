# Changelog

## [0.2.0] - 2026-11-16

### Added
- Interactive local HTTP explorer (`netscope serve`) and single-packet JSON inspector (`netscope inspect`).
- Integration test coverage for 802.1Q VLAN, IPv6, and ICMPv6 dissection.
- Comprehensive README with Mermaid diagram, CLI/HTTP reference, and known limitations.

## [0.1.0] - 2026-11-16

### Added
- Pure-Rust PCAP parser supporting little/big-endian microsecond and nanosecond captures.
- Ethernet II, 802.1Q VLAN, ARP, IPv4, IPv6, ICMP/ICMPv6, TCP, UDP, and DNS dissector.
- Session reconstruction, protocol statistics, top talkers, and communication graph edges.
- CLI subcommands (`analyze`, `packets`, `sessions`, `dns`, `arp`, `export`) and JSON/CSV/DOT/HTML exporters.
