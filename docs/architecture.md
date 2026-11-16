# Architecture — NetScope

## Pipeline

1. **Capture Parsing (`src/pcap.rs`)**: Validates little/big-endian microsecond and nanosecond libpcap global headers (`LINKTYPE_ETHERNET`) and extracts raw packet records.
2. **Protocol Dissection (`src/dissect.rs`)**: Decodes Ethernet II, 802.1Q VLAN tags, ARP requests/replies, IPv4, IPv6, ICMP/ICMPv6, TCP flags/payload length, UDP, and DNS query/response headers.
3. **Flow & Graph Analysis (`src/analysis.rs`)**: Computes protocol distributions, top talkers, 5-tuple TCP/UDP sessions with TCP state tracking, and directed communication edges.
4. **Exporters (`src/export.rs`)**: Renders structured JSON bundles, CSV packet tables, Graphviz DOT graphs, and standalone HTML Canvas visualizations.
