use netscope::analysis::{analyze_packets, filter_packets, PacketFilter};
use netscope::dissect::dissect_packet;
use netscope::export::{export_csv, export_dot, export_html, export_json};
use netscope::pcap::parse_pcap_bytes;

fn build_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    // Little-endian microsecond PCAP global header
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes()); // major
    out.extend_from_slice(&4u16.to_le_bytes()); // minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET

    for (i, frame) in frames.iter().enumerate() {
        let sec = 1700000000u32 + i as u32;
        let usec = 100u32;
        let len = frame.len() as u32;
        out.extend_from_slice(&sec.to_le_bytes());
        out.extend_from_slice(&usec.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(frame);
    }
    out
}

fn eth_header(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f
}

fn arp_frame() -> Vec<u8> {
    let mut f = eth_header([0xff; 6], [0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03], 0x0806);
    f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]); // Ethernet, IPv4, request
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]);
    f.extend_from_slice(&[192, 168, 1, 10]);
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&[192, 168, 1, 1]);
    f
}

fn ipv4_packet(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
    let mut f = eth_header(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03],
        0x0800,
    );
    let total_len = (20 + l4.len()) as u16;
    f.push(0x45); // v4, IHL=5
    f.push(0x00);
    f.extend_from_slice(&total_len.to_be_bytes());
    f.extend_from_slice(&[0, 1, 0, 0, 64, proto, 0, 0]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(l4);
    f
}

fn tcp_segment(sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&sport.to_be_bytes());
    s.extend_from_slice(&dport.to_be_bytes());
    s.extend_from_slice(&1u32.to_be_bytes()); // seq
    s.extend_from_slice(&0u32.to_be_bytes()); // ack
    s.push(0x50); // data offset = 5 (20 bytes)
    s.push(flags);
    s.extend_from_slice(&65535u16.to_be_bytes());
    s.extend_from_slice(&[0, 0, 0, 0]);
    s.extend_from_slice(payload);
    s
}

fn dns_udp_frame() -> Vec<u8> {
    let mut dns = vec![
        0x12, 0x34, // id
        0x01, 0x00, // standard query
        0x00, 0x01, // qdcount = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // qname: example.com
    dns.push(7);
    dns.extend_from_slice(b"example");
    dns.push(3);
    dns.extend_from_slice(b"com");
    dns.push(0);
    dns.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    dns.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    let mut udp = Vec::new();
    udp.extend_from_slice(&53530u16.to_be_bytes());
    udp.extend_from_slice(&53u16.to_be_bytes());
    udp.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&dns);

    ipv4_packet(17, [192, 168, 1, 10], [8, 8, 8, 8], &udp)
}

#[test]
fn test_pcap_dissection_sessions_filters_and_exports() {
    let frames = vec![
        arp_frame(),
        dns_udp_frame(),
        ipv4_packet(
            6,
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            &tcp_segment(51000, 443, 0x02, b""),
        ),
        ipv4_packet(
            6,
            [93, 184, 216, 34],
            [192, 168, 1, 10],
            &tcp_segment(443, 51000, 0x12, b""),
        ),
        ipv4_packet(
            6,
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            &tcp_segment(51000, 443, 0x11, b"hi"),
        ),
    ];

    let pcap_bytes = build_pcap(&frames);
    let capture = parse_pcap_bytes(&pcap_bytes).expect("valid pcap");
    assert_eq!(capture.packets.len(), 5);

    let dissected: Vec<_> = capture
        .packets
        .iter()
        .map(|p| dissect_packet(p.index, p.timestamp_ns, p.orig_len, &p.data))
        .collect();

    assert_eq!(dissected[0].protocol, "ARP");
    assert_eq!(dissected[0].arp.as_ref().unwrap().target_ip, "192.168.1.1");
    assert_eq!(dissected[1].protocol, "DNS");
    assert_eq!(dissected[1].dns.as_ref().unwrap().qname, "example.com");

    let report = analyze_packets(&dissected);
    assert_eq!(report.packet_count, 5);
    assert_eq!(report.protocol_counts.get("TCP"), Some(&3));
    assert_eq!(report.sessions.len(), 2); // 1 DNS/UDP session + 1 TCP session

    let tcp_sess = report
        .sessions
        .iter()
        .find(|s| s.protocol == "TCP")
        .unwrap();
    assert_eq!(tcp_sess.packets, 3);
    assert_eq!(tcp_sess.state, "CLOSED");

    let dns_only = filter_packets(
        &dissected,
        &PacketFilter {
            protocol: Some("dns".to_string()),
            ip: None,
            port: Some(53),
        },
    );
    assert_eq!(dns_only.len(), 1);

    let json_out = export_json(&report, &dissected).unwrap();
    assert!(json_out.contains("example.com"));
    let csv_out = export_csv(&dissected);
    assert!(csv_out.contains("93.184.216.34"));
    let dot_out = export_dot(&report);
    assert!(dot_out.contains("digraph netscope"));
    let html_out = export_html(&report, &dissected);
    assert!(html_out.contains("NetScope PCAP Traffic Analysis"));
}
