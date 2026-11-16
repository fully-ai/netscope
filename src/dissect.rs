use serde::Serialize;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Serialize)]
pub struct ArpInfo {
    pub operation: String,
    pub sender_mac: String,
    pub sender_ip: String,
    pub target_mac: String,
    pub target_ip: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsInfo {
    pub id: u16,
    pub is_response: bool,
    pub qname: String,
    pub qtype: u16,
    pub answer_count: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = Vec::new();
        if self.syn {
            s.push("SYN");
        }
        if self.ack {
            s.push("ACK");
        }
        if self.fin {
            s.push("FIN");
        }
        if self.rst {
            s.push("RST");
        }
        if self.psh {
            s.push("PSH");
        }
        write!(
            f,
            "{}",
            if s.is_empty() {
                "NONE".to_string()
            } else {
                s.join(",")
            }
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DissectedPacket {
    pub index: usize,
    pub timestamp_ns: u64,
    pub length: u32,
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: String,
    pub protocol: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<TcpFlags>,
    pub arp: Option<ArpInfo>,
    pub dns: Option<DnsInfo>,
    pub payload_len: usize,
    pub summary: String,
}

fn fmt_mac(b: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

pub fn dissect_packet(
    index: usize,
    timestamp_ns: u64,
    orig_len: u32,
    data: &[u8],
) -> DissectedPacket {
    let mut pkt = DissectedPacket {
        index,
        timestamp_ns,
        length: orig_len,
        src_mac: String::new(),
        dst_mac: String::new(),
        ethertype: "UNKNOWN".to_string(),
        protocol: "ETHERNET".to_string(),
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        tcp_flags: None,
        arp: None,
        dns: None,
        payload_len: data.len(),
        summary: "Malformed or truncated frame".to_string(),
    };

    if data.len() < 14 {
        return pkt;
    }

    pkt.dst_mac = fmt_mac(&data[0..6]);
    pkt.src_mac = fmt_mac(&data[6..12]);
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut l3_offset = 14usize;

    // 802.1Q VLAN tag
    if ethertype == 0x8100 && data.len() >= 18 {
        ethertype = u16::from_be_bytes([data[16], data[17]]);
        l3_offset = 18;
    }

    let l3 = &data[l3_offset..];
    match ethertype {
        0x0806 => {
            pkt.ethertype = "ARP".to_string();
            pkt.protocol = "ARP".to_string();
            if l3.len() >= 28 {
                let op = u16::from_be_bytes([l3[6], l3[7]]);
                let op_str = match op {
                    1 => "REQUEST",
                    2 => "REPLY",
                    _ => "OTHER",
                };
                let sha = fmt_mac(&l3[8..14]);
                let spa = Ipv4Addr::new(l3[14], l3[15], l3[16], l3[17]).to_string();
                let tha = fmt_mac(&l3[18..24]);
                let tpa = Ipv4Addr::new(l3[24], l3[25], l3[26], l3[27]).to_string();
                pkt.src_ip = Some(spa.clone());
                pkt.dst_ip = Some(tpa.clone());
                pkt.summary = format!("ARP {op_str} {spa} ({sha}) -> {tpa}");
                pkt.arp = Some(ArpInfo {
                    operation: op_str.to_string(),
                    sender_mac: sha,
                    sender_ip: spa,
                    target_mac: tha,
                    target_ip: tpa,
                });
            }
        }
        0x0800 => {
            pkt.ethertype = "IPv4".to_string();
            if l3.len() >= 20 {
                let ihl = ((l3[0] & 0x0f) as usize) * 4;
                if ihl >= 20 && l3.len() >= ihl {
                    let proto = l3[9];
                    let src = Ipv4Addr::new(l3[12], l3[13], l3[14], l3[15]).to_string();
                    let dst = Ipv4Addr::new(l3[16], l3[17], l3[18], l3[19]).to_string();
                    pkt.src_ip = Some(src.clone());
                    pkt.dst_ip = Some(dst.clone());
                    dissect_transport(&mut pkt, proto, &l3[ihl..], &src, &dst);
                }
            }
        }
        0x86dd => {
            pkt.ethertype = "IPv6".to_string();
            if l3.len() >= 40 {
                let next_hdr = l3[6];
                let src = Ipv6Addr::from(<[u8; 16]>::try_from(&l3[8..24]).unwrap()).to_string();
                let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&l3[24..40]).unwrap()).to_string();
                pkt.src_ip = Some(src.clone());
                pkt.dst_ip = Some(dst.clone());
                dissect_transport(&mut pkt, next_hdr, &l3[40..], &src, &dst);
            }
        }
        other => {
            pkt.ethertype = format!("0x{other:04x}");
            pkt.summary = format!("Ethernet frame 0x{other:04x} ({} bytes)", data.len());
        }
    }
    pkt
}

fn dissect_transport(pkt: &mut DissectedPacket, proto: u8, l4: &[u8], src: &str, dst: &str) {
    match proto {
        6 => {
            pkt.protocol = "TCP".to_string();
            if l4.len() >= 20 {
                let sport = u16::from_be_bytes([l4[0], l4[1]]);
                let dport = u16::from_be_bytes([l4[2], l4[3]]);
                let data_off = (((l4[12] >> 4) & 0x0f) as usize) * 4;
                let flags_byte = l4[13];
                let flags = TcpFlags {
                    fin: flags_byte & 0x01 != 0,
                    syn: flags_byte & 0x02 != 0,
                    rst: flags_byte & 0x04 != 0,
                    psh: flags_byte & 0x08 != 0,
                    ack: flags_byte & 0x10 != 0,
                };
                pkt.src_port = Some(sport);
                pkt.dst_port = Some(dport);
                pkt.payload_len = l4.len().saturating_sub(data_off.max(20));
                pkt.summary = format!(
                    "TCP {src}:{sport} -> {dst}:{dport} [{flags}] len={}",
                    pkt.payload_len
                );
                pkt.tcp_flags = Some(flags);
            }
        }
        17 => {
            pkt.protocol = "UDP".to_string();
            if l4.len() >= 8 {
                let sport = u16::from_be_bytes([l4[0], l4[1]]);
                let dport = u16::from_be_bytes([l4[2], l4[3]]);
                pkt.src_port = Some(sport);
                pkt.dst_port = Some(dport);
                let payload = &l4[8..];
                pkt.payload_len = payload.len();
                if (sport == 53 || dport == 53) && payload.len() >= 12 {
                    if let Some(dns) = parse_dns(payload) {
                        pkt.protocol = "DNS".to_string();
                        let kind = if dns.is_response { "Response" } else { "Query" };
                        pkt.summary = format!(
                            "DNS {kind} {src}:{sport} -> {dst}:{dport} {} (type {})",
                            dns.qname, dns.qtype
                        );
                        pkt.dns = Some(dns);
                        return;
                    }
                }
                pkt.summary = format!("UDP {src}:{sport} -> {dst}:{dport} len={}", pkt.payload_len);
            }
        }
        1 | 58 => {
            pkt.protocol = if proto == 1 {
                "ICMP".to_string()
            } else {
                "ICMPv6".to_string()
            };
            pkt.payload_len = l4.len();
            pkt.summary = format!("{} {src} -> {dst} len={}", pkt.protocol, l4.len());
        }
        other => {
            pkt.protocol = format!("IP_PROTO_{other}");
            pkt.payload_len = l4.len();
            pkt.summary = format!("{} {src} -> {dst} len={}", pkt.protocol, l4.len());
        }
    }
}

fn parse_dns(payload: &[u8]) -> Option<DnsInfo> {
    if payload.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12usize;
    let mut labels = Vec::new();
    while pos < payload.len() {
        let len = payload[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if (len & 0xc0) == 0xc0 || pos + len > payload.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&payload[pos..pos + len]).to_string());
        pos += len;
    }
    if pos + 4 > payload.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
    Some(DnsInfo {
        id,
        is_response,
        qname: labels.join("."),
        qtype,
        answer_count: ancount,
    })
}
