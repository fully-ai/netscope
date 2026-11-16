use crate::dissect::DissectedPacket;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Default, Clone)]
pub struct PacketFilter {
    pub protocol: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
}

impl PacketFilter {
    pub fn matches(&self, pkt: &DissectedPacket) -> bool {
        if let Some(ref proto) = self.protocol {
            if !pkt.protocol.eq_ignore_ascii_case(proto) {
                return false;
            }
        }
        if let Some(ref ip) = self.ip {
            let match_ip = pkt.src_ip.as_deref() == Some(ip.as_str())
                || pkt.dst_ip.as_deref() == Some(ip.as_str());
            if !match_ip {
                return false;
            }
        }
        if let Some(port) = self.port {
            let match_port = pkt.src_port == Some(port) || pkt.dst_port == Some(port);
            if !match_port {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub protocol: String,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub packets: usize,
    pub total_bytes: u64,
    pub state: String,
    pub start_ns: u64,
    pub end_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommEdge {
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub packets: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    pub packet_count: usize,
    pub total_bytes: u64,
    pub protocol_counts: BTreeMap<String, usize>,
    pub top_talkers: Vec<(String, u64)>,
    pub sessions: Vec<SessionInfo>,
    pub edges: Vec<CommEdge>,
}

pub fn filter_packets<'a>(
    packets: &'a [DissectedPacket],
    filter: &PacketFilter,
) -> Vec<&'a DissectedPacket> {
    packets.iter().filter(|p| filter.matches(p)).collect()
}

pub fn analyze_packets(packets: &[DissectedPacket]) -> AnalysisReport {
    let mut total_bytes = 0u64;
    let mut protocol_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut talker_bytes: HashMap<String, u64> = HashMap::new();
    let mut session_map: HashMap<(String, String, String), SessionInfo> = HashMap::new();
    let mut edge_map: HashMap<(String, String, String), CommEdge> = HashMap::new();

    for p in packets {
        total_bytes += p.length as u64;
        *protocol_counts.entry(p.protocol.clone()).or_insert(0) += 1;

        if let Some(ref src) = p.src_ip {
            *talker_bytes.entry(src.clone()).or_insert(0) += p.length as u64;
        }
        if let Some(ref dst) = p.dst_ip {
            *talker_bytes.entry(dst.clone()).or_insert(0) += p.length as u64;
        }

        if let (Some(src), Some(dst)) = (&p.src_ip, &p.dst_ip) {
            let e_key = (src.clone(), dst.clone(), p.protocol.clone());
            let edge = edge_map.entry(e_key).or_insert_with(|| CommEdge {
                src: src.clone(),
                dst: dst.clone(),
                protocol: p.protocol.clone(),
                packets: 0,
                bytes: 0,
            });
            edge.packets += 1;
            edge.bytes += p.length as u64;

            if let (Some(sp), Some(dp)) = (p.src_port, p.dst_port) {
                let a = format!("{src}:{sp}");
                let b = format!("{dst}:{dp}");
                let (ep1, ep2) = if a <= b { (a, b) } else { (b, a) };
                let s_key = (p.protocol.clone(), ep1.clone(), ep2.clone());
                let sess = session_map.entry(s_key).or_insert_with(|| SessionInfo {
                    protocol: p.protocol.clone(),
                    endpoint_a: ep1,
                    endpoint_b: ep2,
                    packets: 0,
                    total_bytes: 0,
                    state: "ACTIVE".to_string(),
                    start_ns: p.timestamp_ns,
                    end_ns: p.timestamp_ns,
                });
                sess.packets += 1;
                sess.total_bytes += p.length as u64;
                sess.end_ns = sess.end_ns.max(p.timestamp_ns);
                if let Some(ref f) = p.tcp_flags {
                    if f.rst {
                        sess.state = "RESET".to_string();
                    } else if f.fin {
                        sess.state = "CLOSED".to_string();
                    } else if f.syn && !f.ack && sess.packets == 1 {
                        sess.state = "SYN_SENT".to_string();
                    } else if f.ack && sess.state == "SYN_SENT" {
                        sess.state = "ESTABLISHED".to_string();
                    }
                }
            }
        }
    }

    let mut top_talkers: Vec<(String, u64)> = talker_bytes.into_iter().collect();
    top_talkers.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top_talkers.truncate(10);

    let mut sessions: Vec<SessionInfo> = session_map.into_values().collect();
    sessions.sort_by_key(|a| std::cmp::Reverse(a.total_bytes));

    let mut edges: Vec<CommEdge> = edge_map.into_values().collect();
    edges.sort_by_key(|a| std::cmp::Reverse(a.bytes));

    AnalysisReport {
        packet_count: packets.len(),
        total_bytes,
        protocol_counts,
        top_talkers,
        sessions,
        edges,
    }
}
