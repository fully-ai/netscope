use crate::analysis::AnalysisReport;
use crate::dissect::DissectedPacket;
use std::fmt::Write as _;

pub fn export_json(
    report: &AnalysisReport,
    packets: &[DissectedPacket],
) -> serde_json::Result<String> {
    #[derive(serde::Serialize)]
    struct Bundle<'a> {
        report: &'a AnalysisReport,
        packets: &'a [DissectedPacket],
    }
    serde_json::to_string_pretty(&Bundle { report, packets })
}

pub fn export_csv(packets: &[DissectedPacket]) -> String {
    let mut out = String::from(
        "index,timestamp_ns,length,protocol,src_ip,src_port,dst_ip,dst_port,summary\n",
    );
    for p in packets {
        let src_ip = p.src_ip.as_deref().unwrap_or("");
        let dst_ip = p.dst_ip.as_deref().unwrap_or("");
        let src_port = p.src_port.map(|v| v.to_string()).unwrap_or_default();
        let dst_port = p.dst_port.map(|v| v.to_string()).unwrap_or_default();
        let summary = p.summary.replace('"', "\"\"");
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},\"{}\"",
            p.index,
            p.timestamp_ns,
            p.length,
            p.protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            summary
        );
    }
    out
}

pub fn export_dot(report: &AnalysisReport) -> String {
    let mut out =
        String::from("digraph netscope {\n  rankdir=LR;\n  node [shape=box, style=rounded];\n");
    for edge in &report.edges {
        let _ = writeln!(
            out,
            "  \"{}\" -> \"{}\" [label=\"{} ({} pkts, {} B)\"];",
            edge.src, edge.dst, edge.protocol, edge.packets, edge.bytes
        );
    }
    out.push_str("}\n");
    out
}

pub fn export_html(report: &AnalysisReport, packets: &[DissectedPacket]) -> String {
    let report_json = serde_json::to_string(report).unwrap_or_else(|_| "{}".to_string());
    let packets_json = serde_json::to_string(&packets[..packets.len().min(500)])
        .unwrap_or_else(|_| "[]".to_string());
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>NetScope Traffic Report</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #0f1419; color: #e6edf3; margin: 24px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 20px; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; background: #161b22; }}
th, td {{ border-bottom: 1px solid #30363d; padding: 8px; text-align: left; font-size: 0.88rem; }}
canvas {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; width: 100%; max-width: 900px; }}
</style>
</head>
<body>
<h1>NetScope PCAP Traffic Analysis</h1>
<div class="grid">
  <div class="card"><div>Packets</div><h2>{}</h2></div>
  <div class="card"><div>Total Bytes</div><h2>{}</h2></div>
  <div class="card"><div>Sessions</div><h2>{}</h2></div>
  <div class="card"><div>Communication Edges</div><h2>{}</h2></div>
</div>
<h2>Protocol Breakdown &amp; Communication Graph</h2>
<canvas id="graph" width="900" height="340"></canvas>
<h2>Packets</h2>
<table><thead><tr><th>#</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Len</th><th>Summary</th></tr></thead><tbody id="pkts"></tbody></table>
<script>
const report = {report_json};
const packets = {packets_json};
const tbody = document.getElementById('pkts');
for (const p of packets) {{
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>${{p.index}}</td><td>${{p.protocol}}</td><td>${{p.src_ip||p.src_mac}}:${{p.src_port||''}}</td><td>${{p.dst_ip||p.dst_mac}}:${{p.dst_port||''}}</td><td>${{p.length}}</td><td>${{p.summary}}</td>`;
  tbody.appendChild(tr);
}}
const canvas = document.getElementById('graph');
const ctx = canvas.getContext('2d');
const nodes = [...new Set(report.edges.flatMap(e => [e.src, e.dst]))];
const pos = {{}};
nodes.forEach((n, i) => {{
  const angle = (i / Math.max(1, nodes.length)) * Math.PI * 2;
  pos[n] = {{ x: 450 + Math.cos(angle) * 260, y: 170 + Math.sin(angle) * 115 }};
}});
ctx.strokeStyle = '#3b82f6';
ctx.fillStyle = '#e6edf3';
ctx.font = '12px monospace';
for (const e of report.edges) {{
  const a = pos[e.src], b = pos[e.dst];
  if (!a || !b) continue;
  ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
}}
for (const n of nodes) {{
  const p = pos[n];
  ctx.fillStyle = '#2563eb'; ctx.beginPath(); ctx.arc(p.x, p.y, 8, 0, Math.PI*2); ctx.fill();
  ctx.fillStyle = '#e6edf3'; ctx.fillText(n, p.x + 12, p.y + 4);
}}
</script>
</body>
</html>"#,
        report.packet_count,
        report.total_bytes,
        report.sessions.len(),
        report.edges.len()
    )
}
