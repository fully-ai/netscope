use crate::analysis::AnalysisReport;
use crate::dissect::DissectedPacket;
use crate::export::export_html;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

pub fn serve_report(
    addr: &str,
    report: &AnalysisReport,
    packets: &[DissectedPacket],
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    let html = export_html(report, packets);
    let json_report = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string());
    let json_packets = serde_json::to_string(packets).unwrap_or_else(|_| "[]".to_string());

    println!("NetScope web explorer listening on http://{addr}");
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            continue;
        }
        let path = request_line.split_whitespace().nth(1).unwrap_or("/");
        let (status, ctype, body): (&str, &str, &str) = match path {
            "/" => ("200 OK", "text/html; charset=utf-8", &html),
            "/api/report" => ("200 OK", "application/json", &json_report),
            "/api/packets" => ("200 OK", "application/json", &json_packets),
            _ => ("404 Not Found", "text/plain", "Not found"),
        };
        let header = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body.as_bytes());
    }
    Ok(())
}
