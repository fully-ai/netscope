use clap::{Parser, Subcommand, ValueEnum};
use netscope::analysis::{analyze_packets, filter_packets, PacketFilter};
use netscope::dissect::{dissect_packet, DissectedPacket};
use netscope::export::{export_csv, export_dot, export_html, export_json};
use netscope::pcap::parse_pcap_file;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

#[derive(Parser)]
#[command(
    name = "netscope",
    version,
    about = "PCAP network traffic analyzer and protocol dissector"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Summarize protocols, talkers, sessions, and edges in a PCAP file
    Analyze { file: PathBuf },
    /// List dissected packets with optional protocol/IP/port filters
    Packets {
        file: PathBuf,
        #[arg(long)]
        proto: Option<String>,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Show reconstructed TCP/UDP sessions
    Sessions { file: PathBuf },
    /// Extract DNS queries and responses
    Dns { file: PathBuf },
    /// Extract ARP requests and replies
    Arp { file: PathBuf },
    /// Export analysis and packets to JSON, CSV, Graphviz DOT, or interactive HTML
    Export {
        file: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Json)]
        format: Format,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    Json,
    Csv,
    Dot,
    Html,
}

fn load_dissected(path: &Path) -> Vec<DissectedPacket> {
    let capture = match parse_pcap_file(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error reading {}: {e}", path.display());
            process::exit(1);
        }
    };
    capture
        .packets
        .iter()
        .map(|p| dissect_packet(p.index, p.timestamp_ns, p.orig_len, &p.data))
        .collect()
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Analyze { file } => {
            let packets = load_dissected(&file);
            let report = analyze_packets(&packets);
            println!(
                "Packets: {} | Total Bytes: {}",
                report.packet_count, report.total_bytes
            );
            println!("\nProtocols:");
            for (proto, count) in &report.protocol_counts {
                println!("  {proto:<10} {count}");
            }
            println!("\nTop Talkers:");
            for (ip, bytes) in &report.top_talkers {
                println!("  {ip:<24} {bytes} bytes");
            }
            println!(
                "\nSessions: {} | Communication Edges: {}",
                report.sessions.len(),
                report.edges.len()
            );
        }
        Commands::Packets {
            file,
            proto,
            ip,
            port,
        } => {
            let packets = load_dissected(&file);
            let filter = PacketFilter {
                protocol: proto,
                ip,
                port,
            };
            for p in filter_packets(&packets, &filter) {
                println!("#{:<4} {:<6} {}", p.index, p.protocol, p.summary);
            }
        }
        Commands::Sessions { file } => {
            let packets = load_dissected(&file);
            let report = analyze_packets(&packets);
            for s in &report.sessions {
                println!(
                    "{:<4} {} <-> {} | pkts={} bytes={} state={}",
                    s.protocol, s.endpoint_a, s.endpoint_b, s.packets, s.total_bytes, s.state
                );
            }
        }
        Commands::Dns { file } => {
            let packets = load_dissected(&file);
            for p in &packets {
                if let Some(ref d) = p.dns {
                    let kind = if d.is_response { "RESP" } else { "QUERY" };
                    println!(
                        "#{} [{}] id=0x{:04x} {} qtype={} answers={}",
                        p.index, kind, d.id, d.qname, d.qtype, d.answer_count
                    );
                }
            }
        }
        Commands::Arp { file } => {
            let packets = load_dissected(&file);
            for p in &packets {
                if let Some(ref a) = p.arp {
                    println!(
                        "#{} {} {} ({}) -> {} ({})",
                        p.index, a.operation, a.sender_ip, a.sender_mac, a.target_ip, a.target_mac
                    );
                }
            }
        }
        Commands::Export {
            file,
            format,
            output,
        } => {
            let packets = load_dissected(&file);
            let report = analyze_packets(&packets);
            let rendered = match format {
                Format::Json => export_json(&report, &packets).expect("JSON serialization failed"),
                Format::Csv => export_csv(&packets),
                Format::Dot => export_dot(&report),
                Format::Html => export_html(&report, &packets),
            };
            if let Some(out_path) = output {
                fs::write(&out_path, rendered).expect("failed to write output file");
            } else {
                print!("{rendered}");
            }
        }
    }
}
