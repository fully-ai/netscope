use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PcapHeader {
    pub version_major: u16,
    pub version_minor: u16,
    pub snaplen: u32,
    pub network: u32,
    pub little_endian: bool,
    pub nanoseconds: bool,
}

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub index: usize,
    pub timestamp_ns: u64,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct PcapCapture {
    pub header: PcapHeader,
    pub packets: Vec<RawPacket>,
}

fn read_u16(b: &[u8], le: bool) -> u16 {
    if le {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    }
}

fn read_u32(b: &[u8], le: bool) -> u32 {
    if le {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }
}

pub fn parse_pcap_file(path: &Path) -> io::Result<PcapCapture> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    parse_pcap_bytes(&buf)
}

pub fn parse_pcap_bytes(data: &[u8]) -> io::Result<PcapCapture> {
    if data.len() < 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PCAP file too short for global header",
        ));
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (little_endian, nanoseconds) = match magic {
        0xa1b2c3d4 => (true, false),
        0xd4c3b2a1 => (false, false),
        0xa1b23c4d => (true, true),
        0x4d3cb2a1 => (false, true),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported PCAP magic number: 0x{magic:08x}"),
            ))
        }
    };

    let header = PcapHeader {
        version_major: read_u16(&data[4..6], little_endian),
        version_minor: read_u16(&data[6..8], little_endian),
        snaplen: read_u32(&data[16..20], little_endian),
        network: read_u32(&data[20..24], little_endian),
        little_endian,
        nanoseconds,
    };

    if header.network != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Only Ethernet link-layer (LINKTYPE_ETHERNET=1) is supported, got {}",
                header.network
            ),
        ));
    }

    let mut packets = Vec::new();
    let mut offset = 24usize;
    let mut index = 1usize;

    while offset + 16 <= data.len() {
        let ts_sec = read_u32(&data[offset..offset + 4], little_endian) as u64;
        let ts_sub = read_u32(&data[offset + 4..offset + 8], little_endian) as u64;
        let incl_len = read_u32(&data[offset + 8..offset + 12], little_endian) as usize;
        let orig_len = read_u32(&data[offset + 12..offset + 16], little_endian);
        offset += 16;

        if offset + incl_len > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Truncated PCAP packet record",
            ));
        }

        let timestamp_ns = if nanoseconds {
            ts_sec * 1_000_000_000 + ts_sub
        } else {
            ts_sec * 1_000_000_000 + ts_sub * 1_000
        };

        packets.push(RawPacket {
            index,
            timestamp_ns,
            orig_len,
            data: data[offset..offset + incl_len].to_vec(),
        });
        offset += incl_len;
        index += 1;
    }

    Ok(PcapCapture { header, packets })
}
