//! Bounded packet decoding for passive collection (ZTE-IOT "Packet Metadata
//! Collection", "Passive Discovery", "Protocol Parser Hardening";
//! ZTE-IOTINV-153164 memory/resource bounded parsers).
//!
//! The edge collector receives mirrored frames (classic libpcap files or a
//! TZSP mirror stream exported by switches and sensors) and decodes only the
//! headers it needs: Ethernet (with up to two 802.1Q/802.1ad tags), ARP,
//! IPv4, IPv6 (fixed header plus a bounded walk of extension headers), TCP
//! and UDP. Payloads are borrowed slices; nothing is copied or retained, so
//! payload capture is minimised by construction (ZTE-IOTINV-153169).
//!
//! Every decoder checks lengths before reading and fails with a stable
//! [`DecodeError`] code; there is no recursion and no allocation proportional
//! to attacker-controlled lengths.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Largest frame accepted (jumbo frames included).
pub const MAX_FRAME: usize = 16 * 1024;
/// Largest number of IPv6 extension headers walked.
const MAX_V6_EXT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum DecodeError {
    #[error("frame truncated")]
    Truncated,
    #[error("frame too large")]
    TooLarge,
    #[error("unsupported link or network protocol")]
    Unsupported,
    #[error("malformed header")]
    Malformed,
}

impl DecodeError {
    pub fn code(&self) -> &'static str {
        match self {
            DecodeError::Truncated => "truncated",
            DecodeError::TooLarge => "too_large",
            DecodeError::Unsupported => "unsupported",
            DecodeError::Malformed => "malformed",
        }
    }
}

pub type DResult<T> = Result<T, DecodeError>;

/// A MAC address, rendered `aa:bb:cc:dd:ee:ff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub fn parse(s: &str) -> Option<Mac> {
        let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() != 12 || s.chars().any(|c| !(c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.'))) {
            return None;
        }
        let mut m = [0u8; 6];
        for (i, b) in m.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Mac(m))
    }
    /// Organisationally unique identifier `aa:bb:cc`.
    pub fn oui(&self) -> String {
        format!("{:02x}:{:02x}:{:02x}", self.0[0], self.0[1], self.0[2])
    }
    /// Locally administered (randomised / private) address.
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }
}

impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }
}

impl Serialize for Mac {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Mac {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Mac::parse(&s).ok_or_else(|| serde::de::Error::custom("invalid MAC address"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    Other,
}

/// TCP flag bits.
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

/// Decoded headers of one frame; `payload` borrows the L4 payload.
#[derive(Debug, Clone)]
pub struct Frame<'a> {
    pub src_mac: Mac,
    pub dst_mac: Mac,
    pub vlan: Option<u16>,
    pub ethertype: u16,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub ttl: Option<u8>,
    pub transport: Option<Transport>,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    /// TCP window (OS fingerprint hint).
    pub tcp_window: u16,
    /// ARP: (sender mac, sender ip, target ip, is_reply).
    pub arp: Option<(Mac, Ipv4Addr, Ipv4Addr, bool)>,
    /// Link-layer payload for non-IP ethertypes (LLDP, PROFINET DCP) and
    /// 802.3 LLC frames (CDP).
    pub l2_payload: &'a [u8],
    /// 802.3 with LLC/SNAP: (OUI, protocol id).
    pub snap: Option<([u8; 3], u16)>,
    pub payload: &'a [u8],
    pub wire_len: usize,
}

fn be16(b: &[u8], at: usize) -> DResult<u16> {
    b.get(at..at + 2).map(|x| u16::from_be_bytes([x[0], x[1]])).ok_or(DecodeError::Truncated)
}

pub const ETH_IPV4: u16 = 0x0800;
pub const ETH_ARP: u16 = 0x0806;
pub const ETH_IPV6: u16 = 0x86dd;
pub const ETH_LLDP: u16 = 0x88cc;
pub const ETH_PROFINET: u16 = 0x8892;

/// Decode an Ethernet II / 802.3 frame.
pub fn decode_ethernet(b: &[u8]) -> DResult<Frame<'_>> {
    if b.len() > MAX_FRAME {
        return Err(DecodeError::TooLarge);
    }
    if b.len() < 14 {
        return Err(DecodeError::Truncated);
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&b[0..6]);
    src.copy_from_slice(&b[6..12]);
    let mut off = 12;
    let mut et = be16(b, off)?;
    let mut vlan = None;
    for _ in 0..2 {
        if et == 0x8100 || et == 0x88a8 {
            let tci = be16(b, off + 2)?;
            vlan.get_or_insert(tci & 0x0fff);
            off += 4;
            et = be16(b, off)?;
        }
    }
    off += 2;
    let mut f = Frame {
        src_mac: Mac(src),
        dst_mac: Mac(dst),
        vlan,
        ethertype: et,
        src_ip: None,
        dst_ip: None,
        ttl: None,
        transport: None,
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        tcp_window: 0,
        arp: None,
        l2_payload: &b[off..],
        snap: None,
        payload: &[],
        wire_len: b.len(),
    };
    if et <= 1500 {
        // IEEE 802.3 length field: LLC (and SNAP) header follows.
        let llc = &b[off..];
        if llc.len() >= 8 && llc[0] == 0xaa && llc[1] == 0xaa && llc[2] == 0x03 {
            f.snap = Some(([llc[3], llc[4], llc[5]], u16::from_be_bytes([llc[6], llc[7]])));
            f.l2_payload = &llc[8..];
        } else if llc.len() >= 3 {
            f.l2_payload = &llc[3..];
        }
        return Ok(f);
    }
    match et {
        ETH_IPV4 => decode_ipv4(&b[off..], &mut f)?,
        ETH_IPV6 => decode_ipv6(&b[off..], &mut f)?,
        ETH_ARP => {
            let a = &b[off..];
            if a.len() < 28 {
                return Err(DecodeError::Truncated);
            }
            if be16(a, 0)? != 1 || be16(a, 2)? != ETH_IPV4 || a[4] != 6 || a[5] != 4 {
                return Err(DecodeError::Malformed);
            }
            let op = be16(a, 6)?;
            let mut sm = [0u8; 6];
            sm.copy_from_slice(&a[8..14]);
            let sip = Ipv4Addr::new(a[14], a[15], a[16], a[17]);
            let tip = Ipv4Addr::new(a[24], a[25], a[26], a[27]);
            f.arp = Some((Mac(sm), sip, tip, op == 2));
        }
        _ => {}
    }
    Ok(f)
}

fn decode_l4<'a>(proto: u8, b: &'a [u8], f: &mut Frame<'a>) -> DResult<()> {
    match proto {
        6 => {
            if b.len() < 20 {
                return Err(DecodeError::Truncated);
            }
            let doff = ((b[12] >> 4) as usize) * 4;
            if doff < 20 || doff > b.len() {
                return Err(DecodeError::Malformed);
            }
            f.transport = Some(Transport::Tcp);
            f.src_port = be16(b, 0)?;
            f.dst_port = be16(b, 2)?;
            f.tcp_flags = b[13];
            f.tcp_window = be16(b, 14)?;
            f.payload = &b[doff..];
        }
        17 => {
            if b.len() < 8 {
                return Err(DecodeError::Truncated);
            }
            let len = be16(b, 4)? as usize;
            if len < 8 {
                return Err(DecodeError::Malformed);
            }
            f.transport = Some(Transport::Udp);
            f.src_port = be16(b, 0)?;
            f.dst_port = be16(b, 2)?;
            f.payload = &b[8..len.min(b.len())];
        }
        1 | 58 => {
            f.transport = Some(Transport::Icmp);
            f.payload = b;
        }
        _ => f.transport = Some(Transport::Other),
    }
    Ok(())
}

fn decode_ipv4<'a>(b: &'a [u8], f: &mut Frame<'a>) -> DResult<()> {
    if b.len() < 20 {
        return Err(DecodeError::Truncated);
    }
    if b[0] >> 4 != 4 {
        return Err(DecodeError::Malformed);
    }
    let ihl = ((b[0] & 0x0f) as usize) * 4;
    let total = be16(b, 2)? as usize;
    if ihl < 20 || total < ihl || ihl > b.len() {
        return Err(DecodeError::Malformed);
    }
    let end = total.min(b.len());
    f.src_ip = Some(IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])));
    f.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19])));
    f.ttl = Some(b[8]);
    let frag = be16(b, 6)? & 0x1fff;
    if frag != 0 {
        // Non-first fragment: no L4 header.
        f.transport = Some(Transport::Other);
        return Ok(());
    }
    decode_l4(b[9], &b[ihl..end], f)
}

fn decode_ipv6<'a>(b: &'a [u8], f: &mut Frame<'a>) -> DResult<()> {
    if b.len() < 40 {
        return Err(DecodeError::Truncated);
    }
    if b[0] >> 4 != 6 {
        return Err(DecodeError::Malformed);
    }
    let plen = be16(b, 4)? as usize;
    let mut next = b[6];
    f.ttl = Some(b[7]);
    let mut s = [0u8; 16];
    let mut d = [0u8; 16];
    s.copy_from_slice(&b[8..24]);
    d.copy_from_slice(&b[24..40]);
    f.src_ip = Some(IpAddr::V6(Ipv6Addr::from(s)));
    f.dst_ip = Some(IpAddr::V6(Ipv6Addr::from(d)));
    let end = (40 + plen).min(b.len());
    let mut off = 40;
    for _ in 0..MAX_V6_EXT {
        match next {
            0 | 43 | 60 => {
                let h = b.get(off..off + 2).ok_or(DecodeError::Truncated)?;
                next = h[0];
                off += (h[1] as usize + 1) * 8;
            }
            44 => {
                let h = b.get(off..off + 8).ok_or(DecodeError::Truncated)?;
                next = h[0];
                if u16::from_be_bytes([h[2], h[3]]) >> 3 != 0 {
                    f.transport = Some(Transport::Other);
                    return Ok(());
                }
                off += 8;
            }
            _ => break,
        }
        if off > end {
            return Err(DecodeError::Malformed);
        }
    }
    decode_l4(next, &b[off.min(end)..end], f)
}

/// Strip a TZSP (TaZmen Sniffer Protocol) header from a mirrored UDP
/// datagram and return the encapsulated Ethernet frame.
pub fn decode_tzsp(b: &[u8]) -> DResult<&[u8]> {
    if b.len() < 4 {
        return Err(DecodeError::Truncated);
    }
    if b[0] != 1 {
        return Err(DecodeError::Unsupported);
    }
    // type 0 = received tag list, 1 = packet for transmit; encapsulation 1 = Ethernet.
    if b[1] > 1 || be16(b, 2)? != 1 {
        return Err(DecodeError::Unsupported);
    }
    let mut off = 4;
    for _ in 0..64 {
        let tag = *b.get(off).ok_or(DecodeError::Truncated)?;
        match tag {
            0 => off += 1,
            1 => return b.get(off + 1..).ok_or(DecodeError::Truncated),
            _ => {
                let len = *b.get(off + 1).ok_or(DecodeError::Truncated)? as usize;
                off += 2 + len;
            }
        }
    }
    Err(DecodeError::Malformed)
}

/// One record of a capture file.
#[derive(Debug, Clone)]
pub struct PcapRecord {
    pub ts_micros: i64,
    pub data: Vec<u8>,
    pub orig_len: u32,
}

/// Streaming reader of classic libpcap files (both byte orders,
/// microsecond and nanosecond resolution, Ethernet link type). Records
/// larger than [`MAX_FRAME`] are truncated to it.
pub struct PcapReader<R> {
    r: R,
    swapped: bool,
    nanos: bool,
    pub linktype: u32,
}

impl<R: std::io::Read> PcapReader<R> {
    pub fn new(mut r: R) -> Result<Self, DecodeError> {
        let mut h = [0u8; 24];
        r.read_exact(&mut h).map_err(|_| DecodeError::Truncated)?;
        let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let (swapped, nanos) = match magic {
            0xa1b2c3d4 => (false, false),
            0xd4c3b2a1 => (true, false),
            0xa1b23c4d => (false, true),
            0x4d3cb2a1 => (true, true),
            _ => return Err(DecodeError::Unsupported),
        };
        let rd = |x: [u8; 4]| if swapped { u32::from_be_bytes(x) } else { u32::from_le_bytes(x) };
        let linktype = rd([h[20], h[21], h[22], h[23]]);
        if linktype != 1 {
            return Err(DecodeError::Unsupported);
        }
        Ok(PcapReader { r, swapped, nanos, linktype })
    }

    fn u32(&self, x: [u8; 4]) -> u32 {
        if self.swapped {
            u32::from_be_bytes(x)
        } else {
            u32::from_le_bytes(x)
        }
    }

    /// Next record, `Ok(None)` at a clean end of file.
    pub fn next_record(&mut self) -> Result<Option<PcapRecord>, DecodeError> {
        let mut h = [0u8; 16];
        match self.r.read_exact(&mut h) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(_) => return Err(DecodeError::Truncated),
        }
        let sec = self.u32([h[0], h[1], h[2], h[3]]) as i64;
        let frac = self.u32([h[4], h[5], h[6], h[7]]) as i64;
        let incl = self.u32([h[8], h[9], h[10], h[11]]) as usize;
        let orig = self.u32([h[12], h[13], h[14], h[15]]);
        if incl > 262_144 {
            return Err(DecodeError::Malformed);
        }
        let mut data = vec![0u8; incl];
        self.r.read_exact(&mut data).map_err(|_| DecodeError::Truncated)?;
        data.truncate(MAX_FRAME);
        let micros = if self.nanos { frac / 1000 } else { frac };
        Ok(Some(PcapRecord { ts_micros: sec * 1_000_000 + micros, data, orig_len: orig }))
    }
}

/// Write a classic pcap file (tests, evidence export of synthetic frames).
pub fn write_pcap(records: &[(i64, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![];
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (ts, d) in records {
        out.extend_from_slice(&((ts / 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&((ts % 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&(d.len() as u32).to_le_bytes());
        out.extend_from_slice(&(d.len() as u32).to_le_bytes());
        out.extend_from_slice(d);
    }
    out
}

/// Frame builders for tests, the load driver and the acceptance harness.
pub mod build {
    use super::*;

    fn csum(data: &[u8]) -> u16 {
        let mut s: u32 = 0;
        for c in data.chunks(2) {
            s += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
        }
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }

    pub fn ethernet(src: Mac, dst: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(14 + payload.len());
        v.extend_from_slice(&dst.0);
        v.extend_from_slice(&src.0);
        v.extend_from_slice(&ethertype.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    pub fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, ttl: u8, l4: &[u8]) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 0, 0, 1, 0x40, 0, ttl, proto, 0, 0];
        h.extend_from_slice(&src.octets());
        h.extend_from_slice(&dst.octets());
        let total = (20 + l4.len()) as u16;
        h[2..4].copy_from_slice(&total.to_be_bytes());
        let c = csum(&h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h.extend_from_slice(l4);
        h
    }

    pub fn tcp(sport: u16, dport: u16, flags: u8, window: u16, payload: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0..2].copy_from_slice(&sport.to_be_bytes());
        h[2..4].copy_from_slice(&dport.to_be_bytes());
        h[12] = 5 << 4;
        h[13] = flags;
        h[14..16].copy_from_slice(&window.to_be_bytes());
        h.extend_from_slice(payload);
        h
    }

    pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 8];
        h[0..2].copy_from_slice(&sport.to_be_bytes());
        h[2..4].copy_from_slice(&dport.to_be_bytes());
        h[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        h.extend_from_slice(payload);
        h
    }

    /// A complete Ethernet/IPv4/TCP frame.
    pub fn tcp_frame(src: (Mac, Ipv4Addr, u16), dst: (Mac, Ipv4Addr, u16), flags: u8, payload: &[u8]) -> Vec<u8> {
        ethernet(src.0, dst.0, ETH_IPV4, &ipv4(src.1, dst.1, 6, 64, &tcp(src.2, dst.2, flags, 8192, payload)))
    }

    /// A complete Ethernet/IPv4/UDP frame.
    pub fn udp_frame(src: (Mac, Ipv4Addr, u16), dst: (Mac, Ipv4Addr, u16), payload: &[u8]) -> Vec<u8> {
        ethernet(src.0, dst.0, ETH_IPV4, &ipv4(src.1, dst.1, 17, 64, &udp(src.2, dst.2, payload)))
    }

    /// Wrap a frame in TZSP.
    pub fn tzsp(frame: &[u8]) -> Vec<u8> {
        let mut v = vec![1, 0, 0, 1, 1];
        v.extend_from_slice(frame);
        v
    }
}

/// Deterministic pseudo-random generator used by the fuzz tests and the
/// load driver (no external dependency, reproducible failures).
#[derive(Debug, Clone)]
pub struct XorShift(pub u64);

impl XorShift {
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0.max(1);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
    /// Mutate a valid input: flip, truncate, extend, or overwrite.
    pub fn mutate(&mut self, base: &[u8]) -> Vec<u8> {
        let mut v = base.to_vec();
        match self.next_u64() % 5 {
            0 if !v.is_empty() => {
                let i = (self.next_u64() as usize) % v.len();
                v[i] ^= 1 << (self.next_u64() % 8);
            }
            1 => {
                let n = (self.next_u64() as usize) % (v.len() + 1);
                v.truncate(n);
            }
            2 => {
                let n = (self.next_u64() % 64) as usize;
                let extra = self.bytes(n);
                v.extend(extra);
            }
            3 if !v.is_empty() => {
                let i = (self.next_u64() as usize) % v.len();
                v[i] = 0xff;
            }
            _ => {
                let n = (self.next_u64() % 128) as usize;
                v = self.bytes(n);
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    fn m(s: &str) -> Mac {
        Mac::parse(s).unwrap()
    }

    #[test]
    fn decodes_tcp_udp_vlan_and_arp() {
        let f = tcp_frame((m("00:1d:9c:00:00:01"), Ipv4Addr::new(10, 0, 0, 5), 50123), (m("00:0e:8c:00:00:02"), Ipv4Addr::new(10, 0, 0, 9), 502), tcp_flags::SYN, b"hi");
        let d = decode_ethernet(&f).unwrap();
        assert_eq!(d.src_ip, Some("10.0.0.5".parse().unwrap()));
        assert_eq!((d.dst_port, d.transport, d.tcp_flags, d.payload), (502, Some(Transport::Tcp), tcp_flags::SYN, &b"hi"[..]));
        assert_eq!(d.src_mac.oui(), "00:1d:9c");
        // VLAN tagged UDP.
        let u = udp_frame((m("02:00:00:00:00:01"), Ipv4Addr::new(10, 1, 1, 1), 68), (m("ff:ff:ff:ff:ff:ff"), Ipv4Addr::BROADCAST, 67), b"x");
        let mut tagged = u[..12].to_vec();
        tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x2a]);
        tagged.extend_from_slice(&u[12..]);
        let d = decode_ethernet(&tagged).unwrap();
        assert_eq!((d.vlan, d.dst_port, d.src_mac.is_local()), (Some(42), 67, true));
        // ARP reply.
        let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 2];
        arp.extend_from_slice(&[0, 0x1d, 0x9c, 1, 2, 3, 10, 0, 0, 7]);
        arp.extend_from_slice(&[0; 6]);
        arp.extend_from_slice(&[10, 0, 0, 1]);
        let fr = ethernet(m("00:1d:9c:01:02:03"), m("ff:ff:ff:ff:ff:ff"), ETH_ARP, &arp);
        let d = decode_ethernet(&fr).unwrap();
        assert_eq!(d.arp.unwrap().1, Ipv4Addr::new(10, 0, 0, 7));
    }

    #[test]
    fn rejects_malformed_and_oversized() {
        assert_eq!(decode_ethernet(&[0u8; 5]).unwrap_err(), DecodeError::Truncated);
        assert_eq!(decode_ethernet(&vec![0u8; MAX_FRAME + 1]).unwrap_err(), DecodeError::TooLarge);
        let mut f = tcp_frame((Mac::default(), Ipv4Addr::LOCALHOST, 1), (Mac::default(), Ipv4Addr::LOCALHOST, 2), 0, b"");
        f[14] = 0x4f; // IHL beyond the buffer
        f.truncate(30);
        assert!(decode_ethernet(&f).is_err());
    }

    #[test]
    fn pcap_and_tzsp_round_trip() {
        let f = udp_frame((m("00:00:00:00:00:01"), Ipv4Addr::new(1, 2, 3, 4), 1), (m("00:00:00:00:00:02"), Ipv4Addr::new(5, 6, 7, 8), 2), b"abc");
        let file = write_pcap(&[(1_700_000_000_123_456, f.clone())]);
        let mut r = PcapReader::new(&file[..]).unwrap();
        let rec = r.next_record().unwrap().unwrap();
        assert_eq!((rec.ts_micros, rec.data.clone()), (1_700_000_000_123_456, f.clone()));
        assert!(r.next_record().unwrap().is_none());
        assert_eq!(decode_tzsp(&tzsp(&f)).unwrap(), &f[..]);
        assert!(decode_tzsp(&[2, 0, 0, 1]).is_err());
        assert!(PcapReader::new(&[0u8; 24][..]).is_err());
    }

    #[test]
    fn fuzzed_frames_never_panic() {
        let base = tcp_frame((Mac::default(), Ipv4Addr::new(10, 0, 0, 1), 1), (Mac::default(), Ipv4Addr::new(10, 0, 0, 2), 502), 0x18, &[0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1]);
        let mut rng = XorShift(0x5eed);
        for _ in 0..20_000 {
            let v = rng.mutate(&base);
            let _ = decode_ethernet(&v);
            let _ = decode_tzsp(&v);
        }
    }
}
