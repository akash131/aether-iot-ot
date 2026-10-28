//! TLS client fingerprinting (ZTE-IOT "Tls Fingerprinting", section 11).
//!
//! The ClientHello of a device is reduced to a stable fingerprint: the
//! legacy version, cipher suites, extension types, supported groups and EC
//! point formats (GREASE values removed), hashed with SHA-256 and truncated
//! to 32 hex characters. Embedded devices use fixed TLS stacks, so the
//! fingerprint is a strong family signal; the server name (SNI) reveals
//! cloud dependencies. Records are bounded; only the first ClientHello
//! record is examined.

use crate::model::Signal;
use sha2::{Digest, Sha256};

fn grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn u16at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Fingerprint string (pre-hash) and SNI of a ClientHello record.
pub fn client_hello(b: &[u8]) -> Option<(String, Option<String>, String)> {
    if b.len() < 9 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
        return None;
    }
    let rec_len = u16at(b, 3)? as usize;
    let h = b.get(5..(5 + rec_len).min(b.len()))?;
    let version = u16at(h, 4)?;
    let mut off = 4 + 2 + 32;
    let sid = *h.get(off)? as usize;
    off += 1 + sid;
    let cs_len = u16at(h, off)? as usize;
    let ciphers: Vec<u16> = h.get(off + 2..off + 2 + cs_len)?.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).filter(|c| !grease(*c)).take(128).collect();
    off += 2 + cs_len;
    let comp = *h.get(off)? as usize;
    off += 1 + comp;
    let mut exts = vec![];
    let mut groups = vec![];
    let mut formats = vec![];
    let mut sni = None;
    let mut supported_version = None;
    if let Some(ext_len) = u16at(h, off) {
        let end = (off + 2 + ext_len as usize).min(h.len());
        let mut e = off + 2;
        for _ in 0..64 {
            if e + 4 > end {
                break;
            }
            let ty = u16at(h, e)?;
            let len = u16at(h, e + 2)? as usize;
            let data = h.get(e + 4..e + 4 + len)?;
            if !grease(ty) {
                exts.push(ty);
            }
            match ty {
                0 if data.len() > 5 => {
                    let n = u16at(data, 3)? as usize;
                    sni = data.get(5..5 + n).map(|s| String::from_utf8_lossy(s).to_ascii_lowercase());
                }
                10 if data.len() >= 2 => groups = data[2..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).filter(|g| !grease(*g)).take(32).collect(),
                11 if !data.is_empty() => formats = data[1..].iter().take(8).map(|x| *x as u16).collect(),
                43 if data.len() >= 3 => supported_version = data[1..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).filter(|v| !grease(*v)).max(),
                _ => {}
            }
            e += 4 + len;
        }
    }
    let j = |v: &[u16]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    let raw = format!("{},{},{},{},{}", version, j(&ciphers), j(&exts), j(&groups), j(&formats));
    let ver = match supported_version.unwrap_or(version) {
        0x0304 => "1.3",
        0x0303 => "1.2",
        0x0302 => "1.1",
        0x0301 => "1.0",
        _ => "ssl",
    };
    Some((raw, sni, ver.to_string()))
}

pub fn signal(b: &[u8]) -> Option<Signal> {
    let (raw, sni, version) = client_hello(b)?;
    let fp = hex::encode(&Sha256::digest(raw.as_bytes())[..16]);
    Some(Signal::Tls { fingerprint: fp, sni, version: Some(version) })
}

/// Minimal ClientHello builder (tests).
pub fn hello(sni: &str, ciphers: &[u16]) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[7u8; 32]);
    body.push(0);
    body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in ciphers {
        body.extend_from_slice(&c.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]);
    let mut ext = vec![];
    let name = sni.as_bytes();
    let mut sn = ((name.len() + 3) as u16).to_be_bytes().to_vec();
    sn.push(0);
    sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sn.extend_from_slice(name);
    ext.extend_from_slice(&0u16.to_be_bytes());
    ext.extend_from_slice(&(sn.len() as u16).to_be_bytes());
    ext.extend(sn);
    ext.extend_from_slice(&[0, 10, 0, 4, 0, 2, 0, 0x1d]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend(ext);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend(body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_grease_insensitive() {
        let a = signal(&hello("telemetry.vendor.example", &[0x1301, 0xc02f])).unwrap();
        let b = signal(&hello("telemetry.vendor.example", &[0x0a0a, 0x1301, 0xc02f])).unwrap();
        let c = signal(&hello("telemetry.vendor.example", &[0xc02f])).unwrap();
        match (&a, &b, &c) {
            (Signal::Tls { fingerprint: fa, sni, .. }, Signal::Tls { fingerprint: fb, .. }, Signal::Tls { fingerprint: fc, .. }) => {
                assert_eq!(fa, fb);
                assert_ne!(fa, fc);
                assert_eq!(fa.len(), 32);
                assert_eq!(sni.as_deref(), Some("telemetry.vendor.example"));
            }
            _ => panic!(),
        }
        assert!(signal(b"GET / HTTP/1.1").is_none());
    }
}
