//! DNS and multicast DNS fingerprinting (ZTE-IOT "Dns Fingerprinting",
//! section 9; mDNS service announcements for discovery).
//!
//! Queries reveal the cloud services a device depends on (vendor update and
//! telemetry endpoints); mDNS announcements reveal service types, instance
//! names and TXT model keys. Name decompression follows at most 16 pointers
//! and names are limited to 253 bytes.

use crate::model::{clip, Signal};

fn name(b: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = vec![];
    let mut end = None;
    let mut jumps = 0;
    let mut total = 0;
    loop {
        let len = *b.get(off)? as usize;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *b.get(off + 1)? as usize;
            end.get_or_insert(off + 2);
            jumps += 1;
            if jumps > 16 || ptr >= b.len() {
                return None;
            }
            off = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let l = b.get(off + 1..off + 1 + len)?;
        total += len + 1;
        if total > 253 {
            return None;
        }
        labels.push(String::from_utf8_lossy(l).to_string());
        off += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(off)))
}

/// Questions of a (m)DNS message and, for mDNS responses, PTR targets and
/// TXT `md`/`model`/`ty`/`mdl` values.
pub struct Parsed {
    pub questions: Vec<String>,
    pub ptr: Vec<String>,
    pub txt_model: Option<String>,
    pub is_response: bool,
}

pub fn parse(b: &[u8]) -> Option<Parsed> {
    if b.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([b[2], b[3]]);
    let qd = u16::from_be_bytes([b[4], b[5]]) as usize;
    let an = u16::from_be_bytes([b[6], b[7]]) as usize + u16::from_be_bytes([b[8], b[9]]) as usize + u16::from_be_bytes([b[10], b[11]]) as usize;
    if qd > 32 || an > 64 {
        return None;
    }
    let mut off = 12;
    let mut p = Parsed { questions: vec![], ptr: vec![], txt_model: None, is_response: flags & 0x8000 != 0 };
    for _ in 0..qd {
        let (n, o) = name(b, off)?;
        p.questions.push(n.to_ascii_lowercase());
        off = o + 4;
    }
    for _ in 0..an {
        let (n, o) = name(b, off)?;
        let ty = u16::from_be_bytes([*b.get(o)?, *b.get(o + 1)?]);
        let rdlen = u16::from_be_bytes([*b.get(o + 8)?, *b.get(o + 9)?]) as usize;
        let rd_at = o + 10;
        let rd = b.get(rd_at..rd_at + rdlen)?;
        match ty {
            12 => {
                if let Some((t, _)) = name(b, rd_at) {
                    p.ptr.push(n.to_ascii_lowercase());
                    p.ptr.push(t);
                }
            }
            16 => {
                let mut i = 0;
                while i < rd.len() {
                    let l = rd[i] as usize;
                    if let Some(kv) = rd.get(i + 1..i + 1 + l) {
                        let s = String::from_utf8_lossy(kv);
                        if let Some((k, v)) = s.split_once('=') {
                            if matches!(k.to_ascii_lowercase().as_str(), "md" | "model" | "ty" | "mdl" | "product") && p.txt_model.is_none() && !v.is_empty() {
                                p.txt_model = Some(clip(v, 128));
                            }
                        }
                    }
                    i += 1 + l;
                }
            }
            _ => {}
        }
        off = rd_at + rdlen;
    }
    Some(p)
}

/// Signals from a DNS query (unicast, port 53).
pub fn dns_signals(b: &[u8]) -> Vec<Signal> {
    parse(b).filter(|p| !p.is_response).map(|p| p.questions.into_iter().take(4).map(|q| Signal::Dns { query: q }).collect()).unwrap_or_default()
}

/// Signals from an mDNS packet (port 5353).
pub fn mdns_signals(b: &[u8]) -> Vec<Signal> {
    let Some(p) = parse(b) else { return vec![] };
    let mut services: Vec<String> = vec![];
    let mut instance = None;
    for n in p.ptr.iter().chain(if p.is_response { p.questions.iter() } else { [].iter() }) {
        let found = if n.starts_with('_') { Some(0) } else { n.find("._").map(|i| i + 1) };
        if let Some(start) = found {
            let i = start.saturating_sub(1);
            let svc = n[start..].trim_end_matches(".local");
            if svc.starts_with('_') && !services.iter().any(|s| s == svc) && services.len() < 16 {
                services.push(svc.to_string());
            }
            if i > 0 && instance.is_none() && !n.starts_with('_') {
                instance = Some(clip(&n[..i], 128));
            }
        }
    }
    if services.is_empty() && p.txt_model.is_none() {
        return vec![];
    }
    vec![Signal::Mdns { services, instance, model: p.txt_model }]
}

/// Build a DNS message (tests): questions, plus PTR and TXT answers.
pub fn message(response: bool, questions: &[&str], ptr: &[(&str, &str)], txt: &[(&str, &[&str])]) -> Vec<u8> {
    fn enc(n: &str) -> Vec<u8> {
        let mut v = vec![];
        for l in n.split('.').filter(|l| !l.is_empty()) {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }
    let mut b = vec![0, 0, if response { 0x84 } else { 0x01 }, 0];
    b.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    b.extend_from_slice(&((ptr.len() + txt.len()) as u16).to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 0]);
    for q in questions {
        b.extend(enc(q));
        b.extend_from_slice(&[0, 1, 0, 1]);
    }
    for (n, t) in ptr {
        b.extend(enc(n));
        b.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 120]);
        let rd = enc(t);
        b.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        b.extend(rd);
    }
    for (n, kvs) in txt {
        b.extend(enc(n));
        b.extend_from_slice(&[0, 16, 0, 1, 0, 0, 0, 120]);
        let mut rd = vec![];
        for kv in kvs.iter() {
            rd.push(kv.len() as u8);
            rd.extend_from_slice(kv.as_bytes());
        }
        b.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        b.extend(rd);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_queries_and_mdns_services() {
        let q = message(false, &["Update.Vendor-Cloud.example"], &[], &[]);
        assert_eq!(dns_signals(&q), vec![Signal::Dns { query: "update.vendor-cloud.example".into() }]);
        let m = message(true, &[], &[("_ipp._tcp.local", "Office Printer._ipp._tcp.local")], &[("Office Printer._ipp._tcp.local", &["txtvers=1", "ty=LaserPro 400 MFP"])]);
        let s = mdns_signals(&m);
        match &s[0] {
            Signal::Mdns { services, instance, model } => {
                assert!(services.contains(&"_ipp._tcp".to_string()), "{services:?}");
                assert_eq!(instance.as_deref(), Some("Office Printer"));
                assert_eq!(model.as_deref(), Some("LaserPro 400 MFP"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn compression_loops_are_bounded() {
        let mut b = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        b.extend_from_slice(&[0xc0, 12]); // pointer to itself
        b.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse(&b).is_none());
    }
}
