//! DHCP fingerprinting (ZTE-IOT "Dhcp Fingerprinting", section 8).
//!
//! BOOTP/DHCP messages are decoded with bounded option walking; the
//! parameter request list (option 55), vendor class (60), host name (12),
//! client identifier (61) and requested address (50) are returned. Client
//! identifiers are hashed (they may embed user data).

use crate::model::{clip, Signal};
use sha2::{Digest, Sha256};

pub fn parse(b: &[u8]) -> Option<(String, Signal, u8)> {
    if b.len() < 240 || b[0] != 1 && b[0] != 2 {
        return None;
    }
    if b[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let hlen = b[2] as usize;
    if b[1] != 1 || hlen != 6 {
        return None;
    }
    let mac = crate::packet::Mac([b[28], b[29], b[30], b[31], b[32], b[33]]).to_string();
    let mut off = 240;
    let (mut hostname, mut vendor_class, mut prl, mut requested_ip, mut client_id, mut msg_type) = (None, None, None, None, None, 0u8);
    for _ in 0..128 {
        let code = *b.get(off)?;
        if code == 255 {
            break;
        }
        if code == 0 {
            off += 1;
            continue;
        }
        let len = *b.get(off + 1)? as usize;
        let v = b.get(off + 2..off + 2 + len)?;
        match code {
            12 => hostname = Some(clip(&String::from_utf8_lossy(v), 64)),
            50 if len == 4 => requested_ip = Some(format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3])),
            53 if len == 1 => msg_type = v[0],
            55 => prl = Some(v.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",")),
            60 => vendor_class = Some(clip(&String::from_utf8_lossy(v), 128)),
            61 => client_id = Some(hex::encode(&Sha256::digest(v)[..8])),
            _ => {}
        }
        off += 2 + len;
    }
    Some((mac, Signal::Dhcp { hostname: hostname.filter(|h| !h.is_empty()), vendor_class, prl, requested_ip, client_id }, msg_type))
}

/// Build a DHCP request (tests, simulators).
pub fn request(mac: [u8; 6], hostname: &str, vendor_class: &str, prl: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 240];
    b[0] = 1;
    b[1] = 1;
    b[2] = 6;
    b[28..34].copy_from_slice(&mac);
    b[236..240].copy_from_slice(&[99, 130, 83, 99]);
    b.extend_from_slice(&[53, 1, 3]);
    if !hostname.is_empty() {
        b.extend_from_slice(&[12, hostname.len() as u8]);
        b.extend_from_slice(hostname.as_bytes());
    }
    if !vendor_class.is_empty() {
        b.extend_from_slice(&[60, vendor_class.len() as u8]);
        b.extend_from_slice(vendor_class.as_bytes());
    }
    b.extend_from_slice(&[55, prl.len() as u8]);
    b.extend_from_slice(prl);
    b.push(255);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_options() {
        let p = request([0, 0x40, 0x8c, 1, 2, 3], "AXIS-ACCC8E010203", "udhcp 1.30.1", &[1, 3, 6, 12, 15, 28, 42]);
        let (mac, s, ty) = parse(&p).unwrap();
        assert_eq!((mac.as_str(), ty), ("00:40:8c:01:02:03", 3));
        match s {
            Signal::Dhcp { hostname, vendor_class, prl, .. } => {
                assert_eq!(hostname.as_deref(), Some("AXIS-ACCC8E010203"));
                assert_eq!(vendor_class.as_deref(), Some("udhcp 1.30.1"));
                assert_eq!(prl.as_deref(), Some("1,3,6,12,15,28,42"));
            }
            _ => panic!(),
        }
        assert!(parse(&[0u8; 100]).is_none());
        let mut bad = p.clone();
        bad[241] = 200; // option length beyond buffer
        let _ = parse(&bad);
    }
}
