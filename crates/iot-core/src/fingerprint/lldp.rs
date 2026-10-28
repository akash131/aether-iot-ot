//! LLDP (IEEE 802.1AB) and CDP fingerprinting — switches, phones, access
//! points and industrial devices announce their identity, firmware and
//! capabilities on the link (ZTE-IOT "Passive Discovery").
//!
//! TLVs are walked with a bound of 64 entries; strings are clipped.

use crate::model::{clip, Signal};

const CAPS: &[(u16, &str)] =
    &[(0x0001, "other"), (0x0002, "repeater"), (0x0004, "bridge"), (0x0008, "wlan_ap"), (0x0010, "router"), (0x0020, "telephone"), (0x0040, "docsis"), (0x0080, "station")];

fn caps(bits: u16) -> Vec<String> {
    CAPS.iter().filter(|(b, _)| bits & b != 0).map(|(_, n)| n.to_string()).collect()
}

/// LLDPDU (the Ethernet payload after ethertype 0x88cc).
pub fn lldp(b: &[u8]) -> Option<Signal> {
    let mut off = 0;
    let (mut system_name, mut system_description, mut capabilities, mut chassis_id) = (None, None, vec![], None);
    for _ in 0..64 {
        let h = u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]);
        let (ty, len) = (h >> 9, (h & 0x1ff) as usize);
        if ty == 0 {
            break;
        }
        let v = b.get(off + 2..off + 2 + len)?;
        match ty {
            1 if len > 1 => {
                chassis_id =
                    Some(if v[0] == 4 && len == 7 { crate::packet::Mac([v[1], v[2], v[3], v[4], v[5], v[6]]).to_string() } else { clip(&String::from_utf8_lossy(&v[1..]), 64) })
            }
            5 => system_name = Some(clip(&String::from_utf8_lossy(v), 128)),
            6 => system_description = Some(clip(&String::from_utf8_lossy(v), 512)),
            7 if len >= 4 => capabilities = caps(u16::from_be_bytes([v[2], v[3]])),
            _ => {}
        }
        off += 2 + len;
    }
    if system_name.is_none() && system_description.is_none() && chassis_id.is_none() {
        return None;
    }
    Some(Signal::Lldp { system_name, system_description, capabilities, chassis_id })
}

/// CDP (SNAP OUI 00:00:0c, protocol 0x2000) payload.
pub fn cdp(b: &[u8]) -> Option<Signal> {
    if b.len() < 4 || !(1..=2).contains(&b[0]) {
        return None;
    }
    let mut off = 4;
    let (mut device_id, mut platform, mut software, mut capabilities) = (None, None, None, vec![]);
    for _ in 0..64 {
        let ty = u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]);
        let len = u16::from_be_bytes([*b.get(off + 2)?, *b.get(off + 3)?]) as usize;
        if len < 4 {
            break;
        }
        let v = b.get(off + 4..off + len)?;
        match ty {
            0x0001 => device_id = Some(clip(&String::from_utf8_lossy(v), 128)),
            0x0005 => software = Some(clip(&String::from_utf8_lossy(v), 512)),
            0x0006 => platform = Some(clip(&String::from_utf8_lossy(v), 128)),
            0x0004 if v.len() >= 4 => {
                let bits = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                for (bit, name) in [(0x01, "router"), (0x08, "bridge"), (0x10, "host"), (0x80, "telephone")] {
                    if bits & bit != 0 {
                        capabilities.push(name.to_string());
                    }
                }
            }
            _ => {}
        }
        off += len;
        if off >= b.len() {
            break;
        }
    }
    if device_id.is_none() && platform.is_none() {
        return None;
    }
    Some(Signal::Cdp { device_id, platform, software, capabilities })
}

/// LLDPDU builder (tests, simulators).
pub fn lldpdu(name: &str, descr: &str, cap_bits: u16) -> Vec<u8> {
    let mut v = vec![];
    let mut tlv = |ty: u16, data: &[u8]| {
        v.extend_from_slice(&((ty << 9) | data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
    };
    tlv(1, &[4, 0, 0x0e, 0x8c, 1, 2, 3]);
    tlv(2, &[7, b'1']);
    tlv(3, &[0, 120]);
    tlv(5, name.as_bytes());
    tlv(6, descr.as_bytes());
    let mut c = cap_bits.to_be_bytes().to_vec();
    c.extend_from_slice(&cap_bits.to_be_bytes());
    tlv(7, &c);
    tlv(0, &[]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lldp_and_cdp() {
        let s = lldp(&lldpdu("line3-ctrl", "Controller CPU 1516-3 PN/DP, FW V2.9.4", 0x0080)).unwrap();
        match s {
            Signal::Lldp { system_name, system_description, capabilities, chassis_id } => {
                assert_eq!(system_name.as_deref(), Some("line3-ctrl"));
                assert!(system_description.unwrap().contains("V2.9.4"));
                assert_eq!(capabilities, vec!["station"]);
                assert_eq!(chassis_id.as_deref(), Some("00:0e:8c:01:02:03"));
            }
            _ => panic!(),
        }
        let mut c = vec![2, 180, 0, 0];
        for (ty, val) in [(1u16, &b"SEP001122334455"[..]), (6, b"Cisco IP Phone 8851"), (4, &[0, 0, 0, 0x90])] {
            c.extend_from_slice(&ty.to_be_bytes());
            c.extend_from_slice(&((val.len() + 4) as u16).to_be_bytes());
            c.extend_from_slice(val);
        }
        match cdp(&c).unwrap() {
            Signal::Cdp { platform, capabilities, .. } => {
                assert_eq!(platform.as_deref(), Some("Cisco IP Phone 8851"));
                assert!(capabilities.contains(&"telephone".to_string()));
            }
            _ => panic!(),
        }
        assert!(lldp(&[0xff, 0xff]).is_none());
    }
}
