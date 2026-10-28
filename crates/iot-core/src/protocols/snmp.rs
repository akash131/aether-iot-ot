//! SNMP v1/v2c/v3 (BER) — ZTE-IOT "Snmp Visibility" (section 50).
//!
//! PDUs are classified: Get/GetNext/GetBulk (read), Set (write),
//! responses, traps and informs. The community string is never stored or
//! returned; only whether it is a well-known default (`public`, `private`)
//! is reported, as an insecure-configuration finding. Responses to
//! `sysDescr.0` and `sysObjectID.0` disclose the device description.
//! SNMPv3 messages are reported with their security model only.

use super::*;

/// (tag, value range start, end) of one BER TLV at `at`.
fn tlv(b: &[u8], at: usize) -> PResult<(u8, usize, usize)> {
    let tag = byte(b, at)?;
    let l0 = byte(b, at + 1)?;
    let (len, hdr) = if l0 & 0x80 == 0 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 3 {
            return Err(ParseError::Malformed);
        }
        let v = b.get(at + 2..at + 2 + n).ok_or(ParseError::Truncated)?.iter().fold(0usize, |a, x| (a << 8) | *x as usize);
        (v, 2 + n)
    };
    let start = at + hdr;
    let end = start.checked_add(len).ok_or(ParseError::Malformed)?;
    if end > b.len() {
        return Err(ParseError::Truncated);
    }
    Ok((tag, start, end))
}

fn int(b: &[u8]) -> i64 {
    b.iter().take(8).fold(if b.first().map(|x| x & 0x80 != 0).unwrap_or(false) { -1i64 } else { 0 }, |a, x| (a << 8) | *x as i64)
}

pub fn oid(b: &[u8]) -> String {
    if b.is_empty() {
        return String::new();
    }
    let mut parts = vec![(b[0] / 40) as u64, (b[0] % 40) as u64];
    let mut acc: u64 = 0;
    for &c in &b[1..b.len().min(64)] {
        acc = (acc << 7) | (c & 0x7f) as u64;
        if c & 0x80 == 0 {
            parts.push(acc);
            acc = 0;
        }
    }
    parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".")
}

pub fn parse(b: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    let (tag, s, e) = tlv(b, 0)?;
    if tag != 0x30 {
        return Err(ParseError::NotProtocol);
    }
    let msg = &b[s..e];
    let (vt, vs, ve) = tlv(msg, 0)?;
    if vt != 0x02 {
        return Err(ParseError::NotProtocol);
    }
    let version = int(&msg[vs..ve]);
    if version == 3 {
        let mut ev = ProtoEvent::new(Protocol::Snmp, "snmpv3_message", 3, OpClass::Session).detail("version", "3");
        ev.is_response = dir == Dir::FromServer;
        return Ok(vec![ev]);
    }
    if !(0..=1).contains(&version) {
        return Err(ParseError::Malformed);
    }
    let (ct, cs, ce) = tlv(msg, ve)?;
    if ct != 0x04 {
        return Err(ParseError::Malformed);
    }
    let community = &msg[cs..ce];
    let default_community = community == b"public" || community == b"private";
    let (pt, ps, pe) = tlv(msg, ce)?;
    let (op, class) = match pt {
        0xa0 => ("get", OpClass::Read),
        0xa1 => ("get_next", OpClass::Read),
        0xa2 => ("response", OpClass::Read),
        0xa3 => ("set", OpClass::Write),
        0xa4 => ("trap", OpClass::Read),
        0xa5 => ("get_bulk", OpClass::Read),
        0xa6 => ("inform", OpClass::Read),
        0xa7 => ("trap_v2", OpClass::Read),
        0xa8 => ("report", OpClass::Session),
        _ => return Err(ParseError::Malformed),
    };
    let mut ev =
        ProtoEvent::new(Protocol::Snmp, op, (pt & 0x1f) as u32, class).detail("version", if version == 0 { "1" } else { "2c" }).detail("default_community", default_community);
    ev.is_response = pt == 0xa2 || dir == Dir::FromServer;
    if pt != 0xa4 {
        let pdu = &msg[ps..pe];
        // request-id, error-status, error-index, varbind list
        let (_, _, r1) = tlv(pdu, 0)?;
        let (_, es, ee) = tlv(pdu, r1)?;
        ev.is_error = int(&pdu[es..ee]) != 0 && pt == 0xa2;
        let (_, _, r3) = tlv(pdu, ee)?;
        let (lt, ls, le) = tlv(pdu, r3)?;
        if lt == 0x30 {
            let list = &pdu[ls..le];
            let mut at = 0;
            for _ in 0..MAX_VALUES {
                if at >= list.len() {
                    break;
                }
                let (_, vbs, vbe) = tlv(list, at)?;
                let vb = &list[vbs..vbe];
                let (ot, os, oe) = tlv(vb, 0)?;
                if ot != 0x06 {
                    return Err(ParseError::Malformed);
                }
                let name = oid(&vb[os..oe]);
                if ev.object.is_none() {
                    ev.object = Some(name.clone());
                }
                let (valt, vals, vale) = tlv(vb, oe)?;
                let val = &vb[vals..vale];
                if pt == 0xa2 && name == "1.3.6.1.2.1.1.1.0" && valt == 0x04 {
                    ev.identity.product = Some(ascii(val, 200));
                }
                if pt == 0xa2 && name == "1.3.6.1.2.1.1.5.0" && valt == 0x04 {
                    ev.identity.name = Some(ascii(val, 64));
                }
                if pt == 0xa2 && name == "1.3.6.1.2.1.1.2.0" && valt == 0x06 {
                    ev = ev.detail("sys_object_id", oid(val));
                }
                if pt == 0xa3 && valt == 0x02 {
                    ev.values.push(int(val));
                }
                at = vbe;
            }
        }
    }
    Ok(vec![ev])
}

fn enc(tag: u8, v: &[u8]) -> Vec<u8> {
    let mut o = vec![tag];
    if v.len() < 128 {
        o.push(v.len() as u8);
    } else {
        o.push(0x82);
        o.extend_from_slice(&(v.len() as u16).to_be_bytes());
    }
    o.extend_from_slice(v);
    o
}

fn enc_oid(s: &str) -> Vec<u8> {
    let p: Vec<u64> = s.split('.').filter_map(|x| x.parse().ok()).collect();
    let mut o = vec![(p[0] * 40 + p[1]) as u8];
    for &n in &p[2..] {
        let mut stack = vec![(n & 0x7f) as u8];
        let mut v = n >> 7;
        while v > 0 {
            stack.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        stack.reverse();
        o.extend(stack);
    }
    o
}

/// Build a v2c message with one varbind (tests, simulators).
pub fn message(community: &str, pdu_tag: u8, oid_s: &str, value: (u8, &[u8])) -> Vec<u8> {
    let mut vb = enc(0x06, &enc_oid(oid_s));
    vb.extend(enc(value.0, value.1));
    let list = enc(0x30, &enc(0x30, &vb));
    let mut pdu = enc(0x02, &[1]);
    pdu.extend(enc(0x02, &[0]));
    pdu.extend(enc(0x02, &[0]));
    pdu.extend(list);
    let mut msg = enc(0x02, &[1]);
    msg.extend(enc(0x04, community.as_bytes()));
    msg.extend(enc(pdu_tag, &pdu));
    enc(0x30, &msg)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_set() -> Vec<u8> {
        message("private", 0xa3, "1.3.6.1.4.1.9999.1.1.0", (0x02, &[42]))
    }

    #[test]
    fn classifies_and_redacts_community() {
        let e = parse(&sample_set(), Dir::ToServer).unwrap();
        assert_eq!((e[0].class, e[0].values.clone(), e[0].details.get("default_community").map(|s| s.as_str())), (OpClass::Write, vec![42], Some("true")));
        assert!(!serde_json::to_string(&e).unwrap().contains("private"), "the community string is never exposed");
        let r = parse(&message("s3cret", 0xa2, "1.3.6.1.2.1.1.1.0", (0x04, b"Acme Camera IPC-200 fw 5.1.2")), Dir::FromServer).unwrap();
        assert_eq!((r[0].identity.product.as_deref(), r[0].details.get("default_community").map(|s| s.as_str())), (Some("Acme Camera IPC-200 fw 5.1.2"), Some("false")));
        assert_eq!(oid(&enc_oid("1.3.6.1.4.1.311.21")), "1.3.6.1.4.1.311.21");
    }

    #[test]
    fn rejects_non_snmp() {
        assert_eq!(parse(&[0x31, 0], Dir::ToServer).unwrap_err(), ParseError::NotProtocol);
        assert!(parse(&[0x30, 0x84, 0, 0, 0, 1], Dir::ToServer).is_err());
    }
}
