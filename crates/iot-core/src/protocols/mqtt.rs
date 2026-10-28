//! MQTT 3.1/3.1.1/5 — ZTE-IOT "Mqtt Visibility" (section 48).
//!
//! CONNECT (client id, protocol level, whether credentials are presented —
//! cleartext on port 1883), PUBLISH (topic; a write: commands to devices
//! are published), SUBSCRIBE (read), acknowledgements and keep-alives
//! (session). Several packets in one segment are decoded (bounded).

use super::*;

fn remaining_length(b: &[u8], at: usize) -> PResult<(usize, usize)> {
    let mut mult = 1usize;
    let mut val = 0usize;
    for i in 0..4 {
        let c = byte(b, at + i)?;
        val += (c & 0x7f) as usize * mult;
        if c & 0x80 == 0 {
            return Ok((val, i + 1));
        }
        mult *= 128;
    }
    Err(ParseError::Malformed)
}

fn utf8(b: &[u8], at: usize) -> PResult<(String, usize)> {
    let n = u16be(b, at)? as usize;
    let s = b.get(at + 2..at + 2 + n).ok_or(ParseError::Truncated)?;
    Ok((String::from_utf8_lossy(&s[..s.len().min(256)]).to_string(), at + 2 + n))
}

pub fn parse(b: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    let mut out = vec![];
    let mut off = 0;
    while off < b.len() && out.len() < 64 {
        let p = &b[off..];
        let first = byte(p, 0)?;
        let (rl, n) = remaining_length(p, 1)?;
        let body = p.get(1 + n..1 + n + rl).ok_or(ParseError::Truncated)?;
        out.push(packet(first, body, dir)?);
        off += 1 + n + rl;
    }
    if out.is_empty() {
        return Err(ParseError::Truncated);
    }
    Ok(out)
}

fn packet(first: u8, body: &[u8], dir: Dir) -> PResult<ProtoEvent> {
    let ty = first >> 4;
    let mut e = match ty {
        1 => {
            let (name, at) = utf8(body, 0)?;
            if name != "MQTT" && name != "MQIsdp" {
                return Err(ParseError::NotProtocol);
            }
            let level = byte(body, at)?;
            let flags = byte(body, at + 1)?;
            let mut cid_at = at + 4;
            if level == 5 {
                let (plen, n) = remaining_length(body, cid_at)?;
                cid_at += n + plen;
            }
            let (cid, _) = utf8(body, cid_at)?;
            let mut e = ProtoEvent::new(Protocol::Mqtt, "connect", 1, OpClass::Session).detail("protocol_level", level).detail("client_id", &cid);
            if flags & 0x80 != 0 {
                e = e.detail("username", "present");
            }
            if flags & 0x40 != 0 {
                e = e.detail("password", "present");
            }
            e.identity.name = Some(cid).filter(|c| !c.is_empty());
            e
        }
        2 => {
            let mut e = ProtoEvent::new(Protocol::Mqtt, "connack", 2, OpClass::Session);
            e.is_response = true;
            e.is_error = byte(body, 1).unwrap_or(0) != 0;
            e
        }
        3 => {
            let (topic, _) = utf8(body, 0)?;
            let mut e = ProtoEvent::new(Protocol::Mqtt, "publish", 3, OpClass::Write).detail("qos", (first >> 1) & 3);
            e.object = Some(topic);
            e
        }
        4..=7 => ProtoEvent::new(Protocol::Mqtt, "publish_ack", ty as u32, OpClass::Session),
        8 => {
            let mut e = ProtoEvent::new(Protocol::Mqtt, "subscribe", 8, OpClass::Read);
            if let Ok((t, _)) = utf8(body, 2) {
                e.object = Some(t);
            }
            e
        }
        9 => ProtoEvent::new(Protocol::Mqtt, "suback", 9, OpClass::Session),
        10 => ProtoEvent::new(Protocol::Mqtt, "unsubscribe", 10, OpClass::Session),
        11 => ProtoEvent::new(Protocol::Mqtt, "unsuback", 11, OpClass::Session),
        12 | 13 => ProtoEvent::new(Protocol::Mqtt, if ty == 12 { "pingreq" } else { "pingresp" }, ty as u32, OpClass::Session),
        14 => ProtoEvent::new(Protocol::Mqtt, "disconnect", 14, OpClass::Session),
        15 => ProtoEvent::new(Protocol::Mqtt, "auth", 15, OpClass::Session),
        _ => return Err(ParseError::Malformed),
    };
    if dir == Dir::FromServer {
        e.is_response = true;
    }
    Ok(e)
}

/// PUBLISH packet (QoS 0).
pub fn publish(topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = (topic.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(payload);
    let mut v = vec![0x30, body.len() as u8];
    v.extend(body);
    v
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_publish() -> Vec<u8> {
        publish("plant/line1/valve7/set", b"open")
    }

    #[test]
    fn connect_publish_subscribe() {
        let mut c = vec![0x10, 0];
        let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 0xc2, 0, 60, 0, 6];
        body.extend_from_slice(b"sensor");
        c[1] = body.len() as u8;
        c.extend(body);
        let e = parse(&c, Dir::ToServer).unwrap();
        assert_eq!((e[0].operation.as_str(), e[0].details.get("password").map(|s| s.as_str()), e[0].identity.name.as_deref()), ("connect", Some("present"), Some("sensor")));
        let p = parse(&sample_publish(), Dir::ToServer).unwrap();
        assert_eq!((p[0].class, p[0].object.as_deref()), (OpClass::Write, Some("plant/line1/valve7/set")));
        let mut both = sample_publish();
        both.extend_from_slice(&[0xc0, 0]);
        assert_eq!(parse(&both, Dir::ToServer).unwrap().len(), 2);
    }

    #[test]
    fn rejects_bad_packets() {
        assert!(parse(&[0x30, 0xff, 0xff, 0xff, 0xff], Dir::ToServer).is_err());
        assert_eq!(parse(&[0x10, 6, 0, 4, b'H', b'T', b'T', b'P'], Dir::ToServer).unwrap_err(), ParseError::NotProtocol);
        assert_eq!(parse(&[0x00, 0], Dir::ToServer).unwrap_err(), ParseError::Malformed);
    }
}
