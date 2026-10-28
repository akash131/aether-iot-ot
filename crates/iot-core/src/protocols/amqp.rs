//! AMQP 0-9-1 (and the AMQP 1.0 protocol header) — ZTE-IOT "Amqp
//! Visibility" (section 49).
//!
//! Method frames are classified: connection and channel management
//! (session; `Connection.StartOk` with the PLAIN mechanism carries
//! cleartext credentials), exchange/queue declaration, binding and deletion
//! (write), `Basic.Publish` (write), `Basic.Consume`/`Basic.Get` (read).

use super::*;

pub fn parse(b: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    if b.starts_with(b"AMQP") {
        let v = b.get(4..8).ok_or(ParseError::Truncated)?;
        return Ok(vec![ProtoEvent::new(Protocol::Amqp, "protocol_header", 0, OpClass::Session).detail("version", format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]))]);
    }
    let mut out = vec![];
    let mut off = 0;
    while off < b.len() && out.len() < 64 {
        let f = &b[off..];
        if f.len() < 8 {
            return if out.is_empty() { Err(ParseError::Truncated) } else { Ok(out) };
        }
        let ty = f[0];
        let size = u32::from_be_bytes([f[3], f[4], f[5], f[6]]) as usize;
        if size > MAX_PAYLOAD * 128 {
            return Err(ParseError::Malformed);
        }
        let payload = f.get(7..7 + size).ok_or(ParseError::Truncated)?;
        if byte(f, 7 + size)? != 0xce {
            return Err(ParseError::NotProtocol);
        }
        let mut e = match ty {
            1 => method(payload)?,
            2 => ProtoEvent::new(Protocol::Amqp, "content_header", 2, OpClass::Session),
            3 => ProtoEvent::new(Protocol::Amqp, "content_body", 3, OpClass::Session),
            8 => ProtoEvent::new(Protocol::Amqp, "heartbeat", 8, OpClass::Session),
            _ => return Err(ParseError::NotProtocol),
        };
        e.unit = Some(u16be(f, 1)? as u32);
        if dir == Dir::FromServer {
            e.is_response = true;
        }
        out.push(e);
        off += 8 + size;
    }
    Ok(out)
}

fn method(p: &[u8]) -> PResult<ProtoEvent> {
    let class = u16be(p, 0)?;
    let m = u16be(p, 2)?;
    let (op, c) = match (class, m) {
        (10, 10) => ("connection_start", OpClass::Session),
        (10, 11) => ("connection_start_ok", OpClass::Session),
        (10, 30) | (10, 31) => ("connection_tune", OpClass::Session),
        (10, 40) | (10, 41) => ("connection_open", OpClass::Session),
        (10, 50) | (10, 51) => ("connection_close", OpClass::Session),
        (20, _) => ("channel", OpClass::Session),
        (40, 10) => ("exchange_declare", OpClass::Write),
        (40, 20) => ("exchange_delete", OpClass::Write),
        (40, _) => ("exchange", OpClass::Session),
        (50, 10) => ("queue_declare", OpClass::Write),
        (50, 20) => ("queue_bind", OpClass::Write),
        (50, 30) => ("queue_purge", OpClass::Write),
        (50, 40) => ("queue_delete", OpClass::Write),
        (50, 50) => ("queue_unbind", OpClass::Write),
        (50, _) => ("queue", OpClass::Session),
        (60, 20) => ("basic_consume", OpClass::Read),
        (60, 40) => ("basic_publish", OpClass::Write),
        (60, 60) => ("basic_deliver", OpClass::Read),
        (60, 70) => ("basic_get", OpClass::Read),
        (60, _) => ("basic", OpClass::Session),
        (85, _) | (90, _) => ("transaction", OpClass::Session),
        _ => ("unknown_method", OpClass::Session),
    };
    let mut e = ProtoEvent::new(Protocol::Amqp, op, ((class as u32) << 16) | m as u32, c);
    if (class, m) == (10, 11) {
        // client-properties table (long size), mechanism (short string).
        let tsize = p.get(4..8).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]) as usize).ok_or(ParseError::Truncated)?;
        let at = 8 + tsize;
        let n = byte(p, at)? as usize;
        let mech = ascii(p.get(at + 1..at + 1 + n).ok_or(ParseError::Truncated)?, 32);
        if mech == "PLAIN" || mech == "AMQPLAIN" {
            e = e.detail("password", "present");
        }
        e = e.detail("mechanism", mech);
    }
    if (class, m) == (60, 40) {
        // reserved short, exchange shortstr, routing key shortstr.
        let n = byte(p, 6)? as usize;
        let ex = ascii(p.get(7..7 + n).unwrap_or(&[]), 64);
        let rk_at = 7 + n;
        let rn = byte(p, rk_at).unwrap_or(0) as usize;
        let rk = ascii(p.get(rk_at + 1..rk_at + 1 + rn).unwrap_or(&[]), 128);
        e.object = Some(format!("{ex}/{rk}"));
    }
    Ok(e)
}

/// A method frame (tests).
pub fn method_frame(channel: u16, class: u16, method: u16, args: &[u8]) -> Vec<u8> {
    let mut payload = class.to_be_bytes().to_vec();
    payload.extend_from_slice(&method.to_be_bytes());
    payload.extend_from_slice(args);
    let mut v = vec![1];
    v.extend_from_slice(&channel.to_be_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend(payload);
    v.push(0xce);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_consume_and_credentials() {
        let mut args = vec![0, 0, 3];
        args.extend_from_slice(b"ops");
        args.push(5);
        args.extend_from_slice(b"alarm");
        args.push(0);
        let e = parse(&method_frame(1, 60, 40, &args), Dir::ToServer).unwrap();
        assert_eq!((e[0].class, e[0].object.as_deref()), (OpClass::Write, Some("ops/alarm")));
        assert_eq!(parse(&method_frame(1, 60, 20, &[0, 0]), Dir::ToServer).unwrap()[0].class, OpClass::Read);
        let mut so = vec![0, 0, 0, 0, 5];
        so.extend_from_slice(b"PLAIN");
        let e = parse(&method_frame(0, 10, 11, &so), Dir::ToServer).unwrap();
        assert_eq!(e[0].details.get("password").map(|s| s.as_str()), Some("present"));
        assert_eq!(parse(b"AMQP\x00\x00\x09\x01", Dir::ToServer).unwrap()[0].operation, "protocol_header");
    }

    #[test]
    fn rejects_bad_frame_end() {
        let mut f = method_frame(1, 60, 20, &[0, 0]);
        let n = f.len();
        f[n - 1] = 0;
        assert_eq!(parse(&f, Dir::ToServer).unwrap_err(), ParseError::NotProtocol);
    }
}
