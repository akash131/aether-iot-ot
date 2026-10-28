//! OPC UA binary (UA TCP / UA SecureConversation) — ZTE-IOT "Opc Ua
//! Visibility" (section 43).
//!
//! Hello/Acknowledge/Error, OpenSecureChannel (the security policy URI is
//! extracted: `None` means unauthenticated and unencrypted traffic) and
//! service messages. For messages that are not encrypted the service
//! request type is decoded from its binary encoding id and classified:
//! Read/Browse/HistoryRead (read), Write/HistoryUpdate/AddNodes/DeleteNodes
//! (write), Call (control), session and subscription services (session).
//! Encrypted messages are reported as such without guessing.

use super::*;

fn service(id: u32) -> (&'static str, OpClass) {
    match id {
        422 => ("find_servers", OpClass::Session),
        428 => ("get_endpoints", OpClass::Session),
        446 => ("open_secure_channel", OpClass::Session),
        452 => ("close_secure_channel", OpClass::Session),
        461 => ("create_session", OpClass::Session),
        467 => ("activate_session", OpClass::Session),
        473 => ("close_session", OpClass::Session),
        488 => ("add_nodes", OpClass::Write),
        500 => ("delete_nodes", OpClass::Write),
        527 => ("browse", OpClass::Read),
        554 => ("translate_browse_paths", OpClass::Read),
        631 => ("read", OpClass::Read),
        664 => ("history_read", OpClass::Read),
        673 => ("write", OpClass::Write),
        700 => ("history_update", OpClass::Write),
        712 => ("call", OpClass::Control),
        751 => ("create_monitored_items", OpClass::Session),
        787 => ("create_subscription", OpClass::Session),
        826 => ("publish", OpClass::Session),
        397 => ("service_fault", OpClass::Session),
        634 | 676 | 530 | 715 | 464 | 470 | 449 | 790 | 829 | 431 => ("response", OpClass::Session),
        _ => ("unknown_service", OpClass::Session),
    }
}

fn ua_string(b: &[u8], at: usize, max: usize) -> PResult<(Option<String>, usize)> {
    let len = i32::from_le_bytes(b.get(at..at + 4).ok_or(ParseError::Truncated)?.try_into().map_err(|_| ParseError::Truncated)?);
    if len < 0 {
        return Ok((None, at + 4));
    }
    let len = len as usize;
    if len > 4096 {
        return Err(ParseError::Malformed);
    }
    let s = b.get(at + 4..at + 4 + len).ok_or(ParseError::Truncated)?;
    Ok((Some(String::from_utf8_lossy(&s[..s.len().min(max)]).to_string()), at + 4 + len))
}

/// Decode an expanded NodeId's numeric identifier (encodings 0, 1, 2).
fn node_id(b: &[u8], at: usize) -> Option<u32> {
    match *b.get(at)? {
        0x00 => b.get(at + 1).map(|x| *x as u32),
        0x01 => b.get(at + 2..at + 4).map(|x| u16::from_le_bytes([x[0], x[1]]) as u32),
        0x02 => b.get(at + 3..at + 7).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]])),
        _ => None,
    }
}

pub fn parse(b: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    if b.len() < 8 {
        return Err(ParseError::Truncated);
    }
    let ty = &b[0..3];
    if !matches!(b[3], b'F' | b'C' | b'A') {
        return Err(ParseError::NotProtocol);
    }
    let size = u32le(b, 4)? as usize;
    if !(8..=16 * 1024 * 1024).contains(&size) {
        return Err(ParseError::Malformed);
    }
    let msg = &b[..size.min(b.len())];
    let mut e = match ty {
        b"HEL" => {
            let (url, _) = ua_string(msg, 28, 200)?;
            let mut e = ProtoEvent::new(Protocol::OpcUa, "hello", 0, OpClass::Session);
            if let Some(u) = url {
                e = e.detail("endpoint_url", u);
            }
            e
        }
        b"ACK" => {
            let mut e = ProtoEvent::new(Protocol::OpcUa, "acknowledge", 0, OpClass::Session);
            e.is_response = true;
            e
        }
        b"ERR" => {
            let mut e = ProtoEvent::new(Protocol::OpcUa, "error", u32le(msg, 8).unwrap_or(0), OpClass::Session);
            e.is_error = true;
            e.is_response = true;
            e
        }
        b"RHE" => ProtoEvent::new(Protocol::OpcUa, "reverse_hello", 0, OpClass::Session),
        b"OPN" => {
            let (policy, next) = ua_string(msg, 12, 200)?;
            let policy = policy.unwrap_or_default();
            let mut e = ProtoEvent::new(Protocol::OpcUa, "open_secure_channel", 446, OpClass::Session);
            let mode = policy.rsplit('#').next().unwrap_or("").to_string();
            e = e.detail("security_policy", if mode.is_empty() { "None".to_string() } else { mode.clone() });
            if mode == "None" || mode.is_empty() {
                e = e.detail("insecure", "true");
                // Unencrypted: sender certificate, receiver thumbprint, sequence header, then the request type.
                let (_, n2) = ua_string(msg, next, 0)?;
                let (_, n3) = ua_string(msg, n2, 0)?;
                if let Some(id) = node_id(msg, n3 + 8) {
                    e.is_response = id == 449;
                }
            }
            e
        }
        b"CLO" => ProtoEvent::new(Protocol::OpcUa, "close_secure_channel", 452, OpClass::Session),
        b"MSG" => match node_id(msg, 24) {
            Some(id) => {
                let (op, class) = service(id);
                let mut e = ProtoEvent::new(Protocol::OpcUa, op, id, class);
                e.is_response = op == "response" || op == "service_fault";
                e.is_error = op == "service_fault";
                e
            }
            None => ProtoEvent::new(Protocol::OpcUa, "encrypted_message", 0, OpClass::Session),
        },
        _ => return Err(ParseError::NotProtocol),
    };
    if dir == Dir::FromServer {
        e.is_response = true;
    }
    Ok(vec![e])
}

/// Build an unencrypted service message with a four-byte NodeId type id.
pub fn msg(type_id: u16) -> Vec<u8> {
    let mut v = b"MSGF".to_vec();
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]);
    v.extend_from_slice(&[0x01, 0x00]);
    v.extend_from_slice(&type_id.to_le_bytes());
    v.extend_from_slice(&[0u8; 8]);
    let l = v.len() as u32;
    v[4..8].copy_from_slice(&l.to_le_bytes());
    v
}

/// A Hello message (tests, simulators).
pub fn hello(url: &str) -> Vec<u8> {
    let mut v = b"HELF".to_vec();
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(&[0; 20]);
    v.extend_from_slice(&(url.len() as i32).to_le_bytes());
    v.extend_from_slice(url.as_bytes());
    let l = v.len() as u32;
    v[4..8].copy_from_slice(&l.to_le_bytes());
    v
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_hello() -> Vec<u8> {
        hello("opc.tcp://plc-7:4840")
    }

    #[test]
    fn hello_and_services() {
        let h = parse(&sample_hello(), Dir::ToServer).unwrap();
        assert_eq!(h[0].details.get("endpoint_url").map(|s| s.as_str()), Some("opc.tcp://plc-7:4840"));
        assert_eq!(parse(&msg(673), Dir::ToServer).unwrap()[0].class, OpClass::Write);
        assert_eq!(parse(&msg(631), Dir::ToServer).unwrap()[0].class, OpClass::Read);
        assert_eq!(parse(&msg(712), Dir::ToServer).unwrap()[0].class, OpClass::Control);
        let mut enc = msg(631);
        enc[24] = 0x9f;
        assert_eq!(parse(&enc, Dir::ToServer).unwrap()[0].operation, "encrypted_message");
    }

    #[test]
    fn open_secure_channel_policy() {
        let uri = b"http://opcfoundation.org/UA/SecurityPolicy#None";
        let mut v = b"OPNF".to_vec();
        v.extend_from_slice(&[0; 4]);
        v.extend_from_slice(&[0; 4]);
        v.extend_from_slice(&(uri.len() as i32).to_le_bytes());
        v.extend_from_slice(uri);
        v.extend_from_slice(&(-1i32).to_le_bytes());
        v.extend_from_slice(&(-1i32).to_le_bytes());
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&[0x01, 0x00, 0xbe, 0x01]);
        let l = v.len() as u32;
        v[4..8].copy_from_slice(&l.to_le_bytes());
        let e = parse(&v, Dir::ToServer).unwrap();
        assert_eq!(e[0].details.get("insecure").map(|s| s.as_str()), Some("true"));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse(b"XYZQ\x08\0\0\0", Dir::ToServer).unwrap_err(), ParseError::NotProtocol);
        assert_eq!(parse(b"MSGF\x02\0\0\0", Dir::ToServer).unwrap_err(), ParseError::Malformed);
    }
}
