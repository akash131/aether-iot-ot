//! EtherNet/IP encapsulation and CIP — ZTE-IOT "Ethernet/Ip Visibility"
//! (section 45).
//!
//! Encapsulation commands (ListIdentity, RegisterSession, SendRRData,
//! SendUnitData) are decoded; CIP requests inside SendRRData/SendUnitData
//! are classified by service and target class: attribute and tag reads,
//! attribute and tag writes, reset/start/stop (control), file object writes
//! (program), connection management (session). ListIdentity replies
//! disclose vendor id, device type, product code, revision, serial number
//! and product name.

use super::*;

fn cip_class(service: u8, class: Option<u32>) -> (&'static str, OpClass) {
    let s = service & 0x7f;
    match (class, s) {
        (Some(0x06), 0x54) | (Some(0x06), 0x5b) => ("forward_open", OpClass::Session),
        (Some(0x06), 0x4e) => ("forward_close", OpClass::Session),
        (Some(0x06), 0x52) => ("unconnected_send", OpClass::Session),
        (Some(0x37), 0x10) | (Some(0x37), 0x02) | (Some(0x37), 0x4c..=0x4f) => ("file_write", OpClass::Program),
        (Some(0xa1), _) => ("firmware_update", OpClass::Firmware),
        (_, 0x01) => ("get_attributes_all", OpClass::Read),
        (_, 0x03) => ("get_attribute_list", OpClass::Read),
        (_, 0x0e) => ("get_attribute_single", OpClass::Read),
        (_, 0x02) => ("set_attributes_all", OpClass::Write),
        (_, 0x04) => ("set_attribute_list", OpClass::Write),
        (_, 0x10) => ("set_attribute_single", OpClass::Write),
        (_, 0x05) => ("reset", OpClass::Control),
        (_, 0x06) => ("start", OpClass::Control),
        (_, 0x07) => ("stop", OpClass::Control),
        (_, 0x08) => ("create", OpClass::Write),
        (_, 0x09) => ("delete", OpClass::Write),
        (_, 0x0a) => ("multiple_service_packet", OpClass::Read),
        (_, 0x4c) | (_, 0x52) => ("read_tag", OpClass::Read),
        (_, 0x4d) | (_, 0x53) => ("write_tag", OpClass::Write),
        (_, 0x4e) => ("read_modify_write_tag", OpClass::Write),
        _ => ("unknown_service", OpClass::Control),
    }
}

/// Decode a CIP message path's class id (8/16-bit logical class segments).
fn path_class(path: &[u8]) -> Option<u32> {
    let mut i = 0;
    while i + 1 < path.len() {
        match path[i] {
            0x20 => return Some(path[i + 1] as u32),
            0x21 => return path.get(i + 2..i + 4).map(|x| u16::from_le_bytes([x[0], x[1]]) as u32),
            0x91 => i += 2 + ((path[i + 1] as usize + 1) & !1),
            _ => i += 2,
        }
    }
    None
}

fn cip(msg: &[u8], depth: u8) -> PResult<ProtoEvent> {
    let service = byte(msg, 0)?;
    let is_response = service & 0x80 != 0;
    if is_response {
        let status = byte(msg, 2).unwrap_or(0);
        let (op, _) = cip_class(service, None);
        let mut e = ProtoEvent::new(Protocol::Enip, op, (service & 0x7f) as u32, OpClass::Session);
        e.is_response = true;
        e.is_error = status != 0;
        return Ok(e.detail("general_status", status));
    }
    let words = byte(msg, 1)? as usize;
    let path = msg.get(2..2 + words * 2).ok_or(ParseError::Truncated)?;
    let class = path_class(path);
    let (op, cls) = cip_class(service, class);
    if op == "unconnected_send" && depth == 0 {
        // Unconnected send wraps the real request: priority, ticks, size, message.
        let rest = &msg[2 + words * 2..];
        let size = u16le(rest, 2)? as usize;
        if let Some(inner) = rest.get(4..4 + size) {
            return cip(inner, 1);
        }
    }
    let mut e = ProtoEvent::new(Protocol::Enip, op, (service & 0x7f) as u32, cls);
    if let Some(c) = class {
        e.object = Some(format!("class:{c:#x}"));
    } else if path.first() == Some(&0x91) {
        let n = path.get(1).copied().unwrap_or(0) as usize;
        e.object = Some(format!("tag:{}", ascii(path.get(2..2 + n).unwrap_or(&[]), 40)));
    }
    Ok(e)
}

pub fn parse(b: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    if b.len() < 24 {
        return Err(ParseError::Truncated);
    }
    let cmd = u16le(b, 0)?;
    let len = u16le(b, 2)? as usize;
    let body = b.get(24..24 + len).ok_or(ParseError::Truncated)?;
    let status = u32le(b, 8)?;
    let mut e = match cmd {
        0x0004 => ProtoEvent::new(Protocol::Enip, "list_services", cmd as u32, OpClass::Session),
        0x0063 => {
            let mut e = ProtoEvent::new(Protocol::Enip, "list_identity", cmd as u32, OpClass::Read);
            if !body.is_empty() {
                e.is_response = true;
                e.identity = identity(body)?;
            }
            e
        }
        0x0064 => ProtoEvent::new(Protocol::Enip, "list_interfaces", cmd as u32, OpClass::Session),
        0x0065 => ProtoEvent::new(Protocol::Enip, "register_session", cmd as u32, OpClass::Session),
        0x0066 => ProtoEvent::new(Protocol::Enip, "unregister_session", cmd as u32, OpClass::Session),
        0x006f | 0x0070 => {
            // Interface handle (4), timeout (2), item count (2), items.
            let count = u16le(body, 6)? as usize;
            let mut off = 8;
            let mut found = None;
            for _ in 0..count.min(8) {
                let ty = u16le(body, off)?;
                let ilen = u16le(body, off + 2)? as usize;
                let data = body.get(off + 4..off + 4 + ilen).ok_or(ParseError::Truncated)?;
                match ty {
                    0x00b2 => found = Some(cip(data, 0)?),
                    0x00b1 if data.len() > 2 => found = Some(cip(&data[2..], 0)?),
                    _ => {}
                }
                off += 4 + ilen;
            }
            found.unwrap_or_else(|| ProtoEvent::new(Protocol::Enip, if cmd == 0x006f { "send_rr_data" } else { "send_unit_data" }, cmd as u32, OpClass::Session))
        }
        _ => return Err(ParseError::NotProtocol),
    };
    if dir == Dir::FromServer {
        e.is_response = true;
    }
    if status != 0 {
        e.is_error = true;
    }
    Ok(vec![e])
}

fn identity(body: &[u8]) -> PResult<IdentityHints> {
    // item count (2), type 0x0c (2), length (2), version (2), sockaddr (16), then identity.
    if u16le(body, 2)? != 0x0c {
        return Err(ParseError::Malformed);
    }
    let base = 6 + 2 + 16;
    let vendor = u16le(body, base)?;
    let device_type = u16le(body, base + 2)?;
    let product_code = u16le(body, base + 4)?;
    let (maj, min) = (byte(body, base + 6)?, byte(body, base + 7)?);
    let serial = u32le(body, base + 10)?;
    let nlen = byte(body, base + 14)? as usize;
    let name = ascii(body.get(base + 15..base + 15 + nlen).ok_or(ParseError::Truncated)?, 64);
    Ok(IdentityHints {
        vendor: Some(format!("enip-vendor-{vendor}")),
        product: Some(if name.is_empty() { format!("device-type-{device_type}/product-{product_code}") } else { name.clone() }),
        firmware: Some(format!("{maj}.{min:03}")),
        serial: Some(format!("{serial:08x}")),
        name: None,
    })
}

/// Encapsulation header + body (tests, simulators).
pub fn encap(cmd: u16, body: &[u8]) -> Vec<u8> {
    let mut v = cmd.to_le_bytes().to_vec();
    v.extend_from_slice(&(body.len() as u16).to_le_bytes());
    v.extend_from_slice(&[0u8; 20]);
    v.extend_from_slice(body);
    v
}

/// SendRRData carrying an unconnected CIP request.
pub fn rr_data(cip_msg: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0, 0, 0, 10, 0, 2, 0, 0, 0, 0, 0, 0xb2, 0];
    body.extend_from_slice(&(cip_msg.len() as u16).to_le_bytes());
    body.extend_from_slice(cip_msg);
    encap(0x006f, &body)
}

/// A ListIdentity reply (tests, simulators, acceptance harness).
pub fn list_identity_reply(vendor: u16, device_type: u16, product_code: u16, rev: (u8, u8), serial: u32, name: &str) -> Vec<u8> {
    let mut item = vec![1, 0];
    item.extend_from_slice(&[0u8; 16]);
    item.extend_from_slice(&vendor.to_le_bytes());
    item.extend_from_slice(&device_type.to_le_bytes());
    item.extend_from_slice(&product_code.to_le_bytes());
    item.extend_from_slice(&[rev.0, rev.1]);
    item.extend_from_slice(&0x0030u16.to_le_bytes());
    item.extend_from_slice(&serial.to_le_bytes());
    item.push(name.len() as u8);
    item.extend_from_slice(name.as_bytes());
    item.push(3);
    let mut body = vec![1, 0, 0x0c, 0];
    body.extend_from_slice(&(item.len() as u16).to_le_bytes());
    body.extend(item);
    encap(0x0063, &body)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_list_identity_reply() -> Vec<u8> {
        list_identity_reply(1, 14, 55, (20, 11), 0xc0ffee01, "1756-L83E/B")
    }

    #[test]
    fn list_identity_discloses_device() {
        let e = parse(&sample_list_identity_reply(), Dir::FromServer).unwrap();
        let id = &e[0].identity;
        assert_eq!(
            (id.vendor.as_deref(), id.product.as_deref(), id.firmware.as_deref(), id.serial.as_deref()),
            (Some("enip-vendor-1"), Some("1756-L83E/B"), Some("20.011"), Some("c0ffee01"))
        );
    }

    #[test]
    fn classifies_cip_services() {
        let tag = b"Pump1";
        let mut w = vec![0x4d, (2 + tag.len()).div_ceil(2) as u8, 0x91, tag.len() as u8];
        w.extend_from_slice(tag);
        w.push(0);
        w.extend_from_slice(&[0xc4, 0, 1, 0, 1, 0, 0, 0]);
        let e = parse(&rr_data(&w), Dir::ToServer).unwrap();
        assert_eq!((e[0].operation.as_str(), e[0].class, e[0].object.as_deref()), ("write_tag", OpClass::Write, Some("tag:Pump1")));
        let reset = parse(&rr_data(&[0x05, 2, 0x20, 0x01, 0x24, 0x01]), Dir::ToServer).unwrap();
        assert_eq!(reset[0].class, OpClass::Control);
        let fo = parse(&rr_data(&[0x54, 2, 0x20, 0x06, 0x24, 0x01, 0, 0]), Dir::ToServer).unwrap();
        assert_eq!(fo[0].class, OpClass::Session);
        // Unconnected send wrapping Get_Attribute_Single.
        let inner = [0x0e, 3, 0x20, 0x01, 0x24, 0x01, 0x30, 0x07];
        let mut us = vec![0x52, 2, 0x20, 0x06, 0x24, 0x01, 0x0a, 0x05];
        us.extend_from_slice(&(inner.len() as u16).to_le_bytes());
        us.extend_from_slice(&inner);
        let e = parse(&rr_data(&us), Dir::ToServer).unwrap();
        assert_eq!(e[0].operation, "get_attribute_single");
    }

    #[test]
    fn rejects_unknown_commands() {
        assert_eq!(parse(&encap(0x1234, &[]), Dir::ToServer).unwrap_err(), ParseError::NotProtocol);
        assert_eq!(parse(&[0u8; 10], Dir::ToServer).unwrap_err(), ParseError::Truncated);
    }
}
