//! BACnet/IP (BVLC + NPDU + APDU) — ZTE-IOT "Bacnet Visibility" (section
//! 42), building management systems (section 26).
//!
//! Confirmed and unconfirmed services are classified (read/write property,
//! file transfer, device communication control and reinitialise as control,
//! time synchronisation as write, Who-Is/I-Am as session/identity). I-Am
//! discloses the device object instance and the vendor identifier.

use super::*;

fn confirmed(s: u8) -> (&'static str, OpClass) {
    match s {
        0 => ("acknowledge_alarm", OpClass::Write),
        1..=4 => ("event_notification", OpClass::Session),
        5 | 28 | 30 => ("subscribe_cov", OpClass::Session),
        6 => ("atomic_read_file", OpClass::Read),
        7 => ("atomic_write_file", OpClass::Program),
        8 => ("add_list_element", OpClass::Write),
        9 => ("remove_list_element", OpClass::Write),
        10 => ("create_object", OpClass::Write),
        11 => ("delete_object", OpClass::Write),
        12 => ("read_property", OpClass::Read),
        14 => ("read_property_multiple", OpClass::Read),
        15 => ("write_property", OpClass::Write),
        16 => ("write_property_multiple", OpClass::Write),
        17 => ("device_communication_control", OpClass::Control),
        18 => ("confirmed_private_transfer", OpClass::Control),
        19 => ("confirmed_text_message", OpClass::Session),
        20 => ("reinitialize_device", OpClass::Control),
        26 => ("read_range", OpClass::Read),
        29 => ("get_event_information", OpClass::Read),
        _ => ("unknown_confirmed_service", OpClass::Control),
    }
}

fn unconfirmed(s: u8) -> (&'static str, OpClass) {
    match s {
        0 => ("i_am", OpClass::Session),
        1 => ("i_have", OpClass::Session),
        2 => ("cov_notification", OpClass::Read),
        3 => ("event_notification", OpClass::Read),
        4 => ("unconfirmed_private_transfer", OpClass::Control),
        5 => ("unconfirmed_text_message", OpClass::Session),
        6 => ("time_synchronization", OpClass::Write),
        7 => ("who_has", OpClass::Session),
        8 => ("who_is", OpClass::Session),
        9 => ("utc_time_synchronization", OpClass::Write),
        10 => ("write_group", OpClass::Write),
        _ => ("unknown_unconfirmed_service", OpClass::Control),
    }
}

pub fn parse(b: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    if b.len() < 4 {
        return Err(ParseError::Truncated);
    }
    if b[0] != 0x81 {
        return Err(ParseError::NotProtocol);
    }
    let blen = u16be(b, 2)? as usize;
    if blen < 4 || blen > b.len() {
        return Err(ParseError::Malformed);
    }
    let npdu_at = match b[1] {
        0x0a | 0x0b => 4,
        0x04 => 10,
        f => {
            // BVLC management (registration, BDT/FDT).
            let e = ProtoEvent::new(Protocol::Bacnet, "bvlc_management", f as u32, if matches!(f, 0x01 | 0x05 | 0x08) { OpClass::Write } else { OpClass::Session });
            return Ok(vec![e]);
        }
    };
    let n = b.get(npdu_at..blen).ok_or(ParseError::Truncated)?;
    if byte(n, 0)? != 0x01 {
        return Err(ParseError::Malformed);
    }
    let ctrl = byte(n, 1)?;
    let mut off = 2;
    let mut dnet = None;
    if ctrl & 0x20 != 0 {
        dnet = Some(u16be(n, off)?);
        let dlen = byte(n, off + 2)? as usize;
        off += 3 + dlen;
    }
    if ctrl & 0x08 != 0 {
        let slen = byte(n, off + 2)? as usize;
        off += 3 + slen;
    }
    if dnet.is_some() {
        off += 1; // hop count
    }
    if ctrl & 0x80 != 0 {
        let mt = byte(n, off)?;
        return Ok(vec![ProtoEvent::new(Protocol::Bacnet, "network_layer_message", mt as u32, if mt == 0x08 || mt == 0x09 { OpClass::Write } else { OpClass::Session })]);
    }
    let a = n.get(off..).ok_or(ParseError::Truncated)?;
    let pdu_type = byte(a, 0)? >> 4;
    let mut e = match pdu_type {
        0 => {
            let seg = byte(a, 0)? & 0x08 != 0;
            let svc = byte(a, if seg { 5 } else { 3 })?;
            let (op, class) = confirmed(svc);
            let mut e = ProtoEvent::new(Protocol::Bacnet, op, svc as u32, class).detail("invoke_id", byte(a, 2)?);
            if matches!(svc, 12 | 15) {
                if let Some(obj) = object_id(a.get(if seg { 6 } else { 4 }..).unwrap_or(&[])) {
                    e.object = Some(obj);
                }
            }
            e
        }
        1 => {
            let svc = byte(a, 1)?;
            let (op, class) = unconfirmed(svc);
            let mut e = ProtoEvent::new(Protocol::Bacnet, op, svc as u32, class);
            if svc == 0 {
                i_am(&a[2..], &mut e)?;
            }
            e
        }
        2 | 3 => {
            let svc = byte(a, 2)?;
            let (op, class) = confirmed(svc);
            let mut e = ProtoEvent::new(Protocol::Bacnet, op, svc as u32, class.min(OpClass::Read));
            e.is_response = true;
            e
        }
        5..=7 => {
            let mut e = ProtoEvent::new(Protocol::Bacnet, ["error", "reject", "abort"][pdu_type as usize - 5], pdu_type as u32, OpClass::Session);
            e.is_response = true;
            e.is_error = true;
            e
        }
        4 => ProtoEvent::new(Protocol::Bacnet, "segment_ack", 4, OpClass::Session),
        _ => return Err(ParseError::Malformed),
    };
    if dir == Dir::FromServer {
        e.is_response = true;
    }
    if let Some(d) = dnet {
        e.unit = Some(d as u32);
    }
    Ok(vec![e])
}

/// Context-tagged object identifier `[0]` (tag 0x0c): "type:instance".
fn object_id(b: &[u8]) -> Option<String> {
    if b.len() >= 5 && (b[0] == 0x0c || b[0] == 0xc4) {
        let v = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
        return Some(format!("{}:{}", v >> 22, v & 0x3f_ffff));
    }
    None
}

fn i_am(b: &[u8], e: &mut ProtoEvent) -> PResult<()> {
    // Application tag 12 (object identifier, length 4).
    if byte(b, 0)? != 0xc4 {
        return Err(ParseError::Malformed);
    }
    let v = u32::from_be_bytes([byte(b, 1)?, byte(b, 2)?, byte(b, 3)?, byte(b, 4)?]);
    let (otype, inst) = (v >> 22, v & 0x3f_ffff);
    e.object = Some(format!("{otype}:{inst}"));
    // Max APDU (unsigned), segmentation (enumerated), vendor id (unsigned).
    let mut off = 5;
    let mut vendor = None;
    for i in 0..3 {
        let tag = byte(b, off)?;
        let len = (tag & 0x07) as usize;
        if len > 4 {
            return Err(ParseError::Malformed);
        }
        let val = b.get(off + 1..off + 1 + len).ok_or(ParseError::Truncated)?.iter().fold(0u32, |a, x| (a << 8) | *x as u32);
        if i == 2 {
            vendor = Some(val);
        }
        off += 1 + len;
    }
    if let Some(v) = vendor {
        e.identity.vendor = Some(format!("bacnet-vendor-{v}"));
        e.details.insert("vendor_id".into(), v.to_string());
    }
    e.identity.serial = Some(format!("bacnet-device-{inst}"));
    Ok(())
}

/// Build a BACnet/IP original-unicast frame around an APDU.
pub fn frame(apdu: &[u8]) -> Vec<u8> {
    let mut v = vec![0x81, 0x0a, 0, 0, 0x01, 0x04];
    v.extend_from_slice(apdu);
    let l = v.len() as u16;
    v[2..4].copy_from_slice(&l.to_be_bytes());
    v
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_write_property() -> Vec<u8> {
        // Confirmed request, invoke 1, writeProperty analog-value 3.
        frame(&[0x00, 0x05, 0x01, 15, 0x0c, 0x00, 0x80, 0x00, 0x03, 0x19, 0x55, 0x3e, 0x44, 0x42, 0x20, 0, 0, 0x3f])
    }

    #[test]
    fn classifies_services() {
        let w = parse(&sample_write_property(), Dir::ToServer).unwrap();
        assert_eq!((w[0].operation.as_str(), w[0].class, w[0].object.as_deref()), ("write_property", OpClass::Write, Some("2:3")));
        let r = parse(&frame(&[0x00, 0x05, 0x02, 12, 0x0c, 0x02, 0x00, 0x00, 0x01, 0x19, 0x4d]), Dir::ToServer).unwrap();
        assert_eq!(r[0].class, OpClass::Read);
        let ri = parse(&frame(&[0x00, 0x05, 0x03, 20, 0x09, 0x00]), Dir::ToServer).unwrap();
        assert_eq!(ri[0].class, OpClass::Control);
        let who = parse(&frame(&[0x10, 0x08]), Dir::ToServer).unwrap();
        assert_eq!(who[0].operation, "who_is");
    }

    #[test]
    fn i_am_discloses_identity() {
        // I-Am device 1234, max apdu 1476, segmentation both(0), vendor 8.
        let inst: u32 = (8 << 22) | 1234;
        let mut apdu = vec![0x10, 0x00, 0xc4];
        apdu.extend_from_slice(&inst.to_be_bytes());
        apdu.extend_from_slice(&[0x22, 0x05, 0xc4, 0x91, 0x00, 0x21, 0x08]);
        let e = parse(&frame(&apdu), Dir::ToServer).unwrap();
        assert_eq!(e[0].identity.vendor.as_deref(), Some("bacnet-vendor-8"));
        assert_eq!(e[0].object.as_deref(), Some("8:1234"));
    }

    #[test]
    fn rejects_bad_frames() {
        assert_eq!(parse(&[0x82, 0x0a, 0, 4], Dir::ToServer).unwrap_err(), ParseError::NotProtocol);
        assert_eq!(parse(&[0x81, 0x0a, 0, 99, 1], Dir::ToServer).unwrap_err(), ParseError::Malformed);
    }
}
