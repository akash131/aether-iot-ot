//! PROFINET — ZTE-IOT "Profinet Visibility" (section 46).
//!
//! * DCP (Discovery and Configuration Protocol, ethertype 0x8892):
//!   identify requests/responses disclose station name, vendor/type of
//!   station and vendor/device ids; `Set` requests (station name, IP
//!   parameters) are writes and DCP control blocks (factory reset,
//!   signal) are control operations.
//! * PNIO-CM over DCE/RPC (UDP 34964): connect/release (session),
//!   read (read), write (write) and control (control).

use super::*;

/// Parse a DCP frame (the Ethernet payload after the ethertype).
pub fn parse_dcp(b: &[u8]) -> PResult<ProtoEvent> {
    if b.len() < 12 {
        return Err(ParseError::Truncated);
    }
    let frame_id = u16be(b, 0)?;
    if !(0xfefc..=0xfeff).contains(&frame_id) {
        return Err(ParseError::NotProtocol);
    }
    let service = b[2];
    let stype = b[3];
    let dlen = u16be(b, 10)? as usize;
    let data = b.get(12..12 + dlen).ok_or(ParseError::Truncated)?;
    let response = stype & 0x01 != 0;
    let mut op = match service {
        3 => ("get", OpClass::Read),
        4 => ("set", OpClass::Write),
        5 => ("identify", OpClass::Session),
        6 => ("hello", OpClass::Session),
        _ => return Err(ParseError::Malformed),
    };
    let mut ident = IdentityHints::default();
    let mut details: Vec<(&str, String)> = vec![];
    let mut off = 0;
    for _ in 0..32 {
        if off + 4 > data.len() {
            break;
        }
        let (opt, sub) = (data[off], data[off + 1]);
        let blen = u16be(data, off + 2)? as usize;
        let mut v = data.get(off + 4..off + 4 + blen).ok_or(ParseError::Truncated)?;
        if response && v.len() >= 2 && !(opt == 5 && service == 4) {
            v = &v[2..]; // block info
        } else if service == 4 && v.len() >= 2 {
            v = &v[2..]; // block qualifier
        }
        match (opt, sub) {
            (2, 1) => ident.product = Some(ascii(v, 64)),
            (2, 2) => {
                ident.name = Some(ascii(v, 64));
                if service == 4 {
                    details.push(("sets", "name_of_station".into()));
                }
            }
            (2, 3) if v.len() >= 4 => {
                ident.vendor = Some(format!("profinet-vendor-{:04x}", u16::from_be_bytes([v[0], v[1]])));
                details.push(("device_id", format!("{:04x}", u16::from_be_bytes([v[2], v[3]]))));
            }
            (1, 2) => {
                if service == 4 {
                    details.push(("sets", "ip_parameter".into()));
                }
            }
            (5, s) if service == 4 => {
                op = (if s == 6 { "factory_reset" } else { "control" }, OpClass::Control);
            }
            _ => {}
        }
        off += 4 + blen + (blen & 1);
    }
    let mut e = ProtoEvent::new(Protocol::Profinet, &format!("dcp_{}", op.0), service as u32, op.1);
    e.is_response = response;
    e.is_error = response && stype & 0x04 != 0;
    e.identity = ident;
    for (k, v) in details {
        e = e.detail(k, v);
    }
    Ok(e)
}

/// Parse PNIO-CM DCE/RPC over UDP.
pub fn parse_rpc(b: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    if b.len() < 4 {
        return Err(ParseError::Truncated);
    }
    if b[0] != 4 {
        return Err(ParseError::NotProtocol);
    }
    let ptype = b[1];
    if b.len() < 80 {
        // Short PDUs: ping, ack, working, fack.
        return Ok(vec![ProtoEvent::new(Protocol::Profinet, "rpc_control_pdu", ptype as u32, OpClass::Session)]);
    }
    let little = b[4] & 0x10 != 0;
    let opnum = if little { u16le(b, 68)? } else { u16be(b, 68)? };
    let (name, class) = match opnum {
        0 => ("connect", OpClass::Session),
        1 => ("release", OpClass::Session),
        2 | 5 => ("read", OpClass::Read),
        3 => ("write", OpClass::Write),
        4 => ("control", OpClass::Control),
        _ => ("unknown_operation", OpClass::Control),
    };
    let mut e = ProtoEvent::new(Protocol::Profinet, &format!("rpc_{name}"), opnum as u32, class);
    e.is_response = ptype == 2 || dir == Dir::FromServer;
    e.is_error = ptype == 3 || ptype == 6;
    Ok(vec![e])
}

/// A DCP identify response (tests, simulators).
pub fn dcp_identify_response(station: &str, vendor: u16, device: u16) -> Vec<u8> {
    let mut blocks = vec![];
    let mut push = |opt: u8, sub: u8, val: &[u8]| {
        blocks.extend_from_slice(&[opt, sub]);
        blocks.extend_from_slice(&((val.len() + 2) as u16).to_be_bytes());
        blocks.extend_from_slice(&[0, 0]);
        blocks.extend_from_slice(val);
        if val.len() % 2 == 1 {
            blocks.push(0);
        }
    };
    push(2, 2, station.as_bytes());
    let mut ids = vendor.to_be_bytes().to_vec();
    ids.extend_from_slice(&device.to_be_bytes());
    push(2, 3, &ids);
    let mut v = vec![0xfe, 0xff, 5, 1, 0, 0, 0, 1, 0, 0];
    v.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
    v.extend(blocks);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dcp_identify_and_set() {
        let e = parse_dcp(&dcp_identify_response("press-line-3", 0x002a, 0x0401)).unwrap();
        assert_eq!((e.identity.name.as_deref(), e.identity.vendor.as_deref(), e.is_response), (Some("press-line-3"), Some("profinet-vendor-002a"), true));
        // Set name of station (write).
        let mut set = vec![0xfe, 0xfd, 4, 0, 0, 0, 0, 2, 0, 0];
        let blk = [2u8, 2, 0, 6, 0, 1, b'a', b'b', b'c', b'd'];
        set.extend_from_slice(&(blk.len() as u16).to_be_bytes());
        set.extend_from_slice(&blk);
        let e = parse_dcp(&set).unwrap();
        assert_eq!((e.class, e.details.get("sets").map(|s| s.as_str())), (OpClass::Write, Some("name_of_station")));
        // Factory reset control block.
        let mut rst = vec![0xfe, 0xfd, 4, 0, 0, 0, 0, 3, 0, 0];
        let blk = [5u8, 6, 0, 2, 0, 0];
        rst.extend_from_slice(&(blk.len() as u16).to_be_bytes());
        rst.extend_from_slice(&blk);
        assert_eq!(parse_dcp(&rst).unwrap().class, OpClass::Control);
        assert!(parse_dcp(&[0, 1, 2]).is_err());
    }

    #[test]
    fn rpc_operations() {
        let mut v = vec![0u8; 80];
        v[0] = 4;
        v[4] = 0x10;
        v[68] = 3;
        assert_eq!(parse_rpc(&v, Dir::ToServer).unwrap()[0].class, OpClass::Write);
        v[68] = 4;
        assert_eq!(parse_rpc(&v, Dir::ToServer).unwrap()[0].class, OpClass::Control);
        assert_eq!(parse_rpc(&[5, 0, 0, 0], Dir::ToServer).unwrap_err(), ParseError::NotProtocol);
    }
}
