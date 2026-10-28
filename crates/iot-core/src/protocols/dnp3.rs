//! DNP3 over TCP/UDP — ZTE-IOT "Dnp3 Visibility" (section 41).
//!
//! The link header CRC is verified; user data is reassembled from its
//! 16-byte CRC-protected blocks (bounded) and the transport and application
//! headers are decoded. Function codes are classified: read, write,
//! select/operate/direct-operate (control), freeze, restarts and
//! application start/stop (control), file transfer and configuration
//! activation (program), unsolicited enable/disable and time sync.

use super::*;

/// CRC-16/DNP (reflected polynomial 0xA6BC, inverted output).
pub fn crc(data: &[u8]) -> u16 {
    let mut c: u16 = 0;
    for &b in data {
        c ^= b as u16;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xa6bc } else { c >> 1 };
        }
    }
    !c
}

fn classify(fc: u8) -> (&'static str, OpClass) {
    match fc {
        0 => ("confirm", OpClass::Session),
        1 => ("read", OpClass::Read),
        2 => ("write", OpClass::Write),
        3 => ("select", OpClass::Control),
        4 => ("operate", OpClass::Control),
        5 => ("direct_operate", OpClass::Control),
        6 => ("direct_operate_no_ack", OpClass::Control),
        7..=12 => ("freeze", OpClass::Control),
        13 => ("cold_restart", OpClass::Control),
        14 => ("warm_restart", OpClass::Control),
        15 => ("initialize_data", OpClass::Control),
        16 => ("initialize_application", OpClass::Control),
        17 => ("start_application", OpClass::Control),
        18 => ("stop_application", OpClass::Control),
        19 => ("save_configuration", OpClass::Program),
        20 => ("enable_unsolicited", OpClass::Write),
        21 => ("disable_unsolicited", OpClass::Write),
        22 => ("assign_class", OpClass::Write),
        23 => ("delay_measure", OpClass::Diagnostic),
        24 => ("record_current_time", OpClass::Write),
        25 => ("open_file", OpClass::Program),
        26 => ("close_file", OpClass::Program),
        27 => ("delete_file", OpClass::Program),
        28 => ("get_file_info", OpClass::Read),
        29 => ("authenticate_file", OpClass::Program),
        30 => ("abort_file", OpClass::Program),
        31 => ("activate_configuration", OpClass::Program),
        32 => ("authentication_request", OpClass::Session),
        33 => ("authentication_request_no_ack", OpClass::Session),
        129 => ("response", OpClass::Read),
        130 => ("unsolicited_response", OpClass::Read),
        131 => ("authentication_response", OpClass::Session),
        _ => ("unknown_function", OpClass::Control),
    }
}

/// Parse one DNP3 link frame (several frames in one segment are decoded).
pub fn parse(b: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    let mut out = vec![];
    let mut off = 0;
    while off < b.len() && out.len() < 32 {
        let (ev, used) = frame(&b[off..], dir)?;
        if let Some(e) = ev {
            out.push(e);
        }
        off += used;
    }
    Ok(out)
}

fn frame(b: &[u8], dir: Dir) -> PResult<(Option<ProtoEvent>, usize)> {
    if b.len() < 10 {
        return Err(ParseError::Truncated);
    }
    if b[0] != 0x05 || b[1] != 0x64 {
        return Err(ParseError::NotProtocol);
    }
    let len = b[2] as usize;
    if len < 5 {
        return Err(ParseError::Malformed);
    }
    if crc(&b[0..8]) != u16le(b, 8)? {
        return Err(ParseError::Malformed);
    }
    let ctrl = b[3];
    let dest = u16le(b, 4)?;
    let src = u16le(b, 6)?;
    let user_len = len - 5;
    // Reassemble user data: blocks of 16 bytes, each followed by a CRC.
    let mut data = Vec::with_capacity(user_len);
    let mut off = 10;
    let mut left = user_len;
    while left > 0 {
        let n = left.min(16);
        let blk = b.get(off..off + n).ok_or(ParseError::Truncated)?;
        let c = u16le(b, off + n)?;
        if crc(blk) != c {
            return Err(ParseError::Malformed);
        }
        data.extend_from_slice(blk);
        off += n + 2;
        left -= n;
    }
    let link_fc = ctrl & 0x0f;
    let prm = ctrl & 0x40 != 0;
    if data.is_empty() {
        // Link-layer only frame (reset link, link status, ack).
        let mut e = ProtoEvent::new(Protocol::Dnp3, "link_service", link_fc as u32, OpClass::Session);
        e.unit = Some(dest as u32);
        e.is_response = !prm;
        return Ok((Some(e.detail("source", src)), off));
    }
    // data[0] = transport header; then application control + function code.
    let th = data[0];
    let first = th & 0x40 != 0;
    if !first || data.len() < 3 {
        let mut e = ProtoEvent::new(Protocol::Dnp3, "transport_segment", 0, OpClass::Session);
        e.unit = Some(dest as u32);
        return Ok((Some(e), off));
    }
    let fc = data[2];
    let (op, class) = classify(fc);
    let mut e = ProtoEvent::new(Protocol::Dnp3, op, fc as u32, class).detail("source", src);
    e.unit = Some(dest as u32);
    e.is_response = fc >= 129 || dir == Dir::FromServer;
    let mut obj_at = 3;
    if fc == 129 || fc == 130 {
        let iin = u16be(&data, 3).unwrap_or(0);
        e = e.detail("iin", format!("{iin:04x}"));
        // IIN2 bits 0..2: function not supported / object unknown / parameter error.
        e.is_error = iin & 0x0007 != 0;
        obj_at = 5;
    }
    if let (Some(g), Some(v)) = (data.get(obj_at), data.get(obj_at + 1)) {
        e.object = Some(format!("g{g}v{v}"));
    }
    Ok((Some(e), off))
}

/// Build a DNP3 link frame carrying one application fragment (tests and
/// simulators). `app` starts with the application control byte.
pub fn frame_bytes(dest: u16, src: u16, app: &[u8]) -> Vec<u8> {
    let mut user = vec![0xc0u8]; // FIR|FIN transport header, seq 0
    user.extend_from_slice(app);
    let mut v = vec![0x05, 0x64, (5 + user.len()) as u8, 0xc4];
    v.extend_from_slice(&dest.to_le_bytes());
    v.extend_from_slice(&src.to_le_bytes());
    let c = crc(&v);
    v.extend_from_slice(&c.to_le_bytes());
    for blk in user.chunks(16) {
        v.extend_from_slice(blk);
        v.extend_from_slice(&crc(blk).to_le_bytes());
    }
    v
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_operate() -> Vec<u8> {
        // Direct operate on CROB g12v1, index 0.
        frame_bytes(10, 1, &[0xc0, 0x05, 12, 1, 0x28, 1, 0, 0, 0, 0x03, 1, 0xe8, 3, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn crc_matches_reference() {
        // Catalogue check value of CRC-16/DNP.
        assert_eq!(crc(b"123456789"), 0xea82);
    }

    #[test]
    fn classifies_control_read_and_restart() {
        let e = parse(&sample_operate(), Dir::ToServer).unwrap();
        assert_eq!((e[0].operation.as_str(), e[0].class, e[0].object.as_deref(), e[0].unit), ("direct_operate", OpClass::Control, Some("g12v1"), Some(10)));
        let r = parse(&frame_bytes(10, 1, &[0xc0, 0x01, 60, 2, 0x06]), Dir::ToServer).unwrap();
        assert_eq!(r[0].class, OpClass::Read);
        let cr = parse(&frame_bytes(10, 1, &[0xc0, 13]), Dir::ToServer).unwrap();
        assert_eq!(cr[0].operation, "cold_restart");
        let resp = parse(&frame_bytes(1, 10, &[0xc0, 129, 0x00, 0x01, 30, 1]), Dir::FromServer).unwrap();
        assert!(resp[0].is_response && resp[0].is_error);
    }

    #[test]
    fn rejects_bad_crc() {
        let mut f = sample_operate();
        f[12] ^= 0xff;
        assert_eq!(parse(&f, Dir::ToServer).unwrap_err(), ParseError::Malformed);
        let mut h = sample_operate();
        h[4] ^= 1;
        assert_eq!(parse(&h, Dir::ToServer).unwrap_err(), ParseError::Malformed);
    }
}
