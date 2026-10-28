//! Modbus/TCP (MBAP + PDU) — ZTE-IOT "Modbus Visibility" (section 40).
//!
//! Function codes are classified for policy: reads (1–4), writes (5, 6,
//! 15, 16, 22, 23), control (diagnostics restart / listen-only), program
//! (file record writes, vendor engineering function 90), diagnostics and
//! device identification (43/14, whose response discloses vendor, product
//! and revision). Several ADUs in one segment are decoded (bounded).

use super::*;

const MAX_ADUS: usize = 64;

fn classify(fc: u8, pdu: &[u8]) -> (&'static str, OpClass) {
    match fc {
        1 => ("read_coils", OpClass::Read),
        2 => ("read_discrete_inputs", OpClass::Read),
        3 => ("read_holding_registers", OpClass::Read),
        4 => ("read_input_registers", OpClass::Read),
        5 => ("write_single_coil", OpClass::Write),
        6 => ("write_single_register", OpClass::Write),
        7 => ("read_exception_status", OpClass::Diagnostic),
        8 => match u16be(pdu, 1).unwrap_or(0xffff) {
            1 => ("diagnostics_restart_communications", OpClass::Control),
            4 => ("diagnostics_force_listen_only", OpClass::Control),
            10 => ("diagnostics_clear_counters", OpClass::Control),
            _ => ("diagnostics", OpClass::Diagnostic),
        },
        11 => ("get_comm_event_counter", OpClass::Diagnostic),
        12 => ("get_comm_event_log", OpClass::Diagnostic),
        15 => ("write_multiple_coils", OpClass::Write),
        16 => ("write_multiple_registers", OpClass::Write),
        17 => ("report_server_id", OpClass::Diagnostic),
        20 => ("read_file_record", OpClass::Read),
        21 => ("write_file_record", OpClass::Program),
        22 => ("mask_write_register", OpClass::Write),
        23 => ("read_write_multiple_registers", OpClass::Write),
        24 => ("read_fifo_queue", OpClass::Read),
        43 => ("read_device_identification", OpClass::Read),
        90 => ("vendor_engineering", OpClass::Program),
        _ => ("unknown_function", OpClass::Control),
    }
}

/// Parse one or more Modbus/TCP ADUs.
pub fn parse(b: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    let mut out = vec![];
    let mut off = 0;
    while off < b.len() && out.len() < MAX_ADUS {
        let adu = &b[off..];
        if adu.len() < 8 {
            return if out.is_empty() { Err(ParseError::Truncated) } else { Ok(out) };
        }
        let tid = u16be(adu, 0)?;
        if u16be(adu, 2)? != 0 {
            return Err(ParseError::NotProtocol);
        }
        let len = u16be(adu, 4)? as usize;
        if !(2..=254).contains(&len) {
            return Err(ParseError::Malformed);
        }
        let unit = adu[6];
        let pdu = adu.get(7..6 + len).ok_or(ParseError::Truncated)?;
        out.push(parse_pdu(pdu, unit, tid, dir)?);
        off += 6 + len;
    }
    Ok(out)
}

fn parse_pdu(pdu: &[u8], unit: u8, tid: u16, dir: Dir) -> PResult<ProtoEvent> {
    let raw = byte(pdu, 0)?;
    let is_error = raw & 0x80 != 0;
    let fc = raw & 0x7f;
    let (op, class) = classify(fc, pdu);
    let mut e = ProtoEvent::new(Protocol::Modbus, op, fc as u32, class).detail("transaction_id", tid);
    e.unit = Some(unit as u32);
    e.is_response = dir == Dir::FromServer;
    e.is_error = is_error;
    if is_error {
        return Ok(e.detail("exception_code", byte(pdu, 1).unwrap_or(0)));
    }
    let request = dir == Dir::ToServer;
    match (fc, request) {
        (1..=4, true) => {
            let addr = u16be(pdu, 1)?;
            let qty = u16be(pdu, 3)?;
            if qty == 0 || qty > 2000 {
                return Err(ParseError::Malformed);
            }
            e.object = Some(format!("{}:{}-{}", if fc <= 2 { "bits" } else { "registers" }, addr, addr as u32 + qty as u32 - 1));
        }
        (5 | 6, _) => {
            let addr = u16be(pdu, 1)?;
            let val = u16be(pdu, 3)?;
            e.object = Some(format!("{}:{}", if fc == 5 { "coil" } else { "register" }, addr));
            e.values.push(val as i64);
        }
        (15 | 16, true) => {
            let addr = u16be(pdu, 1)?;
            let qty = u16be(pdu, 3)?;
            let count = byte(pdu, 5)? as usize;
            if qty == 0 || qty > 1968 {
                return Err(ParseError::Malformed);
            }
            pdu.get(6..6 + count).ok_or(ParseError::Truncated)?;
            e.object = Some(format!("{}:{}-{}", if fc == 15 { "coils" } else { "registers" }, addr, addr as u32 + qty as u32 - 1));
            if fc == 16 {
                let data = pdu.get(6..6 + count).ok_or(ParseError::Truncated)?;
                e.values = data.chunks_exact(2).take(MAX_VALUES).map(|c| u16::from_be_bytes([c[0], c[1]]) as i64).collect();
            }
        }
        (22, _) => {
            e.object = Some(format!("register:{}", u16be(pdu, 1)?));
        }
        (23, true) => {
            let waddr = u16be(pdu, 5)?;
            e.object = Some(format!("registers:{waddr}"));
        }
        (43, _) => {
            if byte(pdu, 1)? == 14 && !request {
                e.identity = device_identification(pdu)?;
            }
        }
        (17, false) => {
            let n = byte(pdu, 1)? as usize;
            let id = pdu.get(2..2 + n).ok_or(ParseError::Truncated)?;
            let name = ascii(id, 64);
            if !name.is_empty() {
                e.identity.name = Some(name);
            }
        }
        _ => {}
    }
    Ok(e)
}

/// Read Device Identification (MEI 0x0e) response objects 0 (vendor),
/// 1 (product code), 2 (revision), 4 (product name).
fn device_identification(pdu: &[u8]) -> PResult<IdentityHints> {
    let n = byte(pdu, 6)? as usize;
    let mut off = 7;
    let mut h = IdentityHints::default();
    for _ in 0..n.min(16) {
        let id = byte(pdu, off)?;
        let len = byte(pdu, off + 1)? as usize;
        let v = pdu.get(off + 2..off + 2 + len).ok_or(ParseError::Truncated)?;
        let s = ascii(v, 128);
        match id {
            0 => h.vendor = Some(s),
            1 => h.product = Some(s),
            2 => h.firmware = Some(s),
            4 => h.name = Some(s),
            _ => {}
        }
        off += 2 + len;
    }
    Ok(h)
}

/// Build a Modbus/TCP ADU (tests, simulators, load driver).
pub fn adu(tid: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut v = tid.to_be_bytes().to_vec();
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
    v.push(unit);
    v.extend_from_slice(pdu);
    v
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_write() -> Vec<u8> {
        adu(7, 1, &[16, 0, 10, 0, 2, 4, 0, 100, 1, 0])
    }

    #[test]
    fn classifies_reads_writes_and_control() {
        let r = parse(&adu(1, 1, &[3, 0, 0, 0, 10]), Dir::ToServer).unwrap();
        assert_eq!((r[0].operation.as_str(), r[0].class, r[0].object.as_deref()), ("read_holding_registers", OpClass::Read, Some("registers:0-9")));
        let w = parse(&sample_write(), Dir::ToServer).unwrap();
        assert_eq!((w[0].class, w[0].values.clone(), w[0].unit), (OpClass::Write, vec![100, 256], Some(1)));
        let c = parse(&adu(2, 1, &[8, 0, 1, 0, 0]), Dir::ToServer).unwrap();
        assert_eq!(c[0].class, OpClass::Control);
        let p = parse(&adu(3, 0, &[90, 0, 0x28]), Dir::ToServer).unwrap();
        assert_eq!(p[0].class, OpClass::Program);
        let ex = parse(&adu(4, 1, &[0x83, 2]), Dir::FromServer).unwrap();
        assert!(ex[0].is_error && ex[0].is_response);
    }

    #[test]
    fn device_identification_and_pipelining() {
        let mut pdu = vec![43, 14, 1, 0x81, 0, 0, 3];
        for (id, s) in [(0u8, "Acme Controls"), (1, "PLC-500"), (2, "v2.4.1")] {
            pdu.push(id);
            pdu.push(s.len() as u8);
            pdu.extend_from_slice(s.as_bytes());
        }
        let ev = parse(&adu(9, 1, &pdu), Dir::FromServer).unwrap();
        assert_eq!(ev[0].identity.vendor.as_deref(), Some("Acme Controls"));
        assert_eq!(ev[0].identity.firmware.as_deref(), Some("v2.4.1"));
        let mut two = adu(1, 1, &[1, 0, 0, 0, 8]);
        two.extend(adu(2, 1, &[6, 0, 5, 0, 9]));
        assert_eq!(parse(&two, Dir::ToServer).unwrap().len(), 2);
    }

    #[test]
    fn rejects_invalid() {
        assert_eq!(parse(&[0, 1, 0, 5, 0, 6, 1, 3], Dir::ToServer).unwrap_err(), ParseError::NotProtocol);
        assert_eq!(parse(&adu(1, 1, &[3, 0, 0, 0, 0]), Dir::ToServer).unwrap_err(), ParseError::Malformed);
        assert!(parse(&[0, 1, 0, 0, 0, 200, 1, 3], Dir::ToServer).is_err());
    }
}
