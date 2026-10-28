//! IEC 60870-5-104 — ZTE-IOT "Iec Protocol Visibility" (section 47),
//! SCADA assets (section 31).
//!
//! APCI frames (I, S and U formats) are decoded; I-format ASDUs are
//! classified by type identification: monitoring information (read),
//! single/double/regulating-step commands (control), set-point and
//! bitstring commands and parameter loading (write), interrogation and
//! read commands (read), clock synchronisation (write), reset process
//! (control) and file transfer (program). The cause of transmission and
//! common address are kept.

use super::*;

fn type_id(t: u8) -> (&'static str, OpClass) {
    match t {
        1..=40 => ("monitor_information", OpClass::Read),
        45 | 58 => ("single_command", OpClass::Control),
        46 | 59 => ("double_command", OpClass::Control),
        47 | 60 => ("regulating_step_command", OpClass::Control),
        48..=50 | 61..=63 => ("set_point_command", OpClass::Write),
        51 | 64 => ("bitstring_command", OpClass::Write),
        70 => ("end_of_initialization", OpClass::Session),
        100 => ("interrogation", OpClass::Read),
        101 => ("counter_interrogation", OpClass::Read),
        102 => ("read_command", OpClass::Read),
        103 => ("clock_synchronization", OpClass::Write),
        104 | 107 => ("test_command", OpClass::Diagnostic),
        105 => ("reset_process", OpClass::Control),
        106 => ("delay_acquisition", OpClass::Diagnostic),
        110..=113 => ("parameter_load", OpClass::Write),
        120..=127 => ("file_transfer", OpClass::Program),
        _ => ("unknown_type", OpClass::Control),
    }
}

pub fn parse(b: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    let mut out = vec![];
    let mut off = 0;
    while off < b.len() && out.len() < 64 {
        let a = &b[off..];
        if a.len() < 6 {
            return if out.is_empty() { Err(ParseError::Truncated) } else { Ok(out) };
        }
        if a[0] != 0x68 {
            return Err(ParseError::NotProtocol);
        }
        let len = a[1] as usize;
        if len < 4 {
            return Err(ParseError::Malformed);
        }
        let apdu = a.get(2..2 + len).ok_or(ParseError::Truncated)?;
        out.push(apci(apdu, dir)?);
        off += 2 + len;
    }
    Ok(out)
}

fn apci(a: &[u8], dir: Dir) -> PResult<ProtoEvent> {
    let c1 = a[0];
    if c1 & 0x01 == 0 {
        // I-format.
        let asdu = &a[4..];
        let t = byte(asdu, 0)?;
        let cot = byte(asdu, 2)? & 0x3f;
        let negative = byte(asdu, 2)? & 0x40 != 0;
        let ca = u16le(asdu, 4)?;
        let (op, class) = type_id(t);
        let mut e = ProtoEvent::new(Protocol::Iec104, op, t as u32, class).detail("cause", cot);
        e.unit = Some(ca as u32);
        if let Some(ioa) = asdu.get(6..9) {
            e.object = Some(format!("ioa:{}", ioa[0] as u32 | (ioa[1] as u32) << 8 | (ioa[2] as u32) << 16));
        }
        // Activation confirmation / termination come from the outstation.
        e.is_response = matches!(cot, 7 | 10 | 44..=47) || (class == OpClass::Read && cot == 3) || dir == Dir::FromServer;
        e.is_error = negative || (44..=47).contains(&cot);
        Ok(e)
    } else if c1 & 0x03 == 0x01 {
        Ok(ProtoEvent::new(Protocol::Iec104, "supervisory", 1, OpClass::Session))
    } else {
        let (op, class) = match c1 {
            0x07 => ("startdt_act", OpClass::Control),
            0x0b => ("startdt_con", OpClass::Session),
            0x13 => ("stopdt_act", OpClass::Control),
            0x23 => ("stopdt_con", OpClass::Session),
            0x43 => ("testfr_act", OpClass::Session),
            0x83 => ("testfr_con", OpClass::Session),
            _ => return Err(ParseError::Malformed),
        };
        let mut e = ProtoEvent::new(Protocol::Iec104, op, c1 as u32, class);
        e.is_response = op.ends_with("_con");
        Ok(e)
    }
}

/// An I-format APDU with one information object (tests, simulators).
pub fn i_frame(type_id: u8, cot: u8, ca: u16, ioa: u32, element: &[u8]) -> Vec<u8> {
    let mut asdu = vec![type_id, 1, cot, 0];
    asdu.extend_from_slice(&ca.to_le_bytes());
    asdu.extend_from_slice(&ioa.to_le_bytes()[..3]);
    asdu.extend_from_slice(element);
    let mut v = vec![0x68, (4 + asdu.len()) as u8, 0, 0, 0, 0];
    v.extend(asdu);
    v
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_command() -> Vec<u8> {
        i_frame(45, 6, 1, 4001, &[0x01])
    }

    #[test]
    fn classifies_asdus() {
        let e = parse(&sample_command(), Dir::ToServer).unwrap();
        assert_eq!((e[0].operation.as_str(), e[0].class, e[0].object.as_deref(), e[0].unit), ("single_command", OpClass::Control, Some("ioa:4001"), Some(1)));
        let gi = parse(&i_frame(100, 6, 1, 0, &[20]), Dir::ToServer).unwrap();
        assert_eq!(gi[0].class, OpClass::Read);
        let sp = parse(&i_frame(50, 6, 1, 7, &[0, 0, 0x80, 0x3f, 0]), Dir::ToServer).unwrap();
        assert_eq!(sp[0].class, OpClass::Write);
        let mut two = vec![0x68, 4, 0x07, 0, 0, 0];
        two.extend(i_frame(105, 6, 1, 0, &[1]));
        let ev = parse(&two, Dir::ToServer).unwrap();
        assert_eq!((ev[0].operation.as_str(), ev[1].class), ("startdt_act", OpClass::Control));
        let neg = parse(&i_frame(45, 0x47, 1, 1, &[1]), Dir::FromServer).unwrap();
        assert!(neg[0].is_error);
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(parse(&[0x69, 4, 0, 0, 0, 0], Dir::ToServer).unwrap_err(), ParseError::NotProtocol);
        assert_eq!(parse(&[0x68, 2, 0, 0, 0, 0], Dir::ToServer).unwrap_err(), ParseError::Malformed);
        assert_eq!(parse(&[0x68, 4, 0xff, 0, 0, 0], Dir::ToServer).unwrap_err(), ParseError::Malformed);
    }
}
