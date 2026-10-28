//! S7comm over ISO-on-TCP (TPKT + COTP) — ZTE-IOT "S7 Visibility"
//! (section 44), PLC assets (section 29).
//!
//! Job functions are classified: read/write variable, block download and
//! upload (program), PLC control/stop (control), communication set-up
//! (session). User-data functions are classified by group: programmer
//! commands (program), block info (read), CPU functions / system status
//! lists (diagnostic; module identification responses disclose the order
//! number), security (session) and clock set (write).

use super::*;

fn job(fc: u8) -> (&'static str, OpClass) {
    match fc {
        0x04 => ("read_var", OpClass::Read),
        0x05 => ("write_var", OpClass::Write),
        0x1a => ("request_download", OpClass::Program),
        0x1b => ("download_block", OpClass::Program),
        0x1c => ("download_ended", OpClass::Program),
        0x1d => ("start_upload", OpClass::Program),
        0x1e => ("upload", OpClass::Program),
        0x1f => ("end_upload", OpClass::Program),
        0x28 => ("plc_control", OpClass::Control),
        0x29 => ("plc_stop", OpClass::Control),
        0xf0 => ("setup_communication", OpClass::Session),
        _ => ("unknown_job", OpClass::Control),
    }
}

pub fn parse(b: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    let mut out = vec![];
    let mut off = 0;
    while off < b.len() && out.len() < 16 {
        let t = &b[off..];
        if t.len() < 7 {
            return if out.is_empty() { Err(ParseError::Truncated) } else { Ok(out) };
        }
        if t[0] != 0x03 || t[1] != 0x00 {
            return Err(ParseError::NotProtocol);
        }
        let len = u16be(t, 2)? as usize;
        if len < 7 || len > t.len() {
            return Err(if len > t.len() { ParseError::Truncated } else { ParseError::Malformed });
        }
        out.push(tpdu(&t[4..len], dir)?);
        off += len;
    }
    Ok(out)
}

fn tpdu(c: &[u8], dir: Dir) -> PResult<ProtoEvent> {
    let li = byte(c, 0)? as usize;
    let kind = byte(c, 1)? & 0xf0;
    match kind {
        0xe0 | 0xd0 => {
            let mut e = ProtoEvent::new(Protocol::S7comm, if kind == 0xe0 { "cotp_connect_request" } else { "cotp_connect_confirm" }, kind as u32, OpClass::Session);
            e.is_response = kind == 0xd0;
            // Parameters: 0xc1 calling TSAP, 0xc2 called TSAP.
            let mut p = 7;
            while p + 2 <= li + 1 && p + 2 <= c.len() {
                let (code, plen) = (c[p], c[p + 1] as usize);
                if let Some(v) = c.get(p + 2..p + 2 + plen) {
                    if code == 0xc2 && plen == 2 {
                        e = e.detail("called_tsap", format!("{:02x}{:02x}", v[0], v[1]));
                        // Rack/slot from the called TSAP low byte.
                        e.unit = Some(v[1] as u32);
                    }
                }
                p += 2 + plen;
            }
            Ok(e)
        }
        0xf0 => {
            let s = c.get(li + 1..).ok_or(ParseError::Truncated)?;
            s7pdu(s, dir)
        }
        0x80 => Ok(ProtoEvent::new(Protocol::S7comm, "cotp_disconnect", kind as u32, OpClass::Session)),
        _ => Err(ParseError::Malformed),
    }
}

fn s7pdu(s: &[u8], dir: Dir) -> PResult<ProtoEvent> {
    if byte(s, 0)? != 0x32 {
        return Err(ParseError::NotProtocol);
    }
    let rosctr = byte(s, 1)?;
    let plen = u16be(s, 6)? as usize;
    let dlen = u16be(s, 8)? as usize;
    let hdr = if matches!(rosctr, 2 | 3) { 12 } else { 10 };
    let params = s.get(hdr..hdr + plen).ok_or(ParseError::Truncated)?;
    let data = s.get(hdr + plen..(hdr + plen + dlen).min(s.len())).unwrap_or(&[]);
    match rosctr {
        1..=3 => {
            let fc = byte(params, 0)?;
            let (op, class) = job(fc);
            let mut e = ProtoEvent::new(Protocol::S7comm, op, fc as u32, class).detail("rosctr", rosctr);
            e.is_response = rosctr != 1 || dir == Dir::FromServer;
            if rosctr == 3 || rosctr == 2 {
                let (ec, code) = (byte(s, 10)?, byte(s, 11)?);
                e.is_error = ec != 0 || code != 0;
            }
            if fc == 0x04 || fc == 0x05 {
                e = e.detail("items", byte(params, 1).unwrap_or(0));
                if let Some(area) = params.get(2..14).and_then(|item| item.get(8)) {
                    e.object = Some(
                        match area {
                            0x81 => "inputs",
                            0x82 => "outputs",
                            0x83 => "flags",
                            0x84 => "data_blocks",
                            0x1c => "counters",
                            0x1d => "timers",
                            _ => "other",
                        }
                        .to_string(),
                    );
                }
            }
            if fc == 0x28 {
                // PI service name, e.g. "P_PROGRAM" (start) or "_INSE" (insert block).
                let name = ascii(params.get(params.len().saturating_sub(16)..).unwrap_or(&[]), 16);
                if !name.is_empty() {
                    e = e.detail("pi_service", name);
                }
            }
            Ok(e)
        }
        7 => {
            if params.len() < 8 || params[0..3] != [0x00, 0x01, 0x12] {
                return Err(ParseError::Malformed);
            }
            let tg = params[5];
            let (ty, group) = (tg >> 4, tg & 0x0f);
            let sub = params[6];
            let (op, class) = match (group, sub) {
                (1, _) => ("programmer_command", OpClass::Program),
                (2, _) => ("cyclic_data", OpClass::Read),
                (3, _) => ("block_info", OpClass::Read),
                (4, 1) => ("read_szl", OpClass::Diagnostic),
                (4, _) => ("cpu_function", OpClass::Diagnostic),
                (5, _) => ("security", OpClass::Session),
                (7, 2) => ("set_clock", OpClass::Write),
                (7, _) => ("read_clock", OpClass::Read),
                _ => ("userdata", OpClass::Diagnostic),
            };
            let mut e = ProtoEvent::new(Protocol::S7comm, op, ((group as u32) << 8) | sub as u32, class).detail("rosctr", 7);
            e.is_response = ty == 8 || dir == Dir::FromServer;
            if group == 4 && e.is_response {
                // Module identification: the longest printable run is the order number.
                let mut best = String::new();
                for run in data.split(|c| !(c.is_ascii_graphic() || *c == b' ')) {
                    let s = String::from_utf8_lossy(run).trim().to_string();
                    if s.len() >= 10 && s.len() > best.len() {
                        best = s.chars().take(40).collect();
                    }
                }
                if !best.is_empty() {
                    e.identity.product = Some(best);
                }
            }
            Ok(e)
        }
        _ => Err(ParseError::Malformed),
    }
}

/// Build a TPKT/COTP-DT/S7 job PDU (tests, simulators).
pub fn job_pdu(fc: u8, extra_params: &[u8]) -> Vec<u8> {
    let mut params = vec![fc];
    params.extend_from_slice(extra_params);
    let mut s7 = vec![0x32, 0x01, 0, 0, 0, 1];
    s7.extend_from_slice(&(params.len() as u16).to_be_bytes());
    s7.extend_from_slice(&0u16.to_be_bytes());
    s7.extend_from_slice(&params);
    let mut v = vec![0x03, 0x00, 0, 0, 0x02, 0xf0, 0x80];
    v.extend_from_slice(&s7);
    let l = v.len() as u16;
    v[2..4].copy_from_slice(&l.to_be_bytes());
    v
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_stop() -> Vec<u8> {
        let mut p = vec![0, 0, 0, 0, 0, 9];
        p.extend_from_slice(b"P_PROGRAM");
        job_pdu(0x29, &p)
    }

    #[test]
    fn classifies_jobs() {
        let stop = parse(&sample_stop(), Dir::ToServer).unwrap();
        assert_eq!((stop[0].operation.as_str(), stop[0].class), ("plc_stop", OpClass::Control));
        let w = parse(&job_pdu(0x05, &[1, 0x12, 0x0a, 0x10, 0x02, 0, 1, 0, 1, 0x84, 0, 0, 0]), Dir::ToServer).unwrap();
        assert_eq!((w[0].class, w[0].object.as_deref()), (OpClass::Write, Some("data_blocks")));
        let dl = parse(&job_pdu(0x1a, &[0; 8]), Dir::ToServer).unwrap();
        assert_eq!(dl[0].class, OpClass::Program);
        let setup = parse(&job_pdu(0xf0, &[0, 0, 1, 0, 1, 1, 0xe0]), Dir::ToServer).unwrap();
        assert_eq!(setup[0].class, OpClass::Session);
    }

    #[test]
    fn cotp_connect_and_userdata() {
        let cr = [0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0, 0, 0, 1, 0, 0xc1, 2, 1, 0, 0xc2, 2, 1, 2, 0xc0, 1, 0x0a];
        let e = parse(&cr, Dir::ToServer).unwrap();
        assert_eq!((e[0].operation.as_str(), e[0].unit), ("cotp_connect_request", Some(2)));
        // Userdata SZL read request.
        let params = [0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00];
        let mut s7 = vec![0x32, 0x07, 0, 0, 0, 1, 0, params.len() as u8, 0, 0];
        s7.extend_from_slice(&params);
        let mut v = vec![0x03, 0x00, 0, 0, 0x02, 0xf0, 0x80];
        v.extend(s7);
        let l = v.len() as u16;
        v[2..4].copy_from_slice(&l.to_be_bytes());
        let e = parse(&v, Dir::ToServer).unwrap();
        assert_eq!((e[0].operation.as_str(), e[0].class), ("read_szl", OpClass::Diagnostic));
    }

    #[test]
    fn rejects_non_s7() {
        assert_eq!(parse(&[0x04, 0, 0, 7, 2, 0xf0, 0x80], Dir::ToServer).unwrap_err(), ParseError::NotProtocol);
        let mut v = job_pdu(0x04, &[1]);
        v[7] = 0x33;
        assert_eq!(parse(&v, Dir::ToServer).unwrap_err(), ParseError::NotProtocol);
    }
}
