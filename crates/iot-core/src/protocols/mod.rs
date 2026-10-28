//! Industrial and IoT protocol parser framework (ZTE-IOT "Industrial
//! Protocol Parser Framework", "Modbus/DNP3/BACnet/OPC UA/S7/EtherNet/IP/
//! PROFINET/IEC/MQTT/AMQP/SNMP Visibility", "Protocol Parser Hardening",
//! "Protocol Telemetry"; ZTE-IOT-001199..001208 OT protocol context).
//!
//! Every parser is a pure function over a borrowed payload with explicit
//! length checks, no recursion beyond a fixed depth and no allocation
//! proportional to attacker-controlled fields. Parsers return a
//! [`ProtoEvent`]: the protocol, the operation, its **safety class**
//! (read / write / control / program / firmware / diagnostic / session)
//! and identity hints (vendor, product, firmware, serial) when the protocol
//! carries them. The safety class drives policy: segmentation rules can
//! allow reads while denying writes to a controller.
//!
//! [`identify`] selects a parser by well-known port and, failing that, by
//! payload heuristics, so protocols on non-standard ports are recognised.

pub mod amqp;
pub mod bacnet;
pub mod dnp3;
pub mod enip;
pub mod iec104;
pub mod modbus;
pub mod mqtt;
pub mod opcua;
pub mod profinet;
pub mod s7;
pub mod snmp;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Protocols the collector understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Modbus,
    Dnp3,
    Bacnet,
    S7comm,
    Enip,
    OpcUa,
    Profinet,
    Iec104,
    Mqtt,
    Amqp,
    Snmp,
}

pub const ALL_PROTOCOLS: &[Protocol] = &[
    Protocol::Modbus,
    Protocol::Dnp3,
    Protocol::Bacnet,
    Protocol::S7comm,
    Protocol::Enip,
    Protocol::OpcUa,
    Protocol::Profinet,
    Protocol::Iec104,
    Protocol::Mqtt,
    Protocol::Amqp,
    Protocol::Snmp,
];

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Modbus => "modbus",
            Protocol::Dnp3 => "dnp3",
            Protocol::Bacnet => "bacnet",
            Protocol::S7comm => "s7comm",
            Protocol::Enip => "enip",
            Protocol::OpcUa => "opcua",
            Protocol::Profinet => "profinet",
            Protocol::Iec104 => "iec104",
            Protocol::Mqtt => "mqtt",
            Protocol::Amqp => "amqp",
            Protocol::Snmp => "snmp",
        }
    }
    pub fn parse(s: &str) -> Option<Protocol> {
        ALL_PROTOCOLS.iter().copied().find(|p| p.as_str() == s)
    }
    /// Industrial control protocol (as opposed to IoT messaging/management).
    pub fn is_industrial(&self) -> bool {
        !matches!(self, Protocol::Mqtt | Protocol::Amqp | Protocol::Snmp)
    }
    /// Protocol without authentication or encryption in its common form.
    pub fn is_cleartext(&self) -> bool {
        !matches!(self, Protocol::OpcUa)
    }
    /// Well-known server ports.
    pub fn ports(&self) -> &'static [u16] {
        match self {
            Protocol::Modbus => &[502],
            Protocol::Dnp3 => &[20000],
            Protocol::Bacnet => &[47808],
            Protocol::S7comm => &[102],
            Protocol::Enip => &[44818, 2222],
            Protocol::OpcUa => &[4840, 4843],
            Protocol::Profinet => &[34964],
            Protocol::Iec104 => &[2404],
            Protocol::Mqtt => &[1883, 8883],
            Protocol::Amqp => &[5672, 5671],
            Protocol::Snmp => &[161, 162],
        }
    }
}

/// Safety class of an operation, ordered by potential impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpClass {
    /// Session set-up, keep-alive, browsing, acknowledgements.
    Session,
    /// Reads of process values or device information.
    Read,
    /// Diagnostics without state change.
    Diagnostic,
    /// Writes of process values or set-points.
    Write,
    /// Control commands: start/stop, select/operate, mode change, restart.
    Control,
    /// Logic/program or configuration download/upload.
    Program,
    /// Firmware update.
    Firmware,
}

pub const OP_CLASSES: &[&str] = &["session", "read", "diagnostic", "write", "control", "program", "firmware"];

impl OpClass {
    pub fn as_str(&self) -> &'static str {
        OP_CLASSES[*self as usize]
    }
    /// Changes process or device state.
    pub fn is_modifying(&self) -> bool {
        *self >= OpClass::Write
    }
}

/// Identity details some protocols disclose (device identification).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IdentityHints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl IdentityHints {
    pub fn is_empty(&self) -> bool {
        self.vendor.is_none() && self.product.is_none() && self.firmware.is_none() && self.serial.is_none() && self.name.is_none()
    }
}

/// One decoded protocol operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtoEvent {
    pub protocol: Protocol,
    /// Stable operation key, e.g. `write_multiple_registers`.
    pub operation: String,
    /// Numeric function / service code when the protocol has one.
    pub code: u32,
    pub class: OpClass,
    pub is_response: bool,
    /// Exception / error response.
    pub is_error: bool,
    /// Unit / station / object addressing (e.g. Modbus unit id, DNP3 dest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<u32>,
    /// Data object addressed (register range, object/variation, topic, OID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Numeric values written (bounded), for process-variable baselines.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<i64>,
    #[serde(skip_serializing_if = "IdentityHints::is_empty", default)]
    pub identity: IdentityHints,
    /// Protocol-specific details (bounded).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

impl ProtoEvent {
    pub fn new(protocol: Protocol, operation: &str, code: u32, class: OpClass) -> ProtoEvent {
        ProtoEvent {
            protocol,
            operation: operation.to_string(),
            code,
            class,
            is_response: false,
            is_error: false,
            unit: None,
            object: None,
            values: vec![],
            identity: IdentityHints::default(),
            details: BTreeMap::new(),
        }
    }
    pub fn detail(mut self, k: &str, v: impl ToString) -> ProtoEvent {
        if self.details.len() < 16 {
            let mut v = v.to_string();
            v.truncate(256);
            self.details.insert(k.to_string(), v);
        }
        self
    }
}

/// Stable parser errors (machine-readable codes in telemetry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ParseError {
    #[error("payload truncated")]
    Truncated,
    #[error("not this protocol")]
    NotProtocol,
    #[error("malformed protocol data")]
    Malformed,
    #[error("payload exceeds the parser limit")]
    TooLarge,
}

impl ParseError {
    pub fn code(&self) -> &'static str {
        match self {
            ParseError::Truncated => "truncated",
            ParseError::NotProtocol => "not_protocol",
            ParseError::Malformed => "malformed",
            ParseError::TooLarge => "too_large",
        }
    }
}

pub type PResult<T> = Result<T, ParseError>;

/// Upper bound on bytes any parser inspects.
pub const MAX_PAYLOAD: usize = 8 * 1024;
/// Upper bound on values extracted from one operation.
pub const MAX_VALUES: usize = 32;

pub(crate) fn u16be(b: &[u8], at: usize) -> PResult<u16> {
    b.get(at..at + 2).map(|x| u16::from_be_bytes([x[0], x[1]])).ok_or(ParseError::Truncated)
}
pub(crate) fn u16le(b: &[u8], at: usize) -> PResult<u16> {
    b.get(at..at + 2).map(|x| u16::from_le_bytes([x[0], x[1]])).ok_or(ParseError::Truncated)
}
pub(crate) fn u32le(b: &[u8], at: usize) -> PResult<u32> {
    b.get(at..at + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]])).ok_or(ParseError::Truncated)
}
pub(crate) fn byte(b: &[u8], at: usize) -> PResult<u8> {
    b.get(at).copied().ok_or(ParseError::Truncated)
}
/// Printable ASCII prefix of a byte string (bounded).
pub(crate) fn ascii(b: &[u8], max: usize) -> String {
    b.iter().take(max).take_while(|c| **c != 0).filter(|c| c.is_ascii_graphic() || **c == b' ').map(|c| *c as char).collect::<String>().trim().to_string()
}

/// Direction hint for a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Sent to the server port (request).
    ToServer,
    /// Sent from the server port (response).
    FromServer,
}

/// Parse a payload with a specific protocol parser.
pub fn parse(p: Protocol, payload: &[u8], dir: Dir) -> PResult<Vec<ProtoEvent>> {
    if payload.len() > MAX_PAYLOAD {
        return Err(ParseError::TooLarge);
    }
    match p {
        Protocol::Modbus => modbus::parse(payload, dir),
        Protocol::Dnp3 => dnp3::parse(payload, dir),
        Protocol::Bacnet => bacnet::parse(payload, dir),
        Protocol::S7comm => s7::parse(payload, dir),
        Protocol::Enip => enip::parse(payload, dir),
        Protocol::OpcUa => opcua::parse(payload, dir),
        Protocol::Profinet => profinet::parse_rpc(payload, dir),
        Protocol::Iec104 => iec104::parse(payload, dir),
        Protocol::Mqtt => mqtt::parse(payload, dir),
        Protocol::Amqp => amqp::parse(payload, dir),
        Protocol::Snmp => snmp::parse(payload, dir),
    }
}

/// Protocol of a TCP/UDP payload: by server port first, then by payload
/// signature (protocols on non-standard ports). Returns the protocol and
/// the direction.
pub fn identify(src_port: u16, dst_port: u16, payload: &[u8]) -> Option<(Protocol, Dir)> {
    for p in ALL_PROTOCOLS {
        if p.ports().contains(&dst_port) {
            return Some((*p, Dir::ToServer));
        }
        if p.ports().contains(&src_port) {
            return Some((*p, Dir::FromServer));
        }
    }
    if payload.is_empty() {
        return None;
    }
    // Signatures, cheapest and most specific first.
    if payload.len() >= 3 && payload[0] == 0x05 && payload[1] == 0x64 {
        return Some((Protocol::Dnp3, Dir::ToServer));
    }
    if payload.len() >= 8 && payload[0] == 0x03 && payload[1] == 0x00 && payload.get(7) == Some(&0x32) {
        return Some((Protocol::S7comm, Dir::ToServer));
    }
    if payload.len() >= 4 && &payload[..3] == b"HEL" && payload[3] == b'F' {
        return Some((Protocol::OpcUa, Dir::ToServer));
    }
    if payload.len() >= 8 && payload.starts_with(b"AMQP") {
        return Some((Protocol::Amqp, Dir::ToServer));
    }
    if payload.len() >= 4 && payload[0] == 0x81 && matches!(payload[1], 0x0a | 0x0b | 0x04) {
        return Some((Protocol::Bacnet, Dir::ToServer));
    }
    if payload.len() >= 6 && payload[0] == 0x68 && payload[1] as usize + 2 == payload.len() {
        return Some((Protocol::Iec104, Dir::ToServer));
    }
    if payload.len() >= 8 && u16be(payload, 2).ok() == Some(0) && u16be(payload, 4).ok().map(|l| l as usize + 6 == payload.len()).unwrap_or(false) {
        return Some((Protocol::Modbus, Dir::ToServer));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::XorShift;

    #[test]
    fn identifies_by_port_and_signature() {
        assert_eq!(identify(50000, 502, &[]), Some((Protocol::Modbus, Dir::ToServer)));
        assert_eq!(identify(102, 50000, &[]), Some((Protocol::S7comm, Dir::FromServer)));
        assert_eq!(identify(1, 15020, &[0x05, 0x64, 0x05, 0xc9, 1, 0, 2, 0]).map(|x| x.0), Some(Protocol::Dnp3));
        assert_eq!(identify(1, 15502, &[0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 2]).map(|x| x.0), Some(Protocol::Modbus));
        assert_eq!(identify(1, 9999, b"hello world"), None);
    }

    #[test]
    fn op_classes_order_by_impact() {
        assert!(OpClass::Firmware > OpClass::Program && OpClass::Program > OpClass::Control && OpClass::Control > OpClass::Write && OpClass::Write > OpClass::Read);
        assert!(OpClass::Write.is_modifying() && !OpClass::Diagnostic.is_modifying());
        assert_eq!(OpClass::Program.as_str(), "program");
        assert_eq!(Protocol::parse("opcua"), Some(Protocol::OpcUa));
    }

    /// Every parser survives 5000 mutated and random inputs each without
    /// panicking, and never returns more than the bounded number of events.
    #[test]
    fn all_parsers_are_fuzz_safe() {
        let seeds: Vec<(Protocol, Vec<u8>)> = vec![
            (Protocol::Modbus, modbus::tests::sample_write()),
            (Protocol::Dnp3, dnp3::tests::sample_operate()),
            (Protocol::Bacnet, bacnet::tests::sample_write_property()),
            (Protocol::S7comm, s7::tests::sample_stop()),
            (Protocol::Enip, enip::tests::sample_list_identity_reply()),
            (Protocol::OpcUa, opcua::tests::sample_hello()),
            (Protocol::Profinet, vec![0x04, 0x00, 0x20, 0x00]),
            (Protocol::Iec104, iec104::tests::sample_command()),
            (Protocol::Mqtt, mqtt::tests::sample_publish()),
            (Protocol::Amqp, b"AMQP\x00\x00\x09\x01".to_vec()),
            (Protocol::Snmp, snmp::tests::sample_set()),
        ];
        let mut rng = XorShift(0xdecaf);
        for (p, seed) in &seeds {
            assert!(parse(*p, seed, Dir::ToServer).is_ok(), "{p:?} sample parses");
            for _ in 0..5000 {
                let input = rng.mutate(seed);
                if let Ok(ev) = parse(*p, &input, Dir::ToServer) {
                    assert!(ev.len() <= 64);
                    for e in &ev {
                        assert!(e.values.len() <= MAX_VALUES);
                    }
                }
                let _ = parse(*p, &input, Dir::FromServer);
            }
        }
        assert_eq!(parse(Protocol::Modbus, &vec![0u8; MAX_PAYLOAD + 1], Dir::ToServer).unwrap_err(), ParseError::TooLarge);
    }
}
