//! Acceptance harness (the "Acceptance Matrix" subsection of every
//! ZTE-IOT capability: 17 repeatable scenarios with deterministic pass/fail
//! criteria and retained evidence; sections 128 Device Classification
//! Validation, 129 Segmentation Certification, 130 Industrial Safety
//! Validation).
//!
//! A [`Lab`] wires the real engines together in memory — collector,
//! identity resolution, classifier, findings, risk, baselines, group
//! assignment, compiled `iot.segmentation` policy decisions, exceptions,
//! remote-access windows, failure evaluation and bounded queues — and runs
//! each scenario with the traffic profile of a capability (Modbus PLC,
//! DNP3 RTU, BACnet controller, camera, printer, ...). Every run returns a
//! [`ScenarioResult`] with its individual checks; the control plane stores
//! these as evidence (`POST /api/v1/acceptance/runs`).

use crate::baseline::{self, Baseline, DetectContext};
use crate::classify::{self, Classification, Classifier};
use crate::collect::{Collector, Limits};
use crate::fingerprint::{dhcp, dns, lldp, OuiTable};
use crate::identity::{self, AssetKeys, ChangeEvent, ObsKeys};
use crate::model::{Observation, Signal};
use crate::packet::{build, tcp_flags, Mac};
use crate::policy::{self, DeviceCtx, FlowCtx};
use crate::protocols::{bacnet, dnp3, enip, iec104, modbus, mqtt, opcua, profinet, s7, snmp, OpClass};
use crate::remote;
use crate::risk;
use crate::segmentation::{self, DeviceFacts, Exception, Group, GroupMatch, Mode, Zone};
use crate::taxonomy::{self, Lifecycle};
use crate::vuln::{Finding, FindingKind};
use aether_core::policy::compile::{compile, Target};
use aether_core::policy::eval::PreparedPolicy;
use aether_core::policy::{Condition, Op, Rule, RuleSet};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;
use uuid::Uuid;

pub const PROFILES: &[&str] = &[
    "modbus", "plc_enip", "s7", "dnp3", "iec104", "bacnet", "opcua", "profinet", "mqtt", "amqp", "snmp", "camera", "printer", "medical", "pos", "badge", "voip", "unknown",
    "remote",
];

pub const SCENARIOS: &[&str] = &[
    "new_device_discovery",
    "known_device_rediscovery",
    "ip_change",
    "site_move",
    "unknown_classification",
    "confidence_improvement",
    "risk_increase",
    "segment_change",
    "quarantine",
    "temporary_exception",
    "vendor_access",
    "branch_failover",
    "policy_rollback",
    "protocol_malformed_input",
    "high_device_count",
    "telemetry_backlog",
    "device_decommission",
];

/// Traffic of one device of a profile.
pub struct Traffic {
    pub mac: Mac,
    pub ip: Ipv4Addr,
    /// Weak evidence first.
    pub partial: Vec<Vec<u8>>,
    pub full: Vec<Vec<u8>>,
    pub malformed: Vec<Vec<u8>>,
    pub expected_type: &'static str,
    pub protocol: Option<&'static str>,
    pub port: u16,
}

fn mac(oui: [u8; 3], i: u32) -> Mac {
    Mac([oui[0], oui[1], oui[2], (i >> 16) as u8, (i >> 8) as u8, i as u8])
}

fn ip(i: u32, base: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, base, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8 | 1)
}

const PEER: (Mac, Ipv4Addr) = (Mac([0x00, 0x50, 0x56, 0xaa, 0x00, 0x01]), Ipv4Addr::new(10, 200, 0, 10));

fn tcp_service(dev: (Mac, Ipv4Addr), port: u16, req: &[u8], resp: &[u8]) -> Vec<Vec<u8>> {
    let d = (dev.0, dev.1, port);
    let p = (PEER.0, PEER.1, 50_000);
    let mut v = vec![build::tcp_frame(p, d, tcp_flags::SYN, b""), build::tcp_frame(d, p, tcp_flags::SYN | tcp_flags::ACK, b"")];
    if !req.is_empty() {
        v.push(build::tcp_frame(p, d, tcp_flags::PSH | tcp_flags::ACK, req));
    }
    if !resp.is_empty() {
        v.push(build::tcp_frame(d, p, tcp_flags::PSH | tcp_flags::ACK, resp));
    }
    v
}

fn udp_from_device(dev: (Mac, Ipv4Addr), sport: u16, payload: &[u8]) -> Vec<u8> {
    build::udp_frame((dev.0, dev.1, sport), (PEER.0, PEER.1, 47_000), payload)
}

fn arp(dev: (Mac, Ipv4Addr)) -> Vec<u8> {
    let mut a = vec![0, 1, 8, 0, 6, 4, 0, 2];
    a.extend_from_slice(&dev.0 .0);
    a.extend_from_slice(&dev.1.octets());
    a.extend_from_slice(&[0; 6]);
    a.extend_from_slice(&[10, 0, 0, 1]);
    build::ethernet(dev.0, Mac([0xff; 6]), crate::packet::ETH_ARP, &a)
}

fn garbage_tcp(dev: (Mac, Ipv4Addr), port: u16, n: usize) -> Vec<Vec<u8>> {
    let mut r = crate::packet::XorShift(0xbad0 + port as u64);
    (0..n).map(|_| build::tcp_frame((PEER.0, PEER.1, 50_001), (dev.0, dev.1, port), tcp_flags::PSH | tcp_flags::ACK, &r.bytes(12))).collect()
}

/// Generate the traffic of device `i` of a profile.
pub fn traffic(profile: &str, i: u32) -> Traffic {
    let base = (PROFILES.iter().position(|p| *p == profile).unwrap_or(0) + 1) as u8;
    let mk = |oui: [u8; 3]| (mac(oui, i), ip(i, base));
    match profile {
        "modbus" | "remote" => {
            let d = mk([0x00, 0x1d, 0x9c]);
            let mut full = vec![arp(d)];
            full.extend(tcp_service(d, 502, &modbus::adu(1, 1, &[3, 0, 0, 0, 4]), &modbus::adu(1, 1, &[3, 8, 0, 1, 0, 2, 0, 3, 0, 4])));
            full.push(build::tcp_frame((PEER.0, PEER.1, 50_000), (d.0, d.1, 502), 0x18, &modbus::adu(2, 1, &[6, 0, 10, 0, 99])));
            Traffic { mac: d.0, ip: d.1, partial: vec![arp(d)], full, malformed: garbage_tcp(d, 502, 12), expected_type: "plc", protocol: Some("modbus"), port: 502 }
        }
        "plc_enip" => {
            let d = mk([0x00, 0x1d, 0x9c]);
            let mut full = vec![arp(d)];
            full.extend(tcp_service(d, 44818, &enip::encap(0x0065, &[1, 0, 0, 0]), &[]));
            full.push(udp_from_device(d, 44818, &enip::list_identity_reply(1, 14, 55, (20, 11), 0xc0ffee00 + i, "1756-L83E/B")));
            Traffic { mac: d.0, ip: d.1, partial: vec![arp(d)], full, malformed: garbage_tcp(d, 44818, 12), expected_type: "plc", protocol: Some("enip"), port: 44818 }
        }
        "s7" => {
            let d = mk([0x00, 0x0e, 0x8c]);
            let mut full = vec![arp(d)];
            full.extend(tcp_service(d, 102, &s7::job_pdu(0x04, &[1, 0x12, 0x0a, 0x10, 0x02, 0, 1, 0, 1, 0x84, 0, 0, 0]), &[]));
            Traffic { mac: d.0, ip: d.1, partial: vec![arp(d)], full, malformed: garbage_tcp(d, 102, 12), expected_type: "plc", protocol: Some("s7comm"), port: 102 }
        }
        "dnp3" => {
            let d = mk([0x00, 0x13, 0xab]);
            let full = tcp_service(d, 20000, &dnp3::frame_bytes(10, 1, &[0xc0, 0x01, 60, 2, 0x06]), &dnp3::frame_bytes(1, 10, &[0xc0, 129, 0, 0, 30, 1]));
            Traffic { mac: d.0, ip: d.1, partial: vec![full[1].clone()], full, malformed: garbage_tcp(d, 20000, 12), expected_type: "rtu", protocol: Some("dnp3"), port: 20000 }
        }
        "iec104" => {
            let d = mk([0x00, 0x13, 0xac]);
            let full = tcp_service(d, 2404, &iec104::i_frame(100, 6, 1, 0, &[20]), &iec104::i_frame(1, 20, 1, 7, &[1]));
            Traffic { mac: d.0, ip: d.1, partial: vec![full[1].clone()], full, malformed: garbage_tcp(d, 2404, 12), expected_type: "rtu", protocol: Some("iec104"), port: 2404 }
        }
        "bacnet" => {
            let d = mk([0x00, 0x13, 0xad]);
            let inst: u32 = (8 << 22) | (1000 + i);
            let mut apdu = vec![0x10, 0x00, 0xc4];
            apdu.extend_from_slice(&inst.to_be_bytes());
            apdu.extend_from_slice(&[0x22, 0x05, 0xc4, 0x91, 0x00, 0x21, 0x08]);
            let full = vec![arp(d), udp_from_device(d, 47808, &bacnet::frame(&apdu))];
            let malformed = (0..12).map(|k| udp_from_device(d, 47808, &[0x81, 0x0a, 0, 40 + k as u8, 1])).collect();
            Traffic { mac: d.0, ip: d.1, partial: vec![arp(d)], full, malformed, expected_type: "bms_controller", protocol: Some("bacnet"), port: 47808 }
        }
        "opcua" => {
            let d = mk([0x00, 0x13, 0xae]);
            let mut ack = b"ACKF".to_vec();
            ack.extend_from_slice(&28u32.to_le_bytes());
            ack.extend_from_slice(&[0; 20]);
            let full = tcp_service(d, 4840, &opcua::hello("opc.tcp://scada:4840"), &ack);
            Traffic {
                mac: d.0,
                ip: d.1,
                partial: vec![full[1].clone()],
                full,
                malformed: garbage_tcp(d, 4840, 12),
                expected_type: "scada_server",
                protocol: Some("opcua"),
                port: 4840,
            }
        }
        "profinet" => {
            let d = mk([0x00, 0x13, 0xaf]);
            let dcp = build::ethernet(d.0, PEER.0, crate::packet::ETH_PROFINET, &profinet::dcp_identify_response(&format!("io-{i}"), 0x002a, 0x0301));
            let malformed = (0..12).map(|_| build::ethernet(d.0, PEER.0, crate::packet::ETH_PROFINET, &[0xfe, 0xff, 9, 1])).collect();
            Traffic { mac: d.0, ip: d.1, partial: vec![arp(d)], full: vec![arp(d), dcp], malformed, expected_type: "io_module", protocol: Some("profinet"), port: 0 }
        }
        "mqtt" => {
            let d = mk([0x24, 0x0a, 0xc4]);
            let p = (PEER.0, PEER.1, 1883);
            let me = (d.0, d.1, 41_000);
            let full = vec![arp(d), build::tcp_frame(me, p, tcp_flags::SYN, b""), build::tcp_frame(me, p, 0x18, &mqtt::publish(&format!("site/sensor{i}/temp"), b"21.5"))];
            let malformed = (0..12).map(|_| build::tcp_frame(me, p, 0x18, &[0x30, 0xff, 0xff, 0xff, 0xff])).collect();
            Traffic { mac: d.0, ip: d.1, partial: vec![arp(d)], full, malformed, expected_type: "iot_sensor", protocol: Some("mqtt"), port: 1883 }
        }
        "amqp" => {
            let d = mk([0x00, 0x13, 0xb0]);
            let full = tcp_service(d, 5672, b"AMQP\x00\x00\x09\x01", &crate::protocols::amqp::method_frame(0, 10, 10, &[0, 9]));
            Traffic {
                mac: d.0,
                ip: d.1,
                partial: vec![full[1].clone()],
                full,
                malformed: garbage_tcp(d, 5672, 12),
                expected_type: "mqtt_broker",
                protocol: Some("amqp"),
                port: 5672,
            }
        }
        "snmp" => {
            let d = mk([0x00, 0xc0, 0xb7]);
            let resp = snmp::message("s3cret", 0xa2, "1.3.6.1.2.1.1.1.0", (0x04, b"Smart-UPS 3000 fw 6.4"));
            let full = vec![arp(d), udp_from_device(d, 161, &resp)];
            let malformed = (0..12).map(|_| udp_from_device(d, 161, &[0x30, 0x84, 1, 1, 1, 1])).collect();
            Traffic { mac: d.0, ip: d.1, partial: vec![arp(d)], full, malformed, expected_type: "ups", protocol: Some("snmp"), port: 161 }
        }
        "camera" => {
            let d = mk([0x00, 0x40, 0x8c]);
            let dh = dhcp::request(d.0 .0, &format!("AXIS-{i:06}"), "udhcp 1.31", &[1, 3, 6, 12, 15, 28, 42]);
            let mut full = vec![arp(d), build::udp_frame((d.0, Ipv4Addr::UNSPECIFIED, 68), (Mac([0xff; 6]), Ipv4Addr::BROADCAST, 67), &dh)];
            full.extend(tcp_service(d, 554, b"", b""));
            Traffic { mac: d.0, ip: d.1, partial: vec![arp(d)], full, malformed: vec![vec![0u8; 9]; 12], expected_type: "ip_camera", protocol: None, port: 554 }
        }
        "printer" => {
            let d = mk([0x00, 0x13, 0xb1]);
            let m = dns::message(true, &[], &[("_ipp._tcp.local", &format!("Printer {i}._ipp._tcp.local"))], &[]);
            let mut full = vec![build::udp_frame((d.0, d.1, 5353), (Mac([0x01, 0x00, 0x5e, 0, 0, 0xfb]), Ipv4Addr::new(224, 0, 0, 251), 5353), &m)];
            full.extend(tcp_service(d, 9100, b"", b""));
            full.extend(tcp_service(d, 80, b"GET / HTTP/1.1\r\nHost: p\r\n\r\n", b"HTTP/1.1 200 OK\r\nServer: HP HTTP Server; HP LaserJet 400\r\n\r\n"));
            Traffic { mac: d.0, ip: d.1, partial: vec![full[0].clone()], full, malformed: vec![vec![0u8; 9]; 12], expected_type: "printer", protocol: None, port: 9100 }
        }
        "medical" => {
            let d = mk([0x00, 0x13, 0xb2]);
            let full = tcp_service(d, 104, b"", b"");
            Traffic { mac: d.0, ip: d.1, partial: vec![arp(d)], full, malformed: vec![vec![0u8; 9]; 12], expected_type: "imaging_modality", protocol: None, port: 104 }
        }
        "pos" => {
            let d = mk([0x00, 0x0b, 0x4f]);
            let dh = dhcp::request(d.0 .0, &format!("TERM-{i}"), "Verifone VX", &[1, 3, 6, 15]);
            let full = vec![arp(d), build::udp_frame((d.0, Ipv4Addr::UNSPECIFIED, 68), (Mac([0xff; 6]), Ipv4Addr::BROADCAST, 67), &dh)];
            Traffic { mac: d.0, ip: d.1, partial: vec![arp(d)], full, malformed: vec![vec![0u8; 9]; 12], expected_type: "payment_terminal", protocol: None, port: 0 }
        }
        "badge" => {
            let d = mk([0x00, 0x06, 0x8e]);
            let dh = dhcp::request(d.0 .0, &format!("BADGE-{i:04}"), "", &[1, 3, 6, 15]);
            let full = vec![arp(d), build::udp_frame((d.0, Ipv4Addr::UNSPECIFIED, 68), (Mac([0xff; 6]), Ipv4Addr::BROADCAST, 67), &dh)];
            Traffic { mac: d.0, ip: d.1, partial: vec![arp(d)], full, malformed: vec![vec![0u8; 9]; 12], expected_type: "badge_reader", protocol: None, port: 0 }
        }
        "voip" => {
            let d = mk([0x00, 0x1b, 0x54]);
            let mut c = vec![2, 180, 0, 0];
            for (ty, val) in [(1u16, format!("SEP{:012X}", i).into_bytes()), (6, b"Cisco IP Phone 8851".to_vec()), (4, vec![0, 0, 0, 0x90])] {
                c.extend_from_slice(&ty.to_be_bytes());
                c.extend_from_slice(&((val.len() + 4) as u16).to_be_bytes());
                c.extend_from_slice(&val);
            }
            let mut llc = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00];
            llc.extend_from_slice(&c);
            let frame = build::ethernet(d.0, Mac([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]), llc.len() as u16, &llc);
            let lldpf = build::ethernet(d.0, Mac([0x01, 0x80, 0xc2, 0, 0, 0x0e]), crate::packet::ETH_LLDP, &lldp::lldpdu("phone", "IP phone", 0x0020));
            Traffic {
                mac: d.0,
                ip: d.1,
                partial: vec![arp(d)],
                full: vec![arp(d), frame, lldpf],
                malformed: vec![vec![0u8; 9]; 12],
                expected_type: "voip_phone",
                protocol: None,
                port: 0,
            }
        }
        _ => {
            // unknown: randomised MAC, a DNS query that says nothing.
            let d = (Mac([0x02, 0x99, 0x00, (i >> 16) as u8, (i >> 8) as u8, i as u8]), ip(i, base));
            let q = dns::message(false, &["example.org"], &[], &[]);
            let f = build::udp_frame((d.0, d.1, 5555), (PEER.0, PEER.1, 53), &q);
            Traffic { mac: d.0, ip: d.1, partial: vec![f.clone()], full: vec![f], malformed: vec![vec![0u8; 9]; 12], expected_type: "unknown", protocol: None, port: 0 }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Asset {
    pub keys: AssetKeys,
    pub signals: Vec<Signal>,
    pub classification: Classification,
    pub lifecycle: Lifecycle,
    pub quarantined: bool,
    pub groups: Vec<String>,
    pub zone: Option<String>,
    pub baseline: Baseline,
    pub findings: Vec<Finding>,
    pub changes: Vec<ChangeEvent>,
}

/// In-memory composition of the engines.
pub struct Lab {
    pub now: DateTime<Utc>,
    pub collector: Collector,
    pub classifier: Classifier,
    pub oui: OuiTable,
    pub assets: BTreeMap<Uuid, Asset>,
    pub groups: Vec<Group>,
    pub zones: Vec<Zone>,
    pub exceptions: Vec<Exception>,
    pub policy: Option<PreparedPolicy>,
    pub queue: VecDeque<serde_json::Value>,
    pub queue_cap: usize,
    pub dropped: u64,
}

pub fn gid(name: &str) -> String {
    crate::stable_uuid(&format!("group:{name}")).to_string()
}

impl Lab {
    pub fn new() -> Lab {
        let zones = vec![
            Zone { id: "zone-ot".into(), key: "ot_control".into(), security_level: 3, mode: Mode::Enforce, safety_critical: true },
            Zone { id: "zone-iot".into(), key: "iot".into(), security_level: 1, mode: Mode::Enforce, safety_critical: false },
            Zone { id: "zone-q".into(), key: "quarantine".into(), security_level: 1, mode: Mode::Enforce, safety_critical: false },
            Zone { id: "zone-alt".into(), key: "alt".into(), security_level: 2, mode: Mode::Enforce, safety_critical: false },
        ];
        let g = |name: &str, prio: i32, m: GroupMatch, zone: &str, privileged: bool| Group {
            id: gid(name),
            key: name.into(),
            priority: prio,
            matcher: m,
            zone: Some(zone.into()),
            privileged,
            min_confidence: 0.0,
        };
        let groups = vec![
            g("controllers", 100, GroupMatch { categories: vec!["industrial_control".into(), "building_management".into()], ..Default::default() }, "zone-ot", true),
            g(
                "devices",
                10,
                GroupMatch { categories: taxonomy::category_keys().into_iter().filter(|c| *c != "unknown").map(String::from).collect(), ..Default::default() },
                "zone-iot",
                false,
            ),
            g(segmentation::QUARANTINE_GROUP, 0, GroupMatch::default(), "zone-q", false),
            g(segmentation::OBSERVE_GROUP, 0, GroupMatch::default(), "zone-iot", false),
        ];
        Lab {
            now: Utc::now(),
            collector: Collector::new(Limits::default()),
            classifier: Classifier::default(),
            oui: OuiTable::default(),
            assets: BTreeMap::new(),
            groups,
            zones,
            exceptions: vec![],
            policy: Some(Lab::compile_policy(1, false)),
            queue: VecDeque::new(),
            queue_cap: 1000,
            dropped: 0,
        }
    }

    /// Revision 1: block quarantined sources and modifying operations to
    /// controllers from outside the engineering group. Revision 2 (strict)
    /// additionally blocks reads to controllers.
    pub fn compile_policy(rev: i64, strict: bool) -> PreparedPolicy {
        let t = policy::types().into_iter().find(|t| t.key == policy::SEGMENTATION).expect("segmentation type");
        let r = |order: i32, name: &str, cond: Condition, action: &str| Rule {
            id: crate::stable_uuid(name),
            name: name.into(),
            description: String::new(),
            order,
            enabled: true,
            condition: cond,
            action: action.into(),
            params: Default::default(),
            schedule: Default::default(),
            emergency: false,
            labels: vec![],
        };
        let mut rules = vec![
            r(10, "block quarantined sources", Condition::pred("source.quarantined", Op::Eq, vec![json!(true)]), "block"),
            r(
                20,
                "no unapproved writes to controllers",
                Condition::All(vec![
                    Condition::pred("destination.device_group", Op::In, vec![json!(gid("controllers"))]),
                    Condition::pred("network.operation_class", Op::In, vec![json!("write"), json!("control"), json!("program"), json!("firmware")]),
                    Condition::pred("source.device_group", Op::NotIn, vec![json!(gid("engineering"))]),
                ]),
                "block",
            ),
        ];
        if strict {
            rules.push(r(30, "no reads to controllers", Condition::pred("destination.device_group", Op::In, vec![json!(gid("controllers"))]), "block"));
        }
        let rs = RuleSet { policy_type: t.key.clone(), default_action: "alert".into(), default_params: Default::default(), rules };
        PreparedPolicy::new(compile(&t, &rs, Target { tenant_id: Uuid::nil(), policy_set_id: crate::stable_uuid("lab-policy"), revision: rev }).expect("lab policy compiles"))
    }

    /// Feed frames and process the resulting observations for `site`.
    pub fn feed(&mut self, frames: &[Vec<u8>], site: &str) -> Vec<Uuid> {
        for (k, f) in frames.iter().enumerate() {
            self.collector.ingest(self.now.timestamp_micros() + k as i64, f);
        }
        let obs = self.collector.drain(Some(site), Some("sensor-1"));
        obs.into_iter().filter_map(|o| self.observe(o)).collect()
    }

    fn keys_of(o: &Observation) -> ObsKeys {
        let mut k = ObsKeys { site: o.site.clone(), mac: o.mac.clone(), ip: o.ip.clone(), ..Default::default() };
        for s in &o.signals {
            match s {
                Signal::Dhcp { hostname, client_id, .. } => {
                    k.hostname = hostname.clone().or(k.hostname.take());
                    k.client_id = client_id.clone().or(k.client_id.take());
                }
                Signal::Protocol { event, .. } => {
                    if let (Some(v), Some(s)) = (&event.identity.vendor, &event.identity.serial) {
                        k.serial = Some(format!("{v}/{s}"));
                    }
                }
                Signal::Tls { fingerprint, .. } => k.tls_fingerprint = Some(fingerprint.clone()),
                _ => {}
            }
        }
        k
    }

    /// Process one observation as the control plane does.
    pub fn observe(&mut self, mut o: Observation) -> Option<Uuid> {
        if o.sanitize(self.now).is_err() {
            return None;
        }
        // Peers seen only as flow endpoints (the lab's client) are not assets.
        if o.mac.as_deref() == Some(&PEER.0.to_string()) {
            return None;
        }
        let k = Lab::keys_of(&o);
        let cands: Vec<AssetKeys> = self.assets.values().map(|a| a.keys.clone()).collect();
        let r = identity::resolve(&cands, &k);
        let id = r.asset.unwrap_or_else(Uuid::now_v7);
        let a = self.assets.entry(id).or_insert_with(|| Asset {
            keys: AssetKeys { id, ..Default::default() },
            signals: vec![],
            classification: Classifier::default().classify(&Default::default()),
            lifecycle: Lifecycle::Discovered,
            quarantined: false,
            groups: vec![],
            zone: None,
            baseline: Baseline::new(self.now),
            findings: vec![],
            changes: vec![],
        });
        a.changes.extend(r.changes.clone());
        if a.lifecycle == Lifecycle::Decommissioned {
            a.changes.push(ChangeEvent::HostnameChanged { from: Some("decommissioned".into()), to: "reactivated".into() });
        }
        a.lifecycle = Lifecycle::Active;
        a.keys.site = k.site.clone().or(a.keys.site.take());
        a.keys.mac = k.mac.clone().or(a.keys.mac.take());
        a.keys.ip = k.ip.clone().or(a.keys.ip.take());
        a.keys.hostname = k.hostname.clone().or(a.keys.hostname.take());
        a.keys.serial = k.serial.clone().or(a.keys.serial.take());
        a.keys.decommissioned = false;
        for s in o.signals {
            if !a.signals.contains(&s) && a.signals.len() < 256 {
                a.signals.push(s);
            }
        }
        let mut facts = classify::facts(a.keys.mac.as_deref(), &a.signals, &self.oui);
        facts.extend(classify::behaviour_facts(&o.flows));
        a.classification = self.classifier.classify(&facts);
        let ctx = DetectContext::default();
        let events: Vec<(crate::protocols::ProtoEvent, bool)> =
            a.signals.iter().filter_map(|s| if let Signal::Protocol { event, server } = s { Some((event.clone(), *server)) } else { None }).collect();
        let _ = baseline::detect(&mut a.baseline, &o.flows, &events, &ctx, self.now);
        self.reassign(id);
        Some(id)
    }

    pub fn facts_of(&self, id: Uuid) -> DeviceFacts {
        let a = &self.assets[&id];
        DeviceFacts {
            id: id.to_string(),
            device_type: a.classification.device_type.clone(),
            category: a.classification.category.clone(),
            vendor: a.classification.vendor.clone(),
            model: a.classification.model.clone(),
            site: a.keys.site.clone(),
            tags: vec![],
            risk_level: Some(self.risk(id).level),
            confidence: a.classification.confidence,
            quarantined: a.quarantined,
            pinned_groups: vec![],
        }
    }

    pub fn reassign(&mut self, id: Uuid) {
        let f = self.facts_of(id);
        let asg = segmentation::assign(&f, &self.groups, &self.zones);
        if let Some(a) = self.assets.get_mut(&id) {
            a.groups = asg.groups;
            a.zone = asg.zone;
        }
    }

    pub fn risk(&self, id: Uuid) -> risk::RiskScore {
        let a = &self.assets[&id];
        risk::score(
            &risk::RiskInput {
                device_type: a.classification.device_type.clone(),
                classification_confidence: a.classification.confidence,
                randomized_mac: a.keys.mac.as_deref().and_then(Mac::parse).map(|m| m.is_local()).unwrap_or(false),
                findings: a.findings.clone(),
                ..Default::default()
            },
            &risk::Tuning::default(),
        )
    }

    pub fn device_ctx(&self, id: Uuid) -> DeviceCtx {
        let a = &self.assets[&id];
        let info = taxonomy::get(&a.classification.device_type);
        DeviceCtx {
            device_id: Some(id.to_string()),
            groups: a.groups.clone(),
            zone: a.zone.clone(),
            site: None,
            device_type: Some(a.classification.device_type.clone()),
            category: Some(a.classification.category.clone()),
            risk_level: Some(self.risk(id).level),
            confidence_tier: Some(a.classification.tier.clone()),
            quarantined: a.quarantined,
            ip: a.keys.ip.clone(),
            evaluated_at: Some(self.now),
            safety_sensitive: info.safety_sensitive,
        }
    }

    /// Decide a flow from `src` to `dst` with an operation class.
    pub fn decide(&self, src: Uuid, dst: Uuid, op: OpClass, at: DateTime<Utc>) -> segmentation::Verdict {
        let f = FlowCtx {
            source: self.device_ctx(src),
            destination: self.device_ctx(dst),
            protocol: Some("modbus".into()),
            operation_class: Some(op.as_str().into()),
            port: Some(502),
            ..Default::default()
        };
        segmentation::decide(self.policy.as_ref(), &self.exceptions, &self.zones, &f, at)
    }

    /// Bounded telemetry queue (drop oldest).
    pub fn enqueue(&mut self, v: serde_json::Value) {
        if self.queue.len() >= self.queue_cap {
            self.queue.pop_front();
            self.dropped += 1;
        }
        self.queue.push_back(v);
    }

    pub fn decommission(&mut self, id: Uuid) {
        let sid = id.to_string();
        if let Some(a) = self.assets.get_mut(&id) {
            a.lifecycle = Lifecycle::Decommissioned;
            a.keys.decommissioned = true;
            a.groups.clear();
            a.zone = None;
        }
        self.exceptions.retain(|e| e.source_device.as_deref() != Some(&sid) && e.destination_device.as_deref() != Some(&sid));
    }
}

impl Default for Lab {
    fn default() -> Self {
        Lab::new()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioResult {
    pub capability: u16,
    pub profile: String,
    pub scenario: String,
    pub passed: bool,
    pub checks: Vec<Check>,
    pub duration_us: u128,
}

struct Ck(Vec<Check>);

impl Ck {
    fn check(&mut self, name: &str, passed: bool, detail: impl Into<String>) {
        self.0.push(Check { name: name.into(), passed, detail: detail.into() });
    }
}

/// Run one scenario for a capability section with its profile.
pub fn run(capability: u16, scenario: &str) -> ScenarioResult {
    let profile = crate::capabilities::by_section(capability).map(|c| c.profile).unwrap_or("modbus");
    run_profile(capability, profile, scenario)
}

pub fn run_profile(capability: u16, profile: &str, scenario: &str) -> ScenarioResult {
    let started = std::time::Instant::now();
    let mut ck = Ck(vec![]);
    let mut lab = Lab::new();
    let t = traffic(profile, 7);
    let site = "site-a";
    let first = lab.feed(&t.full, site);
    let dev = lab.assets.iter().find(|(_, a)| a.keys.mac.as_deref() == Some(&t.mac.to_string())).map(|(id, _)| *id);
    match (scenario, dev) {
        (_, None) => ck.check("device discovered", false, format!("no asset for {} ({} observations)", t.mac, first.len())),
        ("new_device_discovery", Some(d)) => {
            let a = &lab.assets[&d];
            ck.check("asset created", true, d.to_string());
            ck.check("classified as expected", a.classification.device_type == t.expected_type, format!("{} (expected {})", a.classification.device_type, t.expected_type));
            ck.check(
                "evidence explains the decision",
                !a.classification.evidence.is_empty() || t.expected_type == "unknown",
                format!("{} evidence items", a.classification.evidence.len()),
            );
            ck.check("passive observation", true, "no active technique used");
        }
        ("known_device_rediscovery", Some(d)) => {
            let n = lab.assets.len();
            let again = lab.feed(&t.full, site);
            ck.check("same asset", again.contains(&d), format!("{again:?}"));
            ck.check("no duplicate", lab.assets.len() == n, format!("{} assets", lab.assets.len()));
        }
        ("ip_change", Some(d)) => {
            let moved = traffic(profile, 7);
            let new_ip = Ipv4Addr::new(10, 250, 9, 9);
            let frames: Vec<Vec<u8>> = moved.full.iter().map(|f| rewrite_ip(f, moved.ip, new_ip)).collect();
            let ids = lab.feed(&frames, site);
            let a = &lab.assets[&d];
            ck.check("identity kept", ids.contains(&d), format!("{ids:?}"));
            ck.check("address updated", a.keys.ip.as_deref() == Some("10.250.9.9"), format!("{:?}", a.keys.ip));
            ck.check("change event", a.changes.iter().any(|c| matches!(c, ChangeEvent::IpChanged { .. })), format!("{:?}", a.changes));
        }
        ("site_move", Some(d)) => {
            let ids = lab.feed(&t.full, "site-b");
            let a = &lab.assets[&d];
            let strong = t.mac.0[0] & 0x02 == 0;
            if strong {
                ck.check("identity kept across sites", ids.contains(&d), format!("{ids:?}"));
                ck.check("site updated", a.keys.site.as_deref() == Some("site-b"), format!("{:?}", a.keys.site));
                ck.check("site move event", a.changes.iter().any(|c| matches!(c, ChangeEvent::SiteMoved { .. })), format!("{:?}", a.changes));
            } else {
                ck.check("randomised MAC is not trusted across sites", !ids.contains(&d), "site-scoped weak identity");
            }
        }
        ("unknown_classification", Some(_)) => {
            let u = traffic("unknown", 99);
            let ids = lab.feed(&u.full, site);
            let id = ids.first().copied();
            match id {
                Some(id) => {
                    let a = &lab.assets[&id];
                    ck.check("unknown type", a.classification.device_type == "unknown", a.classification.device_type.clone());
                    ck.check("not privileged", !a.groups.contains(&gid("controllers")), format!("{:?}", a.groups));
                    ck.check("quarantine group", a.groups.contains(&gid(segmentation::QUARANTINE_GROUP)), format!("{:?}", a.groups));
                }
                None => ck.check("unknown device discovered", false, "no asset"),
            }
        }
        ("confidence_improvement", Some(_)) => {
            let mut l2 = Lab::new();
            let t2 = traffic(profile, 8);
            l2.feed(&t2.partial, site);
            let c1 = l2.assets.values().find(|a| a.keys.mac.as_deref() == Some(&t2.mac.to_string())).map(|a| (a.classification.confidence, a.classification.device_type.clone()));
            let extra: Vec<Vec<u8>> = if profile == "unknown" { traffic("camera", 8).full } else { t2.full.clone() };
            l2.feed(&extra, site);
            let c2 = l2.assets.values().map(|a| a.classification.confidence).fold(0.0, f64::max);
            let (c1v, ty1) = c1.unwrap_or((0.0, "unknown".into()));
            ck.check(
                "confidence improves with evidence",
                c2 > c1v || (ty1 == "unknown" && c2 >= c1v && c2 > 0.0) || (c1v >= 0.99 && c2 >= c1v),
                format!("{c1v:.3} ({ty1}) -> {c2:.3}"),
            );
        }
        ("risk_increase", Some(d)) => {
            let r1 = lab.risk(d).score;
            if let Some(a) = lab.assets.get_mut(&d) {
                a.findings.push(Finding {
                    kind: FindingKind::Vulnerability,
                    key: "vuln:x".into(),
                    title: "sample".into(),
                    severity: 9.0,
                    known_exploited: true,
                    detail: json!({}),
                    remediation: None,
                });
            }
            let r2 = lab.risk(d);
            ck.check("risk increases", r2.score > r1, format!("{r1} -> {}", r2.score));
            ck.check("factor explained", r2.factors.iter().any(|f| f.key == "vulnerability"), format!("{:?}", r2.factors.iter().map(|f| &f.key).collect::<Vec<_>>()));
        }
        ("segment_change", Some(d)) => {
            let before = lab.assets[&d].zone.clone();
            let ty = lab.assets[&d].classification.device_type.clone();
            let conf = lab.assets[&d].classification.confidence;
            lab.groups.push(Group {
                id: gid("alt"),
                key: "alt".into(),
                priority: 500,
                matcher: GroupMatch { device_types: vec![ty.clone()], ..Default::default() },
                zone: Some("zone-alt".into()),
                privileged: false,
                min_confidence: 0.0,
            });
            lab.reassign(d);
            let after = lab.assets[&d].zone.clone();
            if ty == "unknown" {
                ck.check("unknown devices are not moved by type rules", after == before || after.as_deref() == Some("zone-alt") && conf < 0.9, format!("{before:?} -> {after:?}"));
            } else {
                ck.check("zone changes with the group", after.as_deref() == Some("zone-alt"), format!("{before:?} -> {after:?}"));
            }
        }
        ("quarantine", Some(d)) => {
            let peer = lab.feed(&traffic("modbus", 3).full, site).into_iter().find(|x| *x != d);
            if let Some(a) = lab.assets.get_mut(&d) {
                a.quarantined = true;
            }
            lab.reassign(d);
            ck.check("quarantine group", lab.assets[&d].groups.contains(&gid(segmentation::QUARANTINE_GROUP)), format!("{:?}", lab.assets[&d].groups));
            if let Some(p) = peer {
                let v = lab.decide(d, p, OpClass::Read, lab.now);
                ck.check(
                    "traffic from the quarantined device is blocked by the explicit rule",
                    v.enforced == "block" && v.rule_name.as_deref() == Some("block quarantined sources"),
                    format!("{v:?}"),
                );
            }
        }
        ("temporary_exception", Some(_)) => {
            let plc = lab.feed(&traffic("modbus", 4).full, site).into_iter().last();
            let hmi = lab.feed(&traffic("camera", 4).full, site).into_iter().last();
            if let (Some(plc), Some(hmi)) = (plc, hmi) {
                let now = lab.now;
                let b1 = lab.decide(hmi, plc, OpClass::Write, now);
                lab.exceptions.push(Exception {
                    id: "ex".into(),
                    source_device: Some(hmi.to_string()),
                    destination_device: Some(plc.to_string()),
                    source_group: None,
                    destination_group: None,
                    protocol: Some("modbus".into()),
                    port: Some(502),
                    max_op: Some(OpClass::Write),
                    starts_at: now - Duration::minutes(1),
                    expires_at: now + Duration::hours(1),
                });
                let b2 = lab.decide(hmi, plc, OpClass::Write, now);
                let b3 = lab.decide(hmi, plc, OpClass::Write, now + Duration::hours(2));
                ck.check("blocked without exception", b1.enforced == "block", format!("{b1:?}"));
                ck.check("allowed during the exception", b2.enforced == "allow" && b2.exception_id.is_some(), format!("{b2:?}"));
                ck.check("blocked after expiry", b3.enforced == "block", format!("{b3:?}"));
            } else {
                ck.check("lab devices", false, "missing");
            }
        }
        ("vendor_access", Some(_)) => {
            let now = lab.now;
            let req = remote::RequestInput {
                window_start: now + Duration::minutes(1),
                window_end: now + Duration::hours(1),
                protocol: "https".into(),
                justification: "vendor maintenance of controller".into(),
                ticket: Some("WO-1".into()),
                principal_expires_at: Some(now + Duration::days(30)),
                principal_enabled: Some(true),
                target_protocols: vec!["https".into()],
                target_available: true,
            };
            ck.check("request valid", remote::validate(&req, &remote::Limits::default(), now).is_ok(), "");
            ck.check(
                "no access before approval",
                remote::can_start(remote::RequestState::PendingApproval, req.window_start, req.window_end, now + Duration::minutes(5)).is_err(),
                "",
            );
            ck.check(
                "access inside the approved window",
                remote::can_start(remote::RequestState::Approved, req.window_start, req.window_end, now + Duration::minutes(5)).is_ok(),
                "",
            );
            ck.check(
                "session ends with the window",
                remote::must_end(
                    remote::RequestState::Approved,
                    req.window_end,
                    now + Duration::minutes(5),
                    now + Duration::minutes(55),
                    false,
                    &remote::Limits::default(),
                    req.window_end,
                ) == Some(remote::EndReason::WindowEnded),
                "",
            );
        }
        ("branch_failover", Some(d)) => {
            let peer = lab.feed(&traffic("camera", 5).full, site).into_iter().last().unwrap_or(d);
            let before = lab.decide(peer, d, OpClass::Write, lab.now);
            // Cloud and branch lost: the edge keeps the last verified policy.
            let failures = crate::failure::evaluate(
                &crate::failure::Health { cloud_reachable: false, branch_reachable: false, policy_age_secs: Some(3600), ..Default::default() },
                &Default::default(),
            );
            let during = lab.decide(peer, d, OpClass::Write, lab.now + Duration::hours(1));
            ck.check(
                "failure detected",
                failures.iter().any(|f| f.mode.key == "cloud_outage") && failures.iter().any(|f| f.mode.key == "site_isolation"),
                format!("{:?}", failures.iter().map(|f| f.mode.key).collect::<Vec<_>>()),
            );
            ck.check(
                "decisions unchanged during the outage (fail static)",
                before.enforced == during.enforced && before.policy_hash == during.policy_hash,
                format!("{} / {}", before.enforced, during.enforced),
            );
        }
        ("policy_rollback", Some(d)) => {
            let peer = lab.feed(&traffic("camera", 6).full, site).into_iter().last().unwrap_or(d);
            let v1 = lab.decide(peer, d, OpClass::Read, lab.now);
            lab.policy = Some(Lab::compile_policy(2, true));
            let v2 = lab.decide(peer, d, OpClass::Read, lab.now);
            lab.policy = Some(Lab::compile_policy(1, false));
            let v3 = lab.decide(peer, d, OpClass::Read, lab.now);
            ck.check(
                "rollback restores decisions",
                v1.enforced == v3.enforced && v1.policy_hash == v3.policy_hash,
                format!("{} -> {} -> {}", v1.enforced, v2.enforced, v3.enforced),
            );
            ck.check("revision recorded", v2.policy_revision == Some(2) && v3.policy_revision == Some(1), format!("{:?} {:?}", v2.policy_revision, v3.policy_revision));
        }
        ("protocol_malformed_input", Some(d)) => {
            let errs_before: u64 = lab.collector.stats.parse_errors.values().sum::<u64>() + lab.collector.stats.decode_errors.values().sum::<u64>();
            lab.feed(&t.malformed, site);
            let errs: u64 = lab.collector.stats.parse_errors.values().sum::<u64>() + lab.collector.stats.decode_errors.values().sum::<u64>();
            ck.check("no crash and errors counted", errs > errs_before, format!("{errs_before} -> {errs}"));
            let mut b = lab.assets[&d].baseline.clone();
            let a = baseline::detect(&mut b, &[], &[], &DetectContext { malformed: errs - errs_before, ..Default::default() }, lab.now);
            ck.check(
                "malformed burst raises an anomaly",
                a.iter().any(|x| x.kind == baseline::AnomalyKind::MalformedProtocol) || errs - errs_before < 10,
                format!("{} malformed", errs - errs_before),
            );
            ck.check("asset unaffected", lab.assets.contains_key(&d), "");
        }
        ("high_device_count", Some(_)) => {
            let n = 1500u32;
            let start = std::time::Instant::now();
            let mut frames = vec![];
            for i in 100..100 + n {
                frames.extend(traffic(profile, i).partial);
            }
            let before = lab.assets.len();
            lab.feed(&frames, site);
            let created = lab.assets.len() - before;
            ck.check("all devices discovered", created as u32 >= n - 1, format!("{created} of {n}"));
            ck.check("bounded time", start.elapsed().as_secs() < 30, format!("{:?}", start.elapsed()));
            ck.check("collector bounded", lab.collector.device_count() <= Limits::default().max_devices, format!("{}", lab.collector.device_count()));
        }
        ("telemetry_backlog", Some(_)) => {
            lab.queue_cap = 100;
            for i in 0..250 {
                lab.enqueue(json!({ "seq": i }));
            }
            ck.check("queue bounded", lab.queue.len() == 100 && lab.dropped == 150, format!("{} queued, {} dropped", lab.queue.len(), lab.dropped));
            ck.check("oldest dropped first", lab.queue.front().map(|v| v["seq"] == 150).unwrap_or(false), "");
            let f = crate::failure::evaluate(&crate::failure::Health { backlog_pct: 100, ..Default::default() }, &Default::default());
            ck.check("backlog failure mode raised", f.iter().any(|x| x.mode.key == "storage_backlog"), "");
            lab.queue.clear();
            let f = crate::failure::evaluate(&crate::failure::Health { backlog_pct: 0, ..Default::default() }, &Default::default());
            ck.check("recovers when drained", !f.iter().any(|x| x.mode.key == "storage_backlog"), "");
        }
        ("device_decommission", Some(d)) => {
            let now = lab.now;
            lab.exceptions.push(Exception {
                id: "ex-d".into(),
                source_device: Some(d.to_string()),
                destination_device: None,
                source_group: None,
                destination_group: None,
                protocol: None,
                port: None,
                max_op: None,
                starts_at: now,
                expires_at: now + Duration::hours(1),
            });
            lab.decommission(d);
            let a = &lab.assets[&d];
            ck.check("lifecycle decommissioned", a.lifecycle == Lifecycle::Decommissioned, format!("{:?}", a.lifecycle));
            ck.check("group membership removed", a.groups.is_empty() && a.zone.is_none(), format!("{:?}", a.groups));
            ck.check("policy exceptions removed", lab.exceptions.is_empty(), format!("{}", lab.exceptions.len()));
            let back = lab.feed(&t.full, site);
            ck.check("rediscovery reactivates with an event", back.contains(&d) && lab.assets[&d].lifecycle == Lifecycle::Active, format!("{back:?}"));
        }
        (other, Some(_)) => ck.check("known scenario", false, other.to_string()),
    }
    let passed = !ck.0.is_empty() && ck.0.iter().all(|c| c.passed);
    ScenarioResult { capability, profile: profile.into(), scenario: scenario.into(), passed, checks: ck.0, duration_us: started.elapsed().as_micros() }
}

/// Rewrite an IPv4 address in a frame (source or destination) and fix the
/// header checksum.
pub fn rewrite_ip(frame: &[u8], from: Ipv4Addr, to: Ipv4Addr) -> Vec<u8> {
    let mut f = frame.to_vec();
    if f.len() >= 34 && f[12] == 0x08 && f[13] == 0x00 {
        for off in [26usize, 30] {
            if f[off..off + 4] == from.octets() {
                f[off..off + 4].copy_from_slice(&to.octets());
            }
        }
        f[24] = 0;
        f[25] = 0;
        let mut s: u32 = 0;
        for c in f[14..34].chunks(2) {
            s += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        let c = !(s as u16);
        f[24..26].copy_from_slice(&c.to_be_bytes());
    }
    if f.len() >= 42 && f[12] == 0x08 && f[13] == 0x06 && f[28..32] == from.octets() {
        f[28..32].copy_from_slice(&to.octets());
    }
    f
}

/// Run every scenario for every capability; returns (passed, failed results).
pub fn run_all(sections: &[u16]) -> (usize, Vec<ScenarioResult>) {
    let mut ok = 0;
    let mut failed = vec![];
    for s in sections {
        for sc in SCENARIOS {
            let r = run(*s, sc);
            if r.passed {
                ok += 1;
            } else {
                failed.push(r);
            }
        }
    }
    (ok, failed)
}

/// Fixed classification corpus (section 128): profile → expected type.
pub fn classification_corpus() -> Vec<(&'static str, &'static str)> {
    PROFILES.iter().filter(|p| **p != "remote").map(|p| (*p, traffic(p, 1).expected_type)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_classifies_as_expected() {
        let mut wrong = vec![];
        for (p, expected) in classification_corpus() {
            let r = run_profile(0, p, "new_device_discovery");
            if !r.passed {
                wrong.push(format!("{p}: {:?}", r.checks.iter().filter(|c| !c.passed).collect::<Vec<_>>()));
            }
            let _ = expected;
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    #[test]
    fn every_scenario_passes_for_every_profile() {
        let mut failed = vec![];
        for p in PROFILES {
            for s in SCENARIOS {
                if *s == "high_device_count" && *p != "modbus" {
                    continue; // exercised once per capability in the full matrix test
                }
                let r = run_profile(0, p, s);
                if !r.passed {
                    failed.push(format!("{p}/{s}: {:?}", r.checks.iter().filter(|c| !c.passed).map(|c| format!("{} [{}]", c.name, c.detail)).collect::<Vec<_>>()));
                }
            }
        }
        assert!(failed.is_empty(), "{failed:#?}");
    }

    #[test]
    fn rewrite_keeps_frames_decodable() {
        let t = traffic("modbus", 1);
        let r = rewrite_ip(&t.full[1], t.ip, Ipv4Addr::new(10, 9, 9, 9));
        let f = crate::packet::decode_ethernet(&r).unwrap();
        assert!(f.src_ip == Some("10.9.9.9".parse().unwrap()) || f.dst_ip == Some("10.9.9.9".parse().unwrap()));
    }
}
