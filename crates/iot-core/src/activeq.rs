//! Active discovery safeguards and safe active queries (ZTE-IOT section 5
//! Active Discovery Safeguards; ZTE-IOT-*-i5 passive observation separated
//! from active interrogation with explicit authorisation; ZTE-IOTINV-153161;
//! AE-IOT-0007/0008 per-query enablement, schedules, blackout windows,
//! restrictions and attempt limits).
//!
//! Active queries are off by default. A query runs against a target only
//! when: the query is enabled for the tenant; the target is not in a
//! restricted address range, category or device type; the current time is
//! outside every blackout window; the per-target attempt budget is not
//! exhausted; and, for safety-sensitive targets or queries above `safe`
//! risk, an approval exists. [`plan`] explains each decision. The request
//! builders produce the minimal identification requests that the edge
//! executes (and whose answers are parsed by the protocol parsers).

use crate::protocols::{bacnet, enip, modbus, snmp};
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Safe,
    Caution,
    Intrusive,
}

/// (kind, risk, transport, port, description)
pub const QUERIES: &[(&str, Risk, &str, u16, &str)] = &[
    ("icmp_ping", Risk::Safe, "icmp", 0, "reachability"),
    ("tcp_port_check", Risk::Safe, "tcp", 0, "TCP connect to known service ports"),
    ("http_banner", Risk::Safe, "tcp", 80, "HTTP HEAD for the server banner"),
    ("snmp_sysdescr", Risk::Caution, "udp", 161, "SNMP GET sysDescr.0 / sysName.0"),
    ("enip_list_identity", Risk::Caution, "udp", 44818, "EtherNet/IP ListIdentity"),
    ("bacnet_who_is", Risk::Caution, "udp", 47808, "BACnet Who-Is"),
    ("modbus_device_id", Risk::Caution, "tcp", 502, "Modbus Read Device Identification (43/14)"),
    ("s7_read_szl", Risk::Intrusive, "tcp", 102, "S7 module identification (session set-up required)"),
];

pub fn query(kind: &str) -> Option<(&'static str, Risk, &'static str, u16, &'static str)> {
    QUERIES.iter().copied().find(|q| q.0 == kind)
}

/// A blackout window: ISO weekdays (1=Monday) and HH:MM range (UTC).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Blackout {
    pub days: Vec<u8>,
    pub start: String,
    pub end: String,
}

impl Blackout {
    pub fn contains(&self, at: DateTime<Utc>) -> bool {
        let tw = aether_core::policy::TimeWindow { days: self.days.clone(), start: self.start.clone(), end: self.end.clone(), utc_offset_minutes: 0 };
        let _ = (at.weekday(), at.hour());
        tw.contains(at)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub queries: Vec<String>,
    #[serde(default)]
    pub blackouts: Vec<Blackout>,
    /// Restricted CIDR blocks never queried.
    #[serde(default)]
    pub restricted_cidrs: Vec<String>,
    #[serde(default)]
    pub restricted_categories: Vec<String>,
    #[serde(default)]
    pub restricted_device_types: Vec<String>,
    #[serde(default = "attempts")]
    pub max_attempts_per_day: u32,
    #[serde(default = "rate")]
    pub max_queries_per_second: u32,
}

fn attempts() -> u32 {
    3
}
fn rate() -> u32 {
    5
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub ip: String,
    pub category: String,
    pub device_type: String,
    pub safety_sensitive: bool,
    #[serde(default)]
    pub attempts_today: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanItem {
    pub target: String,
    pub allowed: bool,
    pub reason: String,
}

fn in_cidr(ip: &str, cidr: &str) -> bool {
    match (ip.parse::<std::net::IpAddr>(), aether_core::policy::validate::parse_net(cidr)) {
        (Ok(a), Some(n)) => n.contains(&a),
        _ => false,
    }
}

/// Decide, per target, whether a query may run now.
pub fn plan(s: &Settings, kind: &str, targets: &[Target], approved: bool, now: DateTime<Utc>) -> Vec<PlanItem> {
    let q = query(kind);
    targets
        .iter()
        .map(|t| {
            let deny = |r: &str| PlanItem { target: t.id.clone(), allowed: false, reason: r.into() };
            let Some((_, risk, _, _, _)) = q else { return deny("unknown_query") };
            if !s.enabled {
                return deny("active_queries_disabled");
            }
            if !s.queries.iter().any(|x| x == kind) {
                return deny("query_not_enabled");
            }
            if s.blackouts.iter().any(|b| b.contains(now)) {
                return deny("blackout_window");
            }
            if s.restricted_cidrs.iter().any(|c| in_cidr(&t.ip, c)) {
                return deny("restricted_address");
            }
            if s.restricted_categories.contains(&t.category) || s.restricted_device_types.contains(&t.device_type) {
                return deny("restricted_device");
            }
            if t.attempts_today >= s.max_attempts_per_day {
                return deny("attempt_limit");
            }
            if (t.safety_sensitive || risk > Risk::Safe) && !approved {
                return deny("approval_required");
            }
            if t.safety_sensitive && risk == Risk::Intrusive {
                return deny("intrusive_query_on_safety_sensitive_device");
            }
            PlanItem { target: t.id.clone(), allowed: true, reason: "allowed".into() }
        })
        .collect()
}

/// Request bytes for a query (UDP datagram or TCP payload).
pub fn request(kind: &str) -> Option<Vec<u8>> {
    match kind {
        "enip_list_identity" => Some(enip::encap(0x0063, &[])),
        "modbus_device_id" => Some(modbus::adu(0x4954, 0, &[43, 14, 1, 0])),
        "bacnet_who_is" => Some(bacnet::frame(&[0x10, 0x08])),
        "snmp_sysdescr" => Some(snmp::message("public", 0xa0, "1.3.6.1.2.1.1.1.0", (0x05, &[]))),
        "http_banner" => Some(b"HEAD / HTTP/1.0\r\nUser-Agent: aether-iot-edge\r\n\r\n".to_vec()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{parse, Dir, Protocol};

    fn t(id: &str, safety: bool) -> Target {
        Target { id: id.into(), ip: "10.0.0.5".into(), category: "industrial_control".into(), device_type: "plc".into(), safety_sensitive: safety, attempts_today: 0 }
    }

    #[test]
    fn governance() {
        let now = Utc::now();
        let mut s = Settings { enabled: true, queries: vec!["modbus_device_id".into(), "icmp_ping".into(), "s7_read_szl".into()], max_attempts_per_day: 3, ..Default::default() };
        assert_eq!(plan(&Settings::default(), "icmp_ping", &[t("a", false)], true, now)[0].reason, "active_queries_disabled");
        assert!(plan(&s, "icmp_ping", &[t("a", false)], false, now)[0].allowed);
        assert_eq!(plan(&s, "modbus_device_id", &[t("a", false)], false, now)[0].reason, "approval_required");
        assert!(plan(&s, "modbus_device_id", &[t("a", false)], true, now)[0].allowed);
        assert_eq!(plan(&s, "s7_read_szl", &[t("a", true)], true, now)[0].reason, "intrusive_query_on_safety_sensitive_device");
        assert_eq!(plan(&s, "bacnet_who_is", &[t("a", false)], true, now)[0].reason, "query_not_enabled");
        let mut busy = t("b", false);
        busy.attempts_today = 3;
        assert_eq!(plan(&s, "icmp_ping", &[busy], true, now)[0].reason, "attempt_limit");
        s.restricted_cidrs = vec!["10.0.0.0/24".into()];
        assert_eq!(plan(&s, "icmp_ping", &[t("a", false)], true, now)[0].reason, "restricted_address");
        s.restricted_cidrs.clear();
        s.blackouts = vec![Blackout { days: vec![1, 2, 3, 4, 5, 6, 7], start: "00:00".into(), end: "23:59".into() }];
        let at = now.date_naive().and_hms_opt(12, 0, 0).unwrap().and_utc();
        assert_eq!(plan(&s, "icmp_ping", &[t("a", false)], true, at)[0].reason, "blackout_window");
    }

    #[test]
    fn requests_are_valid_protocol_messages() {
        assert_eq!(parse(Protocol::Modbus, &request("modbus_device_id").unwrap(), Dir::ToServer).unwrap()[0].operation, "read_device_identification");
        assert_eq!(parse(Protocol::Enip, &request("enip_list_identity").unwrap(), Dir::ToServer).unwrap()[0].operation, "list_identity");
        assert_eq!(parse(Protocol::Bacnet, &request("bacnet_who_is").unwrap(), Dir::ToServer).unwrap()[0].operation, "who_is");
        assert_eq!(parse(Protocol::Snmp, &request("snmp_sysdescr").unwrap(), Dir::ToServer).unwrap()[0].operation, "get");
        assert!(request("s7_read_szl").is_none(), "intrusive queries have no automatic request builder");
    }
}
