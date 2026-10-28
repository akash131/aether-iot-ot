//! Deterministic, explainable multi-signal device classification
//! (ZTE-IOT sections 14 Multisignal Device Classification, 15
//! Classification Confidence, 16 Unknown Device Handling, 128 Device
//! Classification Validation; Volume 2 "Device Classification";
//! ZTE-IOTINV-153162/153165; AE-IOT-0005 confidence tiers, AE-IOT-0019
//! multi-dimensional taxonomy, AE-IOT-0027 data-quality diagnostics).
//!
//! **Facts.** Signals are reduced to `(source, field, value)` facts: the
//! OUI vendor, DHCP host name / vendor class / parameter list, DNS names,
//! HTTP user agents and server banners, mDNS services and models, SSDP,
//! LLDP/CDP descriptions and capabilities, TLS fingerprints and SNI, TCP
//! SYN OS hints, listening services, industrial protocol roles and
//! operations, protocol-disclosed identity, behaviour derived from flows,
//! and integration assertions.
//!
//! **Rules.** A rule matches one fact (exact, prefix, suffix, contains or
//! glob, case-insensitive) and votes, with a weight in (0, 1), for any of
//! the four dimensions: device type, vendor, model and operating system.
//! Tenant rules (custom and learned) are evaluated with the built-in
//! library and win ties.
//!
//! **Scoring.** For every dimension and candidate value, the strongest vote
//! of each fact source is combined with a noisy-OR across sources (more
//! independent evidence → higher support, repeated evidence from one
//! source is not double counted). The best candidate wins (ties broken by
//! name, so results are deterministic). Confidence is the winner's support
//! reduced by the support of the strongest conflicting candidate. Device
//! types below [`MIN_TYPE_SUPPORT`] are `unknown`.
//!
//! **Explanation.** The result lists every rule that fired with its fact,
//! weight and the dimension it voted for, the conflicts, the rule-set
//! version (hash) and the confidence tier (high ≥ 0.90, medium ≥ 0.70,
//! low otherwise). An administrator override always takes precedence and is
//! reported as such.

use crate::fingerprint::{os_from_syn, OuiTable};
use crate::model::{clip, Flow, Signal};
use crate::protocols::OpClass;
use crate::taxonomy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const CLASSIFIER_VERSION: &str = "2026.10.1";
pub const MIN_TYPE_SUPPORT: f64 = 0.35;

/// One fact about a device.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fact {
    pub source: String,
    pub field: String,
    pub value: String,
}

fn fact(source: &str, field: &str, value: &str) -> Fact {
    Fact { source: source.into(), field: field.into(), value: clip(value, 256) }
}

/// Facts from signals (and the OUI table for the device's MAC).
pub fn facts(mac: Option<&str>, signals: &[Signal], oui: &OuiTable) -> BTreeSet<Fact> {
    let mut out = BTreeSet::new();
    if let Some(m) = mac {
        if let Some(v) = oui.vendor(m) {
            out.insert(fact("oui", "vendor", v));
        }
        if crate::packet::Mac::parse(m).map(|x| x.is_local()).unwrap_or(false) {
            out.insert(fact("oui", "randomized", "true"));
        }
    }
    for s in signals {
        match s {
            Signal::Dhcp { hostname, vendor_class, prl, .. } => {
                if let Some(h) = hostname {
                    out.insert(fact("dhcp", "hostname", h));
                }
                if let Some(v) = vendor_class {
                    out.insert(fact("dhcp", "vendor_class", v));
                }
                if let Some(p) = prl {
                    out.insert(fact("dhcp", "prl", p));
                }
            }
            Signal::Dns { query } => {
                out.insert(fact("dns", "query", query));
            }
            Signal::Http { user_agent, server, .. } => {
                if let Some(u) = user_agent {
                    out.insert(fact("http", "user_agent", u));
                }
                if let Some(v) = server {
                    out.insert(fact("http", "server", v));
                }
            }
            Signal::Mdns { services, model, .. } => {
                for x in services {
                    out.insert(fact("mdns", "service", x));
                }
                if let Some(m) = model {
                    out.insert(fact("mdns", "model", m));
                }
            }
            Signal::Ssdp { server, device_type } => {
                if let Some(v) = server {
                    out.insert(fact("ssdp", "server", v));
                }
                if let Some(v) = device_type {
                    out.insert(fact("ssdp", "device_type", v));
                }
            }
            Signal::Lldp { system_name, system_description, capabilities, .. } => {
                if let Some(v) = system_description {
                    out.insert(fact("lldp", "description", v));
                }
                if let Some(v) = system_name {
                    out.insert(fact("lldp", "name", v));
                }
                for c in capabilities {
                    out.insert(fact("lldp", "capability", c));
                }
            }
            Signal::Cdp { platform, software, capabilities, .. } => {
                if let Some(v) = platform {
                    out.insert(fact("cdp", "platform", v));
                }
                if let Some(v) = software {
                    out.insert(fact("cdp", "software", v));
                }
                for c in capabilities {
                    out.insert(fact("cdp", "capability", c));
                }
            }
            Signal::Tls { fingerprint, sni, .. } => {
                out.insert(fact("tls", "fingerprint", fingerprint));
                if let Some(v) = sni {
                    out.insert(fact("tls", "sni", v));
                }
            }
            Signal::TcpSyn { ttl, window } => {
                if let Some(os) = os_from_syn(*ttl, *window) {
                    out.insert(fact("tcp", "os_hint", os));
                }
            }
            Signal::Service { transport, port } => {
                out.insert(fact("service", "listen", &format!("{transport}:{port}")));
            }
            Signal::Protocol { event, server } => {
                let role = if *server { "server" } else { "client" };
                out.insert(fact("protocol", "role", &format!("{}:{}", event.protocol.as_str(), role)));
                if !*server && event.class >= OpClass::Program {
                    out.insert(fact("protocol", "engineering", event.protocol.as_str()));
                }
                let id = &event.identity;
                if let Some(v) = &id.vendor {
                    out.insert(fact("protocol_identity", "vendor", v));
                }
                if let Some(v) = &id.product {
                    out.insert(fact("protocol_identity", "product", v));
                }
                if let Some(v) = &id.firmware {
                    out.insert(fact("protocol_identity", "firmware", v));
                }
            }
            Signal::CleartextCredentials { .. } => {}
            Signal::Asserted { source, device_type, vendor, model, os, hostname, .. } => {
                let src = format!("asserted:{source}");
                for (f, v) in [("device_type", device_type), ("vendor", vendor), ("model", model), ("os", os), ("hostname", hostname)] {
                    if let Some(v) = v {
                        out.insert(fact(&src, f, v));
                    }
                }
            }
        }
    }
    out
}

/// Behavioural facts from flow summaries (section 13 Network Behavior
/// Fingerprinting).
pub fn behaviour_facts(flows: &[Flow]) -> BTreeSet<Fact> {
    let mut out = BTreeSet::new();
    let mut ot_servers = BTreeSet::new();
    let mut internet_peers = 0;
    for f in flows {
        if f.outbound {
            if let Some(p) = f.protocol {
                if p.is_industrial() {
                    ot_servers.insert(f.peer_ip.clone());
                    if f.max_op.map(|o| o >= OpClass::Program).unwrap_or(false) {
                        out.insert(fact("behaviour", "engineering_client", p.as_str()));
                    }
                }
            }
            if let Ok(ip) = f.peer_ip.parse::<std::net::IpAddr>() {
                if crate::risk::is_public(&ip) {
                    internet_peers += 1;
                }
            }
        } else {
            match f.port {
                104 | 11112 => {
                    out.insert(fact("behaviour", "serves", "dicom"));
                }
                2575 => {
                    out.insert(fact("behaviour", "serves", "hl7"));
                }
                554 => {
                    out.insert(fact("behaviour", "serves", "rtsp"));
                }
                9100 | 631 | 515 => {
                    out.insert(fact("behaviour", "serves", "printing"));
                }
                5060 | 5061 => {
                    out.insert(fact("behaviour", "serves", "sip"));
                }
                _ => {}
            }
        }
    }
    if ot_servers.len() >= 3 {
        out.insert(fact("behaviour", "polls_controllers", "many"));
    }
    if internet_peers >= 1 {
        out.insert(fact("behaviour", "internet", "yes"));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Match {
    Exact,
    Prefix,
    Suffix,
    Contains,
    Glob,
}

/// A classification rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub source: String,
    pub field: String,
    #[serde(rename = "match")]
    pub kind: Match,
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Model text, or `"$value"` to take the matched fact value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    pub weight: f64,
    /// builtin | custom | learned
    #[serde(default = "builtin")]
    pub origin: String,
}

fn builtin() -> String {
    "builtin".into()
}

fn glob(p: &str, s: &str) -> bool {
    // '*' matches any run, '?' one character; iterative with backtracking.
    let (p, s): (Vec<char>, Vec<char>) = (p.chars().collect(), s.chars().collect());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

impl Rule {
    pub fn matches(&self, f: &Fact) -> bool {
        if !f.source.eq_ignore_ascii_case(&self.source) && !(self.source == "asserted" && f.source.starts_with("asserted:")) || f.field != self.field {
            return false;
        }
        let v = f.value.to_ascii_lowercase();
        let p = self.pattern.to_ascii_lowercase();
        match self.kind {
            Match::Exact => v == p,
            Match::Prefix => v.starts_with(&p),
            Match::Suffix => v.ends_with(&p),
            Match::Contains => v.contains(&p),
            Match::Glob => glob(&p, &v),
        }
    }

    /// Validate a tenant rule (stable error codes).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.pattern.trim().is_empty() || self.pattern.len() > 256 {
            return Err("invalid_pattern");
        }
        if !(0.05..=0.99).contains(&self.weight) {
            return Err("weight_out_of_range");
        }
        if self.device_type.is_none() && self.vendor.is_none() && self.model.is_none() && self.os.is_none() {
            return Err("no_votes");
        }
        if let Some(t) = &self.device_type {
            if !taxonomy::is_known(t) {
                return Err("unknown_device_type");
            }
        }
        if !SOURCES.contains(&self.source.as_str()) {
            return Err("unknown_source");
        }
        Ok(())
    }
}

pub const SOURCES: &[&str] = &["oui", "dhcp", "dns", "http", "mdns", "ssdp", "lldp", "cdp", "tls", "tcp", "service", "protocol", "protocol_identity", "behaviour", "asserted"];

type R = (&'static str, &'static str, &'static str, Match, &'static str, Option<&'static str>, Option<&'static str>, Option<&'static str>, Option<&'static str>, f64);

use Match::*;

/// Built-in rule library: (id, source, field, match, pattern, type, vendor, model, os, weight).
const BUILTIN: &[R] = &[
    // OUI vendor -> vendor (and weak type priors for single-purpose vendors).
    ("oui-rockwell", "oui", "vendor", Exact, "rockwell automation", Some("plc"), Some("Rockwell Automation"), None, None, 0.45),
    ("oui-siemens", "oui", "vendor", Exact, "siemens", Some("plc"), Some("Siemens"), None, None, 0.35),
    ("oui-schneider", "oui", "vendor", Exact, "schneider electric", Some("plc"), Some("Schneider Electric"), None, None, 0.35),
    ("oui-apc", "oui", "vendor", Exact, "schneider electric (apc)", Some("ups"), Some("Schneider Electric"), None, None, 0.6),
    ("oui-phoenix", "oui", "vendor", Exact, "phoenix contact", Some("plc"), Some("Phoenix Contact"), None, None, 0.4),
    ("oui-wago", "oui", "vendor", Exact, "wago", Some("plc"), Some("WAGO"), None, None, 0.45),
    ("oui-beckhoff", "oui", "vendor", Exact, "beckhoff automation", Some("plc"), Some("Beckhoff Automation"), None, None, 0.45),
    ("oui-bnr", "oui", "vendor", Exact, "b&r industrial automation", Some("plc"), Some("B&R Industrial Automation"), None, None, 0.45),
    ("oui-moxa", "oui", "vendor", Exact, "moxa", Some("industrial_gateway"), Some("Moxa"), None, None, 0.5),
    ("oui-hirschmann", "oui", "vendor", Exact, "hirschmann", Some("industrial_switch"), Some("Hirschmann"), None, None, 0.55),
    ("oui-weidmueller", "oui", "vendor", Exact, "weidmueller", Some("io_module"), Some("Weidmueller"), None, None, 0.4),
    ("oui-lantronix", "oui", "vendor", Exact, "lantronix", Some("industrial_gateway"), Some("Lantronix"), None, None, 0.5),
    ("oui-digi", "oui", "vendor", Exact, "digi international", Some("industrial_gateway"), Some("Digi International"), None, None, 0.45),
    ("oui-honeywell", "oui", "vendor", Exact, "honeywell", Some("bms_controller"), Some("Honeywell"), None, None, 0.3),
    ("oui-eaton", "oui", "vendor", Exact, "eaton", Some("ups"), Some("Eaton"), None, None, 0.45),
    ("oui-lutron", "oui", "vendor", Exact, "lutron electronics", Some("lighting_controller"), Some("Lutron Electronics"), None, None, 0.6),
    ("oui-hid", "oui", "vendor", Exact, "hid global", Some("badge_reader"), Some("HID Global"), None, None, 0.6),
    ("oui-philips-med", "oui", "vendor", Exact, "philips medical systems", Some("patient_monitor"), Some("Philips"), None, None, 0.5),
    ("oui-axis", "oui", "vendor", Exact, "axis communications", Some("ip_camera"), Some("Axis Communications"), None, None, 0.6),
    ("oui-hikvision", "oui", "vendor", Exact, "hikvision", Some("ip_camera"), Some("Hikvision"), None, None, 0.6),
    ("oui-dahua", "oui", "vendor", Exact, "dahua", Some("ip_camera"), Some("Dahua"), None, None, 0.6),
    ("oui-grandstream", "oui", "vendor", Exact, "grandstream", Some("voip_phone"), Some("Grandstream"), None, None, 0.6),
    ("oui-polycom", "oui", "vendor", Exact, "polycom", Some("voip_phone"), Some("Polycom"), None, None, 0.55),
    ("oui-avaya", "oui", "vendor", Exact, "avaya", Some("voip_phone"), Some("Avaya"), None, None, 0.55),
    ("oui-crestron", "oui", "vendor", Exact, "crestron", Some("video_conference"), Some("Crestron"), None, None, 0.5),
    ("oui-cisco", "oui", "vendor", Exact, "cisco", None, Some("Cisco"), None, None, 0.6),
    ("oui-xerox", "oui", "vendor", Exact, "xerox", Some("mfp"), Some("Xerox"), None, None, 0.6),
    ("oui-canon", "oui", "vendor", Exact, "canon", Some("printer"), Some("Canon"), None, None, 0.5),
    ("oui-brother", "oui", "vendor", Exact, "brother", Some("printer"), Some("Brother"), None, None, 0.6),
    ("oui-epson", "oui", "vendor", Exact, "seiko epson", Some("printer"), Some("Epson"), None, None, 0.55),
    ("oui-kyocera", "oui", "vendor", Exact, "kyocera", Some("mfp"), Some("Kyocera"), None, None, 0.6),
    ("oui-ricoh", "oui", "vendor", Exact, "ricoh", Some("mfp"), Some("Ricoh"), None, None, 0.6),
    ("oui-hp", "oui", "vendor", Exact, "hp", None, Some("HP"), None, None, 0.5),
    ("oui-zebra", "oui", "vendor", Exact, "zebra technologies", Some("scanner"), Some("Zebra Technologies"), None, None, 0.5),
    ("oui-verifone", "oui", "vendor", Exact, "verifone", Some("payment_terminal"), Some("Verifone"), None, None, 0.7),
    ("oui-ingenico", "oui", "vendor", Exact, "ingenico", Some("payment_terminal"), Some("Ingenico"), None, None, 0.7),
    ("oui-signify", "oui", "vendor", Exact, "signify (philips lighting)", Some("lighting_controller"), Some("Signify"), None, None, 0.6),
    ("oui-nest", "oui", "vendor", Exact, "nest labs", Some("thermostat"), Some("Nest"), None, None, 0.6),
    ("oui-google", "oui", "vendor", Exact, "google", Some("media_player"), Some("Google"), None, None, 0.3),
    ("oui-sonos", "oui", "vendor", Exact, "sonos", Some("smart_speaker"), Some("Sonos"), None, None, 0.7),
    ("oui-roku", "oui", "vendor", Exact, "roku", Some("media_player"), Some("Roku"), None, None, 0.7),
    ("oui-amazon", "oui", "vendor", Exact, "amazon", Some("smart_speaker"), Some("Amazon"), None, None, 0.35),
    ("oui-rpi", "oui", "vendor", Prefix, "raspberry pi", Some("embedded_linux"), Some("Raspberry Pi"), None, Some("linux"), 0.5),
    ("oui-espressif", "oui", "vendor", Exact, "espressif", Some("iot_sensor"), Some("Espressif"), None, None, 0.55),
    ("oui-ti", "oui", "vendor", Exact, "texas instruments", Some("iot_sensor"), Some("Texas Instruments"), None, None, 0.35),
    ("oui-microchip", "oui", "vendor", Exact, "microchip technology", Some("iot_sensor"), Some("Microchip Technology"), None, None, 0.35),
    ("oui-ubiquiti", "oui", "vendor", Exact, "ubiquiti", Some("wireless_ap"), Some("Ubiquiti"), None, None, 0.45),
    ("oui-aruba", "oui", "vendor", Exact, "aruba networks", Some("wireless_ap"), Some("Aruba Networks"), None, None, 0.55),
    ("oui-vmware", "oui", "vendor", Exact, "vmware", Some("virtual_machine"), Some("VMware"), None, None, 0.7),
    // DHCP host names.
    ("dhcp-axis", "dhcp", "hostname", Prefix, "axis-", Some("ip_camera"), Some("Axis Communications"), None, Some("embedded_linux"), 0.75),
    ("dhcp-hikvision", "dhcp", "hostname", Contains, "hikvision", Some("ip_camera"), Some("Hikvision"), None, None, 0.75),
    ("dhcp-npi", "dhcp", "hostname", Prefix, "npi", Some("printer"), Some("HP"), None, None, 0.7),
    ("dhcp-brn", "dhcp", "hostname", Prefix, "brn", Some("printer"), Some("Brother"), None, None, 0.7),
    ("dhcp-brw", "dhcp", "hostname", Prefix, "brw", Some("printer"), Some("Brother"), None, None, 0.7),
    ("dhcp-epson", "dhcp", "hostname", Prefix, "epson", Some("printer"), Some("Epson"), None, None, 0.7),
    ("dhcp-sep", "dhcp", "hostname", Glob, "sep????????????", Some("voip_phone"), Some("Cisco"), None, None, 0.8),
    ("dhcp-polycom", "dhcp", "hostname", Contains, "polycom", Some("voip_phone"), Some("Polycom"), None, None, 0.7),
    ("dhcp-iphone", "dhcp", "hostname", Contains, "iphone", Some("mobile"), Some("Apple"), None, Some("ios"), 0.7),
    ("dhcp-ipad", "dhcp", "hostname", Contains, "ipad", Some("mobile"), Some("Apple"), None, Some("ios"), 0.7),
    ("dhcp-android", "dhcp", "hostname", Prefix, "android", Some("mobile"), None, None, Some("android"), 0.7),
    ("dhcp-desktop", "dhcp", "hostname", Prefix, "desktop-", Some("workstation"), None, None, Some("windows"), 0.65),
    ("dhcp-laptop", "dhcp", "hostname", Prefix, "laptop-", Some("workstation"), None, None, Some("windows"), 0.65),
    ("dhcp-rpi", "dhcp", "hostname", Prefix, "raspberrypi", Some("embedded_linux"), Some("Raspberry Pi"), None, Some("linux"), 0.7),
    ("dhcp-esp", "dhcp", "hostname", Prefix, "esp", Some("iot_sensor"), Some("Espressif"), None, None, 0.5),
    ("dhcp-roku", "dhcp", "hostname", Prefix, "roku", Some("media_player"), Some("Roku"), None, None, 0.7),
    ("dhcp-chromecast", "dhcp", "hostname", Contains, "chromecast", Some("media_player"), Some("Google"), None, None, 0.75),
    ("dhcp-hmi", "dhcp", "hostname", Contains, "hmi", Some("hmi"), None, None, None, 0.5),
    ("dhcp-plc", "dhcp", "hostname", Contains, "plc", Some("plc"), None, None, None, 0.45),
    ("dhcp-ews", "dhcp", "hostname", Contains, "ews", Some("engineering_workstation"), None, None, None, 0.45),
    ("dhcp-hist", "dhcp", "hostname", Contains, "historian", Some("historian"), None, None, None, 0.55),
    ("dhcp-scada", "dhcp", "hostname", Contains, "scada", Some("scada_server"), None, None, None, 0.5),
    ("dhcp-pos", "dhcp", "hostname", Prefix, "pos", Some("pos_terminal"), None, None, None, 0.45),
    ("dhcp-badge", "dhcp", "hostname", Prefix, "badge", Some("badge_reader"), None, None, None, 0.6),
    ("dhcp-door", "dhcp", "hostname", Contains, "door-controller", Some("access_controller"), None, None, None, 0.6),
    ("dhcp-msft", "dhcp", "vendor_class", Prefix, "msft", Some("workstation"), Some("Microsoft"), None, Some("windows"), 0.55),
    ("dhcp-android-vc", "dhcp", "vendor_class", Prefix, "android-dhcp", Some("mobile"), None, None, Some("android"), 0.75),
    ("dhcp-udhcp", "dhcp", "vendor_class", Prefix, "udhcp", Some("embedded_linux"), None, None, Some("embedded_linux"), 0.4),
    ("dhcp-dhcpcd", "dhcp", "vendor_class", Prefix, "dhcpcd", None, None, None, Some("linux"), 0.5),
    ("dhcp-cisco-phone", "dhcp", "vendor_class", Contains, "ip phone", Some("voip_phone"), Some("Cisco"), Some("$value"), None, 0.85),
    ("dhcp-polycom-vc", "dhcp", "vendor_class", Contains, "polycom", Some("voip_phone"), Some("Polycom"), None, None, 0.8),
    ("dhcp-verifone-vc", "dhcp", "vendor_class", Contains, "verifone", Some("payment_terminal"), Some("Verifone"), None, None, 0.8),
    ("dhcp-hp-printer", "dhcp", "vendor_class", Contains, "laserjet", Some("printer"), Some("HP"), Some("$value"), None, 0.8),
    ("dhcp-prl-windows", "dhcp", "prl", Exact, "1,3,6,15,31,33,43,44,46,47,119,121,249,252", Some("workstation"), None, None, Some("windows"), 0.6),
    ("dhcp-prl-apple", "dhcp", "prl", Prefix, "1,121,3,6,15,119,252", None, Some("Apple"), None, Some("macos_ios"), 0.6),
    ("dhcp-prl-embedded", "dhcp", "prl", Exact, "1,3,6,12,15,28,42", Some("embedded_linux"), None, None, Some("embedded_linux"), 0.35),
    // DNS / SNI dependencies.
    ("dns-windows", "dns", "query", Suffix, "time.windows.com", Some("workstation"), Some("Microsoft"), None, Some("windows"), 0.45),
    ("dns-apple", "dns", "query", Suffix, ".apple.com", None, Some("Apple"), None, Some("macos_ios"), 0.4),
    ("dns-android", "dns", "query", Exact, "connectivitycheck.gstatic.com", Some("mobile"), None, None, Some("android"), 0.5),
    ("dns-hikconnect", "dns", "query", Suffix, "hik-connect.com", Some("ip_camera"), Some("Hikvision"), None, None, 0.7),
    ("dns-dahua", "dns", "query", Suffix, "easy4ipcloud.com", Some("ip_camera"), Some("Dahua"), None, None, 0.7),
    ("dns-hpeprint", "dns", "query", Suffix, "hpeprint.com", Some("printer"), Some("HP"), None, None, 0.65),
    ("dns-nest", "dns", "query", Suffix, "nest.com", Some("thermostat"), Some("Nest"), None, None, 0.45),
    ("dns-roku", "dns", "query", Suffix, "roku.com", Some("media_player"), Some("Roku"), None, None, 0.6),
    ("dns-sonos", "dns", "query", Suffix, "sonos.com", Some("smart_speaker"), Some("Sonos"), None, None, 0.6),
    ("dns-amazon-alexa", "dns", "query", Suffix, "avs-alexa-na.amazon.com", Some("smart_speaker"), Some("Amazon"), None, None, 0.7),
    ("dns-meraki", "dns", "query", Suffix, "meraki.com", Some("wireless_ap"), Some("Cisco"), None, None, 0.5),
    ("sni-hikconnect", "tls", "sni", Suffix, "hik-connect.com", Some("ip_camera"), Some("Hikvision"), None, None, 0.7),
    ("sni-axis", "tls", "sni", Suffix, "axis.com", Some("ip_camera"), Some("Axis Communications"), None, None, 0.5),
    // HTTP user agents and server banners.
    ("ua-windows", "http", "user_agent", Contains, "windows nt", Some("workstation"), None, None, Some("windows"), 0.6),
    ("ua-mac", "http", "user_agent", Contains, "macintosh", Some("workstation"), Some("Apple"), None, Some("macos_ios"), 0.6),
    ("ua-iphone", "http", "user_agent", Contains, "iphone", Some("mobile"), Some("Apple"), None, Some("ios"), 0.7),
    ("ua-dalvik", "http", "user_agent", Prefix, "dalvik/", Some("mobile"), None, None, Some("android"), 0.7),
    ("ua-roku", "http", "user_agent", Prefix, "roku/", Some("media_player"), Some("Roku"), None, None, 0.8),
    ("ua-smarttv", "http", "user_agent", Contains, "smart-tv", Some("smart_tv"), None, None, None, 0.7),
    ("ua-tizen", "http", "user_agent", Contains, "tizen", Some("smart_tv"), Some("Samsung"), None, Some("tizen"), 0.6),
    ("ua-webos", "http", "user_agent", Contains, "web0s", Some("smart_tv"), Some("LG"), None, Some("webos"), 0.6),
    ("srv-goahead", "http", "server", Prefix, "goahead", Some("embedded_linux"), None, None, Some("embedded_linux"), 0.35),
    ("srv-boa", "http", "server", Prefix, "boa/", Some("ip_camera"), None, None, Some("embedded_linux"), 0.35),
    ("srv-rompager", "http", "server", Contains, "rompager", Some("embedded_linux"), None, None, Some("embedded_rtos"), 0.35),
    ("srv-hp", "http", "server", Contains, "hp http server", Some("printer"), Some("HP"), None, None, 0.7),
    ("srv-laserjet", "http", "server", Contains, "laserjet", Some("printer"), Some("HP"), Some("$value"), None, 0.75),
    ("srv-axis", "http", "server", Contains, "axis", Some("ip_camera"), Some("Axis Communications"), None, None, 0.6),
    ("srv-windriver", "http", "server", Contains, "windriver", Some("plc"), None, None, Some("vxworks"), 0.3),
    ("srv-codesys", "http", "server", Contains, "codesys", Some("plc"), None, None, None, 0.6),
    ("srv-niagara", "http", "server", Contains, "niagara", Some("bms_controller"), None, None, None, 0.7),
    // mDNS / SSDP.
    ("mdns-ipp", "mdns", "service", Exact, "_ipp._tcp", Some("printer"), None, None, None, 0.75),
    ("mdns-printer", "mdns", "service", Exact, "_printer._tcp", Some("printer"), None, None, None, 0.75),
    ("mdns-pdl", "mdns", "service", Exact, "_pdl-datastream._tcp", Some("printer"), None, None, None, 0.75),
    ("mdns-scanner", "mdns", "service", Exact, "_scanner._tcp", Some("mfp"), None, None, None, 0.6),
    ("mdns-axis", "mdns", "service", Exact, "_axis-video._tcp", Some("ip_camera"), Some("Axis Communications"), None, None, 0.85),
    ("mdns-rtsp", "mdns", "service", Exact, "_rtsp._tcp", Some("ip_camera"), None, None, None, 0.5),
    ("mdns-airplay", "mdns", "service", Exact, "_airplay._tcp", Some("media_player"), Some("Apple"), None, None, 0.5),
    ("mdns-googlecast", "mdns", "service", Exact, "_googlecast._tcp", Some("media_player"), Some("Google"), None, None, 0.7),
    ("mdns-hue", "mdns", "service", Exact, "_hue._tcp", Some("lighting_controller"), Some("Signify"), None, None, 0.8),
    ("mdns-sonos", "mdns", "service", Exact, "_sonos._tcp", Some("smart_speaker"), Some("Sonos"), None, None, 0.85),
    ("mdns-hap", "mdns", "service", Exact, "_hap._tcp", Some("iot_sensor"), None, None, None, 0.45),
    ("mdns-matter", "mdns", "service", Exact, "_matter._tcp", Some("iot_sensor"), None, None, None, 0.45),
    ("mdns-workstation", "mdns", "service", Exact, "_workstation._tcp", Some("workstation"), None, None, Some("linux"), 0.45),
    ("mdns-model", "mdns", "model", Glob, "*", None, None, Some("$value"), None, 0.6),
    ("ssdp-renderer", "ssdp", "device_type", Contains, "mediarenderer", Some("media_player"), None, None, None, 0.55),
    ("ssdp-camera", "ssdp", "device_type", Contains, "networkcamera", Some("ip_camera"), None, None, None, 0.65),
    ("ssdp-printer", "ssdp", "device_type", Contains, "printer", Some("printer"), None, None, None, 0.6),
    // LLDP / CDP.
    ("lldp-phone", "lldp", "capability", Exact, "telephone", Some("voip_phone"), None, None, None, 0.75),
    ("lldp-ap", "lldp", "capability", Exact, "wlan_ap", Some("wireless_ap"), None, None, None, 0.8),
    ("lldp-router", "lldp", "capability", Exact, "router", Some("router"), None, None, None, 0.6),
    ("lldp-bridge", "lldp", "capability", Exact, "bridge", Some("switch"), None, None, None, 0.55),
    ("lldp-cpu", "lldp", "description", Contains, "cpu", Some("plc"), None, Some("$value"), None, 0.55),
    ("lldp-scalance", "lldp", "description", Contains, "scalance", Some("industrial_switch"), Some("Siemens"), Some("$value"), None, 0.8),
    ("lldp-simatic", "lldp", "description", Contains, "simatic", Some("plc"), Some("Siemens"), Some("$value"), None, 0.75),
    ("lldp-1756", "lldp", "description", Contains, "1756-", Some("plc"), Some("Rockwell Automation"), Some("$value"), None, 0.75),
    ("lldp-stratix", "lldp", "description", Contains, "stratix", Some("industrial_switch"), Some("Rockwell Automation"), Some("$value"), None, 0.8),
    ("cdp-phone", "cdp", "platform", Contains, "ip phone", Some("voip_phone"), Some("Cisco"), Some("$value"), None, 0.9),
    ("cdp-ap", "cdp", "platform", Contains, "air-", Some("wireless_ap"), Some("Cisco"), Some("$value"), None, 0.8),
    ("cdp-switch", "cdp", "capability", Exact, "bridge", Some("switch"), Some("Cisco"), None, None, 0.6),
    ("cdp-router", "cdp", "capability", Exact, "router", Some("router"), Some("Cisco"), None, None, 0.6),
    ("cdp-telephone", "cdp", "capability", Exact, "telephone", Some("voip_phone"), Some("Cisco"), None, None, 0.75),
    // Listening services.
    ("svc-rtsp", "service", "listen", Exact, "tcp:554", Some("ip_camera"), None, None, None, 0.5),
    ("svc-jetdirect", "service", "listen", Exact, "tcp:9100", Some("printer"), None, None, None, 0.65),
    ("svc-ipp", "service", "listen", Exact, "tcp:631", Some("printer"), None, None, None, 0.5),
    ("svc-lpd", "service", "listen", Exact, "tcp:515", Some("printer"), None, None, None, 0.5),
    ("svc-sip", "service", "listen", Exact, "tcp:5060", Some("voip_phone"), None, None, None, 0.45),
    ("svc-dicom", "service", "listen", Exact, "tcp:104", Some("imaging_modality"), None, None, None, 0.7),
    ("svc-hl7", "service", "listen", Exact, "tcp:2575", Some("clinical_workstation"), None, None, None, 0.5),
    ("svc-mqtt", "service", "listen", Exact, "tcp:1883", Some("mqtt_broker"), None, None, None, 0.6),
    ("svc-rdp", "service", "listen", Exact, "tcp:3389", Some("workstation"), None, None, Some("windows"), 0.5),
    ("svc-smb", "service", "listen", Exact, "tcp:445", Some("workstation"), None, None, Some("windows"), 0.35),
    ("svc-ssh", "service", "listen", Exact, "tcp:22", None, None, None, Some("linux"), 0.3),
    ("svc-modbus", "service", "listen", Exact, "tcp:502", Some("plc"), None, None, None, 0.55),
    ("svc-s7", "service", "listen", Exact, "tcp:102", Some("plc"), Some("Siemens"), None, None, 0.6),
    ("svc-enip", "service", "listen", Exact, "tcp:44818", Some("plc"), None, None, None, 0.55),
    ("svc-dnp3", "service", "listen", Exact, "tcp:20000", Some("rtu"), None, None, None, 0.6),
    ("svc-iec104", "service", "listen", Exact, "tcp:2404", Some("rtu"), None, None, None, 0.6),
    ("svc-opcua", "service", "listen", Exact, "tcp:4840", Some("scada_server"), None, None, None, 0.4),
    ("svc-amqp", "service", "listen", Exact, "tcp:5672", Some("mqtt_broker"), None, None, None, 0.55),
    ("svc-bacnet", "service", "listen", Exact, "udp:47808", Some("bms_controller"), None, None, None, 0.5),
    // Industrial protocol roles and identity.
    ("proto-modbus-server", "protocol", "role", Exact, "modbus:server", Some("plc"), None, None, None, 0.65),
    ("proto-s7-server", "protocol", "role", Exact, "s7comm:server", Some("plc"), Some("Siemens"), None, None, 0.8),
    ("proto-enip-server", "protocol", "role", Exact, "enip:server", Some("plc"), None, None, None, 0.6),
    ("proto-dnp3-server", "protocol", "role", Exact, "dnp3:server", Some("rtu"), None, None, None, 0.75),
    ("proto-iec104-server", "protocol", "role", Exact, "iec104:server", Some("rtu"), None, None, None, 0.75),
    ("proto-bacnet-server", "protocol", "role", Exact, "bacnet:server", Some("bms_controller"), None, None, None, 0.7),
    ("proto-bacnet-client", "protocol", "role", Exact, "bacnet:client", Some("bms_controller"), None, None, None, 0.4),
    ("proto-profinet-server", "protocol", "role", Exact, "profinet:server", Some("io_module"), None, None, None, 0.5),
    ("proto-opcua-server", "protocol", "role", Exact, "opcua:server", Some("scada_server"), None, None, None, 0.45),
    ("proto-mqtt-server", "protocol", "role", Exact, "mqtt:server", Some("mqtt_broker"), None, None, None, 0.7),
    ("proto-mqtt-client", "protocol", "role", Exact, "mqtt:client", Some("iot_sensor"), None, None, None, 0.4),
    ("proto-amqp-server", "protocol", "role", Exact, "amqp:server", Some("mqtt_broker"), None, None, None, 0.6),
    ("proto-modbus-client", "protocol", "role", Exact, "modbus:client", Some("hmi"), None, None, None, 0.4),
    ("proto-s7-client", "protocol", "role", Exact, "s7comm:client", Some("hmi"), None, None, None, 0.35),
    ("proto-enip-client", "protocol", "role", Exact, "enip:client", Some("hmi"), None, None, None, 0.35),
    ("proto-dnp3-client", "protocol", "role", Exact, "dnp3:client", Some("scada_server"), None, None, None, 0.55),
    ("proto-iec104-client", "protocol", "role", Exact, "iec104:client", Some("scada_server"), None, None, None, 0.55),
    ("proto-engineering", "protocol", "engineering", Glob, "*", Some("engineering_workstation"), None, None, None, 0.85),
    ("pid-vendor", "protocol_identity", "vendor", Glob, "*", None, Some("$value"), None, None, 0.9),
    ("pid-enip-1", "protocol_identity", "vendor", Exact, "enip-vendor-1", Some("plc"), Some("Rockwell Automation"), None, None, 0.9),
    ("pid-product", "protocol_identity", "product", Glob, "*", None, None, Some("$value"), None, 0.9),
    ("pid-1756", "protocol_identity", "product", Prefix, "1756-l", Some("plc"), Some("Rockwell Automation"), None, None, 0.9),
    ("pid-6es7", "protocol_identity", "product", Prefix, "6es7", Some("plc"), Some("Siemens"), None, None, 0.9),
    ("pid-ups", "protocol_identity", "product", Contains, "ups", Some("ups"), None, None, None, 0.6),
    ("pid-pdu", "protocol_identity", "product", Contains, "rack pdu", Some("pdu"), None, None, None, 0.6),
    // Behaviour.
    ("beh-engineering", "behaviour", "engineering_client", Glob, "*", Some("engineering_workstation"), None, None, None, 0.8),
    ("beh-polls", "behaviour", "polls_controllers", Exact, "many", Some("scada_server"), None, None, None, 0.6),
    ("beh-dicom", "behaviour", "serves", Exact, "dicom", Some("imaging_modality"), None, None, None, 0.7),
    ("beh-hl7", "behaviour", "serves", Exact, "hl7", Some("clinical_workstation"), None, None, None, 0.45),
    ("beh-rtsp", "behaviour", "serves", Exact, "rtsp", Some("ip_camera"), None, None, None, 0.6),
    ("beh-printing", "behaviour", "serves", Exact, "printing", Some("printer"), None, None, None, 0.6),
    ("beh-sip", "behaviour", "serves", Exact, "sip", Some("voip_phone"), None, None, None, 0.5),
    // TCP OS hints.
    ("tcp-windows", "tcp", "os_hint", Exact, "windows", None, None, None, Some("windows"), 0.5),
    ("tcp-linux", "tcp", "os_hint", Exact, "linux", None, None, None, Some("linux"), 0.45),
    ("tcp-apple", "tcp", "os_hint", Exact, "macos_ios", None, None, None, Some("macos_ios"), 0.45),
    ("tcp-rtos", "tcp", "os_hint", Exact, "embedded_rtos", None, None, None, Some("embedded_rtos"), 0.4),
    // Integration assertions (branch inventory, CMDB imports): weighted by the integration.
    ("asserted-type", "asserted", "device_type", Glob, "*", Some("$value"), None, None, None, 0.7),
    ("asserted-vendor", "asserted", "vendor", Glob, "*", None, Some("$value"), None, None, 0.7),
    ("asserted-model", "asserted", "model", Glob, "*", None, None, Some("$value"), None, 0.7),
    ("asserted-os", "asserted", "os", Glob, "*", None, None, None, Some("$value"), 0.7),
];

pub fn builtin_rules() -> Vec<Rule> {
    BUILTIN
        .iter()
        .map(|r| Rule {
            id: r.0.into(),
            source: r.1.into(),
            field: r.2.into(),
            kind: r.3,
            pattern: r.4.into(),
            device_type: r.5.map(String::from),
            vendor: r.6.map(String::from),
            model: r.7.map(String::from),
            os: r.8.map(String::from),
            weight: r.9,
            origin: "builtin".into(),
        })
        .collect()
}

/// Vendor names for protocol-disclosed numeric vendor identifiers.
pub fn protocol_vendor_name(v: &str) -> Option<&'static str> {
    match v {
        "enip-vendor-1" => Some("Rockwell Automation"),
        "profinet-vendor-002a" => Some("Siemens"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub rule_id: String,
    pub origin: String,
    pub source: String,
    pub field: String,
    pub value: String,
    pub dimension: String,
    pub vote: String,
    pub weight: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dimension {
    pub value: Option<String>,
    pub confidence: f64,
    /// Other candidates with their support (conflicting evidence).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<(String, f64)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Classification {
    pub device_type: String,
    pub category: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub os: Option<String>,
    pub firmware: Option<String>,
    /// Confidence of the device type (0..1).
    pub confidence: f64,
    pub tier: String,
    pub dimensions: BTreeMap<String, Dimension>,
    pub evidence: Vec<Evidence>,
    pub conflicts: Vec<String>,
    pub classifier_version: String,
    pub ruleset_hash: String,
    /// `classifier` or `override`.
    pub source: String,
    pub fact_count: usize,
}

pub fn tier(confidence: f64) -> &'static str {
    if confidence >= 0.90 {
        "high"
    } else if confidence >= 0.70 {
        "medium"
    } else {
        "low"
    }
}

/// Fingerprint of a rule set (reproducibility of decisions).
pub fn ruleset_hash(rules: &[Rule]) -> String {
    let mut h = Sha256::new();
    h.update(CLASSIFIER_VERSION.as_bytes());
    for r in rules {
        h.update(serde_json::to_vec(r).unwrap_or_default());
    }
    format!("sha256:{}", &hex::encode(h.finalize())[..16])
}

/// A prepared classifier: the built-in library plus tenant rules.
#[derive(Debug, Clone)]
pub struct Classifier {
    rules: Vec<Rule>,
    hash: String,
}

impl Default for Classifier {
    fn default() -> Self {
        Classifier::new(vec![])
    }
}

impl Classifier {
    /// Tenant rules (custom, learned) are placed first: they win ties.
    pub fn new(tenant_rules: Vec<Rule>) -> Classifier {
        let mut rules: Vec<Rule> = tenant_rules.into_iter().filter(|r| r.validate().is_ok()).collect();
        rules.extend(builtin_rules());
        let hash = ruleset_hash(&rules);
        Classifier { rules, hash }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn classify(&self, facts: &BTreeSet<Fact>) -> Classification {
        // dimension -> value -> source -> best weight
        let mut votes: BTreeMap<&str, BTreeMap<String, BTreeMap<String, (f64, usize)>>> = BTreeMap::new();
        let mut evidence = vec![];
        for f in facts {
            for (ri, r) in self.rules.iter().enumerate() {
                if !r.matches(f) {
                    continue;
                }
                let mut dims: Vec<(&str, String)> = vec![];
                let resolve = |v: &String| if v == "$value" { f.value.clone() } else { v.clone() };
                if let Some(t) = &r.device_type {
                    let t = resolve(t);
                    if taxonomy::is_known(&t) {
                        dims.push(("device_type", t));
                    }
                }
                if let Some(v) = &r.vendor {
                    let mut v = resolve(v);
                    if let Some(n) = protocol_vendor_name(&v.to_ascii_lowercase()) {
                        v = n.to_string();
                    }
                    dims.push(("vendor", v));
                }
                if let Some(v) = &r.model {
                    dims.push(("model", clip(&resolve(v), 128)));
                }
                if let Some(v) = &r.os {
                    dims.push(("os", resolve(v)));
                }
                // Integration-asserted facts carry their own confidence via weight.
                let source = f.source.split(':').next().unwrap_or("").to_string();
                for (d, v) in dims {
                    if v.is_empty() {
                        continue;
                    }
                    let by_src = votes.entry(d).or_default().entry(v.clone()).or_default();
                    let e = by_src.entry(source.clone()).or_insert((0.0, ri));
                    if r.weight > e.0 || (r.weight == e.0 && ri < e.1) {
                        *e = (r.weight, ri);
                    }
                    evidence.push(Evidence {
                        rule_id: r.id.clone(),
                        origin: r.origin.clone(),
                        source: f.source.clone(),
                        field: f.field.clone(),
                        value: f.value.clone(),
                        dimension: d.to_string(),
                        vote: v,
                        weight: r.weight,
                    });
                }
            }
        }
        let mut dimensions = BTreeMap::new();
        let mut conflicts = vec![];
        for d in ["device_type", "vendor", "model", "os"] {
            let mut cands: Vec<(String, f64, usize)> = votes
                .get(d)
                .map(|m| {
                    m.iter()
                        .map(|(v, srcs)| {
                            let support = 1.0 - srcs.values().map(|(w, _)| 1.0 - w).product::<f64>();
                            // Lowest rule index among supporters: tenant rules first.
                            let pri = srcs.values().map(|(_, i)| *i).min().unwrap_or(usize::MAX);
                            (v.clone(), support, pri)
                        })
                        .collect()
                })
                .unwrap_or_default();
            cands.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then(a.2.cmp(&b.2)).then(a.0.cmp(&b.0)));
            let dim = match cands.first() {
                Some((v, s, _)) => {
                    let opposing = cands.get(1).map(|c| c.1).unwrap_or(0.0);
                    if opposing > 0.3 && d == "device_type" {
                        conflicts.push(format!("{d}: {v} vs {}", cands[1].0));
                    }
                    let conf = (s * (1.0 - 0.5 * opposing)).clamp(0.0, 1.0);
                    Dimension {
                        value: Some(v.clone()),
                        confidence: (conf * 1000.0).round() / 1000.0,
                        alternatives: cands.iter().skip(1).take(4).map(|c| (c.0.clone(), (c.1 * 1000.0).round() / 1000.0)).collect(),
                    }
                }
                None => Dimension { value: None, confidence: 0.0, alternatives: vec![] },
            };
            dimensions.insert(d.to_string(), dim);
        }
        let td = &dimensions["device_type"];
        let (device_type, confidence) = match &td.value {
            Some(t) if td.confidence >= MIN_TYPE_SUPPORT => (t.clone(), td.confidence),
            _ => ("unknown".to_string(), td.confidence.min(MIN_TYPE_SUPPORT)),
        };
        let firmware = facts.iter().find(|f| f.source == "protocol_identity" && f.field == "firmware").map(|f| f.value.clone()).or_else(|| firmware_from_text(facts));
        evidence.sort_by(|a, b| (&a.dimension, &a.rule_id, &a.value).cmp(&(&b.dimension, &b.rule_id, &b.value)));
        evidence.dedup();
        evidence.truncate(64);
        Classification {
            category: taxonomy::get(&device_type).category.to_string(),
            device_type,
            vendor: dimensions["vendor"].value.clone(),
            model: dimensions["model"].value.clone(),
            os: dimensions["os"].value.clone(),
            firmware,
            tier: tier(confidence).into(),
            confidence,
            dimensions,
            evidence,
            conflicts,
            classifier_version: CLASSIFIER_VERSION.into(),
            ruleset_hash: self.hash.clone(),
            source: "classifier".into(),
            fact_count: facts.len(),
        }
    }
}

/// Firmware version mentioned in LLDP/CDP/SNMP descriptions ("FW V2.9.4",
/// "Version 15.2(7)E").
pub fn firmware_from_text(facts: &BTreeSet<Fact>) -> Option<String> {
    for f in facts {
        if !matches!((f.source.as_str(), f.field.as_str()), ("lldp", "description") | ("cdp", "software") | ("protocol_identity", "product")) {
            continue;
        }
        let low = f.value.to_ascii_lowercase();
        for key in ["fw v", "firmware v", "firmware ", "version ", "fw ", " v"] {
            if let Some(i) = low.find(key) {
                let rest = &f.value[i + key.len()..];
                let ver: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '(' | ')' | '_')).collect();
                if ver.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) && ver.contains('.') {
                    return Some(ver);
                }
            }
        }
    }
    None
}

/// Administrator override (section 16 override workflow).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Override {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware: Option<String>,
}

impl Override {
    pub fn is_empty(&self) -> bool {
        self.device_type.is_none() && self.vendor.is_none() && self.model.is_none() && self.os.is_none() && self.firmware.is_none()
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(t) = &self.device_type {
            if !taxonomy::is_known(t) {
                return Err("unknown_device_type");
            }
        }
        for v in [&self.vendor, &self.model, &self.os, &self.firmware].into_iter().flatten() {
            if v.trim().is_empty() || v.len() > 128 {
                return Err("invalid_value");
            }
        }
        Ok(())
    }
    /// Apply over a classifier result; overridden dimensions get
    /// confidence 1 and the source becomes `override`.
    pub fn apply(&self, mut c: Classification) -> Classification {
        if self.is_empty() {
            return c;
        }
        if let Some(t) = &self.device_type {
            c.device_type = t.clone();
            c.category = taxonomy::get(t).category.to_string();
            c.confidence = 1.0;
            c.tier = "high".into();
        }
        for (d, v) in [("vendor", &self.vendor), ("model", &self.model), ("os", &self.os)] {
            if let Some(v) = v {
                c.dimensions.insert(d.into(), Dimension { value: Some(v.clone()), confidence: 1.0, alternatives: vec![] });
            }
        }
        c.vendor = self.vendor.clone().or(c.vendor);
        c.model = self.model.clone().or(c.model);
        c.os = self.os.clone().or(c.os);
        c.firmware = self.firmware.clone().or(c.firmware);
        c.source = "override".into();
        c
    }
}

/// Learn tenant rules from confirmed devices (fingerprint propagation,
/// AE-IOT-0005): a TLS fingerprint or DHCP parameter list shared by at
/// least `min_devices` high-confidence devices of one type, and by no
/// device of another type, becomes a `learned` rule.
pub fn learn_rules(devices: &[(BTreeSet<Fact>, String, f64)], min_devices: usize) -> Vec<Rule> {
    let mut by_fact: BTreeMap<(String, String, String), BTreeMap<String, usize>> = BTreeMap::new();
    for (facts, ty, conf) in devices {
        if *conf < 0.9 || ty == "unknown" {
            continue;
        }
        for f in facts {
            if (f.source == "tls" && f.field == "fingerprint") || (f.source == "dhcp" && f.field == "prl") {
                *by_fact.entry((f.source.clone(), f.field.clone(), f.value.clone())).or_default().entry(ty.clone()).or_default() += 1;
            }
        }
    }
    let mut out = vec![];
    for ((source, field, value), types) in by_fact {
        if types.len() == 1 {
            let (ty, n) = types.into_iter().next().expect("one type");
            if n >= min_devices {
                out.push(Rule {
                    id: format!("learned-{source}-{}", &hex::encode(Sha256::digest(value.as_bytes()))[..12]),
                    source,
                    field,
                    kind: Match::Exact,
                    pattern: value,
                    device_type: Some(ty),
                    vendor: None,
                    model: None,
                    os: None,
                    weight: (0.5 + 0.05 * n as f64).min(0.85),
                    origin: "learned".into(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{IdentityHints, ProtoEvent, Protocol};

    fn classify(mac: &str, signals: Vec<Signal>) -> Classification {
        Classifier::default().classify(&facts(Some(mac), &signals, &OuiTable::default()))
    }

    #[test]
    fn plc_from_oui_protocol_and_identity() {
        let mut ev = ProtoEvent::new(Protocol::Enip, "list_identity", 0x63, OpClass::Read);
        ev.identity = IdentityHints { vendor: Some("enip-vendor-1".into()), product: Some("1756-L83E/B".into()), firmware: Some("33.011".into()), ..Default::default() };
        let c = classify("00:1d:9c:00:00:01", vec![Signal::Service { transport: "tcp".into(), port: 44818 }, Signal::Protocol { event: ev, server: true }]);
        assert_eq!(c.device_type, "plc");
        assert_eq!(c.category, "industrial_control");
        assert_eq!(c.vendor.as_deref(), Some("Rockwell Automation"));
        assert_eq!(c.model.as_deref(), Some("1756-L83E/B"));
        assert_eq!(c.firmware.as_deref(), Some("33.011"));
        assert!(c.confidence >= 0.9, "{}", c.confidence);
        assert_eq!(c.tier, "high");
        assert!(c.evidence.iter().any(|e| e.rule_id == "pid-1756"));
    }

    #[test]
    fn camera_printer_phone_and_unknown() {
        let cam = classify("00:40:8c:01:02:03", vec![Signal::Dhcp { hostname: Some("AXIS-ACCC8E".into()), vendor_class: None, prl: None, requested_ip: None, client_id: None }]);
        assert_eq!((cam.device_type.as_str(), cam.vendor.as_deref()), ("ip_camera", Some("Axis Communications")));
        let pr = classify(
            "02:11:22:33:44:55",
            vec![Signal::Mdns { services: vec!["_ipp._tcp".into()], instance: None, model: Some("LaserPro 400".into()) }, Signal::Service { transport: "tcp".into(), port: 9100 }],
        );
        assert_eq!((pr.device_type.as_str(), pr.model.as_deref()), ("printer", Some("LaserPro 400")));
        let ph = classify(
            "00:1b:54:00:00:01",
            vec![Signal::Cdp { device_id: Some("SEP001B54000001".into()), platform: Some("Cisco IP Phone 8851".into()), software: None, capabilities: vec!["telephone".into()] }],
        );
        assert_eq!(ph.device_type, "voip_phone");
        let unk = classify("02:00:00:00:00:01", vec![Signal::Dns { query: "example.org".into() }]);
        assert_eq!((unk.device_type.as_str(), unk.category.as_str(), unk.tier.as_str()), ("unknown", "unknown", "low"));
    }

    #[test]
    fn deterministic_and_conflicts_lower_confidence() {
        let s = vec![
            Signal::Dhcp { hostname: Some("plc-line-4".into()), vendor_class: Some("MSFT 5.0".into()), prl: None, requested_ip: None, client_id: None },
            Signal::Http { user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64)".into()), server: None, host: None, basic_auth: false },
        ];
        let a = classify("02:00:00:00:00:02", s.clone());
        let b = classify("02:00:00:00:00:02", s.into_iter().rev().collect());
        assert_eq!(a, b, "order of evidence does not change the result");
        assert_eq!(a.device_type, "workstation");
        assert!(!a.conflicts.is_empty(), "plc vs workstation conflict is reported");
        let pure = classify(
            "02:00:00:00:00:02",
            vec![
                Signal::Http { user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64)".into()), server: None, host: None, basic_auth: false },
                Signal::Dhcp { hostname: None, vendor_class: Some("MSFT 5.0".into()), prl: None, requested_ip: None, client_id: None },
            ],
        );
        assert!(pure.confidence > a.confidence);
    }

    #[test]
    fn tenant_rules_override_and_learning() {
        let custom = Rule {
            id: "c1".into(),
            source: "dns".into(),
            field: "query".into(),
            kind: Match::Suffix,
            pattern: "acme-pumps.example".into(),
            device_type: Some("infusion_pump".into()),
            vendor: Some("Acme Medical".into()),
            model: None,
            os: None,
            weight: 0.9,
            origin: "custom".into(),
        };
        assert!(custom.validate().is_ok());
        let cl = Classifier::new(vec![custom.clone()]);
        let c = cl.classify(&facts(Some("02:00:00:00:00:03"), &[Signal::Dns { query: "telemetry.acme-pumps.example".into() }], &OuiTable::default()));
        assert_eq!((c.device_type.as_str(), c.category.as_str()), ("infusion_pump", "medical"));
        assert_ne!(cl.hash(), Classifier::default().hash());
        let o = Override { device_type: Some("patient_monitor".into()), vendor: Some("Acme".into()), ..Default::default() };
        let c2 = o.apply(c);
        assert_eq!((c2.device_type.as_str(), c2.source.as_str(), c2.confidence), ("patient_monitor", "override", 1.0));
        assert!(Override { device_type: Some("toaster".into()), ..Default::default() }.validate().is_err());
        let bad = Rule { weight: 1.5, ..custom };
        assert_eq!(bad.validate(), Err("weight_out_of_range"));
        let fp = fact("tls", "fingerprint", "abc");
        let devs: Vec<(BTreeSet<Fact>, String, f64)> = (0..3).map(|_| ([fp.clone()].into_iter().collect(), "ip_camera".to_string(), 0.95)).collect();
        let learned = learn_rules(&devs, 3);
        assert_eq!(learned.len(), 1);
        assert_eq!(learned[0].device_type.as_deref(), Some("ip_camera"));
    }

    #[test]
    fn behaviour_and_firmware_text() {
        let flows = vec![Flow {
            peer_ip: "10.0.0.5".into(),
            peer_mac: None,
            transport: "tcp".into(),
            port: 102,
            outbound: true,
            packets: 4,
            bytes: 400,
            protocol: Some(Protocol::S7comm),
            max_op: Some(OpClass::Program),
            operations: vec![],
        }];
        let bf = behaviour_facts(&flows);
        let c = Classifier::default().classify(&bf);
        assert_eq!(c.device_type, "engineering_workstation");
        let mut f = BTreeSet::new();
        f.insert(fact("lldp", "description", "Controller CPU 1516-3 PN/DP, FW V2.9.4"));
        assert_eq!(firmware_from_text(&f).as_deref(), Some("2.9.4"));
        assert!(glob("sep????", "sep1234") && !glob("sep????", "sep12"));
    }
}
