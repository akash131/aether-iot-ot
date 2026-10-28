//! Vulnerability and exposure context (ZTE-IOT sections 63 Vulnerability
//! Context Ingestion, 64 CVE/CPE Mapping, 65 Firmware/Version Intelligence,
//! 66 End-Of-Life Device Risk; AE-IOT-0015 vulnerability acknowledgement,
//! AE-IOT-0016 cleartext credential findings).
//!
//! Advisory knowledge sits behind the [`VulnFeed`] trait so commercial or
//! national feeds can be plugged in; [`OfflineFeed`] reads a JSON document
//! (the repository ships a small **sample** feed with synthetic advisory
//! identifiers — it is test data, not real vulnerability intelligence).
//! Devices are mapped to CPE 2.3 names from their classification and
//! firmware, versions are compared segment-wise (numeric segments
//! numerically), and findings are produced for vulnerabilities, end of
//! life, insecure protocols and cleartext / default credentials.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Compare version strings ("2.9.4" < "2.10", "v1.2a" vs "1.2b").
pub fn cmp_version(a: &str, b: &str) -> Ordering {
    fn segs(s: &str) -> Vec<String> {
        s.trim_start_matches(['v', 'V']).split(['.', '-', '_', '(', ')', ' ']).filter(|x| !x.is_empty()).map(|x| x.to_ascii_lowercase()).collect()
    }
    let (x, y) = (segs(a), segs(b));
    for i in 0..x.len().max(y.len()) {
        let (p, q) = (x.get(i).map(|s| s.as_str()).unwrap_or("0"), y.get(i).map(|s| s.as_str()).unwrap_or("0"));
        let pn: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
        let qn: String = q.chars().take_while(|c| c.is_ascii_digit()).collect();
        let o = match (pn.parse::<u64>(), qn.parse::<u64>()) {
            (Ok(m), Ok(n)) => m.cmp(&n).then_with(|| p[pn.len()..].cmp(&q[qn.len()..])),
            _ => p.cmp(q),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

fn norm(s: &str) -> String {
    s.trim().to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect::<String>().trim_matches('_').to_string()
}

/// CPE 2.3 formatted names for a device: hardware and firmware/OS parts.
pub fn cpe(vendor: &str, model: &str, firmware: Option<&str>) -> Vec<String> {
    let (v, m) = (norm(vendor), norm(model));
    if v.is_empty() || m.is_empty() {
        return vec![];
    }
    let mut out = vec![format!("cpe:2.3:h:{v}:{m}:-:*:*:*:*:*:*:*")];
    if let Some(f) = firmware.map(norm).filter(|f| !f.is_empty()) {
        out.push(format!("cpe:2.3:o:{v}:{m}_firmware:{f}:*:*:*:*:*:*:*"));
    }
    out
}

/// One advisory of a feed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub vendor: String,
    /// Product/model pattern: case-insensitive prefix match ("*" for any).
    pub product: String,
    /// Affected when `version_start <= firmware < version_end` (bounds optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_end: Option<String>,
    pub cvss: f64,
    #[serde(default)]
    pub known_exploited: bool,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Exploitation requires network access to this protocol/port (exposure context).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EolEntry {
    pub vendor: String,
    pub product: String,
    pub end_of_support: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DefaultCredential {
    pub vendor: String,
    pub product: String,
    /// Service where the vendor default applies (http, telnet, snmp, ftp...).
    pub service: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FeedDocument {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub advisories: Vec<Advisory>,
    #[serde(default)]
    pub end_of_life: Vec<EolEntry>,
    #[serde(default)]
    pub default_credentials: Vec<DefaultCredential>,
}

/// Source of vulnerability knowledge.
pub trait VulnFeed: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn advisories(&self, vendor: &str, model: &str, firmware: Option<&str>) -> Vec<Advisory>;
    fn end_of_life(&self, vendor: &str, model: &str) -> Option<EolEntry>;
    fn default_credentials(&self, vendor: &str, model: &str) -> Vec<DefaultCredential>;
}

fn product_matches(pattern: &str, model: &str) -> bool {
    pattern == "*" || model.to_ascii_lowercase().starts_with(&pattern.to_ascii_lowercase())
}

fn vendor_matches(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    !a.is_empty() && !b.is_empty() && (a == b || a.starts_with(&b) || b.starts_with(&a))
}

/// A feed held in memory from a JSON document.
#[derive(Debug, Clone, Default)]
pub struct OfflineFeed {
    doc: FeedDocument,
}

pub const SAMPLE_FEED: &str = include_str!("../data/vuln_feed.sample.json");

impl OfflineFeed {
    pub fn from_json(s: &str) -> Result<OfflineFeed, String> {
        let doc: FeedDocument = serde_json::from_str(s).map_err(|e| format!("invalid feed: {e}"))?;
        if doc.advisories.len() > 200_000 {
            return Err("feed too large".into());
        }
        for a in &doc.advisories {
            if !(0.0..=10.0).contains(&a.cvss) || a.id.is_empty() {
                return Err(format!("invalid advisory {}", a.id));
            }
        }
        Ok(OfflineFeed { doc })
    }
    pub fn sample() -> OfflineFeed {
        OfflineFeed::from_json(SAMPLE_FEED).expect("bundled sample feed is valid")
    }
    pub fn document(&self) -> &FeedDocument {
        &self.doc
    }
}

impl VulnFeed for OfflineFeed {
    fn name(&self) -> &str {
        &self.doc.name
    }
    fn version(&self) -> &str {
        &self.doc.version
    }
    fn advisories(&self, vendor: &str, model: &str, firmware: Option<&str>) -> Vec<Advisory> {
        self.doc
            .advisories
            .iter()
            .filter(|a| vendor_matches(&a.vendor, vendor) && product_matches(&a.product, model))
            .filter(|a| match firmware {
                Some(f) => {
                    a.version_start.as_deref().map(|s| cmp_version(f, s) != Ordering::Less).unwrap_or(true)
                        && a.version_end.as_deref().map(|e| cmp_version(f, e) == Ordering::Less).unwrap_or(true)
                }
                // Unknown firmware: only advisories affecting every version apply.
                None => a.version_start.is_none() && a.version_end.is_none(),
            })
            .cloned()
            .collect()
    }
    fn end_of_life(&self, vendor: &str, model: &str) -> Option<EolEntry> {
        self.doc.end_of_life.iter().find(|e| vendor_matches(&e.vendor, vendor) && product_matches(&e.product, model)).cloned()
    }
    fn default_credentials(&self, vendor: &str, model: &str) -> Vec<DefaultCredential> {
        self.doc.default_credentials.iter().filter(|d| vendor_matches(&d.vendor, vendor) && product_matches(&d.product, model)).cloned().collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Vulnerability,
    EndOfLife,
    InsecureProtocol,
    CleartextCredentials,
    DefaultCredentials,
}

impl FindingKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingKind::Vulnerability => "vulnerability",
            FindingKind::EndOfLife => "end_of_life",
            FindingKind::InsecureProtocol => "insecure_protocol",
            FindingKind::CleartextCredentials => "cleartext_credentials",
            FindingKind::DefaultCredentials => "default_credentials",
        }
    }
}

pub const FINDING_KINDS: &[&str] = &["vulnerability", "end_of_life", "insecure_protocol", "cleartext_credentials", "default_credentials"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    /// Stable key per device (dedup across evaluations).
    pub key: String,
    pub title: String,
    /// 0..10.
    pub severity: f64,
    #[serde(default)]
    pub known_exploited: bool,
    pub detail: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Device facts needed for exposure findings.
#[derive(Debug, Clone, Default)]
pub struct ExposureInput<'a> {
    pub vendor: Option<&'a str>,
    pub model: Option<&'a str>,
    pub firmware: Option<&'a str>,
    /// Protocols the device serves or uses in cleartext form.
    pub cleartext_protocols: Vec<String>,
    /// Services where cleartext credentials were observed.
    pub cleartext_credentials: Vec<String>,
    /// Device answers on these services (tcp:23, tcp:80...).
    pub services: Vec<String>,
    /// OPC UA secure channel without security policy seen.
    pub opcua_insecure: bool,
    pub now: chrono::NaiveDate,
}

/// All findings for one device.
pub fn assess(feed: &dyn VulnFeed, d: &ExposureInput<'_>) -> Vec<Finding> {
    let mut out = vec![];
    if let (Some(v), Some(m)) = (d.vendor, d.model) {
        for a in feed.advisories(v, m, d.firmware) {
            out.push(Finding {
                kind: FindingKind::Vulnerability,
                key: format!("vuln:{}", a.id),
                title: format!("{} ({})", a.summary, a.id),
                severity: a.cvss,
                known_exploited: a.known_exploited,
                detail: serde_json::json!({ "advisory": a.id, "aliases": a.aliases, "cvss": a.cvss, "cpe": cpe(v, m, d.firmware), "firmware": d.firmware, "feed": feed.name(), "feed_version": feed.version(), "vector": a.vector }),
                remediation: a.remediation.clone(),
            });
        }
        if let Some(e) = feed.end_of_life(v, m) {
            let past = chrono::NaiveDate::parse_from_str(&e.end_of_support, "%Y-%m-%d").map(|d0| d0 <= d.now).unwrap_or(false);
            out.push(Finding {
                kind: FindingKind::EndOfLife,
                key: format!("eol:{}", norm(&e.product)),
                title: if past {
                    format!("{} {} is past end of support ({})", v, m, e.end_of_support)
                } else {
                    format!("{} {} reaches end of support on {}", v, m, e.end_of_support)
                },
                severity: if past { 7.0 } else { 3.0 },
                known_exploited: false,
                detail: serde_json::json!({ "end_of_support": e.end_of_support, "past": past, "replacement": e.replacement }),
                remediation: e.replacement.map(|r| format!("plan replacement with {r}")),
            });
        }
        for c in feed.default_credentials(v, m) {
            if d.cleartext_credentials.iter().any(|s| s.starts_with(&c.service)) || d.services.iter().any(|s| service_name(s) == c.service) {
                out.push(Finding {
                    kind: FindingKind::DefaultCredentials,
                    key: format!("default_credentials:{}", c.service),
                    title: format!("{} ships with a vendor default credential on {}; verify it was changed", v, c.service),
                    severity: 8.0,
                    known_exploited: false,
                    detail: serde_json::json!({ "service": c.service, "basis": "vendor default credential knowledge and an exposed login service" }),
                    remediation: Some("rotate the device credential and restrict management access".into()),
                });
            }
        }
    }
    for p in &d.cleartext_credentials {
        let default_snmp = p == "snmp_default_community";
        out.push(Finding {
            kind: if default_snmp { FindingKind::DefaultCredentials } else { FindingKind::CleartextCredentials },
            key: format!("cleartext_credentials:{p}"),
            title: if default_snmp { "SNMP uses a well-known default community".to_string() } else { format!("credentials sent in cleartext over {p}") },
            severity: if default_snmp { 8.0 } else { 6.5 },
            known_exploited: false,
            detail: serde_json::json!({ "protocol": p, "credential_retained": false }),
            remediation: Some("use an encrypted management protocol and rotate the exposed credential".into()),
        });
    }
    let mut insecure: Vec<&str> = vec![];
    for s in &d.services {
        match s.as_str() {
            "tcp:23" => insecure.push("telnet"),
            "tcp:21" => insecure.push("ftp"),
            "tcp:80" => insecure.push("http_management"),
            "udp:69" => insecure.push("tftp"),
            _ => {}
        }
    }
    for p in &d.cleartext_protocols {
        insecure.push(p.as_str());
    }
    if d.opcua_insecure {
        insecure.push("opcua_security_none");
    }
    insecure.sort_unstable();
    insecure.dedup();
    for p in insecure {
        let sev = match p {
            "telnet" | "tftp" | "opcua_security_none" => 6.0,
            "modbus" | "dnp3" | "s7comm" | "enip" | "iec104" | "bacnet" | "profinet" => 4.0,
            _ => 3.5,
        };
        out.push(Finding {
            kind: FindingKind::InsecureProtocol,
            key: format!("insecure_protocol:{p}"),
            title: format!("insecure protocol in use: {p}"),
            severity: sev,
            known_exploited: false,
            detail: serde_json::json!({ "protocol": p, "authenticated": false, "encrypted": false }),
            remediation: Some(match p {
                "telnet" => "disable telnet; use SSH".to_string(),
                "ftp" | "tftp" => "disable cleartext file transfer".to_string(),
                "opcua_security_none" => "require Sign or SignAndEncrypt security policies".to_string(),
                _ => "restrict the protocol to authorised peers with segmentation".to_string(),
            }),
        });
    }
    out.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap_or(Ordering::Equal).then(a.key.cmp(&b.key)));
    out
}

fn service_name(s: &str) -> &str {
    match s {
        "tcp:23" => "telnet",
        "tcp:21" => "ftp",
        "tcp:80" | "tcp:8080" | "tcp:443" => "http",
        "udp:161" => "snmp",
        "tcp:22" => "ssh",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering() {
        assert_eq!(cmp_version("2.9.4", "2.10"), Ordering::Less);
        assert_eq!(cmp_version("v20.011", "20.11"), Ordering::Equal);
        assert_eq!(cmp_version("1.2b", "1.2a"), Ordering::Greater);
        assert_eq!(cmp_version("15.2(7)E", "15.2(4)"), Ordering::Greater);
        assert_eq!(cmp_version("3", "3.0.0"), Ordering::Equal);
    }

    #[test]
    fn feed_matching_eol_and_exposure_findings() {
        let feed = OfflineFeed::sample();
        assert!(feed.name().contains("sample"));
        let now = chrono::NaiveDate::from_ymd_opt(2026, 10, 28).unwrap();
        let d = ExposureInput {
            vendor: Some("Rockwell Automation"),
            model: Some("1756-L83E/B"),
            firmware: Some("32.011"),
            cleartext_protocols: vec!["enip".into()],
            cleartext_credentials: vec![],
            services: vec!["tcp:23".into(), "tcp:44818".into()],
            opcua_insecure: false,
            now,
        };
        let f = assess(&feed, &d);
        assert!(f.iter().any(|x| x.kind == FindingKind::Vulnerability && x.key == "vuln:AETHER-SAMPLE-0001"), "{f:?}");
        assert!(!f.iter().any(|x| x.key == "vuln:AETHER-SAMPLE-0002"), "fixed-version advisory does not apply");
        assert!(f.iter().any(|x| x.key == "insecure_protocol:telnet"));
        assert!(f.iter().any(|x| x.key == "insecure_protocol:enip"));
        assert!(f.windows(2).all(|w| w[0].severity >= w[1].severity), "sorted by severity");
        let cam = ExposureInput {
            vendor: Some("Hikvision"),
            model: Some("DS-2CD2043G0"),
            firmware: None,
            services: vec!["tcp:80".into()],
            cleartext_credentials: vec!["http".into(), "snmp_default_community".into()],
            now,
            ..Default::default()
        };
        let f = assess(&feed, &cam);
        assert!(f.iter().any(|x| x.kind == FindingKind::DefaultCredentials && x.key == "default_credentials:http"));
        assert!(f.iter().any(|x| x.key == "cleartext_credentials:snmp_default_community" && x.kind == FindingKind::DefaultCredentials));
        assert!(f.iter().any(|x| x.kind == FindingKind::EndOfLife));
        assert_eq!(cpe("Rockwell Automation", "1756-L83E/B", Some("32.011"))[0], "cpe:2.3:h:rockwell_automation:1756-l83e_b:-:*:*:*:*:*:*:*");
        assert!(OfflineFeed::from_json(r#"{"name":"x","version":"1","advisories":[{"id":"a","vendor":"v","product":"*","cvss":11,"summary":"s"}]}"#).is_err());
    }
}
