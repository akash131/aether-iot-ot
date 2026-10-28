//! Asset identity resolution, deduplication, merge and split (ZTE-IOT
//! sections 17 Asset Identity Lifecycle, 18 Asset Deduplication, 19 Asset
//! Merge And Split; ZTE-IOTDATA-153133/153134; ZTE-IOTINV-153165 identity
//! from multiple signals, never from IP alone; AE-IOT-0004 consolidation of
//! the same device seen by several sensors).
//!
//! Identity keys of an observation, strongest first:
//!
//! 1. protocol-disclosed **serial number** (vendor + serial), unique per
//!    tenant across sites — survives MAC and IP changes and site moves;
//! 2. **globally administered MAC** within the tenant;
//! 3. **DHCP client identifier** hash or **host name** within the site —
//!    links randomised (locally administered) MACs to an existing asset;
//! 4. **IP address** within the site, accepted only together with a
//!    corroborating key (host name or TLS fingerprint) or when the asset has
//!    no other identity; IP-only matches are flagged as weak.
//!
//! The resolver is a pure function over candidate assets; it reports the
//! match, its strength and the change events implied (IP change, site
//! move, MAC change), and proposes merges when two assets share a strong
//! key and splits when one asset presents conflicting strong keys.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Keys held for an existing asset.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetKeys {
    pub id: Uuid,
    pub site: Option<String>,
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub serial: Option<String>,
    pub client_id: Option<String>,
    pub tls_fingerprint: Option<String>,
    pub decommissioned: bool,
    pub merged: bool,
}

/// Keys of one observation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ObsKeys {
    pub site: Option<String>,
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub serial: Option<String>,
    pub client_id: Option<String>,
    pub tls_fingerprint: Option<String>,
}

impl ObsKeys {
    pub fn randomized_mac(&self) -> bool {
        self.mac.as_deref().and_then(crate::packet::Mac::parse).map(|m| m.is_local()).unwrap_or(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    /// IP address only (provisional identity).
    Weak,
    /// Host name / client identifier / IP with corroboration.
    Medium,
    /// MAC (globally administered) or serial.
    Strong,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ChangeEvent {
    IpChanged { from: Option<String>, to: String },
    SiteMoved { from: Option<String>, to: String },
    MacChanged { from: Option<String>, to: String },
    HostnameChanged { from: Option<String>, to: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resolution {
    pub asset: Option<Uuid>,
    pub strength: Option<Strength>,
    pub matched_on: Vec<String>,
    pub changes: Vec<ChangeEvent>,
    /// Other live assets sharing a strong key with this observation.
    pub merge_candidates: Vec<Uuid>,
    /// The matched asset presents a conflicting strong key (split proposal).
    pub split_suspected: bool,
}

fn eq(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => !x.is_empty() && x.eq_ignore_ascii_case(y),
        _ => false,
    }
}

fn same_site(a: &AssetKeys, o: &ObsKeys) -> bool {
    a.site.is_none() || o.site.is_none() || eq(&a.site, &o.site)
}

/// Resolve an observation against candidate assets of the tenant.
pub fn resolve(cands: &[AssetKeys], o: &ObsKeys) -> Resolution {
    let live: Vec<&AssetKeys> = cands.iter().filter(|a| !a.merged).collect();
    let random = o.randomized_mac();
    let mut scored: Vec<(&AssetKeys, Strength, Vec<String>)> = vec![];
    for a in &live {
        let mut on = vec![];
        let mut s: Option<Strength> = None;
        if o.serial.is_some() && eq(&a.serial, &o.serial) {
            on.push("serial".to_string());
            s = Some(Strength::Strong);
        }
        if !random && o.mac.is_some() && eq(&a.mac, &o.mac) {
            on.push("mac".to_string());
            s = Some(Strength::Strong);
        }
        if same_site(a, o) {
            if eq(&a.client_id, &o.client_id) {
                on.push("dhcp_client_id".to_string());
                s = s.max(Some(Strength::Medium));
            }
            if eq(&a.hostname, &o.hostname) {
                on.push("hostname".to_string());
                s = s.max(Some(Strength::Medium));
            }
            if random && o.mac.is_some() && eq(&a.mac, &o.mac) {
                on.push("randomized_mac".to_string());
                s = s.max(Some(Strength::Medium));
            }
            if eq(&a.ip, &o.ip) && eq(&a.site, &o.site) {
                let corroborated = eq(&a.tls_fingerprint, &o.tls_fingerprint) || eq(&a.hostname, &o.hostname);
                // IP alone only matches an asset that has no stronger identity
                // and only when the observation carries none either.
                let neither_has_mac = a.mac.is_none() && o.mac.is_none() && a.serial.is_none();
                if corroborated || neither_has_mac {
                    on.push("ip".to_string());
                    s = s.max(Some(if corroborated { Strength::Medium } else { Strength::Weak }));
                }
            }
        }
        // A conflicting strong key excludes the candidate (different device).
        let mac_conflict = !random && o.mac.is_some() && a.mac.is_some() && !eq(&a.mac, &o.mac) && !on.contains(&"serial".to_string());
        let serial_conflict = o.serial.is_some() && a.serial.is_some() && !eq(&a.serial, &o.serial);
        if let Some(st) = s {
            if (mac_conflict && st < Strength::Strong) || (serial_conflict && !on.contains(&"mac".to_string())) {
                continue;
            }
            scored.push((a, st, on));
        }
    }
    // Strongest, then most keys, then live (not decommissioned), then id.
    scored.sort_by(|x, y| y.1.cmp(&x.1).then(y.2.len().cmp(&x.2.len())).then(x.0.decommissioned.cmp(&y.0.decommissioned)).then(x.0.id.cmp(&y.0.id)));
    let Some((best, st, on)) = scored.first().cloned() else {
        return Resolution { asset: None, strength: None, matched_on: vec![], changes: vec![], merge_candidates: vec![], split_suspected: false };
    };
    let mut changes = vec![];
    if let Some(ip) = &o.ip {
        if !eq(&best.ip, &o.ip) {
            changes.push(ChangeEvent::IpChanged { from: best.ip.clone(), to: ip.clone() });
        }
    }
    if let Some(site) = &o.site {
        if best.site.is_some() && !eq(&best.site, &o.site) {
            changes.push(ChangeEvent::SiteMoved { from: best.site.clone(), to: site.clone() });
        }
    }
    if let Some(m) = &o.mac {
        if best.mac.is_some() && !eq(&best.mac, &o.mac) {
            changes.push(ChangeEvent::MacChanged { from: best.mac.clone(), to: m.clone() });
        }
    }
    if let Some(h) = &o.hostname {
        if best.hostname.is_some() && !eq(&best.hostname, &o.hostname) {
            changes.push(ChangeEvent::HostnameChanged { from: best.hostname.clone(), to: h.clone() });
        }
    }
    let merge_candidates: Vec<Uuid> = scored.iter().skip(1).filter(|(a, s, _)| *s == Strength::Strong && a.id != best.id && !a.decommissioned).map(|(a, _, _)| a.id).collect();
    let split_suspected = o.serial.is_some() && best.serial.is_some() && !eq(&best.serial, &o.serial);
    Resolution { asset: Some(best.id), strength: Some(st), matched_on: on, changes, merge_candidates, split_suspected }
}

/// Keys after merging `from` into `into` (the surviving asset keeps its
/// own keys and inherits missing ones).
pub fn merge_keys(into: &AssetKeys, from: &AssetKeys) -> AssetKeys {
    let pick = |a: &Option<String>, b: &Option<String>| a.clone().or_else(|| b.clone());
    AssetKeys {
        id: into.id,
        site: pick(&into.site, &from.site),
        mac: pick(&into.mac, &from.mac),
        ip: pick(&into.ip, &from.ip),
        hostname: pick(&into.hostname, &from.hostname),
        serial: pick(&into.serial, &from.serial),
        client_id: pick(&into.client_id, &from.client_id),
        tls_fingerprint: pick(&into.tls_fingerprint, &from.tls_fingerprint),
        decommissioned: false,
        merged: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(id: u128, site: &str, mac: Option<&str>, ip: Option<&str>) -> AssetKeys {
        AssetKeys { id: Uuid::from_u128(id), site: Some(site.into()), mac: mac.map(String::from), ip: ip.map(String::from), ..Default::default() }
    }

    fn obs(site: &str, mac: Option<&str>, ip: Option<&str>) -> ObsKeys {
        ObsKeys { site: Some(site.into()), mac: mac.map(String::from), ip: ip.map(String::from), ..Default::default() }
    }

    #[test]
    fn mac_match_with_ip_change_and_site_move() {
        let a = vec![asset(1, "s1", Some("00:1d:9c:00:00:01"), Some("10.0.0.5")), asset(2, "s1", Some("00:1d:9c:00:00:02"), Some("10.0.0.6"))];
        let r = resolve(&a, &obs("s2", Some("00:1d:9c:00:00:01"), Some("10.9.0.7")));
        assert_eq!((r.asset, r.strength), (Some(Uuid::from_u128(1)), Some(Strength::Strong)));
        assert!(r.changes.contains(&ChangeEvent::IpChanged { from: Some("10.0.0.5".into()), to: "10.9.0.7".into() }));
        assert!(r.changes.iter().any(|c| matches!(c, ChangeEvent::SiteMoved { .. })));
    }

    #[test]
    fn ip_alone_never_identifies_a_device_with_a_mac() {
        let a = vec![asset(1, "s1", Some("00:1d:9c:00:00:01"), Some("10.0.0.5"))];
        // Different device took over the address.
        let r = resolve(&a, &obs("s1", Some("00:40:8c:00:00:09"), Some("10.0.0.5")));
        assert_eq!(r.asset, None);
        // Routed device (no MAC) at an address of a MAC-identified asset: no match.
        assert_eq!(resolve(&a, &obs("s1", None, Some("10.0.0.5"))).asset, None);
        // IP-only asset matched weakly by IP-only observation in the same site.
        let b = vec![asset(3, "s1", None, Some("172.16.0.9"))];
        let r = resolve(&b, &obs("s1", None, Some("172.16.0.9")));
        assert_eq!(r.strength, Some(Strength::Weak));
        assert_eq!(resolve(&b, &obs("s2", None, Some("172.16.0.9"))).asset, None, "IP is site-scoped");
    }

    #[test]
    fn randomized_mac_links_by_hostname_and_serial_survives_mac_change() {
        let mut a = asset(1, "s1", Some("02:aa:bb:cc:dd:01"), Some("10.0.0.20"));
        a.hostname = Some("badge-reader-7".into());
        let mut o = obs("s1", Some("02:aa:bb:cc:dd:99"), Some("10.0.0.21"));
        o.hostname = Some("BADGE-READER-7".into());
        let r = resolve(&[a], &o);
        assert_eq!((r.asset, r.strength), (Some(Uuid::from_u128(1)), Some(Strength::Medium)));
        assert!(r.changes.iter().any(|c| matches!(c, ChangeEvent::MacChanged { .. })));
        let mut plc = asset(5, "s1", Some("00:0e:8c:00:00:01"), None);
        plc.serial = Some("S C-123".into());
        let mut o = obs("s1", Some("00:0e:8c:00:00:77"), None);
        o.serial = Some("S C-123".into());
        let r = resolve(&[plc], &o);
        assert_eq!(r.asset, Some(Uuid::from_u128(5)), "module swap keeps the asset by serial");
    }

    #[test]
    fn merge_and_split_proposals() {
        let mut x = asset(1, "s1", Some("00:0e:8c:00:00:01"), None);
        x.serial = Some("SER-1".into());
        let mut y = asset(2, "s2", None, Some("10.2.0.1"));
        y.serial = Some("SER-2".into());
        let mut z = asset(3, "s1", Some("00:0e:8c:00:00:03"), None);
        z.serial = Some("SER-3".into());
        // Observation: MAC of x, serial of z -> x matched on MAC, z shares serial (merge), split suspected on x.
        let mut o = obs("s1", Some("00:0e:8c:00:00:01"), None);
        o.serial = Some("SER-3".into());
        let r = resolve(&[x.clone(), y.clone(), z.clone()], &o);
        assert!(r.asset == Some(x.id) || r.asset == Some(z.id));
        assert!(!r.merge_candidates.is_empty());
        assert!(r.split_suspected);
        let m = merge_keys(&y, &x);
        assert_eq!((m.id, m.mac.as_deref(), m.serial.as_deref()), (y.id, Some("00:0e:8c:00:00:01"), Some("SER-2")));
        // Merged assets are not candidates.
        let mut gone = x.clone();
        gone.merged = true;
        assert_eq!(resolve(&[gone], &obs("s1", Some("00:0e:8c:00:00:01"), None)).asset, None);
    }
}
