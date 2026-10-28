//! Passive fingerprint extraction (ZTE-IOT sections 4, 8–13: passive
//! discovery, DHCP, DNS, MAC/OUI, TLS, HTTP and network-behaviour
//! fingerprinting; Volume 2 "Asset Discovery", "Passive Telemetry").
//!
//! Each submodule turns one kind of traffic into [`Signal`]s. This module
//! holds the MAC/OUI intelligence: a built-in table of vendor prefixes
//! common on enterprise, IoT and OT networks (the full IEEE registry can be
//! loaded at run time with [`OuiTable::parse_ieee`]) and detection of
//! randomised (locally administered) addresses, which carry no vendor
//! information.

pub mod dhcp;
pub mod dns;
pub mod http;
pub mod lldp;
pub mod tls;

pub use crate::model::Signal;
use std::collections::HashMap;

/// Built-in OUI subset: prefix → vendor.
pub const BUILTIN_OUI: &[(&str, &str)] = &[
    ("00:00:bc", "Rockwell Automation"),
    ("00:1d:9c", "Rockwell Automation"),
    ("00:0e:8c", "Siemens"),
    ("00:1b:1b", "Siemens"),
    ("08:00:06", "Siemens"),
    ("00:80:f4", "Schneider Electric"),
    ("00:00:54", "Schneider Electric"),
    ("00:c0:b7", "Schneider Electric (APC)"),
    ("00:a0:45", "Phoenix Contact"),
    ("00:30:de", "WAGO"),
    ("00:01:05", "Beckhoff Automation"),
    ("00:60:65", "B&R Industrial Automation"),
    ("00:90:e8", "Moxa"),
    ("00:80:63", "Hirschmann"),
    ("00:15:7e", "Weidmueller"),
    ("00:20:4a", "Lantronix"),
    ("00:80:a3", "Lantronix"),
    ("00:40:9d", "Digi International"),
    ("00:40:84", "Honeywell"),
    ("00:20:85", "Eaton"),
    ("00:0f:e7", "Lutron Electronics"),
    ("00:06:8e", "HID Global"),
    ("00:09:fb", "Philips Medical Systems"),
    ("00:40:8c", "Axis Communications"),
    ("ac:cc:8e", "Axis Communications"),
    ("b8:a4:4f", "Axis Communications"),
    ("44:19:b6", "Hikvision"),
    ("c0:56:e3", "Hikvision"),
    ("bc:ad:28", "Hikvision"),
    ("3c:ef:8c", "Dahua"),
    ("00:0b:82", "Grandstream"),
    ("00:04:f2", "Polycom"),
    ("64:16:7f", "Polycom"),
    ("00:04:0d", "Avaya"),
    ("00:1b:4f", "Avaya"),
    ("00:10:7f", "Crestron"),
    ("00:00:0c", "Cisco"),
    ("00:1b:54", "Cisco"),
    ("00:00:aa", "Xerox"),
    ("00:00:85", "Canon"),
    ("00:80:77", "Brother"),
    ("00:1b:a9", "Brother"),
    ("00:26:ab", "Seiko Epson"),
    ("00:00:48", "Seiko Epson"),
    ("00:17:c8", "Kyocera"),
    ("00:26:73", "Ricoh"),
    ("00:21:5a", "HP"),
    ("3c:d9:2b", "HP"),
    ("00:1b:78", "HP"),
    ("00:07:4d", "Zebra Technologies"),
    ("00:0b:4f", "Verifone"),
    ("00:03:81", "Ingenico"),
    ("00:17:88", "Signify (Philips Lighting)"),
    ("18:b4:30", "Nest Labs"),
    ("f4:f5:d8", "Google"),
    ("00:0e:58", "Sonos"),
    ("b0:a7:37", "Roku"),
    ("f0:27:2d", "Amazon"),
    ("b8:27:eb", "Raspberry Pi Foundation"),
    ("dc:a6:32", "Raspberry Pi"),
    ("24:0a:c4", "Espressif"),
    ("30:ae:a4", "Espressif"),
    ("a4:cf:12", "Espressif"),
    ("00:12:4b", "Texas Instruments"),
    ("00:04:a3", "Microchip Technology"),
    ("00:1e:c0", "Microchip Technology"),
    ("f0:9f:c2", "Ubiquiti"),
    ("24:a4:3c", "Ubiquiti"),
    ("00:1a:1e", "Aruba Networks"),
    ("00:0c:29", "VMware"),
    ("00:50:56", "VMware"),
    ("00:e0:4c", "Realtek"),
];

/// Vendor prefix table (built-in subset plus tenant/registry entries).
#[derive(Debug, Clone)]
pub struct OuiTable {
    map: HashMap<String, String>,
}

impl Default for OuiTable {
    fn default() -> Self {
        OuiTable { map: BUILTIN_OUI.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() }
    }
}

impl OuiTable {
    /// Vendor of a MAC address; `None` for randomised addresses.
    pub fn vendor(&self, mac: &str) -> Option<&str> {
        let m = crate::packet::Mac::parse(mac)?;
        if m.is_local() {
            return None;
        }
        self.map.get(&m.oui()).map(|s| s.as_str())
    }

    pub fn insert(&mut self, prefix: &str, vendor: &str) -> bool {
        let hex: String = prefix.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase();
        if hex.len() != 6 || vendor.trim().is_empty() {
            return false;
        }
        self.map.insert(format!("{}:{}:{}", &hex[0..2], &hex[2..4], &hex[4..6]), crate::model::clip(vendor, 128));
        true
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Load entries in the IEEE `oui.txt` format (`AA-BB-CC   (hex)\t\tVendor`).
    /// Returns the number of entries loaded.
    pub fn parse_ieee(&mut self, text: &str) -> usize {
        let mut n = 0;
        for line in text.lines().take(1_000_000) {
            if let Some((prefix, rest)) = line.split_once("(hex)") {
                if self.insert(prefix.trim(), rest.trim()) {
                    n += 1;
                }
            }
        }
        n
    }
}

/// Passive OS family from the initial TTL and SYN window (coarse).
pub fn os_from_syn(ttl: u8, window: u16) -> Option<&'static str> {
    let initial = if ttl <= 64 {
        64
    } else if ttl <= 128 {
        128
    } else {
        255
    };
    match (initial, window) {
        (128, 8192) | (128, 64240) | (128, 65535) => Some("windows"),
        (64, 65535) => Some("macos_ios"),
        (64, 29200) | (64, 64240) | (64, 5840) | (64, 14600) => Some("linux"),
        (255, 4128) | (255, 8192) => Some("network_os"),
        (64, 512..=4096) | (255, 512..=2048) => Some("embedded_rtos"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oui_lookup_and_randomised_addresses() {
        let mut t = OuiTable::default();
        assert_eq!(t.vendor("00:1D:9C:12:34:56"), Some("Rockwell Automation"));
        assert_eq!(t.vendor("02:1d:9c:12:34:56"), None, "locally administered addresses carry no vendor");
        assert_eq!(t.parse_ieee("A1-B2-C3   (hex)\t\tExample Industrial\nnoise\n"), 1);
        assert_eq!(t.vendor("a1:b2:c3:00:00:01"), Some("Example Industrial"));
        assert!(!t.insert("zz", "x"));
        let mut seen = std::collections::HashSet::new();
        for (p, _) in BUILTIN_OUI {
            assert!(seen.insert(*p), "duplicate {p}");
            assert_eq!(p.len(), 8);
        }
    }

    #[test]
    fn syn_os_hints() {
        assert_eq!(os_from_syn(127, 64240), Some("windows"));
        assert_eq!(os_from_syn(60, 29200), Some("linux"));
        assert_eq!(os_from_syn(64, 2048), Some("embedded_rtos"));
        assert_eq!(os_from_syn(30, 1), None);
    }
}
