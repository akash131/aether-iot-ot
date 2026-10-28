//! Observations: the normalised, minimised evidence collectors send to the
//! control plane (ZTE-IOTDATA-153135 DeviceObservation, -153140
//! ProtocolObservation, -153141 FlowObservation; ZTE-IOT "Passive
//! Discovery", "Packet Metadata Collection", "Flow-Based Discovery").
//!
//! An observation always names the site and sensor that saw it and the
//! device's link-layer address when known; IP addresses are carried as
//! attributes, never as identity (ZTE-IOTINV-153165). Payloads are never
//! included: only parsed header fields and bounded strings.

use crate::protocols::{OpClass, ProtoEvent, Protocol};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Bounded string helper for untrusted fields.
pub fn clip(s: &str, max: usize) -> String {
    let s: String = s.chars().filter(|c| !c.is_control()).take(max).collect();
    s.trim().to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Signal {
    Dhcp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vendor_class: Option<String>,
        /// Parameter request list (option 55), comma separated codes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prl: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        requested_ip: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
    },
    Dns {
        query: String,
    },
    Http {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_agent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        /// HTTP Basic authorization header seen in cleartext (credential
        /// itself is never kept).
        #[serde(default)]
        basic_auth: bool,
    },
    Mdns {
        #[serde(default)]
        services: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        instance: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
    },
    Ssdp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_type: Option<String>,
    },
    Lldp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        system_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        system_description: Option<String>,
        /// Enabled capability names (bridge, router, telephone, wlan_ap, station...).
        #[serde(default)]
        capabilities: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chassis_id: Option<String>,
    },
    Cdp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        platform: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        software: Option<String>,
        #[serde(default)]
        capabilities: Vec<String>,
    },
    Tls {
        /// Client hello fingerprint (hash of version, ciphers, extensions,
        /// groups and point formats).
        fingerprint: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
    /// TCP SYN characteristics (passive OS hint).
    TcpSyn {
        ttl: u8,
        window: u16,
    },
    /// Listening service seen answering (port profile).
    Service {
        transport: String,
        port: u16,
    },
    Protocol {
        event: ProtoEvent,
        /// The device acted as the server side of the protocol.
        server: bool,
    },
    /// Cleartext credential use seen (protocol name only).
    CleartextCredentials {
        protocol: String,
    },
    /// Identity asserted by an integration (branch inventory, CMDB import).
    Asserted {
        source: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vendor: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        os: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        firmware: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(default)]
        confidence: f64,
    },
}

impl Signal {
    pub fn kind(&self) -> &'static str {
        match self {
            Signal::Dhcp { .. } => "dhcp",
            Signal::Dns { .. } => "dns",
            Signal::Http { .. } => "http",
            Signal::Mdns { .. } => "mdns",
            Signal::Ssdp { .. } => "ssdp",
            Signal::Lldp { .. } => "lldp",
            Signal::Cdp { .. } => "cdp",
            Signal::Tls { .. } => "tls",
            Signal::TcpSyn { .. } => "tcp_syn",
            Signal::Service { .. } => "service",
            Signal::Protocol { .. } => "protocol",
            Signal::CleartextCredentials { .. } => "cleartext_credentials",
            Signal::Asserted { .. } => "asserted",
        }
    }
}

/// A flow summary between a device and a peer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    pub peer_ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_mac: Option<String>,
    pub transport: String,
    /// Server port of the conversation.
    pub port: u16,
    /// The device initiated the conversation.
    pub outbound: bool,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    /// Highest operation class seen in the flow (industrial protocols).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_op: Option<OpClass>,
    /// Operations seen: "protocol:operation" (bounded).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<String>,
}

/// One observation of one device by one sensor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub observed_at: DateTime<Utc>,
    /// Site the sensor belongs to (assigned by the control plane from the
    /// sensor's registration; a sensor cannot claim another site).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    #[serde(default)]
    pub signals: Vec<Signal>,
    #[serde(default)]
    pub flows: Vec<Flow>,
    /// The sensor observed this passively (false: active query result).
    #[serde(default = "yes")]
    pub passive: bool,
}

fn yes() -> bool {
    true
}

/// Limits enforced on ingested observations (bounded inputs, stable
/// errors; ZTE-IOT-*-i4).
pub const MAX_SIGNALS: usize = 64;
pub const MAX_FLOWS: usize = 256;
pub const MAX_OBSERVATIONS_PER_BATCH: usize = 5000;

impl Observation {
    pub fn new(at: DateTime<Utc>, mac: Option<&str>, ip: Option<&str>) -> Observation {
        Observation { observed_at: at, site: None, sensor: None, mac: mac.map(String::from), ip: ip.map(String::from), vlan: None, signals: vec![], flows: vec![], passive: true }
    }

    /// Validate and normalise an untrusted observation. Returns the
    /// stable error code on rejection.
    pub fn sanitize(&mut self, now: DateTime<Utc>) -> Result<(), &'static str> {
        if self.mac.is_none() && self.ip.is_none() {
            return Err("no_address");
        }
        if let Some(m) = &self.mac {
            let p = crate::packet::Mac::parse(m).ok_or("invalid_mac")?;
            if p.is_multicast() {
                return Err("multicast_mac");
            }
            self.mac = Some(p.to_string());
        }
        if let Some(ip) = &self.ip {
            let p: std::net::IpAddr = ip.parse().map_err(|_| "invalid_ip")?;
            self.ip = Some(p.to_string());
        }
        if self.observed_at > now + chrono::Duration::minutes(5) {
            return Err("future_timestamp");
        }
        if self.observed_at < now - chrono::Duration::days(30) {
            return Err("stale_timestamp");
        }
        if self.signals.len() > MAX_SIGNALS || self.flows.len() > MAX_FLOWS {
            return Err("too_many_items");
        }
        for s in &mut self.signals {
            clip_signal(s);
        }
        for f in &mut self.flows {
            f.peer_ip = clip(&f.peer_ip, 45);
            f.operations.truncate(32);
            for o in &mut f.operations {
                *o = clip(o, 80);
            }
        }
        Ok(())
    }
}

fn clip_opt(o: &mut Option<String>, max: usize) {
    if let Some(s) = o {
        *s = clip(s, max);
    }
}

fn clip_signal(s: &mut Signal) {
    match s {
        Signal::Dhcp { hostname, vendor_class, prl, requested_ip, client_id } => {
            for (f, m) in [(hostname, 64), (vendor_class, 128), (prl, 256), (requested_ip, 45), (client_id, 64)] {
                clip_opt(f, m);
            }
        }
        Signal::Dns { query } => *query = clip(&query.to_ascii_lowercase(), 253),
        Signal::Http { user_agent, server, host, .. } => {
            for (f, m) in [(user_agent, 512), (server, 256), (host, 253)] {
                clip_opt(f, m);
            }
        }
        Signal::Mdns { services, instance, model } => {
            services.truncate(16);
            for x in services.iter_mut() {
                *x = clip(x, 100);
            }
            clip_opt(instance, 128);
            clip_opt(model, 128);
        }
        Signal::Ssdp { server, device_type } => {
            clip_opt(server, 256);
            clip_opt(device_type, 256);
        }
        Signal::Lldp { system_name, system_description, capabilities, chassis_id } => {
            clip_opt(system_name, 128);
            clip_opt(system_description, 512);
            clip_opt(chassis_id, 64);
            capabilities.truncate(8);
        }
        Signal::Cdp { device_id, platform, software, capabilities } => {
            clip_opt(device_id, 128);
            clip_opt(platform, 128);
            clip_opt(software, 512);
            capabilities.truncate(8);
        }
        Signal::Tls { fingerprint, sni, version } => {
            *fingerprint = clip(fingerprint, 64);
            clip_opt(sni, 253);
            clip_opt(version, 16);
        }
        Signal::Asserted { source, device_type, vendor, model, os, firmware, hostname, confidence } => {
            *source = clip(source, 64);
            for (f, m) in [(device_type, 64), (vendor, 128), (model, 128), (os, 128), (firmware, 64), (hostname, 64)] {
                clip_opt(f, m);
            }
            *confidence = confidence.clamp(0.0, 1.0);
        }
        Signal::CleartextCredentials { protocol } => *protocol = clip(protocol, 32),
        Signal::Protocol { event, .. } => {
            event.operation = clip(&event.operation, 64);
            if let Some(o) = &mut event.object {
                *o = clip(o, 128);
            }
            event.values.truncate(crate::protocols::MAX_VALUES);
        }
        Signal::TcpSyn { .. } | Signal::Service { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_untrusted_observations() {
        let now = Utc::now();
        let mut o = Observation::new(now, Some("00-1D-9C-AA-BB-CC"), Some("10.0.0.5"));
        o.signals.push(Signal::Dns { query: "Time.Windows.COM\u{7}".into() });
        o.sanitize(now).unwrap();
        assert_eq!(o.mac.as_deref(), Some("00:1d:9c:aa:bb:cc"));
        assert_eq!(o.signals[0], Signal::Dns { query: "time.windows.com".into() });
        let mut bad = Observation::new(now, Some("01:00:5e:00:00:01"), None);
        assert_eq!(bad.sanitize(now), Err("multicast_mac"));
        let mut none = Observation::new(now, None, None);
        assert_eq!(none.sanitize(now), Err("no_address"));
        let mut fut = Observation::new(now + chrono::Duration::hours(1), None, Some("10.0.0.1"));
        assert_eq!(fut.sanitize(now), Err("future_timestamp"));
        let mut many = Observation::new(now, None, Some("10.0.0.1"));
        many.signals = vec![Signal::TcpSyn { ttl: 64, window: 1 }; MAX_SIGNALS + 1];
        assert_eq!(many.sanitize(now), Err("too_many_items"));
    }
}
