//! Passive collector: turns mirrored frames into per-device observations
//! (ZTE-IOT sections 4 Passive Discovery, 6 Packet Metadata Collection,
//! 7 Flow-Based Discovery, 93 Device Flow Telemetry, 94 Protocol
//! Telemetry; ZTE-IOTINV-153161 passive by default, -153164 bounded,
//! -153169 minimised evidence).
//!
//! The collector keeps a bounded table of devices keyed by MAC address
//! (or by IP address behind a router: a MAC that sources many addresses is
//! a gateway and is never used as a device identity). For every frame it
//! extracts fingerprint signals (DHCP, DNS, mDNS, SSDP, HTTP, TLS, LLDP,
//! CDP, PROFINET DCP, TCP SYN), industrial and IoT protocol operations and
//! flow summaries. [`Collector::drain`] emits one [`Observation`] per device
//! with what changed since the last drain. Only header fields are kept;
//! payload bytes never leave this module.

use crate::fingerprint::{dhcp, dns, http, lldp, os_from_syn, tls};
use crate::model::{Flow, Observation, Signal};
use crate::packet::{decode_ethernet, tcp_flags, Frame, Mac, Transport, ETH_LLDP, ETH_PROFINET};
use crate::protocols::{self, Dir, OpClass, ProtoEvent, Protocol};
use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_devices: usize,
    pub max_flows_per_device: usize,
    pub max_signals_per_device: usize,
    /// A MAC sourcing more IP addresses than this is treated as a gateway.
    pub gateway_ip_threshold: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_devices: 50_000, max_flows_per_device: 256, max_signals_per_device: 48, gateway_ip_threshold: 8 }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Stats {
    pub frames: u64,
    pub bytes: u64,
    pub decode_errors: BTreeMap<String, u64>,
    /// Parser errors by protocol and code.
    pub parse_errors: BTreeMap<String, u64>,
    pub protocol_events: BTreeMap<String, u64>,
    pub dropped_devices: u64,
    pub dropped_flows: u64,
    pub devices: usize,
}

#[derive(Default)]
struct Dev {
    mac: Option<Mac>,
    ip: Option<String>,
    vlan: Option<u16>,
    signals: Vec<Signal>,
    seen_signals: HashSet<String>,
    flows: HashMap<(String, String, u16, bool), Flow>,
    last: i64,
    dirty: bool,
}

/// Device key: MAC unless the MAC is a gateway, then IP.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Mac(Mac),
    Ip(String),
}

pub struct Collector {
    limits: Limits,
    devices: HashMap<Key, Dev>,
    mac_ips: HashMap<Mac, HashSet<String>>,
    gateways: HashSet<Mac>,
    pub stats: Stats,
}

impl Default for Collector {
    fn default() -> Self {
        Collector::new(Limits::default())
    }
}

fn signal_key(s: &Signal) -> String {
    // Dedup key: the signal minus volatile fields.
    match s {
        Signal::Protocol { event, server } => {
            format!("p|{}|{}|{}|{}|{:?}", event.protocol.as_str(), event.operation, server, event.object.as_deref().unwrap_or(""), event.identity)
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

impl Collector {
    pub fn new(limits: Limits) -> Collector {
        Collector { limits, devices: HashMap::new(), mac_ips: HashMap::new(), gateways: HashSet::new(), stats: Stats::default() }
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    fn key_for(&mut self, mac: Mac, ip: Option<&str>) -> Option<Key> {
        if mac.is_multicast() || mac.0 == [0; 6] {
            return ip.map(|i| Key::Ip(i.to_string()));
        }
        if let Some(i) = ip {
            let set = self.mac_ips.entry(mac).or_default();
            if set.len() <= self.limits.gateway_ip_threshold {
                set.insert(i.to_string());
            }
            if set.len() > self.limits.gateway_ip_threshold {
                self.gateways.insert(mac);
            }
        }
        if self.gateways.contains(&mac) {
            return ip.map(|i| Key::Ip(i.to_string()));
        }
        Some(Key::Mac(mac))
    }

    fn dev(&mut self, key: Key, ts: i64) -> Option<&mut Dev> {
        if !self.devices.contains_key(&key) {
            if self.devices.len() >= self.limits.max_devices {
                self.stats.dropped_devices += 1;
                return None;
            }
            let mut d = Dev::default();
            if let Key::Mac(m) = &key {
                d.mac = Some(*m);
            }
            if let Key::Ip(i) = &key {
                d.ip = Some(i.clone());
            }
            self.devices.insert(key.clone(), d);
        }
        let d = self.devices.get_mut(&key)?;
        d.last = d.last.max(ts);
        Some(d)
    }

    fn add_signal(&mut self, key: Option<Key>, ts: i64, s: Signal) {
        let max = self.limits.max_signals_per_device;
        let Some(key) = key else { return };
        let Some(d) = self.dev(key, ts) else { return };
        let k = signal_key(&s);
        if d.seen_signals.contains(&k) {
            return;
        }
        if d.signals.len() < max {
            d.seen_signals.insert(k);
            d.signals.push(s);
            d.dirty = true;
        }
    }

    fn add_flow(&mut self, key: Option<Key>, ts: i64, f: Flow, ev: Option<&ProtoEvent>) {
        let max = self.limits.max_flows_per_device;
        let Some(key) = key else { return };
        let Some(d) = self.dev(key, ts) else { return };
        let fk = (f.peer_ip.clone(), f.transport.clone(), f.port, f.outbound);
        let n = d.flows.len();
        let entry = match d.flows.get_mut(&fk) {
            Some(e) => e,
            None if n < max => d.flows.entry(fk).or_insert_with(|| Flow { packets: 0, bytes: 0, operations: vec![], ..f.clone() }),
            None => {
                self.stats.dropped_flows += 1;
                return;
            }
        };
        entry.packets += f.packets;
        entry.bytes += f.bytes;
        if entry.peer_mac.is_none() {
            entry.peer_mac = f.peer_mac.clone();
        }
        if let Some(e) = ev {
            entry.protocol = Some(e.protocol);
            if entry.max_op.map(|m| e.class > m).unwrap_or(true) && !e.is_response {
                entry.max_op = Some(e.class);
            }
            let op = format!("{}:{}", e.protocol.as_str(), e.operation);
            if !entry.operations.contains(&op) && entry.operations.len() < 32 {
                entry.operations.push(op);
            }
        }
        d.dirty = true;
    }

    /// Ingest one Ethernet frame captured at `ts_micros`.
    pub fn ingest(&mut self, ts_micros: i64, bytes: &[u8]) {
        self.stats.frames += 1;
        self.stats.bytes += bytes.len() as u64;
        let f = match decode_ethernet(bytes) {
            Ok(f) => f,
            Err(e) => {
                *self.stats.decode_errors.entry(e.code().to_string()).or_default() += 1;
                return;
            }
        };
        let ts = ts_micros / 1_000_000;
        self.frame(ts, &f);
    }

    fn frame(&mut self, ts: i64, f: &Frame<'_>) {
        let src_ip = f.src_ip.map(|i| i.to_string());
        let dst_ip = f.dst_ip.map(|i| i.to_string());
        let src = self.key_for(f.src_mac, src_ip.as_deref());
        if let Some(k) = &src {
            if let Some(d) = self.dev(k.clone(), ts) {
                if d.ip.is_none() || src_ip.as_deref().map(|i| !i.starts_with("0.") && i != "0.0.0.0").unwrap_or(false) {
                    if let Some(i) = &src_ip {
                        if i != "0.0.0.0" {
                            d.ip = Some(i.clone());
                        }
                    }
                }
                if f.vlan.is_some() {
                    d.vlan = f.vlan;
                }
            }
        }
        // Link-layer protocols.
        if let Some((m, ip, _, _)) = f.arp {
            let k = self.key_for(m, Some(&ip.to_string()));
            if let Some(k) = k {
                if let Some(d) = self.dev(k, ts) {
                    d.ip = Some(ip.to_string());
                    d.dirty = true;
                }
            }
            return;
        }
        if f.ethertype == ETH_LLDP {
            if let Some(s) = lldp::lldp(f.l2_payload) {
                self.add_signal(src, ts, s);
            }
            return;
        }
        if let Some((oui, pid)) = f.snap {
            if oui == [0, 0, 0x0c] && pid == 0x2000 {
                if let Some(s) = lldp::cdp(f.l2_payload) {
                    self.add_signal(src, ts, s);
                }
            }
            return;
        }
        if f.ethertype == ETH_PROFINET {
            match protocols::profinet::parse_dcp(f.l2_payload) {
                Ok(ev) => {
                    *self.stats.protocol_events.entry("profinet".into()).or_default() += 1;
                    let server = ev.is_response;
                    self.add_signal(src, ts, Signal::Protocol { event: ev, server });
                }
                Err(e) => *self.stats.parse_errors.entry(format!("profinet:{}", e.code())).or_default() += 1,
            }
            return;
        }
        let Some(transport) = f.transport else { return };
        let dst = if f.dst_mac.is_multicast() { None } else { self.key_for(f.dst_mac, dst_ip.as_deref()) };
        let p = f.payload;
        match transport {
            Transport::Udp => {
                if (f.dst_port == 67 && f.src_port == 68) || (f.src_port == 68) {
                    if let Some((mac, s, _)) = dhcp::parse(p) {
                        if let Some(m) = Mac::parse(&mac) {
                            let k = self.key_for(m, None);
                            self.add_signal(k, ts, s);
                        }
                    }
                    return;
                }
                if f.dst_port == 53 {
                    for s in dns::dns_signals(p) {
                        self.add_signal(src.clone(), ts, s);
                    }
                }
                if f.dst_port == 5353 || f.src_port == 5353 {
                    for s in dns::mdns_signals(p) {
                        self.add_signal(src.clone(), ts, s);
                    }
                    return;
                }
                if f.dst_port == 1900 || f.src_port == 1900 {
                    if let Some(s) = http::ssdp_signal(p) {
                        self.add_signal(src.clone(), ts, s);
                    }
                    return;
                }
            }
            Transport::Tcp => {
                let syn = f.tcp_flags & tcp_flags::SYN != 0;
                let ack = f.tcp_flags & tcp_flags::ACK != 0;
                if syn && !ack {
                    if let Some(ttl) = f.ttl {
                        if os_from_syn(ttl, f.tcp_window).is_some() {
                            self.add_signal(src.clone(), ts, Signal::TcpSyn { ttl, window: f.tcp_window });
                        }
                    }
                }
                if syn && ack {
                    self.add_signal(src.clone(), ts, Signal::Service { transport: "tcp".into(), port: f.src_port });
                }
                if !p.is_empty() {
                    if let Some(s) = http::http_signal(p) {
                        let basic = matches!(s, Signal::Http { basic_auth: true, .. });
                        self.add_signal(src.clone(), ts, s);
                        if basic {
                            self.add_signal(src.clone(), ts, Signal::CleartextCredentials { protocol: "http".into() });
                        }
                    } else if let Some(s) = tls::signal(p) {
                        self.add_signal(src.clone(), ts, s);
                    }
                    if f.dst_port == 23 {
                        self.add_signal(src.clone(), ts, Signal::CleartextCredentials { protocol: "telnet".into() });
                    }
                    if f.dst_port == 21 && (p.starts_with(b"PASS ") || p.starts_with(b"USER ")) {
                        self.add_signal(src.clone(), ts, Signal::CleartextCredentials { protocol: "ftp".into() });
                    }
                }
            }
            _ => return,
        }
        // Industrial / IoT protocols and flows.
        let mut events = vec![];
        let proto = protocols::identify(f.src_port, f.dst_port, p);
        if let (Some((pr, dir)), false) = (proto, p.is_empty()) {
            match protocols::parse(pr, p, dir) {
                Ok(evs) => {
                    *self.stats.protocol_events.entry(pr.as_str().into()).or_default() += evs.len() as u64;
                    events = evs.into_iter().map(|e| (e, dir)).collect();
                }
                Err(e) => *self.stats.parse_errors.entry(format!("{}:{}", pr.as_str(), e.code())).or_default() += 1,
            }
        }
        let to_server = match proto {
            Some((_, d)) => d == Dir::ToServer,
            None => f.dst_port < f.src_port,
        };
        let (server_port, tname) = (if to_server { f.dst_port } else { f.src_port }, if transport == Transport::Tcp { "tcp" } else { "udp" });
        for (ev, dir) in &events {
            let server = *dir == Dir::FromServer;
            if !ev.identity.is_empty() || ev.class >= OpClass::Read || server {
                let mut e = ev.clone();
                e.values.clear();
                self.add_signal(src.clone(), ts, Signal::Protocol { event: e, server });
            }
            if (ev.protocol == Protocol::Mqtt || ev.protocol == Protocol::Amqp)
                && ev.details.contains_key("password")
                && !ev.protocol.ports().iter().any(|p| *p == 8883 || *p == 5671)
            {
                self.add_signal(src.clone(), ts, Signal::CleartextCredentials { protocol: ev.protocol.as_str().into() });
            }
            if ev.protocol == Protocol::Snmp && ev.details.get("default_community").map(|v| v == "true").unwrap_or(false) {
                self.add_signal(src.clone(), ts, Signal::CleartextCredentials { protocol: "snmp_default_community".into() });
            }
        }
        let first = events.first().map(|(e, _)| e.clone());
        let (Some(sip), Some(dip)) = (src_ip, dst_ip) else { return };
        let mk = |peer_ip: String, peer_mac: Mac, outbound: bool| Flow {
            peer_ip,
            peer_mac: (!peer_mac.is_multicast()).then(|| peer_mac.to_string()),
            transport: tname.into(),
            port: server_port,
            outbound,
            packets: 1,
            bytes: f.wire_len as u64,
            protocol: proto.map(|p| p.0),
            max_op: None,
            operations: vec![],
        };
        let a = mk(dip, f.dst_mac, to_server);
        let b = mk(sip, f.src_mac, !to_server);
        self.add_flow(src, ts, a, first.as_ref());
        self.add_flow(dst, ts, b, first.as_ref());
    }

    /// Emit observations for devices that changed and reset their deltas.
    pub fn drain(&mut self, site: Option<&str>, sensor: Option<&str>) -> Vec<Observation> {
        let mut out = vec![];
        let gateways = self.gateways.clone();
        for (k, d) in self.devices.iter_mut() {
            if !d.dirty {
                continue;
            }
            if let Key::Mac(m) = k {
                if gateways.contains(m) {
                    continue;
                }
            }
            let at: DateTime<Utc> = Utc.timestamp_opt(d.last, 0).single().unwrap_or_else(Utc::now);
            let mut o = Observation::new(at, d.mac.map(|m| m.to_string()).as_deref(), d.ip.as_deref());
            o.site = site.map(String::from);
            o.sensor = sensor.map(String::from);
            o.vlan = d.vlan;
            o.signals = std::mem::take(&mut d.signals);
            let mut flows: Vec<Flow> = d.flows.drain().map(|(_, f)| f).collect();
            flows.sort_by(|a, b| (&a.peer_ip, a.port, a.outbound).cmp(&(&b.peer_ip, b.port, b.outbound)));
            o.flows = flows;
            d.dirty = false;
            out.push(o);
        }
        // Forget signal dedup state periodically so changes re-surface.
        if self.devices.len() > self.limits.max_devices / 2 {
            self.devices.retain(|_, d| !d.seen_signals.is_empty() || d.dirty);
        }
        self.stats.devices = self.devices.len();
        out.sort_by(|a, b| (&a.mac, &a.ip).cmp(&(&b.mac, &b.ip)));
        out
    }

    /// Forget per-device dedup state (called on a long interval so that
    /// unchanged evidence is periodically re-confirmed).
    pub fn reset_dedup(&mut self) {
        for d in self.devices.values_mut() {
            d.seen_signals.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::build::*;
    use crate::protocols::modbus;
    use std::net::Ipv4Addr;

    fn m(s: &str) -> Mac {
        Mac::parse(s).unwrap()
    }

    #[test]
    fn collects_signals_protocols_and_flows() {
        let mut c = Collector::default();
        let plc = (m("00:1d:9c:00:00:01"), Ipv4Addr::new(10, 10, 0, 5), 502);
        let hmi = (m("00:0e:8c:00:00:02"), Ipv4Addr::new(10, 10, 0, 9), 50211);
        c.ingest(1_000_000, &tcp_frame(hmi, plc, tcp_flags::SYN, b""));
        c.ingest(1_000_001, &tcp_frame(plc, hmi, tcp_flags::SYN | tcp_flags::ACK, b""));
        c.ingest(1_000_002, &tcp_frame(hmi, plc, 0x18, &modbus::adu(1, 1, &[16, 0, 1, 0, 1, 2, 0, 9])));
        c.ingest(1_000_003, &tcp_frame(hmi, plc, 0x18, &modbus::adu(2, 1, &[3, 0, 0, 0, 4])));
        // DHCP from a camera.
        let dh = dhcp::request([0, 0x40, 0x8c, 9, 9, 9], "AXIS-01", "udhcp 1.31", &[1, 3, 6, 12, 15, 28, 42]);
        c.ingest(1_000_004, &udp_frame((m("00:40:8c:09:09:09"), Ipv4Addr::UNSPECIFIED, 68), (m("ff:ff:ff:ff:ff:ff"), Ipv4Addr::BROADCAST, 67), &dh));
        // Garbage frame.
        c.ingest(1_000_005, &[1, 2, 3]);
        let obs = c.drain(Some("site-a"), Some("sensor-1"));
        let plc_o = obs.iter().find(|o| o.mac.as_deref() == Some("00:1d:9c:00:00:01")).unwrap();
        assert!(plc_o.signals.iter().any(|s| matches!(s, Signal::Service { port: 502, .. })));
        let inbound = plc_o.flows.iter().find(|f| !f.outbound && f.port == 502).unwrap();
        assert_eq!(inbound.max_op, Some(OpClass::Write));
        assert!(inbound.operations.contains(&"modbus:write_multiple_registers".to_string()));
        let hmi_o = obs.iter().find(|o| o.mac.as_deref() == Some("00:0e:8c:00:00:02")).unwrap();
        assert!(hmi_o.signals.iter().any(|s| matches!(s, Signal::Protocol { server: false, .. })));
        let cam = obs.iter().find(|o| o.mac.as_deref() == Some("00:40:8c:09:09:09")).unwrap();
        assert!(matches!(&cam.signals[0], Signal::Dhcp { hostname: Some(h), .. } if h == "AXIS-01"));
        assert_eq!(plc_o.site.as_deref(), Some("site-a"));
        assert_eq!(c.stats.decode_errors.get("truncated"), Some(&1));
        // Second drain: nothing changed.
        assert!(c.drain(None, None).is_empty());
        // Payload never appears in observations.
        assert!(!serde_json::to_string(&obs).unwrap().contains("\"payload\""));
    }

    #[test]
    fn gateway_macs_are_not_identities_and_limits_hold() {
        let mut c = Collector::new(Limits { max_devices: 10, ..Limits::default() });
        let router = m("00:00:0c:aa:bb:cc");
        for i in 0..30u8 {
            c.ingest(1, &udp_frame((router, Ipv4Addr::new(192, 168, 9, i), 4000), (m("00:00:00:00:00:99"), Ipv4Addr::new(10, 0, 0, 1), 9999), b"x"));
        }
        let obs = c.drain(None, None);
        assert!(obs.iter().all(|o| o.mac.as_deref() != Some("00:00:0c:aa:bb:cc")), "router MAC is not reported as a device");
        assert!(obs.iter().any(|o| o.mac.is_none() && o.ip.as_deref() == Some("192.168.9.9")));
        assert!(c.device_count() <= 10);
        assert!(c.stats.dropped_devices > 0);
    }
}
