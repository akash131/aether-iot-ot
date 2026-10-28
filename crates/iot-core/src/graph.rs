//! Peer relationship and asset dependency graphs (ZTE-IOT sections 54 Peer
//! Relationship Graph, 55 Asset Dependency Graph, 56 Internet Destination
//! Analysis, 57 Private Application Dependency Analysis, 111 Graph Store;
//! ZTE-IOTDATA-153142/153143; AE-IOT-0012 zones and conduits, AE-IOT-0034
//! topology export).
//!
//! The graph is built from the edges of device baselines and recent flows:
//! nodes are assets (or external addresses), edges carry the protocols,
//! ports, highest operation class and traffic. Dependency queries answer
//! "what does X depend on" (servers X initiates to) and "what depends on
//! X" (blast radius) with bounded breadth-first search; conduit summaries
//! aggregate edges between zones. Bounds keep queries predictable (graph
//! lag is reported by the caller when the build is stale).

use crate::protocols::OpClass;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default)]
    pub external: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    /// Initiator (client).
    pub from: String,
    /// Responder (server).
    pub to: String,
    pub protocols: BTreeSet<String>,
    pub ports: BTreeSet<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_op: Option<OpClass>,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Graph {
    pub nodes: BTreeMap<String, Node>,
    pub edges: BTreeMap<(String, String), Edge>,
}

pub const MAX_NODES: usize = 200_000;
pub const MAX_DEPTH: usize = 6;

impl Graph {
    pub fn add_node(&mut self, n: Node) {
        if self.nodes.len() < MAX_NODES || self.nodes.contains_key(&n.id) {
            self.nodes.insert(n.id.clone(), n);
        }
    }

    /// Add or merge an edge (client → server).
    pub fn add_edge(&mut self, from: &str, to: &str, protocol: Option<&str>, port: u16, op: Option<OpClass>, bytes: u64) {
        for id in [from, to] {
            if !self.nodes.contains_key(id) {
                self.add_node(Node { id: id.into(), label: id.into(), device_type: None, zone: None, external: true });
            }
        }
        let e = self.edges.entry((from.into(), to.into())).or_insert_with(|| Edge {
            from: from.into(),
            to: to.into(),
            protocols: BTreeSet::new(),
            ports: BTreeSet::new(),
            max_op: None,
            bytes: 0,
        });
        if let Some(p) = protocol {
            e.protocols.insert(p.into());
        }
        if e.ports.len() < 64 {
            e.ports.insert(port);
        }
        if op > e.max_op {
            e.max_op = op;
        }
        e.bytes = e.bytes.saturating_add(bytes);
    }

    fn walk(&self, start: &str, forward: bool, depth: usize) -> Vec<(String, usize)> {
        let depth = depth.min(MAX_DEPTH);
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (from, to) in self.edges.keys() {
            if forward {
                adj.entry(from).or_default().push(to);
            } else {
                adj.entry(to).or_default().push(from);
            }
        }
        let mut seen = BTreeSet::new();
        let mut out = vec![];
        let mut q = VecDeque::from([(start, 0usize)]);
        seen.insert(start);
        while let Some((n, d)) = q.pop_front() {
            if d >= depth {
                continue;
            }
            for next in adj.get(n).into_iter().flatten() {
                if seen.insert(next) {
                    out.push((next.to_string(), d + 1));
                    q.push_back((next, d + 1));
                }
            }
        }
        out
    }

    /// Servers `id` depends on (transitively, bounded).
    pub fn dependencies(&self, id: &str, depth: usize) -> Vec<(String, usize)> {
        self.walk(id, true, depth)
    }

    /// Assets that depend on `id` (impact / blast radius).
    pub fn dependents(&self, id: &str, depth: usize) -> Vec<(String, usize)> {
        self.walk(id, false, depth)
    }

    /// Direct peers of a node with the edges.
    pub fn peers(&self, id: &str) -> Vec<&Edge> {
        self.edges.values().filter(|e| e.from == id || e.to == id).collect()
    }

    /// Conduits: aggregated communication between zones.
    pub fn conduits(&self) -> Vec<Conduit> {
        let mut m: BTreeMap<(String, String), Conduit> = BTreeMap::new();
        for e in self.edges.values() {
            let z = |id: &str| {
                self.nodes.get(id).and_then(|n| n.zone.clone()).unwrap_or_else(|| {
                    if self.nodes.get(id).map(|n| n.external).unwrap_or(true) {
                        "external".into()
                    } else {
                        "unassigned".into()
                    }
                })
            };
            let (zf, zt) = (z(&e.from), z(&e.to));
            if zf == zt {
                continue;
            }
            let c = m.entry((zf.clone(), zt.clone())).or_insert_with(|| Conduit { from_zone: zf, to_zone: zt, protocols: BTreeSet::new(), edges: 0, max_op: None });
            c.protocols.extend(e.protocols.iter().cloned());
            c.edges += 1;
            if e.max_op > c.max_op {
                c.max_op = e.max_op;
            }
        }
        m.into_values().collect()
    }

    /// Internet destinations contacted by `id` (section 56).
    pub fn internet_destinations(&self, id: &str) -> Vec<&Edge> {
        self.edges.values().filter(|e| e.from == id && e.to.parse::<std::net::IpAddr>().map(|ip| crate::risk::is_public(&ip)).unwrap_or(false)).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conduit {
    pub from_zone: String,
    pub to_zone: String,
    pub protocols: BTreeSet<String>,
    pub edges: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_op: Option<OpClass>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependencies_dependents_and_conduits() {
        let mut g = Graph::default();
        for (id, zone) in [("hmi", "ot_supervisory"), ("plc", "ot_control"), ("hist", "ot_operations"), ("erp", "corporate")] {
            g.add_node(Node { id: id.into(), label: id.into(), device_type: None, zone: Some(zone.into()), external: false });
        }
        g.add_edge("hmi", "plc", Some("modbus"), 502, Some(OpClass::Write), 100);
        g.add_edge("hist", "hmi", Some("opcua"), 4840, Some(OpClass::Read), 50);
        g.add_edge("erp", "hist", None, 1433, None, 10);
        g.add_edge("plc", "8.8.8.8", None, 53, None, 1);
        assert_eq!(g.dependencies("hist", 6).iter().map(|x| x.0.as_str()).collect::<Vec<_>>(), vec!["hmi", "plc", "8.8.8.8"]);
        assert_eq!(g.dependents("plc", 6).len(), 3);
        assert_eq!(g.dependents("plc", 1).len(), 1, "depth bounded");
        let c = g.conduits();
        assert!(c.iter().any(|c| c.from_zone == "ot_supervisory" && c.to_zone == "ot_control" && c.max_op == Some(OpClass::Write)));
        assert!(c.iter().any(|c| c.to_zone == "external"));
        assert_eq!(g.internet_destinations("plc").len(), 1);
        g.add_edge("hmi", "plc", Some("modbus"), 502, Some(OpClass::Read), 5);
        assert_eq!(g.edges[&("hmi".to_string(), "plc".to_string())].max_op, Some(OpClass::Write));
    }
}
