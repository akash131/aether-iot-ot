//! Execution of approved safe active queries on the edge (ZTE-IOT section
//! 5 Active Discovery Safeguards; AE-IOT-0007/0008).
//!
//! The control plane plans every query (enablement, restricted ranges and
//! device types, blackout windows, attempt budgets, approvals) and only
//! approved queries reach the edge in the verified snapshot. The edge then
//! sends the minimal identification request per target — rate limited,
//! one attempt, short timeouts, never a write — parses answers with the
//! same protocol parsers used for passive capture, and reports results
//! as non-passive observations.

use super::Agent;
use chrono::Utc;
use iot_core::activeq;
use iot_core::model::{Observation, Signal};
use iot_core::protocols::{self, Dir, Protocol};
use reqwest::Method;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(2);
const PROBE_PORTS: &[u16] = &[22, 23, 80, 102, 161, 443, 502, 1883, 2404, 4840, 20000, 44818, 47808];

fn protocol_for(kind: &str) -> Option<Protocol> {
    match kind {
        "snmp_sysdescr" => Some(Protocol::Snmp),
        "enip_list_identity" => Some(Protocol::Enip),
        "bacnet_who_is" => Some(Protocol::Bacnet),
        "modbus_device_id" => Some(Protocol::Modbus),
        _ => None,
    }
}

async fn tcp_exchange(ip: &str, port: u16, req: Option<&[u8]>) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect((ip, port))).await.map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    let Some(req) = req else { return Ok(vec![]) };
    s.write_all(req).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(TIMEOUT, s.read(&mut buf)).await.map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    buf.truncate(n);
    Ok(buf)
}

async fn udp_exchange(ip: &str, port: u16, req: &[u8]) -> std::io::Result<Vec<u8>> {
    let bind = if ip.contains(':') { "[::]:0" } else { "0.0.0.0:0" };
    let s = tokio::net::UdpSocket::bind(bind).await?;
    s.connect((ip, port)).await?;
    s.send(req).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(TIMEOUT, s.recv(&mut buf)).await.map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    buf.truncate(n);
    Ok(buf)
}

/// Run one query against one target, returning the result record and the
/// observation built from the answer.
pub async fn execute(kind: &str, ip: &str, port_override: Option<u16>) -> (Value, Option<Observation>) {
    let Some((_, risk, transport, port, _)) = activeq::query(kind) else {
        return (json!({ "ip": ip, "ok": false, "error": "unknown_query" }), None);
    };
    if risk == activeq::Risk::Intrusive {
        // Intrusive queries are never executed by the edge.
        return (json!({ "ip": ip, "ok": false, "error": "intrusive_query_refused" }), None);
    }
    let port = port_override.unwrap_or(port);
    let mut obs =
        Observation { observed_at: Utc::now(), site: None, sensor: None, mac: None, ip: Some(ip.to_string()), vlan: None, signals: vec![], flows: vec![], passive: false };
    match kind {
        "icmp_ping" | "tcp_port_check" => {
            let mut open = vec![];
            for p in PROBE_PORTS {
                if tcp_exchange(ip, *p, None).await.is_ok() {
                    open.push(*p);
                    obs.signals.push(Signal::Service { transport: "tcp".into(), port: *p });
                }
                if kind == "icmp_ping" && !open.is_empty() {
                    break;
                }
            }
            let reachable = !open.is_empty();
            (json!({ "ip": ip, "ok": true, "reachable": reachable, "open_ports": open }), reachable.then_some(obs))
        }
        "http_banner" => match tcp_exchange(ip, port, activeq::request(kind).as_deref()).await {
            Ok(b) => {
                let text = String::from_utf8_lossy(&b[..b.len().min(2048)]).to_string();
                let server =
                    text.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("server")).map(|(_, v)| v.trim().chars().take(200).collect::<String>()));
                obs.signals.push(Signal::Http { user_agent: None, server: server.clone(), host: None, basic_auth: false });
                obs.signals.push(Signal::Service { transport: "tcp".into(), port });
                (json!({ "ip": ip, "ok": true, "server": server }), Some(obs))
            }
            Err(e) => (json!({ "ip": ip, "ok": false, "error": e.kind().to_string() }), None),
        },
        _ => {
            let (Some(proto), Some(req)) = (protocol_for(kind), activeq::request(kind)) else {
                return (json!({ "ip": ip, "ok": false, "error": "unsupported_query" }), None);
            };
            let ans = if transport == "udp" { udp_exchange(ip, port, &req).await } else { tcp_exchange(ip, port, Some(&req)).await };
            match ans {
                Ok(b) => match protocols::parse(proto, &b, Dir::FromServer) {
                    Ok(events) => {
                        let identity: Vec<Value> = events.iter().filter(|e| !e.identity.is_empty()).map(|e| serde_json::to_value(&e.identity).unwrap_or_default()).collect();
                        obs.signals.push(Signal::Service { transport: transport.into(), port });
                        obs.signals.extend(events.into_iter().map(|event| Signal::Protocol { event, server: true }));
                        (json!({ "ip": ip, "ok": true, "identity": identity }), Some(obs))
                    }
                    Err(e) => (json!({ "ip": ip, "ok": false, "error": e.code() }), None),
                },
                Err(e) => (json!({ "ip": ip, "ok": false, "error": e.kind().to_string() }), None),
            }
        }
    }
}

/// Execute the approved queries in the current snapshot that this edge has
/// not run yet and report the results.
pub async fn run_approved(agent: &Arc<Agent>) -> anyhow::Result<usize> {
    if !agent.cfg.active_queries {
        return Ok(0);
    }
    let rt = agent.runtime();
    let queries = rt.snapshot["active_queries"].as_array().cloned().unwrap_or_default();
    let mut done = 0;
    for q in queries {
        let Some(id) = q["id"].as_str().map(String::from) else { continue };
        if !agent.queries_done.lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone()) {
            continue;
        }
        let kind = q["kind"].as_str().unwrap_or_default().to_string();
        let mut results = vec![];
        let mut observations = vec![];
        for t in q["targets"].as_array().cloned().unwrap_or_default() {
            let Some(ip) = t["ip"].as_str() else { continue };
            let (mut r, obs) = execute(&kind, ip, None).await;
            r["asset_id"] = t["id"].clone();
            results.push(r);
            observations.extend(obs);
            // Rate limit (at most 5 targets per second).
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let body = json!({ "results": results, "observations": observations });
        let url = format!("{}/api/v1/node/active-queries/{id}/results", agent.cfg.control_url);
        match agent.node_send(Method::POST, &url, Some(&body), &[], true).await {
            Ok(r) if r.status().is_success() || r.status().as_u16() == 409 => done += 1,
            Ok(r) => tracing::warn!(status = %r.status(), query = %id, "active query results refused"),
            Err(e) => {
                tracing::warn!(error = %e, query = %id, "could not report active query results; will retry");
                agent.queries_done.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
            }
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn modbus_identification_against_a_local_responder() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 64];
            let n = s.read(&mut b).await.unwrap();
            // The request is a read-only Read Device Identification.
            assert_eq!(b[7], 43, "{:?}", &b[..n]);
            // Reply: MEI 14, object 0 vendor "Acme", 1 product code "PLC-9".
            let pdu = [&[43u8, 14, 1, 1, 0, 0, 2, 0, 4][..], b"Acme", &[1, 5], b"PLC-9"].concat();
            s.write_all(&iot_core::protocols::modbus::adu(0x4954, 0, &pdu)).await.unwrap();
        });
        let (r, obs) = execute("modbus_device_id", "127.0.0.1", Some(port)).await;
        assert_eq!(r["ok"], true, "{r}");
        let o = obs.unwrap();
        assert!(!o.passive);
        assert!(o.signals.iter().any(|s| matches!(s, Signal::Protocol { server: true, .. })));
    }

    #[tokio::test]
    async fn intrusive_queries_are_refused_and_unreachable_targets_fail_cleanly() {
        let (r, o) = execute("s7_read_szl", "127.0.0.1", None).await;
        assert_eq!(r["error"], "intrusive_query_refused");
        assert!(o.is_none());
        let (r, _) = execute("http_banner", "127.0.0.1", Some(1)).await;
        assert_eq!(r["ok"], false);
    }
}
