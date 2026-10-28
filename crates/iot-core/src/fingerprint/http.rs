//! HTTP and SSDP fingerprinting (ZTE-IOT "Http Fingerprinting", section
//! 12).
//!
//! Only request/response heads are examined (bounded to 4 KiB): the
//! request `User-Agent` and `Host`, the response `Server` header and
//! whether cleartext HTTP Basic authorisation is used (the credential is
//! never retained). SSDP announcements (UDP 1900) provide `SERVER` and
//! device type (`NT`/`ST`) values.

use crate::model::{clip, Signal};

const MAX_HEAD: usize = 4096;

fn headers(b: &[u8]) -> Option<(String, Vec<(String, String)>)> {
    let head = &b[..b.len().min(MAX_HEAD)];
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let first = lines.next()?.to_string();
    let mut hs = vec![];
    for l in lines.take(64) {
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            hs.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    Some((first, hs))
}

fn get<'a>(hs: &'a [(String, String)], k: &str) -> Option<&'a str> {
    hs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

const METHODS: &[&str] = &["GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH "];

/// HTTP request or response head.
pub fn http_signal(b: &[u8]) -> Option<Signal> {
    let start = String::from_utf8_lossy(&b[..b.len().min(8)]).to_string();
    let request = METHODS.iter().any(|m| start.starts_with(m));
    let response = start.starts_with("HTTP/1.");
    if !request && !response {
        return None;
    }
    let (_, hs) = headers(b)?;
    let s = Signal::Http {
        user_agent: if request { get(&hs, "user-agent").map(|v| clip(v, 512)) } else { None },
        server: if response { get(&hs, "server").map(|v| clip(v, 256)) } else { None },
        host: if request { get(&hs, "host").map(|v| clip(v, 253)) } else { None },
        basic_auth: request && get(&hs, "authorization").map(|v| v.to_ascii_lowercase().starts_with("basic ")).unwrap_or(false),
    };
    match &s {
        Signal::Http { user_agent: None, server: None, host: None, basic_auth: false } => None,
        _ => Some(s),
    }
}

/// SSDP NOTIFY / M-SEARCH response.
pub fn ssdp_signal(b: &[u8]) -> Option<Signal> {
    let (first, hs) = headers(b)?;
    if !(first.starts_with("NOTIFY") || first.starts_with("HTTP/1.1 200")) {
        return None;
    }
    let server = get(&hs, "server").map(|v| clip(v, 256));
    let device_type = get(&hs, "nt").or_else(|| get(&hs, "st")).map(|v| clip(v, 256));
    if server.is_none() && device_type.is_none() {
        return None;
    }
    Some(Signal::Ssdp { server, device_type })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_response_and_ssdp() {
        let r = b"GET /status HTTP/1.1\r\nHost: plc-1\r\nUser-Agent: Vendor-Updater/2.1 (embedded)\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n";
        match http_signal(r).unwrap() {
            Signal::Http { user_agent, basic_auth, host, .. } => {
                assert_eq!(user_agent.as_deref(), Some("Vendor-Updater/2.1 (embedded)"));
                assert!(basic_auth);
                assert_eq!(host.as_deref(), Some("plc-1"));
            }
            _ => panic!(),
        }
        assert!(!format!("{:?}", http_signal(r)).contains("YWRtaW4"), "credentials are never kept");
        let s = http_signal(b"HTTP/1.1 200 OK\r\nServer: GoAhead-Webs\r\n\r\n").unwrap();
        assert!(matches!(s, Signal::Http { server: Some(ref v), .. } if v == "GoAhead-Webs"));
        let n = ssdp_signal(b"NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\r\nSERVER: Linux/4.9 UPnP/1.0 StreamBox/3\r\n\r\n").unwrap();
        assert!(matches!(n, Signal::Ssdp { device_type: Some(ref d), .. } if d.contains("MediaRenderer")));
        assert!(http_signal(b"\x16\x03\x01").is_none());
    }
}
