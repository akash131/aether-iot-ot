//! Passive capture inputs of the edge (ZTE-IOT sections 4 Passive Discovery
//! and 6 Packet Metadata Collection): capture files dropped into a spool
//! directory (by a span/tap capture process such as `tcpdump -G`) and
//! TZSP-encapsulated frames mirrored by switches or access points.
//!
//! Every frame goes through [`Agent::ingest_frame`], which isolates parser
//! failures (a panic in a decoder is counted, never fatal — failure mode
//! `parser_failure`). Only metadata leaves the edge; payloads are parsed in
//! memory and discarded.

use super::Agent;
use iot_core::packet::{decode_tzsp, PcapReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

impl Agent {
    /// Feed one Ethernet frame to the collector.
    pub fn ingest_frame(&self, ts_micros: i64, frame: &[u8]) {
        let mut c = self.collector.lock().unwrap_or_else(|e| e.into_inner());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.ingest(ts_micros, frame)));
        if r.is_err() {
            self.parser_panics.fetch_add(1, Ordering::Relaxed);
            self.metrics.count("parser_panic", "frame");
        }
    }

    /// Process one capture file; returns the number of frames read.
    pub fn ingest_pcap_file(&self, path: &Path) -> anyhow::Result<u64> {
        let f = std::fs::File::open(path)?;
        let mut r = PcapReader::new(std::io::BufReader::new(f)).map_err(|e| anyhow::anyhow!("{}: {}", path.display(), e.code()))?;
        let mut n = 0u64;
        loop {
            match r.next_record() {
                Ok(Some(rec)) => {
                    self.ingest_frame(rec.ts_micros, &rec.data);
                    n += 1;
                }
                Ok(None) => break,
                Err(e) => {
                    // A truncated tail (file still being written or cut) ends the file.
                    self.metrics.count("pcap_error", e.code());
                    break;
                }
            }
        }
        self.metrics.count("pcap_file", "processed");
        Ok(n)
    }

    /// Feed one TZSP datagram.
    pub fn ingest_tzsp(&self, ts_micros: i64, datagram: &[u8]) -> bool {
        match decode_tzsp(datagram) {
            Ok(frame) => {
                self.ingest_frame(ts_micros, frame);
                true
            }
            Err(e) => {
                self.metrics.count("tzsp_error", e.code());
                false
            }
        }
    }
}

fn pending(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> =
        std::fs::read_dir(dir).map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().map(|x| x == "pcap").unwrap_or(false)).collect()).unwrap_or_default();
    v.sort();
    v
}

/// Poll the spool directory: process complete files (oldest first, a file
/// is complete once it has not grown for one poll) and delete them.
pub async fn run_spool(agent: Arc<Agent>, dir: String) {
    let dir = PathBuf::from(dir);
    let mut sizes: std::collections::HashMap<PathBuf, u64> = Default::default();
    loop {
        for p in pending(&dir) {
            let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            if sizes.get(&p) != Some(&len) {
                sizes.insert(p.clone(), len);
                continue;
            }
            sizes.remove(&p);
            let a = agent.clone();
            let path = p.clone();
            let res = tokio::task::spawn_blocking(move || a.ingest_pcap_file(&path)).await;
            match res {
                Ok(Ok(n)) => tracing::debug!(file = %p.display(), frames = n, "capture file processed"),
                Ok(Err(e)) => tracing::warn!(error = %e, "capture file rejected"),
                Err(e) => tracing::warn!(error = %e, "capture worker failed"),
            }
            if let Err(e) = std::fs::remove_file(&p) {
                tracing::warn!(error = %e, file = %p.display(), "could not remove processed capture file");
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Receive TZSP datagrams (default UDP 37008).
pub async fn run_tzsp(agent: Arc<Agent>, bind: String) {
    let sock = match tokio::net::UdpSocket::bind(&bind).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, %bind, "cannot bind the TZSP listener");
            return;
        }
    };
    tracing::info!(%bind, "TZSP listener");
    let mut buf = vec![0u8; 65_536];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, _)) => {
                agent.ingest_tzsp(chrono::Utc::now().timestamp_micros(), &buf[..n]);
            }
            Err(e) => {
                tracing::warn!(error = %e, "TZSP receive failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
