//! Aether IoT/OT Security engines (pure, synchronous, no I/O).
#![allow(clippy::type_complexity, clippy::too_many_arguments)]

pub mod baseline;
pub mod classify;
pub mod collect;
pub mod fingerprint;
pub mod graph;
pub mod identity;
pub mod model;
pub mod packet;
pub mod policy;
pub mod protocols;
pub mod risk;
pub mod segmentation;
pub mod taxonomy;
pub mod vuln;

/// Deterministic UUID (version 8 layout) from a name: stable identifiers for
/// generated objects such as recommended rules.
pub fn stable_uuid(name: &str) -> uuid::Uuid {
    use sha2::Digest;
    let h = sha2::Sha256::digest(name.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(b)
}
pub mod acceptance;
pub mod activeq;
pub mod assertions;
pub mod capabilities;
pub mod failure;
pub mod remote;
pub mod resilience;
pub mod schemas;
