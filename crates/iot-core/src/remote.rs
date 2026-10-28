//! Privileged remote access to OT assets: request validation, just-in-time
//! windows, approval state machine, session supervision and recording
//! metadata (ZTE-IOT sections 86 Temporary Access Workflow, 87 Vendor
//! Remote Access, 88 Third-Party Maintenance Access, 89 Privileged OT
//! Access, 90 Session Approval, 91 Session Auditing; Volume 2 "Access
//! Mediation"; ZTE-IOTINV-153166 time-bounded, least-privileged, auditable
//! vendor access; AE-IOT-0021..0025 JIT windows, vendor self-service
//! requests with owner approval, credential vaulting, live termination,
//! recording).
//!
//! Sessions are browser-based and brokered by Aether Private Access (its
//! privileged consoles hold the vaulted credentials, so vendors never see
//! them); this module decides *whether* and *until when* a session may run
//! and supervises it: a session can only start inside an approved window,
//! is cut at the window end, after the maximum duration, after idle time,
//! or when the request is revoked.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    PendingApproval,
    Approved,
    Denied,
    Cancelled,
    Expired,
    Revoked,
    Completed,
}

pub const REQUEST_STATES: &[&str] = &["pending_approval", "approved", "denied", "cancelled", "expired", "revoked", "completed"];

impl RequestState {
    pub fn as_str(&self) -> &'static str {
        REQUEST_STATES[*self as usize]
    }
    pub fn parse(s: &str) -> Option<RequestState> {
        REQUEST_STATES.iter().position(|x| *x == s).map(|i| match i {
            0 => RequestState::PendingApproval,
            1 => RequestState::Approved,
            2 => RequestState::Denied,
            3 => RequestState::Cancelled,
            4 => RequestState::Expired,
            5 => RequestState::Revoked,
            _ => RequestState::Completed,
        })
    }
    pub fn can_move_to(&self, to: RequestState) -> bool {
        use RequestState::*;
        matches!(
            (self, to),
            (PendingApproval, Approved)
                | (PendingApproval, Denied)
                | (PendingApproval, Cancelled)
                | (PendingApproval, Expired)
                | (Approved, Revoked)
                | (Approved, Expired)
                | (Approved, Completed)
                | (Approved, Cancelled)
        )
    }
    pub fn is_terminal(&self) -> bool {
        !matches!(self, RequestState::PendingApproval | RequestState::Approved)
    }
}

/// Limits from the tenant's remote access settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// Longest window that can be requested.
    pub max_window_minutes: i64,
    /// Longest single session.
    pub max_session_minutes: i64,
    pub idle_timeout_minutes: i64,
    /// How far in advance a window may start.
    pub max_advance_days: i64,
    /// Require a ticket / work-order reference.
    pub require_ticket: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_window_minutes: 8 * 60, max_session_minutes: 4 * 60, idle_timeout_minutes: 15, max_advance_days: 30, require_ticket: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestInput {
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub protocol: String,
    pub justification: String,
    #[serde(default)]
    pub ticket: Option<String>,
    /// Vendor principal expiry, when the requester is a vendor.
    #[serde(default)]
    pub principal_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub principal_enabled: Option<bool>,
    /// Protocols the target allows for remote access.
    pub target_protocols: Vec<String>,
    /// The target is decommissioned or not OT-accessible.
    #[serde(default)]
    pub target_available: bool,
}

/// Validate a request (stable error codes).
pub fn validate(r: &RequestInput, l: &Limits, now: DateTime<Utc>) -> Result<(), &'static str> {
    if r.window_end <= r.window_start {
        return Err("window_end_before_start");
    }
    if r.window_start < now - Duration::minutes(5) {
        return Err("window_in_past");
    }
    if r.window_start > now + Duration::days(l.max_advance_days) {
        return Err("window_too_far_ahead");
    }
    if r.window_end - r.window_start > Duration::minutes(l.max_window_minutes) {
        return Err("window_too_long");
    }
    if r.justification.trim().len() < 10 {
        return Err("justification_required");
    }
    if l.require_ticket && r.ticket.as_deref().map(|t| t.trim().is_empty()).unwrap_or(true) {
        return Err("ticket_required");
    }
    if !r.target_available {
        return Err("target_unavailable");
    }
    if !r.target_protocols.iter().any(|p| p == &r.protocol) {
        return Err("protocol_not_allowed");
    }
    if r.principal_enabled == Some(false) {
        return Err("principal_disabled");
    }
    if let Some(exp) = r.principal_expires_at {
        if exp <= r.window_end {
            return Err("principal_expires_before_window_end");
        }
    }
    Ok(())
}

/// Whether a session may start now for an approved request.
pub fn can_start(state: RequestState, window_start: DateTime<Utc>, window_end: DateTime<Utc>, now: DateTime<Utc>) -> Result<DateTime<Utc>, &'static str> {
    match state {
        RequestState::Approved => {}
        RequestState::PendingApproval => return Err("approval_pending"),
        _ => return Err("request_not_approved"),
    }
    if now < window_start {
        return Err("window_not_started");
    }
    if now >= window_end {
        return Err("window_ended");
    }
    Ok(window_end)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    Completed,
    WindowEnded,
    MaxDuration,
    Idle,
    Revoked,
    Terminated,
}

impl EndReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            EndReason::Completed => "completed",
            EndReason::WindowEnded => "window_ended",
            EndReason::MaxDuration => "max_duration",
            EndReason::Idle => "idle",
            EndReason::Revoked => "revoked",
            EndReason::Terminated => "terminated",
        }
    }
}

/// Supervision: the reason a running session must end now, if any.
pub fn must_end(
    state: RequestState,
    window_end: DateTime<Utc>,
    started_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
    terminate_requested: bool,
    l: &Limits,
    now: DateTime<Utc>,
) -> Option<EndReason> {
    if terminate_requested {
        return Some(EndReason::Terminated);
    }
    if state == RequestState::Revoked {
        return Some(EndReason::Revoked);
    }
    if now >= window_end {
        return Some(EndReason::WindowEnded);
    }
    if now - started_at >= Duration::minutes(l.max_session_minutes) {
        return Some(EndReason::MaxDuration);
    }
    if now - last_activity >= Duration::minutes(l.idle_timeout_minutes) {
        return Some(EndReason::Idle);
    }
    None
}

/// Recording metadata attached to a session (content is held by the
/// broker; only its integrity digest and size are kept here).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordingMeta {
    pub recording_id: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub duration_ms: u64,
    pub stored_by: String,
}

impl RecordingMeta {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.sha256.len() != 64 || !self.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid_digest");
        }
        if self.recording_id.is_empty() || self.recording_id.len() > 128 {
            return Err("invalid_recording_id");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(now: DateTime<Utc>) -> RequestInput {
        RequestInput {
            window_start: now + Duration::minutes(5),
            window_end: now + Duration::hours(2),
            protocol: "rdp".into(),
            justification: "replace drive parameters on line 3".into(),
            ticket: Some("WO-1182".into()),
            principal_expires_at: Some(now + Duration::days(90)),
            principal_enabled: Some(true),
            target_protocols: vec!["rdp".into(), "https".into()],
            target_available: true,
        }
    }

    #[test]
    fn request_validation() {
        let now = Utc::now();
        let l = Limits { require_ticket: true, ..Limits::default() };
        assert!(validate(&req(now), &l, now).is_ok());
        let mut r = req(now);
        r.window_end = r.window_start + Duration::hours(9);
        assert_eq!(validate(&r, &l, now), Err("window_too_long"));
        let mut r = req(now);
        r.protocol = "telnet".into();
        assert_eq!(validate(&r, &l, now), Err("protocol_not_allowed"));
        let mut r = req(now);
        r.ticket = None;
        assert_eq!(validate(&r, &l, now), Err("ticket_required"));
        let mut r = req(now);
        r.principal_expires_at = Some(now + Duration::hours(1));
        assert_eq!(validate(&r, &l, now), Err("principal_expires_before_window_end"));
        let mut r = req(now);
        r.justification = "fix".into();
        assert_eq!(validate(&r, &l, now), Err("justification_required"));
    }

    #[test]
    fn jit_windows_and_supervision() {
        let now = Utc::now();
        let (s, e) = (now - Duration::minutes(1), now + Duration::hours(1));
        assert_eq!(can_start(RequestState::Approved, s, e, now), Ok(e));
        assert_eq!(can_start(RequestState::PendingApproval, s, e, now), Err("approval_pending"));
        assert_eq!(can_start(RequestState::Approved, now + Duration::hours(1), now + Duration::hours(2), now), Err("window_not_started"));
        assert_eq!(can_start(RequestState::Denied, s, e, now), Err("request_not_approved"));
        let l = Limits::default();
        assert_eq!(must_end(RequestState::Approved, e, now, now, false, &l, now), None);
        assert_eq!(must_end(RequestState::Approved, e, now, now, false, &l, e), Some(EndReason::WindowEnded));
        assert_eq!(must_end(RequestState::Approved, e, now, now - Duration::minutes(20), false, &l, now), Some(EndReason::Idle));
        assert_eq!(must_end(RequestState::Revoked, e, now, now, false, &l, now), Some(EndReason::Revoked));
        assert_eq!(must_end(RequestState::Approved, e, now, now, true, &l, now), Some(EndReason::Terminated));
        assert!(RequestState::PendingApproval.can_move_to(RequestState::Approved));
        assert!(!RequestState::Denied.can_move_to(RequestState::Approved));
        assert!(RecordingMeta { recording_id: "r".into(), sha256: "a".repeat(64), size_bytes: 1, duration_ms: 1, stored_by: "private_access".into() }.validate().is_ok());
    }
}
