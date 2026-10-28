//! Device taxonomy (ZTE-IOT "Device Taxonomy" section 22 and the device
//! family sections 23–38: enterprise IoT, printers, cameras, building
//! management, medical, industrial control (PLC, HMI, SCADA, historian,
//! engineering workstation, robotics), retail/POS, smart building,
//! badge/access and voice/video; AE-IOT-0019 multi-dimensional
//! classification).
//!
//! Each device type belongs to one category and carries defaults used by
//! risk and segmentation: business criticality, whether it is
//! safety-sensitive (fragile equipment: passive observation only, no
//! automatic blocking without an approved enforcement policy —
//! ZTE-IOTINV-153161/153168) and the default segment zone.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TypeInfo {
    pub key: &'static str,
    pub label: &'static str,
    pub category: &'static str,
    /// 1 (low) .. 5 (critical).
    pub criticality: u8,
    pub safety_sensitive: bool,
    /// Default zone for segment assignment.
    pub zone: &'static str,
    /// Purdue level (0 process .. 5 enterprise) for OT/IT positioning.
    pub purdue: u8,
}

pub const CATEGORIES: &[(&str, &str)] = &[
    ("industrial_control", "Industrial control systems"),
    ("building_management", "Building management systems"),
    ("medical", "Medical and clinical devices"),
    ("physical_security", "Cameras and physical security"),
    ("physical_access", "Badge and access control"),
    ("printer", "Printers and peripherals"),
    ("voice_video", "Voice and video"),
    ("retail", "Retail and point of sale"),
    ("enterprise_iot", "Enterprise IoT"),
    ("smart_building", "Smart building devices"),
    ("network_infrastructure", "Network infrastructure"),
    ("it", "IT endpoints and servers"),
    ("unknown", "Unknown"),
];

macro_rules! t {
    ($k:expr, $l:expr, $c:expr, $crit:expr, $safe:expr, $z:expr, $p:expr) => {
        TypeInfo { key: $k, label: $l, category: $c, criticality: $crit, safety_sensitive: $safe, zone: $z, purdue: $p }
    };
}

pub const TYPES: &[TypeInfo] = &[
    // Industrial control (sections 28-34).
    t!("plc", "Programmable logic controller", "industrial_control", 5, true, "ot_control", 1),
    t!("safety_controller", "Safety instrumented controller", "industrial_control", 5, true, "ot_safety", 1),
    t!("rtu", "Remote terminal unit", "industrial_control", 5, true, "ot_control", 1),
    t!("ied", "Intelligent electronic device / protection relay", "industrial_control", 5, true, "ot_control", 1),
    t!("drive", "Drive / motor controller", "industrial_control", 4, true, "ot_control", 0),
    t!("io_module", "Remote I/O module", "industrial_control", 4, true, "ot_control", 0),
    t!("hmi", "Human-machine interface", "industrial_control", 4, true, "ot_supervisory", 2),
    t!("scada_server", "SCADA server", "industrial_control", 5, true, "ot_supervisory", 2),
    t!("historian", "Process historian", "industrial_control", 4, false, "ot_operations", 3),
    t!("engineering_workstation", "Engineering workstation", "industrial_control", 5, false, "ot_operations", 2),
    t!("robot", "Industrial robot / robot controller", "industrial_control", 5, true, "ot_control", 1),
    t!("cnc", "CNC / machine tool", "industrial_control", 4, true, "ot_control", 1),
    t!("industrial_gateway", "Industrial protocol gateway", "industrial_control", 4, true, "ot_supervisory", 2),
    t!("industrial_switch", "Industrial network switch", "industrial_control", 4, false, "ot_supervisory", 2),
    // Building management (sections 26, 36).
    t!("bms_controller", "Building automation controller", "building_management", 4, true, "bms", 1),
    t!("hvac_controller", "HVAC controller", "building_management", 3, true, "bms", 1),
    t!("lighting_controller", "Lighting controller", "smart_building", 2, false, "bms", 1),
    t!("elevator_controller", "Elevator controller", "building_management", 4, true, "bms", 1),
    t!("energy_meter", "Energy meter", "smart_building", 2, false, "bms", 1),
    t!("ups", "Uninterruptible power supply", "smart_building", 4, true, "facilities", 1),
    t!("pdu", "Power distribution unit", "smart_building", 3, true, "facilities", 1),
    t!("thermostat", "Smart thermostat", "smart_building", 2, false, "iot", 1),
    // Medical (section 27).
    t!("infusion_pump", "Infusion pump", "medical", 5, true, "clinical", 1),
    t!("patient_monitor", "Patient monitor", "medical", 5, true, "clinical", 1),
    t!("imaging_modality", "Imaging modality (DICOM)", "medical", 4, true, "clinical", 2),
    t!("clinical_workstation", "Clinical workstation / PACS", "medical", 3, false, "clinical", 3),
    // Physical security and access (sections 25, 37).
    t!("ip_camera", "IP camera", "physical_security", 3, false, "physical_security", 1),
    t!("nvr", "Network video recorder", "physical_security", 3, false, "physical_security", 2),
    t!("badge_reader", "Badge reader", "physical_access", 3, false, "physical_security", 1),
    t!("access_controller", "Door / access controller", "physical_access", 4, true, "physical_security", 1),
    // Printers (section 24).
    t!("printer", "Printer", "printer", 2, false, "printers", 4),
    t!("mfp", "Multifunction printer", "printer", 2, false, "printers", 4),
    t!("scanner", "Scanner / barcode reader", "retail", 2, false, "iot", 4),
    // Voice and video (section 38).
    t!("voip_phone", "VoIP phone", "voice_video", 2, false, "voice", 4),
    t!("video_conference", "Video conferencing system", "voice_video", 2, false, "voice", 4),
    t!("smart_tv", "Smart TV / display", "voice_video", 1, false, "iot", 4),
    t!("media_player", "Media / streaming player", "voice_video", 1, false, "iot", 4),
    t!("digital_signage", "Digital signage", "enterprise_iot", 1, false, "iot", 4),
    // Retail (section 35).
    t!("pos_terminal", "Point-of-sale terminal", "retail", 4, false, "payments", 4),
    t!("payment_terminal", "Payment terminal", "retail", 4, false, "payments", 4),
    t!("kiosk", "Kiosk", "retail", 2, false, "iot", 4),
    // Enterprise IoT (section 23).
    t!("iot_sensor", "IoT sensor", "enterprise_iot", 2, false, "iot", 1),
    t!("iot_gateway", "IoT gateway / hub", "enterprise_iot", 3, false, "iot", 2),
    t!("mqtt_broker", "Message broker", "enterprise_iot", 3, false, "iot", 3),
    t!("smart_speaker", "Smart speaker / assistant", "enterprise_iot", 1, false, "iot", 4),
    t!("embedded_linux", "Embedded Linux device", "enterprise_iot", 2, false, "iot", 4),
    // Network infrastructure.
    t!("switch", "Network switch", "network_infrastructure", 4, false, "infrastructure", 3),
    t!("router", "Router", "network_infrastructure", 4, false, "infrastructure", 3),
    t!("wireless_ap", "Wireless access point", "network_infrastructure", 3, false, "infrastructure", 3),
    t!("firewall_appliance", "Firewall appliance", "network_infrastructure", 4, false, "infrastructure", 3),
    // IT.
    t!("workstation", "Workstation / laptop", "it", 2, false, "corporate", 4),
    t!("server", "Server", "it", 3, false, "corporate", 4),
    t!("mobile", "Mobile device", "it", 1, false, "corporate", 5),
    t!("virtual_machine", "Virtual machine", "it", 2, false, "corporate", 4),
    t!("unknown", "Unknown device", "unknown", 3, false, "quarantine", 5),
];

pub fn get(key: &str) -> &'static TypeInfo {
    TYPES.iter().find(|t| t.key == key).unwrap_or_else(|| TYPES.last().expect("taxonomy has the unknown type"))
}

pub fn is_known(key: &str) -> bool {
    TYPES.iter().any(|t| t.key == key)
}

pub fn type_keys() -> Vec<&'static str> {
    TYPES.iter().map(|t| t.key).collect()
}

pub fn category_keys() -> Vec<&'static str> {
    CATEGORIES.iter().map(|c| c.0).collect()
}

/// Category keys counted as operational technology.
pub fn is_ot(category: &str) -> bool {
    matches!(category, "industrial_control" | "building_management" | "medical" | "physical_access")
}

/// Lifecycle states of an asset (section 17 Asset Identity Lifecycle,
/// section 135 Lifecycle and Decommissioning).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Seen, not yet confirmed (single observation or low confidence).
    Discovered,
    Active,
    /// Not seen within the inactivity window.
    Inactive,
    /// Merged into another asset (kept for audit).
    Merged,
    /// Retired by an administrator; policy references removed.
    Decommissioned,
}

pub const LIFECYCLE: &[&str] = &["discovered", "active", "inactive", "merged", "decommissioned"];

impl Lifecycle {
    pub fn as_str(&self) -> &'static str {
        LIFECYCLE[*self as usize]
    }
    pub fn parse(s: &str) -> Option<Lifecycle> {
        Some(match s {
            "discovered" => Lifecycle::Discovered,
            "active" => Lifecycle::Active,
            "inactive" => Lifecycle::Inactive,
            "merged" => Lifecycle::Merged,
            "decommissioned" => Lifecycle::Decommissioned,
            _ => return None,
        })
    }
    /// Allowed administrative or automatic transitions.
    pub fn can_move_to(&self, to: Lifecycle) -> bool {
        use Lifecycle::*;
        matches!(
            (self, to),
            (Discovered, Active)
                | (Discovered, Inactive)
                | (Discovered, Merged)
                | (Discovered, Decommissioned)
                | (Active, Inactive)
                | (Active, Merged)
                | (Active, Decommissioned)
                | (Inactive, Active)
                | (Inactive, Merged)
                | (Inactive, Decommissioned)
                | (Decommissioned, Active)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_is_consistent() {
        let cats = category_keys();
        let mut seen = std::collections::HashSet::new();
        for t in TYPES {
            assert!(cats.contains(&t.category), "{} has unknown category", t.key);
            assert!(seen.insert(t.key), "duplicate {}", t.key);
            assert!((1..=5).contains(&t.criticality) && t.purdue <= 5);
        }
        assert_eq!(get("nonsense").key, "unknown");
        assert!(get("plc").safety_sensitive && is_ot(get("plc").category));
        assert!(!is_ot(get("printer").category));
    }

    #[test]
    fn lifecycle_transitions() {
        assert!(Lifecycle::Active.can_move_to(Lifecycle::Decommissioned));
        assert!(!Lifecycle::Merged.can_move_to(Lifecycle::Active));
        assert!(Lifecycle::Decommissioned.can_move_to(Lifecycle::Active));
        assert_eq!(Lifecycle::parse("inactive"), Some(Lifecycle::Inactive));
    }
}
