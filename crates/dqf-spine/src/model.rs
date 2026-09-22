//! Input model: driver records and the qualification documents on file.
//!
//! Everything here is caller-supplied input. Shape violations are refused by
//! the engine (fail-closed), never repaired silently.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

/// The driver-file envelope: the canonical JSON shape of the engine's input
/// bytes. The envelope (not a bare array) is the contract so the file names
/// itself and top-level metadata can be added without a breaking change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverFile {
    pub drivers: Vec<DriverRecord>,
}

/// Kind of a DQF checklist document. Variants map 1:1 to the checklist items
/// in the spec's dqf-spine product block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocKind {
    Cdl,
    MedicalCertificate,
    Mvr,
    AnnualReview,
    RoadTest,
    EmploymentHistory,
}

/// Medical certificate type. A variance certificate (federal exemption —
/// vision, diabetes, hearing, and the like) carries a shorter validity
/// ceiling than a full certificate; both ceilings are config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MedicalCertType {
    Full,
    Variance,
}

/// One qualification document on file. Kind-specific fields are `None` when
/// they do not apply; the engine validates the shape per kind and refuses
/// documents that contradict their kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub doc_id: String,
    pub kind: DocKind,
    /// Employment-file cycle this document belongs to. Checklist completeness
    /// is evaluated against the driver's current cycle only.
    pub cycle_id: String,
    /// Issuance / completion date. Must not be after the campaign date.
    pub issued_on: NaiveDate,
    /// Expiry printed on the document. Only expiry-typed kinds (CDL, medical
    /// certificate) may set it; window-typed kinds derive their boundary from
    /// `issued_on` plus a config window.
    pub expires_on: Option<NaiveDate>,
    /// CDL issuing state, CDL-kind only. Informational: state rules key on
    /// the driver's operating state (`DriverRecord::cdl_state`).
    pub state: Option<String>,
    /// CDL endorsement codes (e.g. "H", "N", "T"), CDL-kind only.
    pub endorsements: Option<Vec<String>>,
    /// Medical certificate type, medical-kind only.
    pub cert_type: Option<MedicalCertType>,
}

impl Document {
    /// Endorsement codes held on this document (empty for non-CDL kinds).
    pub fn endorsement_codes(&self) -> &[String] {
        self.endorsements.as_deref().unwrap_or(&[])
    }
}

/// Rehire linkage: a rehired driver opens a new file cycle that must name the
/// prior cycle it supersedes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rehire {
    pub rehire_date: NaiveDate,
    pub prior_cycle_id: String,
}

/// A driver under the carrier's qualification program.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverRecord {
    /// Stable business key — findings and signoff receipts name this subject.
    pub driver_id: String,
    pub employee_id: String,
    /// Current employment-file cycle id.
    pub cycle_id: String,
    pub hire_date: NaiveDate,
    /// Separation date when the driver has left. A driver separated on or
    /// before the campaign date is not driving, whatever `active` says.
    pub separation_date: Option<NaiveDate>,
    /// True while the driver performs safety-sensitive driving for the
    /// carrier. The engine additionally excludes drivers separated by date.
    pub active: bool,
    pub rehire: Option<Rehire>,
    /// Known prior file-cycle ids; rehire linkage must reference one of them.
    #[serde(default)]
    pub prior_cycles: Vec<String>,
    /// State whose CDL rules apply to this driver's operation.
    pub cdl_state: String,
    /// Endorsement codes the driver's operation requires (e.g. "H" for
    /// hazmat) regardless of state rules.
    #[serde(default)]
    pub operation_required_endorsements: Vec<String>,
    #[serde(default)]
    pub documents: Vec<Document>,
}
