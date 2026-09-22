//! The deterministic DQF engine: pure functions over explicit inputs.
//!
//! Purity contract (family rule): no clock reads — the campaign date is an
//! input; no filesystem, no network, no RNG. All date arithmetic is checked
//! and fails closed on overflow. Money does not occur in this domain, so the
//! integer-cents rule is not exercised here.
//!
//! Boundary conventions (documented in the README):
//! * An expiry-typed document is expired when its effective expiry is
//!   strictly before the campaign date — valid through the printed date.
//! * A window-typed document is stale when `issued_on + window` is strictly
//!   before the campaign date — valid through the boundary day.
//! * The expiring-soon warning fires when the boundary is within
//!   `expiring_warn_days` of the campaign date, inclusive.
//! * Month arithmetic clamps to the end of the target month.

use std::collections::{BTreeMap, HashSet};

use chrono::{Days, Months, NaiveDate};
use spine::{Finding, Severity};

use crate::config::{DqfConfig, StateCdlRule};
use crate::error::DqfError;
use crate::model::{DocKind, Document, DriverRecord, MedicalCertType};

// Rule ids — stable contract for downstream filtering; see the README rule
// table. Severity is enforced by the emitters, not the constants.
pub const R_CDL_EXPIRED: &str = "DQF-CDL-EXPIRED";
pub const R_CDL_MISSING: &str = "DQF-CDL-MISSING";
pub const R_CDL_WINDOW_OVERMAX: &str = "DQF-CDL-WINDOW-OVERMAX";
pub const R_MED_EXPIRED: &str = "DQF-MED-EXPIRED";
pub const R_MED_MISSING: &str = "DQF-MED-MISSING";
pub const R_MED_WINDOW_OVERMAX: &str = "DQF-MED-WINDOW-OVERMAX";
pub const R_MVR_MISSING: &str = "DQF-MVR-MISSING";
pub const R_MVR_STALE: &str = "DQF-MVR-STALE";
pub const R_ANNUAL_MISSING: &str = "DQF-ANNUAL-REVIEW-MISSING";
pub const R_ANNUAL_STALE: &str = "DQF-ANNUAL-REVIEW-STALE";
pub const R_ROADTEST_MISSING: &str = "DQF-ROADTEST-MISSING";
pub const R_EMPHIST_MISSING: &str = "DQF-EMPLOYMENT-HISTORY-MISSING";
pub const R_ENDORSEMENT_MISSING: &str = "DQF-ENDORSEMENT-MISSING";
pub const R_STATE_CDL_RULE: &str = "DQF-STATE-CDL-RULE";
pub const R_REHIRE_LINKAGE: &str = "DQF-REHIRE-LINKAGE";
pub const R_OUT_OF_CYCLE_DOC: &str = "DQF-OUT-OF-CYCLE-DOC";
pub const R_EXPIRING_SOON: &str = "DQF-EXPIRING-SOON";

/// Evaluate a whole driver file. Findings are deterministic and sorted by
/// (subject, rule_id, message). Malformed input is refused, never patched.
pub fn evaluate(
    drivers: &[DriverRecord],
    config: &DqfConfig,
    as_of: NaiveDate,
) -> Result<Vec<Finding>, DqfError> {
    config.validate()?;
    let mut seen: HashSet<&str> = HashSet::new();
    for driver in drivers {
        if !seen.insert(driver.driver_id.trim()) {
            return Err(DqfError::MalformedDriver {
                driver_id: driver.driver_id.clone(),
                detail: "duplicate driver_id".to_string(),
            });
        }
    }
    let mut findings = Vec::new();
    for driver in drivers {
        evaluate_driver(driver, config, as_of, &mut findings)?;
    }
    findings.sort_by(|a, b| {
        (&a.subject, &a.rule_id, &a.message).cmp(&(&b.subject, &b.rule_id, &b.message))
    });
    Ok(findings)
}

fn evaluate_driver(
    d: &DriverRecord,
    config: &DqfConfig,
    as_of: NaiveDate,
    out: &mut Vec<Finding>,
) -> Result<(), DqfError> {
    validate_driver(d, as_of)?;
    for doc in &d.documents {
        validate_document(doc, as_of)?;
    }

    // "Active driving" means the record says active and the driver has not
    // separated on or before the campaign date.
    let separated = match d.separation_date {
        Some(sep) => sep <= as_of,
        None => false,
    };
    let driving = d.active && !separated;

    // Rehire linkage: a rehired driver's new file cycle must name a known
    // prior cycle.
    if let Some(rehire) = &d.rehire {
        let known = d.prior_cycles.contains(&rehire.prior_cycle_id);
        if rehire.prior_cycle_id == d.cycle_id || !known {
            out.push(warn(
                R_REHIRE_LINKAGE,
                &d.driver_id,
                format!(
                    "rehire linkage invalid: prior_cycle_id {prior:?} is not a known prior cycle",
                    prior = rehire.prior_cycle_id
                ),
            ));
        }
    }

    // Partition documents into the current cycle (grouped by kind) and
    // out-of-cycle strays. Only current-cycle documents can satisfy the
    // checklist — a rehired driver's prior-cycle MVR does not carry over.
    let mut by_kind: BTreeMap<DocKind, Vec<&Document>> = BTreeMap::new();
    for doc in &d.documents {
        if doc.cycle_id == d.cycle_id {
            by_kind.entry(doc.kind).or_default().push(doc);
        } else {
            out.push(warn(
                R_OUT_OF_CYCLE_DOC,
                &d.driver_id,
                format!(
                    "document {} is stamped with cycle {:?}, not the current cycle {:?}",
                    doc.doc_id, doc.cycle_id, d.cycle_id
                ),
            ));
        }
    }

    for kind in [
        DocKind::Cdl,
        DocKind::MedicalCertificate,
        DocKind::Mvr,
        DocKind::AnnualReview,
        DocKind::RoadTest,
        DocKind::EmploymentHistory,
    ] {
        // The governing document of a kind is the latest issuance; a renewal
        // history is normal and older documents are not re-checked.
        let governing = by_kind.get(&kind).and_then(|docs| {
            docs.iter()
                .copied()
                .max_by(|a, b| (a.issued_on, &a.doc_id).cmp(&(b.issued_on, &b.doc_id)))
        });
        match governing {
            None => {
                if config.required(kind) {
                    out.push(missing_finding(kind, d, driving));
                }
            }
            Some(doc) => match kind {
                DocKind::Cdl => eval_cdl(d, doc, config, as_of, driving, out)?,
                DocKind::MedicalCertificate => {
                    eval_medical(d, doc, config, as_of, driving, out)?;
                }
                DocKind::Mvr => eval_window(
                    d,
                    doc,
                    config.mvr_validity_days,
                    R_MVR_STALE,
                    "MVR",
                    as_of,
                    config.expiring_warn_days,
                    out,
                )?,
                DocKind::AnnualReview => eval_window(
                    d,
                    doc,
                    config.annual_review_validity_days,
                    R_ANNUAL_STALE,
                    "annual review",
                    as_of,
                    config.expiring_warn_days,
                    out,
                )?,
                // One-time items: presence is the check.
                DocKind::RoadTest | DocKind::EmploymentHistory => {}
            },
        }
    }
    Ok(())
}

fn eval_cdl(
    d: &DriverRecord,
    doc: &Document,
    config: &DqfConfig,
    as_of: NaiveDate,
    driving: bool,
    out: &mut Vec<Finding>,
) -> Result<(), DqfError> {
    let expires = match doc.expires_on {
        Some(e) => e,
        None => return Err(malformed(doc, "CDL requires expires_on")),
    };
    let state = match doc.state.as_deref() {
        Some(s) => s.trim().to_string(),
        None => return Err(malformed(doc, "CDL requires the issuing state")),
    };
    // State rules key on the driver's operating state.
    let rule = config.state_rule(&d.cdl_state);

    // Effective expiry honors a per-state maximum validity window.
    let mut effective = expires;
    if let Some(sr) = rule {
        if let Some(max_months) = sr.max_cdl_validity_months {
            let cap = checked_add_months(doc.issued_on, max_months)?;
            if expires > cap {
                out.push(warn(
                    R_CDL_WINDOW_OVERMAX,
                    &d.driver_id,
                    format!(
                        "CDL {doc_id} validity exceeds the {state} maximum of {max_months} months; expiry capped at {cap}",
                        doc_id = doc.doc_id
                    ),
                ));
                effective = cap;
            }
        }
    }

    if effective < as_of {
        let message = if driving {
            format!(
                "CDL {doc_id} expired {effective}; out-of-service risk: active driving with an expired CDL",
                doc_id = doc.doc_id
            )
        } else {
            format!(
                "CDL {doc_id} expired {effective} (driver not active)",
                doc_id = doc.doc_id
            )
        };
        push_expiry(out, driving, R_CDL_EXPIRED, &d.driver_id, message);
    } else {
        maybe_expiring_soon(
            out,
            effective,
            as_of,
            config.expiring_warn_days,
            &d.driver_id,
            "CDL",
        );
        eval_endorsements(d, doc, rule, out);
    }
    Ok(())
}

fn eval_medical(
    d: &DriverRecord,
    doc: &Document,
    config: &DqfConfig,
    as_of: NaiveDate,
    driving: bool,
    out: &mut Vec<Finding>,
) -> Result<(), DqfError> {
    let expires = match doc.expires_on {
        Some(e) => e,
        None => return Err(malformed(doc, "medical certificate requires expires_on")),
    };
    let cert_type = match doc.cert_type {
        Some(t) => t,
        None => return Err(malformed(doc, "medical certificate requires cert_type")),
    };
    // Validity ceiling per certificate type: a variance certificate may not
    // borrow the full certificate's longer window.
    let max_months = match cert_type {
        MedicalCertType::Full => config.medical.full_max_months,
        MedicalCertType::Variance => config.medical.variance_max_months,
    };
    let cap = checked_add_months(doc.issued_on, max_months)?;
    let effective = expires.min(cap);
    if expires > cap {
        out.push(warn(
            R_MED_WINDOW_OVERMAX,
            &d.driver_id,
            format!(
                "medical certificate {doc_id} ({cert_type:?}) validity exceeds the {max_months}-month ceiling for its type; expiry capped at {cap}",
                doc_id = doc.doc_id
            ),
        ));
    }
    if effective < as_of {
        let message = if driving {
            format!(
                "medical certificate {doc_id} ({cert_type:?}) expired {effective}; out-of-service risk: active driving with an expired medical certificate",
                doc_id = doc.doc_id
            )
        } else {
            format!(
                "medical certificate {doc_id} ({cert_type:?}) expired {effective} (driver not active)",
                doc_id = doc.doc_id
            )
        };
        push_expiry(out, driving, R_MED_EXPIRED, &d.driver_id, message);
    } else {
        maybe_expiring_soon(
            out,
            effective,
            as_of,
            config.expiring_warn_days,
            &d.driver_id,
            "medical certificate",
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn eval_window(
    d: &DriverRecord,
    doc: &Document,
    validity_days: u32,
    stale_rule: &str,
    label: &str,
    as_of: NaiveDate,
    warn_days: u32,
    out: &mut Vec<Finding>,
) -> Result<(), DqfError> {
    let boundary = checked_add_days(doc.issued_on, validity_days)?;
    if boundary < as_of {
        out.push(warn(
            stale_rule,
            &d.driver_id,
            format!(
                "{label} completed {issued} is older than the {validity_days}-day window (boundary {boundary})",
                issued = doc.issued_on
            ),
        ));
    } else {
        maybe_expiring_soon(out, boundary, as_of, warn_days, &d.driver_id, label);
    }
    Ok(())
}

fn eval_endorsements(
    d: &DriverRecord,
    doc: &Document,
    rule: Option<&StateCdlRule>,
    out: &mut Vec<Finding>,
) {
    let held = doc.endorsement_codes();
    let missing_op = missing_codes(&d.operation_required_endorsements, held);
    if !missing_op.is_empty() {
        out.push(warn(
            R_ENDORSEMENT_MISSING,
            &d.driver_id,
            format!(
                "CDL {doc_id} is missing operation-required endorsements: {missing_op:?}",
                doc_id = doc.doc_id
            ),
        ));
    }
    if let Some(sr) = rule {
        let missing_state = missing_codes(&sr.required_endorsements, held);
        if !missing_state.is_empty() {
            out.push(warn(
                R_STATE_CDL_RULE,
                &d.driver_id,
                format!(
                    "CDL {doc_id} does not satisfy the {state} rule; missing endorsements: {missing_state:?}",
                    doc_id = doc.doc_id,
                    state = sr.state
                ),
            ));
        }
    }
}

fn missing_codes(required: &[String], held: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|r| !held.iter().any(|h| h.trim().eq_ignore_ascii_case(r.trim())))
        .cloned()
        .collect()
}

/// Missing-document gap. For an actively driving driver, a missing CDL or
/// medical certificate is the same risk class as an expired one — breach
/// severity; other gaps and inactive drivers are warnings.
fn missing_finding(kind: DocKind, d: &DriverRecord, driving: bool) -> Finding {
    let subject = d.driver_id.as_str();
    let label = match kind {
        DocKind::Cdl => "CDL",
        DocKind::MedicalCertificate => "medical certificate",
        DocKind::Mvr => "MVR",
        DocKind::AnnualReview => "annual review",
        DocKind::RoadTest => "road-test certificate",
        DocKind::EmploymentHistory => "employment history",
    };
    let oos = driving && matches!(kind, DocKind::Cdl | DocKind::MedicalCertificate);
    let message = if oos {
        format!(
            "no current-cycle {label} on file; out-of-service risk: active driving without a {label}"
        )
    } else {
        format!("no current-cycle {label} on file")
    };
    let rule_id = match kind {
        DocKind::Cdl => R_CDL_MISSING,
        DocKind::MedicalCertificate => R_MED_MISSING,
        DocKind::Mvr => R_MVR_MISSING,
        DocKind::AnnualReview => R_ANNUAL_MISSING,
        DocKind::RoadTest => R_ROADTEST_MISSING,
        DocKind::EmploymentHistory => R_EMPHIST_MISSING,
    };
    if oos {
        Finding::breach(rule_id, subject, message)
    } else {
        warn(rule_id, subject, message)
    }
}

fn maybe_expiring_soon(
    out: &mut Vec<Finding>,
    boundary: NaiveDate,
    as_of: NaiveDate,
    warn_days: u32,
    subject: &str,
    label: &str,
) {
    let days_left = (boundary - as_of).num_days();
    if days_left <= i64::from(warn_days) {
        out.push(warn(
            R_EXPIRING_SOON,
            subject,
            format!("{label} boundary {boundary} is within {days_left} days of the campaign date"),
        ));
    }
}

fn push_expiry(
    out: &mut Vec<Finding>,
    driving: bool,
    rule_id: &str,
    subject: &str,
    message: String,
) {
    if driving {
        out.push(Finding::breach(rule_id, subject, message));
    } else {
        out.push(warn(rule_id, subject, message));
    }
}

fn warn(rule_id: &str, subject: &str, message: impl Into<String>) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::Warn,
        subject: subject.to_string(),
        message: message.into(),
        requires_signoff: false,
    }
}

fn checked_add_months(date: NaiveDate, months: u32) -> Result<NaiveDate, DqfError> {
    date.checked_add_months(Months::new(months))
        .ok_or_else(|| DqfError::DateOverflow {
            detail: format!("window of {months} months overflows the date range from {date}"),
        })
}

fn checked_add_days(date: NaiveDate, days: u32) -> Result<NaiveDate, DqfError> {
    date.checked_add_days(Days::new(u64::from(days)))
        .ok_or_else(|| DqfError::DateOverflow {
            detail: format!("window of {days} days overflows the date range from {date}"),
        })
}

fn malformed(doc: &Document, detail: &str) -> DqfError {
    DqfError::MalformedDocument {
        doc_id: doc.doc_id.clone(),
        detail: detail.to_string(),
    }
}

fn validate_driver(d: &DriverRecord, as_of: NaiveDate) -> Result<(), DqfError> {
    let err = |detail: String| -> DqfError {
        DqfError::MalformedDriver {
            driver_id: d.driver_id.clone(),
            detail,
        }
    };
    if d.driver_id.trim().is_empty() {
        return Err(err("driver_id is empty".to_string()));
    }
    if d.employee_id.trim().is_empty() {
        return Err(err("employee_id is empty".to_string()));
    }
    if d.cycle_id.trim().is_empty() {
        return Err(err("cycle_id is empty".to_string()));
    }
    if d.cdl_state.trim().is_empty() {
        return Err(err("cdl_state is empty".to_string()));
    }
    if d.hire_date > as_of {
        return Err(err(format!(
            "hire_date {hire} is after the campaign date {as_of}",
            hire = d.hire_date
        )));
    }
    if let Some(sep) = d.separation_date {
        if sep <= d.hire_date {
            return Err(err(format!(
                "separation_date {sep} is not after hire_date {hire}",
                sep = sep,
                hire = d.hire_date
            )));
        }
    }
    if let Some(rehire) = &d.rehire {
        if rehire.rehire_date < d.hire_date {
            return Err(err(format!(
                "rehire_date {} is before hire_date {}",
                rehire.rehire_date, d.hire_date
            )));
        }
        if rehire.prior_cycle_id.trim().is_empty() {
            return Err(err("rehire prior_cycle_id is empty".to_string()));
        }
    }
    let mut seen: HashSet<&str> = HashSet::new();
    for doc in &d.documents {
        if !seen.insert(doc.doc_id.trim()) {
            return Err(err(format!("duplicate document id {:?}", doc.doc_id)));
        }
    }
    Ok(())
}

fn validate_document(doc: &Document, as_of: NaiveDate) -> Result<(), DqfError> {
    if doc.doc_id.trim().is_empty() {
        return Err(DqfError::MalformedDocument {
            doc_id: doc.doc_id.clone(),
            detail: "doc_id is empty".to_string(),
        });
    }
    if doc.cycle_id.trim().is_empty() {
        return Err(DqfError::MalformedDocument {
            doc_id: doc.doc_id.clone(),
            detail: "cycle_id is empty".to_string(),
        });
    }
    if doc.issued_on > as_of {
        return Err(DqfError::MalformedDocument {
            doc_id: doc.doc_id.clone(),
            detail: format!(
                "issued_on {issued} is after the campaign date {as_of}",
                issued = doc.issued_on
            ),
        });
    }
    match doc.kind {
        DocKind::Cdl => {
            require(doc, doc.expires_on.is_some(), "CDL requires expires_on")?;
            require(doc, doc.state.is_some(), "CDL requires the issuing state")?;
            require(doc, doc.cert_type.is_none(), "CDL must not carry cert_type")?;
        }
        DocKind::MedicalCertificate => {
            require(
                doc,
                doc.expires_on.is_some(),
                "medical certificate requires expires_on",
            )?;
            require(
                doc,
                doc.cert_type.is_some(),
                "medical certificate requires cert_type",
            )?;
            require(
                doc,
                doc.state.is_none(),
                "medical certificate must not carry state",
            )?;
            require(
                doc,
                doc.endorsements.is_none(),
                "medical certificate must not carry endorsements",
            )?;
        }
        DocKind::Mvr | DocKind::AnnualReview | DocKind::RoadTest | DocKind::EmploymentHistory => {
            require(
                doc,
                doc.expires_on.is_none(),
                "window-typed documents must not carry expires_on",
            )?;
            require(
                doc,
                doc.state.is_none(),
                "window-typed documents must not carry state",
            )?;
            require(
                doc,
                doc.endorsements.is_none(),
                "window-typed documents must not carry endorsements",
            )?;
            require(
                doc,
                doc.cert_type.is_none(),
                "window-typed documents must not carry cert_type",
            )?;
        }
    }
    Ok(())
}

fn require(doc: &Document, ok: bool, detail: &str) -> Result<(), DqfError> {
    if ok {
        Ok(())
    } else {
        Err(malformed(doc, detail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{all_required, MedicalWindows};
    use crate::model::Rehire;
    use spine::{LockState, Signoff, SignoffDecision, VerifyError};

    const R_MED: &str = R_MED_EXPIRED;

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).expect("test date is valid")
    }

    fn as_of() -> NaiveDate {
        date(2026, 9, 22)
    }

    fn cfg() -> DqfConfig {
        DqfConfig {
            expiring_warn_days: 30,
            mvr_validity_days: 365,
            annual_review_validity_days: 365,
            medical: MedicalWindows {
                full_max_months: 24,
                variance_max_months: 12,
            },
            checklist: all_required(),
            state_cdl_rules: vec![],
        }
    }

    fn driver(documents: Vec<Document>) -> DriverRecord {
        DriverRecord {
            driver_id: "D-001".to_string(),
            employee_id: "E-100".to_string(),
            cycle_id: "CY-2026".to_string(),
            hire_date: date(2020, 1, 1),
            separation_date: None,
            active: true,
            rehire: None,
            prior_cycles: vec![],
            cdl_state: "TX".to_string(),
            operation_required_endorsements: vec![],
            documents,
        }
    }

    fn doc(id: &str, kind: DocKind, issued: NaiveDate) -> Document {
        Document {
            doc_id: id.to_string(),
            kind,
            cycle_id: "CY-2026".to_string(),
            issued_on: issued,
            expires_on: None,
            state: None,
            endorsements: None,
            cert_type: None,
        }
    }

    fn cdl(id: &str, issued: NaiveDate, expires: NaiveDate, endorsements: &[&str]) -> Document {
        Document {
            endorsements: Some(endorsements.iter().map(|e| e.to_string()).collect()),
            ..cdl_base(id, issued, expires)
        }
    }

    fn cdl_base(id: &str, issued: NaiveDate, expires: NaiveDate) -> Document {
        Document {
            doc_id: id.to_string(),
            kind: DocKind::Cdl,
            cycle_id: "CY-2026".to_string(),
            issued_on: issued,
            expires_on: Some(expires),
            state: Some("TX".to_string()),
            endorsements: None,
            cert_type: None,
        }
    }

    fn medical(id: &str, issued: NaiveDate, expires: NaiveDate, cert: MedicalCertType) -> Document {
        Document {
            doc_id: id.to_string(),
            kind: DocKind::MedicalCertificate,
            cycle_id: "CY-2026".to_string(),
            issued_on: issued,
            expires_on: Some(expires),
            state: None,
            endorsements: None,
            cert_type: Some(cert),
        }
    }

    /// A complete, currently valid file — no findings expected.
    fn full_dqf() -> Vec<Document> {
        vec![
            cdl("cdl-1", date(2024, 9, 1), date(2027, 9, 1), &[]),
            medical(
                "med-1",
                date(2025, 9, 1),
                date(2027, 9, 1),
                MedicalCertType::Full,
            ),
            doc("mvr-1", DocKind::Mvr, date(2026, 5, 1)),
            doc("annual-1", DocKind::AnnualReview, date(2026, 8, 1)),
            doc("road-1", DocKind::RoadTest, date(2024, 2, 1)),
            doc("hist-1", DocKind::EmploymentHistory, date(2020, 1, 1)),
        ]
    }

    /// Replace the document of `doc.kind` in a complete file with `doc`.
    fn file_with(doc: Document) -> Vec<Document> {
        let mut docs = full_dqf();
        docs.retain(|d| d.kind != doc.kind);
        docs.push(doc);
        docs
    }

    fn rules_of(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn complete_file_has_no_findings() {
        let findings = evaluate(&[driver(full_dqf())], &cfg(), as_of()).expect("valid input");
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    // -- CDL expiry boundary -------------------------------------------------

    #[test]
    fn cdl_is_valid_through_the_expiry_day() {
        let doc = cdl_base("cdl-1", date(2020, 1, 1), as_of());
        let findings = evaluate(&[driver(file_with(doc))], &cfg(), as_of()).expect("valid input");
        assert!(!rules_of(&findings).contains(&R_CDL_EXPIRED));
        // The expiry day itself is inside the warn window.
        assert!(rules_of(&findings).contains(&R_EXPIRING_SOON));
    }

    #[test]
    fn cdl_expired_the_day_after_expiry_is_an_oos_breach() {
        let doc = cdl_base("cdl-1", date(2020, 1, 1), as_of() - Days::new(1));
        let findings = evaluate(&[driver(file_with(doc))], &cfg(), as_of()).expect("valid input");
        let expired = findings
            .iter()
            .find(|f| f.rule_id == R_CDL_EXPIRED)
            .expect("expired CDL must be found");
        assert_eq!(expired.severity, Severity::Breach);
        assert!(expired.requires_signoff);
        assert!(expired.message.contains("out-of-service"));
        assert_eq!(expired.subject, "D-001");
    }

    #[test]
    fn cdl_expired_for_an_inactive_driver_is_a_warn() {
        let mut d = driver(file_with(cdl_base(
            "cdl-1",
            date(2020, 1, 1),
            as_of() - Days::new(1),
        )));
        d.active = false;
        let findings = evaluate(&[d], &cfg(), as_of()).expect("valid input");
        let expired = findings
            .iter()
            .find(|f| f.rule_id == R_CDL_EXPIRED)
            .expect("expired CDL must be found");
        assert_eq!(expired.severity, Severity::Warn);
        assert!(!expired.requires_signoff);
    }

    #[test]
    fn separated_on_the_campaign_date_is_not_active_driving() {
        let mut d = driver(file_with(cdl_base(
            "cdl-1",
            date(2020, 1, 1),
            as_of() - Days::new(1),
        )));
        d.separation_date = Some(as_of());
        let findings = evaluate(&[d], &cfg(), as_of()).expect("valid input");
        let expired = findings
            .iter()
            .find(|f| f.rule_id == R_CDL_EXPIRED)
            .expect("expired CDL must be found");
        assert_eq!(
            expired.severity,
            Severity::Warn,
            "separated driver is not OOS"
        );
    }

    // -- Missing-document gaps ----------------------------------------------

    #[test]
    fn missing_cdl_for_an_active_driver_is_a_breach_gap() {
        let docs: Vec<Document> = full_dqf()
            .into_iter()
            .filter(|d| d.kind != DocKind::Cdl)
            .collect();
        let findings = evaluate(&[driver(docs)], &cfg(), as_of()).expect("valid input");
        let gap = findings
            .iter()
            .find(|f| f.rule_id == R_CDL_MISSING)
            .expect("missing CDL must be found");
        assert_eq!(gap.severity, Severity::Breach);
        assert!(gap.message.contains("out-of-service"));
    }

    #[test]
    fn missing_medical_for_an_inactive_driver_is_a_warn_gap() {
        let docs: Vec<Document> = full_dqf()
            .into_iter()
            .filter(|d| d.kind != DocKind::MedicalCertificate)
            .collect();
        let mut d = driver(docs);
        d.active = false;
        let findings = evaluate(&[d], &cfg(), as_of()).expect("valid input");
        let gap = findings
            .iter()
            .find(|f| f.rule_id == R_MED_MISSING)
            .expect("missing medical must be found");
        assert_eq!(gap.severity, Severity::Warn);
    }

    #[test]
    fn missing_road_test_is_a_gap() {
        let docs: Vec<Document> = full_dqf()
            .into_iter()
            .filter(|d| d.kind != DocKind::RoadTest)
            .collect();
        let findings = evaluate(&[driver(docs)], &cfg(), as_of()).expect("valid input");
        assert!(rules_of(&findings).contains(&R_ROADTEST_MISSING));
        assert!(findings.iter().all(|f| f.severity == Severity::Warn));
    }

    #[test]
    fn missing_employment_history_is_a_gap() {
        let docs: Vec<Document> = full_dqf()
            .into_iter()
            .filter(|d| d.kind != DocKind::EmploymentHistory)
            .collect();
        let findings = evaluate(&[driver(docs)], &cfg(), as_of()).expect("valid input");
        assert!(rules_of(&findings).contains(&R_EMPHIST_MISSING));
    }

    #[test]
    fn optional_item_does_not_gap_when_absent() {
        let mut config = cfg();
        config.checklist.road_test.required = false;
        let docs: Vec<Document> = full_dqf()
            .into_iter()
            .filter(|d| d.kind != DocKind::RoadTest)
            .collect();
        let findings = evaluate(&[driver(docs)], &config, as_of()).expect("valid input");
        assert!(!rules_of(&findings).contains(&R_ROADTEST_MISSING));
    }

    // -- Medical certificate: full vs variance windows -----------------------

    #[test]
    fn medical_is_valid_through_the_expiry_day() {
        let doc = medical("med-1", date(2025, 9, 1), as_of(), MedicalCertType::Full);
        let findings = evaluate(&[driver(file_with(doc))], &cfg(), as_of()).expect("valid input");
        assert!(!rules_of(&findings).contains(&R_MED_EXPIRED));
    }

    #[test]
    fn medical_expired_the_day_after_expiry_is_an_oos_breach() {
        let doc = medical(
            "med-1",
            date(2024, 6, 1),
            as_of() - Days::new(1),
            MedicalCertType::Full,
        );
        let findings = evaluate(&[driver(file_with(doc))], &cfg(), as_of()).expect("valid input");
        let expired = findings
            .iter()
            .find(|f| f.rule_id == R_MED_EXPIRED)
            .expect("expired medical must be found");
        assert_eq!(expired.severity, Severity::Breach);
        assert!(expired.message.contains("out-of-service"));
    }

    #[test]
    fn variance_window_is_capped_shorter_than_full() {
        // Same printed dates for both drivers; the variance ceiling (12
        // months) expires the variance certificate while the full
        // certificate (24 months) stays valid.
        let issued = date(2025, 8, 22);
        let printed_expiry = date(2027, 8, 22);
        let variance = evaluate(
            &[driver(file_with(medical(
                "med-1",
                issued,
                printed_expiry,
                MedicalCertType::Variance,
            )))],
            &cfg(),
            as_of(),
        )
        .expect("valid input");
        assert!(rules_of(&variance).contains(&R_MED_WINDOW_OVERMAX));
        let expired = variance
            .iter()
            .find(|f| f.rule_id == R_MED)
            .expect("capped variance must expire before the campaign date");
        assert_eq!(expired.severity, Severity::Breach);

        let full = evaluate(
            &[driver(file_with(medical(
                "med-1",
                issued,
                printed_expiry,
                MedicalCertType::Full,
            )))],
            &cfg(),
            as_of(),
        )
        .expect("valid input");
        assert!(!rules_of(&full).contains(&R_MED_EXPIRED));
        assert!(!rules_of(&full).contains(&R_MED_WINDOW_OVERMAX));
    }

    #[test]
    fn overmax_full_certificate_is_capped_and_can_expire() {
        // Printed expiry 2027-06-01 exceeds issuance (2024-01-01) + 24
        // months; the effective expiry is 2026-01-01 — already past.
        let doc = medical(
            "med-1",
            date(2024, 1, 1),
            date(2027, 6, 1),
            MedicalCertType::Full,
        );
        let findings = evaluate(&[driver(file_with(doc))], &cfg(), as_of()).expect("valid input");
        assert!(rules_of(&findings).contains(&R_MED_WINDOW_OVERMAX));
        assert!(rules_of(&findings).contains(&R_MED_EXPIRED));
    }

    // -- Window-typed items ---------------------------------------------------

    #[test]
    fn mvr_is_valid_through_the_window_boundary_day() {
        // Pulled exactly 365 days before the campaign date.
        let doc = doc("mvr-1", DocKind::Mvr, as_of() - Days::new(365));
        let findings = evaluate(&[driver(file_with(doc))], &cfg(), as_of()).expect("valid input");
        assert!(!rules_of(&findings).contains(&R_MVR_STALE));
        assert!(rules_of(&findings).contains(&R_EXPIRING_SOON));
    }

    #[test]
    fn mvr_is_stale_the_day_after_the_window_boundary() {
        let doc = doc("mvr-1", DocKind::Mvr, as_of() - Days::new(366));
        let findings = evaluate(&[driver(file_with(doc))], &cfg(), as_of()).expect("valid input");
        let stale = findings
            .iter()
            .find(|f| f.rule_id == R_MVR_STALE)
            .expect("stale MVR must be found");
        assert_eq!(stale.severity, Severity::Warn);
        assert!(!rules_of(&findings).contains(&R_EXPIRING_SOON));
    }

    #[test]
    fn annual_review_window_boundary() {
        // One day inside the 365-day window: warn, not stale.
        let inside = doc("annual-1", DocKind::AnnualReview, as_of() - Days::new(364));
        let findings =
            evaluate(&[driver(file_with(inside))], &cfg(), as_of()).expect("valid input");
        assert!(!rules_of(&findings).contains(&R_ANNUAL_STALE));
        assert!(rules_of(&findings).contains(&R_EXPIRING_SOON));

        // One day outside: stale.
        let outside = doc("annual-1", DocKind::AnnualReview, as_of() - Days::new(366));
        let findings =
            evaluate(&[driver(file_with(outside))], &cfg(), as_of()).expect("valid input");
        assert!(rules_of(&findings).contains(&R_ANNUAL_STALE));
    }

    // -- Expiring-soon window -------------------------------------------------

    #[test]
    fn expiring_soon_fires_on_the_last_included_day() {
        let doc = cdl_base("cdl-1", date(2020, 1, 1), as_of() + Days::new(30));
        let findings = evaluate(&[driver(file_with(doc))], &cfg(), as_of()).expect("valid input");
        assert!(rules_of(&findings).contains(&R_EXPIRING_SOON));
        assert!(!rules_of(&findings).contains(&R_CDL_EXPIRED));
    }

    #[test]
    fn expiring_soon_does_not_fire_one_day_outside() {
        let doc = cdl_base("cdl-1", date(2020, 1, 1), as_of() + Days::new(31));
        let findings = evaluate(&[driver(file_with(doc))], &cfg(), as_of()).expect("valid input");
        assert!(!rules_of(&findings).contains(&R_EXPIRING_SOON));
        assert!(!rules_of(&findings).contains(&R_CDL_EXPIRED));
    }

    // -- Endorsements and state rules -----------------------------------------

    #[test]
    fn operation_required_endorsement_missing_is_flagged() {
        let mut d = driver(full_dqf());
        d.operation_required_endorsements = vec!["H".to_string()];
        let findings = evaluate(&[d], &cfg(), as_of()).expect("valid input");
        let flagged = findings
            .iter()
            .find(|f| f.rule_id == R_ENDORSEMENT_MISSING)
            .expect("missing operation endorsement must be found");
        assert_eq!(flagged.severity, Severity::Warn);
        assert!(format!("{:?}", flagged.message).contains("H"));
    }

    #[test]
    fn state_rule_endorsement_and_its_satisfaction() {
        let mut config = cfg();
        config.state_cdl_rules = vec![crate::config::StateCdlRule {
            state: "CA".to_string(),
            required_endorsements: vec!["T".to_string()],
            max_cdl_validity_months: None,
        }];
        let mut d = driver(full_dqf());
        d.cdl_state = "CA".to_string();
        let findings = evaluate(&[d.clone()], &config, as_of()).expect("valid input");
        let flagged = findings
            .iter()
            .find(|f| f.rule_id == R_STATE_CDL_RULE)
            .expect("missing state endorsement must be found");
        assert!(flagged.message.contains("CA"));

        // A CDL holding the endorsement satisfies the rule (case-insensitive).
        let docs: Vec<Document> = full_dqf()
            .into_iter()
            .map(|mut doc| {
                if doc.kind == DocKind::Cdl {
                    doc.endorsements = Some(vec!["t".to_string()]);
                }
                doc
            })
            .collect();
        d.documents = docs;
        let findings = evaluate(&[d], &config, as_of()).expect("valid input");
        assert!(!rules_of(&findings).contains(&R_STATE_CDL_RULE));
    }

    #[test]
    fn state_max_cdl_validity_caps_expiry() {
        let mut config = cfg();
        config.state_cdl_rules = vec![crate::config::StateCdlRule {
            state: "TX".to_string(),
            required_endorsements: vec![],
            max_cdl_validity_months: Some(12),
        }];
        // Printed expiry 2027-09-01 exceeds issuance (2025-09-01) + 12
        // months; effective expiry 2026-09-01 is already past.
        let doc = cdl_base("cdl-1", date(2025, 9, 1), date(2027, 9, 1));
        let findings = evaluate(&[driver(file_with(doc))], &config, as_of()).expect("valid input");
        assert!(rules_of(&findings).contains(&R_CDL_WINDOW_OVERMAX));
        assert!(rules_of(&findings).contains(&R_CDL_EXPIRED));
    }

    // -- Governing document ----------------------------------------------------

    #[test]
    fn latest_document_governs_renewal_history() {
        // An expired CDL superseded by a current renewal must not flag.
        let old = cdl_base("cdl-old", date(2020, 1, 1), date(2024, 6, 1));
        let new = cdl_base("cdl-new", date(2025, 6, 1), date(2027, 6, 1));
        let docs = vec![old, new, rest_of_file_without(DocKind::Cdl)];
        let findings = evaluate(&[driver(docs)], &cfg(), as_of()).expect("valid input");
        assert!(!rules_of(&findings).contains(&R_CDL_EXPIRED));
    }

    #[test]
    fn latest_document_governs_even_when_worse() {
        // A current CDL superseded by an expired renewal must flag: the
        // governing document is the latest, not the best.
        let old = cdl_base("cdl-old", date(2025, 1, 1), date(2027, 1, 1));
        let new = cdl_base("cdl-new", date(2025, 12, 1), date(2026, 1, 1));
        let docs = vec![old, new, rest_of_file_without(DocKind::Cdl)];
        let findings = evaluate(&[driver(docs)], &cfg(), as_of()).expect("valid input");
        assert!(rules_of(&findings).contains(&R_CDL_EXPIRED));
    }

    fn rest_of_file_without(kind: DocKind) -> Document {
        full_dqf()
            .into_iter()
            .find(|d| d.kind != kind && d.kind != DocKind::MedicalCertificate)
            .expect("full file has other kinds")
    }

    // -- Rehire linkage ---------------------------------------------------------

    #[test]
    fn rehire_linkage_unknown_prior_cycle_is_flagged() {
        let mut d = driver(full_dqf());
        d.rehire = Some(Rehire {
            rehire_date: date(2026, 1, 5),
            prior_cycle_id: "CY-2025".to_string(),
        });
        d.prior_cycles = vec![];
        let findings = evaluate(&[d], &cfg(), as_of()).expect("valid input");
        let flagged = findings
            .iter()
            .find(|f| f.rule_id == R_REHIRE_LINKAGE)
            .expect("unknown prior cycle must be flagged");
        assert_eq!(flagged.severity, Severity::Warn);
    }

    #[test]
    fn prior_cycle_documents_do_not_satisfy_the_current_cycle() {
        let mut d = driver(vec![]);
        d.cycle_id = "CY-2026".to_string();
        d.prior_cycles = vec!["CY-2025".to_string()];
        d.rehire = Some(Rehire {
            rehire_date: date(2026, 1, 5),
            prior_cycle_id: "CY-2025".to_string(),
        });
        let mut old_cdl = cdl_base("cdl-old", date(2020, 1, 1), date(2025, 6, 1));
        old_cdl.cycle_id = "CY-2025".to_string();
        let mut old_mvr = doc("mvr-old", DocKind::Mvr, date(2025, 6, 1));
        old_mvr.cycle_id = "CY-2025".to_string();
        d.documents = vec![old_cdl, old_mvr];
        let findings = evaluate(&[d], &cfg(), as_of()).expect("valid input");
        let rules = rules_of(&findings);
        // Prior-cycle docs are out of cycle and every required item gaps.
        assert!(rules.iter().filter(|r| **r == R_OUT_OF_CYCLE_DOC).count() == 2);
        assert!(rules.contains(&R_CDL_MISSING));
        assert!(rules.contains(&R_MED_MISSING));
        assert!(rules.contains(&R_MVR_MISSING));
        assert!(rules.contains(&R_ANNUAL_MISSING));
        assert!(rules.contains(&R_ROADTEST_MISSING));
        assert!(rules.contains(&R_EMPHIST_MISSING));
        // The rehire linkage itself is valid (prior cycle is known).
        assert!(!rules.contains(&R_REHIRE_LINKAGE));
    }

    #[test]
    fn rehire_with_fresh_current_cycle_docs_is_clean() {
        let mut d = driver(full_dqf());
        d.prior_cycles = vec!["CY-2025".to_string()];
        d.rehire = Some(Rehire {
            rehire_date: date(2026, 1, 5),
            prior_cycle_id: "CY-2025".to_string(),
        });
        let findings = evaluate(&[d], &cfg(), as_of()).expect("valid input");
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    // -- Fail-closed input shape -------------------------------------------------

    #[test]
    fn future_issued_document_is_refused() {
        let mut doc = doc("mvr-1", DocKind::Mvr, as_of() + Days::new(1));
        doc.cycle_id = "CY-2026".to_string();
        let result = evaluate(&[driver(vec![doc])], &cfg(), as_of());
        assert!(matches!(result, Err(DqfError::MalformedDocument { .. })));
    }

    #[test]
    fn future_hire_date_is_refused() {
        let mut d = driver(full_dqf());
        d.hire_date = as_of() + Days::new(1);
        let result = evaluate(&[d], &cfg(), as_of());
        assert!(matches!(result, Err(DqfError::MalformedDriver { .. })));
    }

    #[test]
    fn duplicate_driver_id_is_refused() {
        let result = evaluate(&[driver(full_dqf()), driver(full_dqf())], &cfg(), as_of());
        let err = result.expect_err("duplicate driver id must be refused");
        assert!(err.to_string().contains("duplicate"), "got: {err}");
    }

    #[test]
    fn duplicate_doc_id_is_refused() {
        let a = cdl_base("same", date(2020, 1, 1), date(2027, 1, 1));
        let b = cdl_base("same", date(2025, 1, 1), date(2027, 1, 1));
        let result = evaluate(&[driver(vec![a, b])], &cfg(), as_of());
        let err = result.expect_err("duplicate document id must be refused");
        assert!(err.to_string().contains("duplicate"), "got: {err}");
    }

    #[test]
    fn document_contradicting_its_kind_is_refused() {
        // An MVR cannot carry a cert_type.
        let mut mvr = doc("mvr-1", DocKind::Mvr, date(2026, 5, 1));
        mvr.cert_type = Some(MedicalCertType::Full);
        let result = evaluate(&[driver(vec![mvr])], &cfg(), as_of());
        assert!(matches!(result, Err(DqfError::MalformedDocument { .. })));
    }

    // -- Determinism --------------------------------------------------------------

    #[test]
    fn findings_are_sorted_and_reproducible() {
        let mut messy = driver(file_with(medical(
            "med-1",
            date(2024, 6, 1),
            as_of() - Days::new(1),
            MedicalCertType::Full,
        )));
        messy.driver_id = "D-002".to_string();
        let drivers = vec![messy, driver(full_dqf())];
        let first = evaluate(&drivers, &cfg(), as_of()).expect("valid input");
        let second = evaluate(&drivers, &cfg(), as_of()).expect("valid input");
        // `Finding` carries no `PartialEq` — compare the canonical JSON forms.
        assert_eq!(
            serde_json::to_string(&first).expect("serialization cannot fail"),
            serde_json::to_string(&second).expect("serialization cannot fail")
        );
        let keys: Vec<(&str, &str)> = first
            .iter()
            .map(|f| (f.subject.as_str(), f.rule_id.as_str()))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "findings must be sorted by (subject, rule)");
    }

    // -- Governance through the spine contract (JSON path) ------------------------

    const CONFIG_JSON: &str = r#"{
        "expiring_warn_days": 30,
        "mvr_validity_days": 365,
        "annual_review_validity_days": 365,
        "medical": {"full_max_months": 24, "variance_max_months": 12},
        "checklist": {
            "cdl": {}, "medical_certificate": {}, "mvr": {},
            "annual_review": {}, "road_test": {}, "employment_history": {}
        },
        "state_cdl_rules": []
    }"#;

    const CLEAN_DRIVERS_JSON: &str = r#"{"drivers": [{
        "driver_id": "D-001", "employee_id": "E-100", "cycle_id": "CY-2026",
        "hire_date": "2020-01-01", "active": true, "cdl_state": "TX",
        "documents": [
            {"doc_id": "c1", "kind": "cdl", "cycle_id": "CY-2026", "issued_on": "2024-09-01", "expires_on": "2027-09-01", "state": "TX", "endorsements": []},
            {"doc_id": "m1", "kind": "medical_certificate", "cycle_id": "CY-2026", "issued_on": "2025-09-01", "expires_on": "2027-09-01", "cert_type": "full"},
            {"doc_id": "v1", "kind": "mvr", "cycle_id": "CY-2026", "issued_on": "2026-05-01"},
            {"doc_id": "a1", "kind": "annual_review", "cycle_id": "CY-2026", "issued_on": "2026-08-01"},
            {"doc_id": "r1", "kind": "road_test", "cycle_id": "CY-2026", "issued_on": "2024-02-01"},
            {"doc_id": "h1", "kind": "employment_history", "cycle_id": "CY-2026", "issued_on": "2020-01-01"}
        ]
    }]}"#;

    const BREACH_DRIVERS_JSON: &str = r#"{"drivers": [{
        "driver_id": "D-101", "employee_id": "E-101", "cycle_id": "CY-2026",
        "hire_date": "2020-01-01", "active": true, "cdl_state": "TX",
        "documents": [
            {"doc_id": "c1", "kind": "cdl", "cycle_id": "CY-2026", "issued_on": "2024-01-01", "expires_on": "2027-01-01", "state": "TX", "endorsements": []},
            {"doc_id": "m1", "kind": "medical_certificate", "cycle_id": "CY-2026", "issued_on": "2024-01-01", "expires_on": "2025-06-01", "cert_type": "full"},
            {"doc_id": "v1", "kind": "mvr", "cycle_id": "CY-2026", "issued_on": "2026-05-01"},
            {"doc_id": "a1", "kind": "annual_review", "cycle_id": "CY-2026", "issued_on": "2026-05-01"},
            {"doc_id": "r1", "kind": "road_test", "cycle_id": "CY-2026", "issued_on": "2024-01-01"},
            {"doc_id": "h1", "kind": "employment_history", "cycle_id": "CY-2026", "issued_on": "2020-01-01"}
        ]
    }]}"#;

    const MIXED_DRIVERS_JSON: &str = r#"{"drivers": [
        {"driver_id": "D-201", "employee_id": "E-201", "cycle_id": "CY-2026",
         "hire_date": "2020-01-01", "active": true, "cdl_state": "TX", "documents": []},
        {"driver_id": "D-101", "employee_id": "E-101", "cycle_id": "CY-2026",
         "hire_date": "2020-01-01", "active": true, "cdl_state": "TX",
         "documents": [
            {"doc_id": "m1", "kind": "medical_certificate", "cycle_id": "CY-2026",
             "issued_on": "2024-01-01", "expires_on": "2025-06-01", "cert_type": "full"}
         ]},
        {"driver_id": "D-301", "employee_id": "E-301", "cycle_id": "CY-2026",
         "hire_date": "2020-01-01", "active": true, "cdl_state": "TX",
         "rehire": {"rehire_date": "2026-01-05", "prior_cycle_id": "CY-2025"},
         "prior_cycles": ["CY-2025"],
         "documents": [
            {"doc_id": "v1", "kind": "mvr", "cycle_id": "CY-2025", "issued_on": "2025-06-01"}
         ]}
    ]}"#;

    fn clean_pack() -> spine::EvidencePack {
        crate::build_pack(
            CLEAN_DRIVERS_JSON.as_bytes(),
            CONFIG_JSON.as_bytes(),
            as_of(),
        )
        .expect("clean fixture computes")
    }

    fn breach_pack() -> spine::EvidencePack {
        crate::build_pack(
            BREACH_DRIVERS_JSON.as_bytes(),
            CONFIG_JSON.as_bytes(),
            as_of(),
        )
        .expect("breach fixture computes")
    }

    #[test]
    fn clean_pack_seals_and_verifies() {
        let pack = clean_pack();
        assert_eq!(pack.engine_id, crate::ENGINE_ID);
        assert_eq!(pack.spine_version, spine::SPINE_VERSION);
        assert!(!pack.body_hash.is_empty(), "compute emits a sealed pack");
        assert!(pack.findings.is_empty());
        let inputs = CLEAN_DRIVERS_JSON.as_bytes();
        let params = CONFIG_JSON.as_bytes();
        assert_eq!(pack.verify(inputs, params), Ok(()));
        assert_eq!(
            pack.inputs_hash,
            spine::sha256_hex(inputs),
            "inputs hash covers the exact input bytes"
        );
        assert_eq!(pack.params_hash, spine::sha256_hex(params));
    }

    #[test]
    fn oos_pack_refuses_verify_until_a_subject_scoped_signoff() {
        let inputs = BREACH_DRIVERS_JSON.as_bytes();
        let params = CONFIG_JSON.as_bytes();
        let mut pack = breach_pack();
        assert!(pack
            .findings
            .iter()
            .any(|f| f.rule_id == R_MED_EXPIRED && f.severity == Severity::Breach));

        // Unsigned: refuse.
        assert_eq!(
            pack.verify(inputs, params),
            Err(VerifyError::UnresolvedBreach {
                rule_id: R_MED_EXPIRED.to_string()
            })
        );

        // An engine cannot countersign its own pack (separate duties).
        pack.signoffs.push(signoff(crate::ENGINE_ID, "D-101"));
        let voided = pack.clone().sealed();
        assert_eq!(
            voided.verify(inputs, params),
            Err(VerifyError::UnresolvedBreach {
                rule_id: R_MED_EXPIRED.to_string()
            })
        );

        // A signoff names the subject it covers — a different driver's
        // receipt resolves nothing.
        pack.signoffs = vec![signoff("sam", "D-OTHER")];
        let scoped = pack.clone().sealed();
        assert_eq!(
            scoped.verify(inputs, params),
            Err(VerifyError::UnresolvedBreach {
                rule_id: R_MED_EXPIRED.to_string()
            })
        );

        // A human receipt for the finding's subject resolves it — but only
        // through the lock lifecycle, which re-seals on Signed.
        pack.signoffs = vec![signoff("sam", "D-101")];
        let state = spine::advance_lock(LockState::Draft, &mut pack).expect("draft advances");
        assert_eq!(state, LockState::AwaitingSignoff);
        let state = spine::advance_lock(state, &mut pack).expect("breach resolved");
        assert_eq!(state, LockState::Signed);
        assert_eq!(pack.verify(inputs, params), Ok(()));
    }

    #[test]
    fn four_eyes_is_required_to_resolve_an_oos_breach() {
        let mut pack = breach_pack();
        pack.signoffs = vec![signoff("sam", "D-101")];
        assert!(
            !crate::four_eyes_ok_for_subject(&pack, "D-101"),
            "one signer is not four-eyes"
        );
        // Same signer in different case is still one signer (fail-closed
        // under-count of distinctness).
        pack.signoffs = vec![signoff("sam", "D-101"), signoff("SAM", "D-101")];
        assert!(!crate::four_eyes_ok_for_subject(&pack, "D-101"));
        // An engine-actor receipt does not count toward the two signers.
        pack.signoffs = vec![signoff(crate::ENGINE_ID, "D-101"), signoff("sam", "D-101")];
        assert!(!crate::four_eyes_ok_for_subject(&pack, "D-101"));
        // Two distinct human signers satisfy the gate.
        pack.signoffs = vec![signoff("sam", "D-101"), signoff("alex", "D-101")];
        assert!(crate::four_eyes_ok_for_subject(&pack, "D-101"));
    }

    #[test]
    fn tampered_body_refuses_verify() {
        let pack = breach_pack();
        let mut tampered = pack.clone();
        tampered.findings.clear();
        assert_eq!(
            tampered.verify(BREACH_DRIVERS_JSON.as_bytes(), CONFIG_JSON.as_bytes()),
            Err(VerifyError::BodyHashMismatch)
        );
        let mut altered = breach_pack();
        altered.tool_version = "9.9.9".to_string();
        assert_eq!(
            altered.verify(BREACH_DRIVERS_JSON.as_bytes(), CONFIG_JSON.as_bytes()),
            Err(VerifyError::BodyHashMismatch)
        );
    }

    #[test]
    fn tampered_inputs_and_params_refuse_verify() {
        let pack = breach_pack();
        assert_eq!(
            pack.verify(b"tampered", CONFIG_JSON.as_bytes()),
            Err(VerifyError::HashMismatch { field: "inputs" })
        );
        assert_eq!(
            pack.verify(BREACH_DRIVERS_JSON.as_bytes(), b"tampered"),
            Err(VerifyError::HashMismatch { field: "params" })
        );
    }

    #[test]
    fn foreign_spine_version_refuses_verify() {
        let mut pack = clean_pack();
        pack.spine_version = "0.0.1".to_string();
        assert_eq!(
            pack.verify(CLEAN_DRIVERS_JSON.as_bytes(), CONFIG_JSON.as_bytes()),
            Err(VerifyError::ForeignVersion)
        );
    }

    #[test]
    fn compute_is_deterministic() {
        let args = (
            MIXED_DRIVERS_JSON.as_bytes(),
            CONFIG_JSON.as_bytes(),
            as_of(),
        );
        let a = crate::build_pack(args.0, args.1, args.2).expect("mixed fixture computes");
        let b = crate::build_pack(args.0, args.1, args.2).expect("mixed fixture computes");
        assert_eq!(
            serde_json::to_vec(&a).expect("serialization cannot fail"),
            serde_json::to_vec(&b).expect("serialization cannot fail"),
            "identical inputs and params must produce identical pack bytes"
        );
    }

    fn signoff(actor: &str, subject: &str) -> Signoff {
        Signoff {
            actor: actor.to_string(),
            role: "safety_director".to_string(),
            subject: subject.to_string(),
            decision: SignoffDecision::Approve,
            at: "2026-09-22T00:00:00Z".to_string(),
        }
    }
}
