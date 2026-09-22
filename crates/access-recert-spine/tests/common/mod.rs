//! Shared fixtures for engine and pack-lifecycle tests.

#![allow(dead_code)]

use chrono::NaiveDate;
use spine::{Signoff, SignoffDecision};

use access_recert_spine::model::{
    CampaignInput, EntitlementRecord, IdentityRecord, RecertConfig, SystemRecord,
};

pub const ENGINE: &str = "access-recert-spine";
pub const CAMPAIGN_DATE: &str = "2026-09-22";

/// Parse a `YYYY-MM-DD` test date.
pub fn d(value: &str) -> NaiveDate {
    value.parse().expect("valid YYYY-MM-DD test date")
}

/// An identity with a resolvable manager of record (E-MGR) and a fresh
/// authentication history — override fields per scenario.
pub fn identity(employee_id: &str) -> IdentityRecord {
    IdentityRecord {
        employee_id: employee_id.to_string(),
        email: format!("{employee_id}@corp.example"),
        display_name: format!("identity {employee_id}"),
        manager_id: Some("E-MGR".to_string()),
        hire_date: d("2020-01-01"),
        separation_date: None,
    }
}

pub fn system(system_id: &str) -> SystemRecord {
    SystemRecord {
        system_id: system_id.to_string(),
        display_name: format!("system {system_id}"),
    }
}

pub fn one_system() -> Vec<SystemRecord> {
    vec![system("github")]
}

/// A clean entitlement: managed system, existing identity, fresh auth.
pub fn entitlement(entitlement_id: &str) -> EntitlementRecord {
    EntitlementRecord {
        entitlement_id: entitlement_id.to_string(),
        system_id: "github".to_string(),
        employee_id: "E-1".to_string(),
        email: "one@corp.example".to_string(),
        entitlement_key: format!("repo:acme/{entitlement_id}"),
        privileged: false,
        granted_at: d("2025-01-01"),
        last_authenticated_at: Some(d("2026-09-01")),
    }
}

pub fn campaign(
    identities: Vec<IdentityRecord>,
    entitlements: Vec<EntitlementRecord>,
) -> CampaignInput {
    CampaignInput {
        campaign_id: "2026-Q3".to_string(),
        campaign_date: d(CAMPAIGN_DATE),
        identities,
        systems: one_system(),
        entitlements,
        retention_approvals: Vec::new(),
    }
}

pub fn config() -> RecertConfig {
    RecertConfig {
        stale_days: 90,
        new_hire_grace_days: 30,
    }
}

pub fn approval(actor: &str, subject: &str, decision: SignoffDecision) -> Signoff {
    Signoff {
        actor: actor.to_string(),
        role: "manager".to_string(),
        subject: subject.to_string(),
        decision,
        at: "2026-09-20T10:00:00Z".to_string(),
    }
}
