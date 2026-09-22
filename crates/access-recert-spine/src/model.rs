//! Typed, schema-checked campaign inputs and config tables.
//!
//! Every struct refuses unknown fields (`deny_unknown_fields`): a feed
//! that drifts from the agreed schema fails loudly instead of silently
//! changing rule semantics. Dates deserialize from `YYYY-MM-DD` strings
//! into chrono `NaiveDate`. The engine never reads a clock — every date
//! is caller input.

use std::collections::HashSet;

use chrono::NaiveDate;
use serde::Deserialize;
use spine::Signoff;

/// Quarterly recertification campaign: the population under review.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignInput {
    /// Campaign identifier, echoed in operator output for correlation.
    pub campaign_id: String,
    /// Caller-supplied clock. Every dated rule evaluates against this date.
    pub campaign_date: NaiveDate,
    /// HR identity directory. The match key is `employee_id`, never email.
    pub identities: Vec<IdentityRecord>,
    /// Managed systems an entitlement may belong to.
    pub systems: Vec<SystemRecord>,
    /// Entitlements under review.
    pub entitlements: Vec<EntitlementRecord>,
    /// Retention approvals collected during the campaign. Each approval's
    /// subject is an entitlement id. They feed the privileged four-eyes
    /// rule and travel on the evidence pack as signoff receipts.
    #[serde(default)]
    pub retention_approvals: Vec<Signoff>,
}

/// An HR identity. `employee_id` is the only match key; `email` is carried
/// for display and is explicitly never used to attribute entitlements
/// (mailboxes are recycled).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRecord {
    pub employee_id: String,
    pub email: String,
    pub display_name: String,
    /// Manager of record; `None` or a dangling id is an orphan-manager
    /// finding, not a schema error — it describes the population.
    pub manager_id: Option<String>,
    pub hire_date: NaiveDate,
    /// Separation date, if the identity has left.
    pub separation_date: Option<NaiveDate>,
}

/// A managed system an entitlement may belong to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemRecord {
    pub system_id: String,
    pub display_name: String,
}

/// An entitlement under review.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementRecord {
    pub entitlement_id: String,
    /// Owning system; unknown ids are an orphan-system finding.
    pub system_id: String,
    /// The only identity match key this engine honors. A value that does
    /// not resolve to an HR identity is quarantined — never matched by
    /// email.
    pub employee_id: String,
    /// Email the source system reported for this grant. NEVER used to
    /// attribute the entitlement (mailboxes are recycled).
    pub email: String,
    /// System-specific entitlement name, e.g. `repo:acme/api`.
    pub entitlement_key: String,
    /// Privileged access requires four-eyes approval to retain.
    pub privileged: bool,
    pub granted_at: NaiveDate,
    /// Last successful authentication, if any. `None` is always stale.
    pub last_authenticated_at: Option<NaiveDate>,
}

/// Rule thresholds. Shipped values are seed data (see README).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecertConfig {
    /// Stale window: an authentication older than this many days (or
    /// never recorded) is a stale finding. An authentication exactly this
    /// many days old is inside the window.
    pub stale_days: u32,
    /// New-hire grace: identities hired within this many days of the
    /// campaign date (inclusive) are exempt from the stale and
    /// orphan-manager rules.
    pub new_hire_grace_days: u32,
}

/// Schema-level validation the rules assume: unique, non-blank keys and
/// internally consistent dates. Rule-level problems (unknown system,
/// dangling manager, unmatchable identity) are findings, not validation
/// errors — they describe the population under review.
pub fn validate(input: &CampaignInput) -> Result<(), String> {
    let mut problems: Vec<String> = Vec::new();

    if input.campaign_id.trim().is_empty() {
        problems.push("campaign_id must be non-blank".to_string());
    }

    let mut identity_ids: HashSet<&str> = HashSet::new();
    for identity in &input.identities {
        if identity.employee_id.trim().is_empty() {
            problems.push(format!(
                "identity {name:?} has a blank employee_id",
                name = identity.display_name
            ));
        }
        if !identity_ids.insert(identity.employee_id.as_str()) {
            problems.push(format!(
                "duplicate identity employee_id {id:?}",
                id = identity.employee_id
            ));
        }
        if identity.hire_date > input.campaign_date {
            problems.push(format!(
                "identity {id} has hire_date {hire} after campaign date {campaign}",
                id = identity.employee_id,
                hire = identity.hire_date,
                campaign = input.campaign_date
            ));
        }
        if let Some(separated_on) = identity.separation_date {
            if separated_on < identity.hire_date {
                problems.push(format!(
                    "identity {id} has separation_date {sep} before hire_date {hire}",
                    id = identity.employee_id,
                    sep = separated_on,
                    hire = identity.hire_date
                ));
            }
        }
    }

    let mut entitlement_ids: HashSet<&str> = HashSet::new();
    for entitlement in &input.entitlements {
        if entitlement.entitlement_id.trim().is_empty() {
            problems.push("entitlement with blank entitlement_id".to_string());
        }
        if !entitlement_ids.insert(entitlement.entitlement_id.as_str()) {
            problems.push(format!(
                "duplicate entitlement_id {id:?}",
                id = entitlement.entitlement_id
            ));
        }
        if entitlement.system_id.trim().is_empty() {
            problems.push(format!(
                "entitlement {id} has a blank system_id",
                id = entitlement.entitlement_id
            ));
        }
        if entitlement.granted_at > input.campaign_date {
            problems.push(format!(
                "entitlement {id} has granted_at {grant} after campaign date {campaign}",
                id = entitlement.entitlement_id,
                grant = entitlement.granted_at,
                campaign = input.campaign_date
            ));
        }
        if let Some(last) = entitlement.last_authenticated_at {
            if last > input.campaign_date {
                problems.push(format!(
                    "entitlement {id} has last_authenticated_at {last} after campaign date {campaign}",
                    id = entitlement.entitlement_id,
                    last = last,
                    campaign = input.campaign_date
                ));
            }
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "campaign input failed schema validation: {}",
            problems.join("; ")
        ))
    }
}
