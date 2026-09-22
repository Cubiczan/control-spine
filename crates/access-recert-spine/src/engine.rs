//! Pure rule evaluation for the access recertification campaign.
//!
//! [`evaluate`] is a pure function of (input, config, engine_id): no
//! clock, no filesystem, no network, no randomness. All dates arrive in
//! the input; all thresholds arrive in the config. Findings are sorted by
//! (subject, rule_id) so identical inputs produce identical output
//! regardless of input ordering.

use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;
use spine::{four_eyes_satisfied, Finding, Severity, Signoff};

use crate::model::{CampaignInput, EntitlementRecord, IdentityRecord, RecertConfig};

/// Active entitlement held by an identity separated before the campaign
/// date. Breach severity: the access must be revoked or explicitly signed
/// off before the pack can qualify as evidence.
pub const RULE_LEAVER_ACTIVE: &str = "leaver-active-entitlement";
/// Entitlement on a system with no managed-system record.
pub const RULE_ORPHAN_SYSTEM: &str = "orphan-system";
/// Identity's manager of record is missing or unresolvable.
pub const RULE_ORPHAN_MANAGER: &str = "orphan-manager";
/// No successful authentication within the configured window.
pub const RULE_STALE_AUTH: &str = "stale-auth";
/// Privileged entitlement retained without four-eyes approval.
pub const RULE_PRIVILEGED_FOUR_EYES: &str = "privileged-four-eyes";
/// Entitlement could not be matched to an HR identity by employee_id.
pub const RULE_QUARANTINE: &str = "quarantine";

/// Evaluate every entitlement against every rule.
///
/// Rules are independent and compose: one entitlement can carry several
/// findings. A separation date strictly before the campaign date makes the
/// identity a leaver. An authentication exactly `stale_days` old is still
/// inside the window (strict `>` fires). New-hire grace (inclusive window)
/// exempts only the stale and orphan-manager rules.
pub fn evaluate(input: &CampaignInput, config: &RecertConfig, engine_id: &str) -> Vec<Finding> {
    let systems: HashSet<&str> = input.systems.iter().map(|s| s.system_id.as_str()).collect();
    let identities: HashMap<&str, &IdentityRecord> = input
        .identities
        .iter()
        .map(|i| (i.employee_id.as_str(), i))
        .collect();
    let employee_ids: HashSet<&str> = identities.keys().copied().collect();

    let mut findings = Vec::new();
    for entitlement in &input.entitlements {
        let identity = match identities.get(entitlement.employee_id.as_str()) {
            Some(identity) => *identity,
            None => {
                // Fail-closed: an entitlement that cannot be attributed to
                // an HR identity by employee_id is quarantined for manual
                // handling — never dropped, never attributed by email.
                findings.push(Finding {
                    rule_id: RULE_QUARANTINE.to_string(),
                    severity: Severity::Warn,
                    subject: entitlement.entitlement_id.clone(),
                    message: format!(
                        "entitlement {ent} on system {sys} could not be matched to an HR identity by employee_id {emp:?}; quarantined for manual attribution",
                        ent = entitlement.entitlement_id,
                        sys = entitlement.system_id,
                        emp = entitlement.employee_id
                    ),
                    requires_signoff: true,
                });
                continue;
            }
        };

        // Leaver rule: a separation date on the campaign date itself has
        // not taken effect yet — strictly-before fires.
        if let Some(separated_on) = identity.separation_date {
            if separated_on < input.campaign_date {
                findings.push(Finding::breach(
                    RULE_LEAVER_ACTIVE,
                    entitlement.entitlement_id.as_str(),
                    format!(
                        "identity {id} was separated on {sep} (before campaign date {campaign}) but retains entitlement {ent} on system {sys}",
                        id = identity.employee_id,
                        sep = separated_on,
                        campaign = input.campaign_date,
                        ent = entitlement.entitlement_id,
                        sys = entitlement.system_id
                    ),
                ));
            }
        }

        // Orphan-system rule: the entitlement's owning system has no
        // managed-system record, so it can be neither reviewed nor revoked
        // through a managed channel.
        if !systems.contains(entitlement.system_id.as_str()) {
            findings.push(Finding::breach(
                RULE_ORPHAN_SYSTEM,
                entitlement.entitlement_id.as_str(),
                format!(
                    "entitlement {ent} references system {sys} which has no managed-system record",
                    ent = entitlement.entitlement_id,
                    sys = entitlement.system_id
                ),
            ));
        }

        let in_grace = in_new_hire_grace(identity, input.campaign_date, config.new_hire_grace_days);

        // Orphan-manager rule: without a resolvable manager of record the
        // review cannot be routed. New hires inside the grace window are
        // exempt (manager records may still be landing).
        if !in_grace && !manager_resolvable(identity, &employee_ids) {
            findings.push(Finding {
                rule_id: RULE_ORPHAN_MANAGER.to_string(),
                severity: Severity::Warn,
                subject: entitlement.entitlement_id.clone(),
                message: match &identity.manager_id {
                    Some(manager_id) => format!(
                        "identity {id} has manager of record {mgr} which does not resolve to an HR identity",
                        id = identity.employee_id,
                        mgr = manager_id
                    ),
                    None => format!(
                        "identity {id} has no manager of record",
                        id = identity.employee_id
                    ),
                },
                requires_signoff: false,
            });
        }

        // Stale rule: no successful authentication within the configured
        // window. `None` (never authenticated) is always stale.
        if !in_grace {
            let days_since_auth = entitlement
                .last_authenticated_at
                .map(|last| (input.campaign_date - last).num_days());
            let stale = match days_since_auth {
                None => true,
                Some(days) => days > config.stale_days as i64,
            };
            if stale {
                findings.push(Finding {
                    rule_id: RULE_STALE_AUTH.to_string(),
                    severity: Severity::Warn,
                    subject: entitlement.entitlement_id.clone(),
                    message: match entitlement.last_authenticated_at {
                        Some(last) => format!(
                            "no authentication on entitlement {ent} in {days} days (last on {last}, window is {window} days)",
                            ent = entitlement.entitlement_id,
                            days = days_since_auth.unwrap_or_default(),
                            window = config.stale_days
                        ),
                        None => format!(
                            "entitlement {ent} has no recorded authentication (window is {window} days)",
                            ent = entitlement.entitlement_id,
                            window = config.stale_days
                        ),
                    },
                    requires_signoff: false,
                });
            }
        }

        // Privileged four-eyes rule: retaining a privileged entitlement
        // requires two distinct approving signers (spine four-eyes).
        // Approvals are subject-scoped to the entitlement; the producing
        // engine's own approvals are void (separation of duties).
        if entitlement.privileged {
            let approvals = retention_approvals_for(entitlement, input, engine_id);
            if !four_eyes_satisfied(&approvals) {
                findings.push(Finding {
                    rule_id: RULE_PRIVILEGED_FOUR_EYES.to_string(),
                    severity: Severity::Warn,
                    subject: entitlement.entitlement_id.clone(),
                    message: format!(
                        "privileged entitlement {ent} lacks four-eyes approval to retain (requires 2 distinct approving signers)",
                        ent = entitlement.entitlement_id
                    ),
                    requires_signoff: true,
                });
            }
        }
    }

    findings.sort_by(|a, b| (&a.subject, &a.rule_id).cmp(&(&b.subject, &b.rule_id)));
    findings
}

/// New-hire grace: an identity hired within `grace_days` days of the
/// campaign date (inclusive) is inside the onboarding grace window.
fn in_new_hire_grace(identity: &IdentityRecord, campaign_date: NaiveDate, grace_days: u32) -> bool {
    (campaign_date - identity.hire_date).num_days() <= grace_days as i64
}

fn manager_resolvable(identity: &IdentityRecord, employee_ids: &HashSet<&str>) -> bool {
    match &identity.manager_id {
        None => false,
        Some(manager_id) => employee_ids.contains(manager_id.as_str()),
    }
}

/// Approvals scoped to this entitlement's subject, with the producing
/// engine's own approvals and blank actors removed (separation of duties).
fn retention_approvals_for(
    entitlement: &EntitlementRecord,
    input: &CampaignInput,
    engine_id: &str,
) -> Vec<Signoff> {
    input
        .retention_approvals
        .iter()
        .filter(|s| {
            s.subject == entitlement.entitlement_id
                && !s.actor.trim().is_empty()
                && !s.actor.trim().eq_ignore_ascii_case(engine_id.trim())
        })
        .cloned()
        .collect()
}
